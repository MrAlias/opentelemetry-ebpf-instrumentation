/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.ConnectionInfo;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiConsumer;

public final class JdkHttpClientPropagation implements BiConsumer<Object, Throwable> {
  public static final String PROPERTY = "otel.obi.java.agent.httpclient.propagation";
  private static final int MAX_TRACKED_REQUESTS = 10_000;
  private static final int CONNECTION_SIZE = 36;
  private static final int TRACE_ID_SIZE = 16;
  private static final int SPAN_ID_SIZE = 8;
  private static final int TRACE_ID_OFFSET = 3;
  private static final int SPAN_ID_OFFSET = TRACE_ID_OFFSET + TRACE_ID_SIZE * 2 + 1;
  private static final int FLAGS_OFFSET = SPAN_ID_OFFSET + SPAN_ID_SIZE * 2 + 1;
  private static final int TRACEPARENT_SIZE = FLAGS_OFFSET + 2;
  private static final int VALUE_OFFSET = 1 + CONNECTION_SIZE + Integer.BYTES;
  private static final int PARENT_OFFSET = VALUE_OFFSET + TRACEPARENT_SIZE;
  private static final int PARENT_SIZE = TRACE_ID_SIZE + SPAN_ID_SIZE + 2;
  private static final byte[] HEADER = "traceparent: ".getBytes(StandardCharsets.US_ASCII);
  private static final ThreadLocal<JdkHttpClientPropagation> current = new ThreadLocal<>();
  private static final Map<Object, JdkHttpClientPropagation> requests =
      Collections.synchronizedMap(new IdentityHashMap<>());
  private static int retainedReservations;

  // Resolved inside the JDK module by the inlined advice, then published together.
  public static volatile Method[] connectionMethods;
  private static volatile boolean available = true;

  private final JdkHttpClientPropagation previous;
  private final List<Object> instances = new ArrayList<>();
  private final List<NativeMemory> reservations = new ArrayList<>();
  private byte[] parent;
  private boolean active = true;

  private JdkHttpClientPropagation(JdkHttpClientPropagation previous) {
    this.previous = previous;
  }

  public static JdkHttpClientPropagation enter() {
    if (!available) {
      return null;
    }
    JdkHttpClientPropagation scope = new JdkHttpClientPropagation(current.get());
    current.set(scope);
    return scope;
  }

  public static void captureParent(JdkHttpClientPropagation scope) {
    if (scope == null) {
      return;
    }
    try {
      NativeMemory packet = new NativeMemory(1 + PARENT_SIZE);
      packet.setByte(0, OperationType.HTTP1_PARENT.code);
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
      if (packet.getBuffer().get(0) != 0) {
        scope.active = false;
        return;
      }
      scope.parent = new byte[PARENT_SIZE];
      ByteBuffer value = packet.getBuffer().duplicate();
      ((java.nio.Buffer) value).position(1);
      value.get(scope.parent);
    } catch (Throwable error) {
      disable(error);
    }
  }

  public static void restore(JdkHttpClientPropagation scope) {
    if (scope != null) {
      current.set(scope);
    }
  }

  public static void register(Object request, Object[] arguments, boolean initial) {
    JdkHttpClientPropagation scope = initial ? current.get() : null;
    if (!initial) {
      for (Object argument : arguments) {
        scope = requests.get(argument);
        if (scope != null) {
          break;
        }
      }
    }
    if (scope == null) {
      return;
    }
    synchronized (scope) {
      synchronized (requests) {
        if (scope.active
            && requests.size() < MAX_TRACKED_REQUESTS
            && !requests.containsKey(request)) {
          requests.put(request, scope);
          scope.instances.add(request);
        }
      }
    }
  }

  public static boolean contains(Object request) {
    return available && requests.containsKey(request);
  }

  public static void exit(JdkHttpClientPropagation scope) {
    if (scope == null) {
      return;
    }
    current.remove();
    restore(scope.previous);
    scope.accept(null, null);
  }

  public static void finishAsync(JdkHttpClientPropagation scope, CompletableFuture<?> future) {
    if (scope == null) {
      return;
    }
    current.remove();
    restore(scope.previous);
    if (future == null) {
      scope.accept(null, null);
    } else {
      future.whenComplete(scope);
    }
  }

  @Override
  public void accept(Object response, Throwable failure) {
    synchronized (this) {
      active = false;
      for (Object request : instances) {
        requests.remove(request);
      }
      for (NativeMemory packet : reservations) {
        try {
          packet.setByte(0, OperationType.HTTP1_TRACEPARENT_RELEASE.code);
          Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
        } catch (Throwable error) {
          disable(error);
        }
      }
      synchronized (requests) {
        retainedReservations -= reservations.size();
      }
      instances.clear();
      reservations.clear();
    }
  }

  public static synchronized void disable(Throwable error) {
    if (available) {
      available = false;
      try {
        System.setProperty(PROPERTY, "false");
      } catch (SecurityException ignored) {
      }
      System.err.println(
          "[OBI] Java HttpClient header propagation disabled: " + error.getClass().getName());
    }
  }

  static ByteBuffer prepareHeaders(List<ByteBuffer> buffers) {
    int length = 0;
    for (ByteBuffer buffer : buffers) {
      if (buffer == null
          || buffer.remaining()
              > ByteBufferExtractor.MAX_SIZE - HEADER.length - TRACEPARENT_SIZE - 2 - length) {
        return null;
      }
      length += buffer.remaining();
    }
    if (length < 4) {
      return null;
    }
    ByteBuffer result = ByteBuffer.allocate(length + HEADER.length + TRACEPARENT_SIZE + 2);
    for (ByteBuffer buffer : buffers) {
      result.put(buffer.duplicate());
    }
    byte[] bytes = result.array();
    if (bytes[length - 4] != '\r'
        || bytes[length - 3] != '\n'
        || bytes[length - 2] != '\r'
        || bytes[length - 1] != '\n') {
      return null;
    }
    int start = 0;
    for (int end = 1; end < length; end++) {
      if (bytes[end - 1] != '\r' || bytes[end] != '\n') {
        continue;
      }
      if (end - 1 == start && end != length - 1) {
        return null;
      }
      if (end - 1 - start >= HEADER.length - 1 && bytes[start + HEADER.length - 2] == ':') {
        int matched = 0;
        while (matched < HEADER.length - 2 && (bytes[start + matched] | 0x20) == HEADER[matched]) {
          matched++;
        }
        if (matched == HEADER.length - 2) {
          return null;
        }
      }
      start = end + 1;
    }
    ((java.nio.Buffer) result).position(length - 2);
    result.put(HEADER);
    int valueOffset = result.position();
    ((java.nio.Buffer) result).position(valueOffset + TRACEPARENT_SIZE);
    result.put((byte) '\r').put((byte) '\n').put((byte) '\r').put((byte) '\n');
    ((java.nio.Buffer) result).position(valueOffset);
    return result;
  }

  static boolean validTraceparent(ByteBuffer packet, int offset) {
    if (packet.get(offset) != '0' || packet.get(offset + 1) != '0') {
      return false;
    }
    boolean trace = false;
    boolean span = false;
    for (int i = TRACE_ID_OFFSET - 1; i < TRACEPARENT_SIZE; i++) {
      if (i == TRACE_ID_OFFSET - 1 || i == SPAN_ID_OFFSET - 1 || i == FLAGS_OFFSET - 1) {
        if (packet.get(offset + i) != '-') {
          return false;
        }
        continue;
      }
      byte value = packet.get(offset + i);
      if (!(value >= '0' && value <= '9') && !(value >= 'a' && value <= 'f')) {
        return false;
      }
      trace |= i < SPAN_ID_OFFSET - 1 && value != '0';
      span |= i >= SPAN_ID_OFFSET && i < FLAGS_OFFSET - 1 && value != '0';
    }
    return trace && span;
  }

  public static List<ByteBuffer> inject(
      Object request, SocketChannel channel, List<ByteBuffer> buffers) throws Exception {
    JdkHttpClientPropagation scope = requests.get(request);
    if (scope == null) {
      return buffers;
    }
    ByteBuffer headers = prepareHeaders(buffers);
    if (headers == null) {
      return buffers;
    }
    InetSocketAddress local = (InetSocketAddress) channel.getLocalAddress();
    InetSocketAddress remote = (InetSocketAddress) channel.getRemoteAddress();
    Connection connection =
        new Connection(local.getAddress(), local.getPort(), remote.getAddress(), remote.getPort());
    synchronized (scope) {
      if (!scope.active || scope.parent == null) {
        return buffers;
      }
      NativeMemory packet = new NativeMemory(PARENT_OFFSET + PARENT_SIZE);
      packet.setByte(0, OperationType.HTTP1_TRACEPARENT.code);
      ConnectionInfo.writeSendConnectionInfo(packet, 1, connection);
      packet.setInt(1 + CONNECTION_SIZE, headers.position());
      if (scope.parent != null) {
        packet.write(PARENT_OFFSET, scope.parent, 0, scope.parent.length);
      }
      synchronized (requests) {
        if (retainedReservations >= MAX_TRACKED_REQUESTS) {
          return buffers;
        }
        scope.reservations.add(packet);
        retainedReservations++;
      }
      Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
      if (packet.getBuffer().get(0) != 0 || !validTraceparent(packet.getBuffer(), VALUE_OFFSET)) {
        scope.reservations.remove(packet);
        synchronized (requests) {
          retainedReservations--;
        }
        return buffers;
      }
      ByteBuffer value = packet.getBuffer().duplicate();
      ((java.nio.Buffer) value).position(PARENT_OFFSET);
      value.get(scope.parent);
      ((java.nio.Buffer) value).limit(PARENT_OFFSET);
      ((java.nio.Buffer) value).position(VALUE_OFFSET);
      headers.put(value);
      ((java.nio.Buffer) headers).position(0);
      return Collections.singletonList(headers);
    }
  }
}
