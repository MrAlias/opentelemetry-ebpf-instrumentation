/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.ConnectionInfo;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.util.CappedConcurrentHashMap;
import java.lang.ref.WeakReference;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiPredicate;

public final class JdkHttpClientPropagation {
  public static final BiPredicate<String, String> ALL_HEADERS = (name, value) -> true;
  // Native tp_info_t, followed by connection_info_t and the HTTP/2 stream ID.
  public static final int CONTEXT_SIZE = 48;
  private static final int PACKET_PREFIX = 2;
  private static final int CONNECTION_SIZE = 36;
  private static final int TRACE_ID_SIZE = 16;
  private static final int SPAN_ID_SIZE = 8;
  private static final int FLAGS_OFFSET = 40;
  private static final int MAX_REQUESTS = 10_000;
  private static final char[] HEX = "0123456789abcdef".toCharArray();
  private static final ThreadLocal<Scope> current = new ThreadLocal<>();
  private static final CappedConcurrentHashMap<IdentityKey, byte[]> requests =
      new CappedConcurrentHashMap<>(MAX_REQUESTS);

  public static final class Scope {
    private final Scope previous;
    private final List<IdentityKey> keys = new ArrayList<>();

    private Scope(Scope previous) {
      this.previous = previous;
    }
  }

  public static final class IdentityKey {
    // Ring slots outlive map removals, so keys must not retain request bodies.
    private final WeakReference<Object> request;
    private final int identityHash;

    public IdentityKey(Object request) {
      this.request = new WeakReference<>(request);
      this.identityHash = System.identityHashCode(request);
    }

    @Override
    public int hashCode() {
      return identityHash;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      Object target = request.get();
      return target != null
          && other instanceof IdentityKey
          && ((IdentityKey) other).request.get() == target;
    }
  }

  public static Scope enter() {
    Scope scope = new Scope(current.get());
    current.set(scope);
    return scope;
  }

  public static void exit(Scope scope) {
    if (scope == null) {
      return;
    }
    for (IdentityKey key : scope.keys) {
      requests.remove(key);
    }
    if (scope.previous == null) {
      current.remove();
    } else {
      current.set(scope.previous);
    }
  }

  public static void remember(Object request) {
    if (current.get() == null) {
      return;
    }
    NativeMemory packet = new NativeMemory(PACKET_PREFIX + CONTEXT_SIZE);
    packet.setByte(0, OperationType.JDK_HTTP2_CONTEXT.code);
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
    if (packet.getBuffer().get(1) == 0) {
      return;
    }
    byte[] context = new byte[CONTEXT_SIZE];
    for (int i = 0; i < context.length; i++) {
      context[i] = packet.getBuffer().get(PACKET_PREFIX + i);
    }
    remember(request, context);
  }

  static void remember(Object request, byte[] context) {
    Scope scope = current.get();
    if (scope == null) {
      return;
    }
    IdentityKey key = new IdentityKey(request);
    scope.keys.add(key);
    requests.put(key, context);
  }

  public static boolean tracked(Object request) {
    return requests.get(new IdentityKey(request)) != null;
  }

  public static String value(Object request) {
    byte[] context = requests.get(new IdentityKey(request));
    return context == null ? null : traceparent(context);
  }

  public static boolean bind(Object request, SocketChannel channel, int streamId) throws Exception {
    byte[] context = requests.remove(new IdentityKey(request));
    if (context == null || streamId <= 0 || (streamId & 1) == 0) {
      return false;
    }
    InetSocketAddress local = (InetSocketAddress) channel.getLocalAddress();
    InetSocketAddress remote = (InetSocketAddress) channel.getRemoteAddress();
    NativeMemory packet =
        new NativeMemory(PACKET_PREFIX + CONTEXT_SIZE + CONNECTION_SIZE + Integer.BYTES);
    packet.setByte(0, OperationType.JDK_HTTP2_BIND.code);
    packet.write(PACKET_PREFIX, context, 0, context.length);
    int end =
        ConnectionInfo.writeSendConnectionInfo(
            packet,
            PACKET_PREFIX + CONTEXT_SIZE,
            new Connection(
                local.getAddress(), local.getPort(), remote.getAddress(), remote.getPort()));
    packet.setInt(end, streamId);
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
    return packet.getBuffer().get(1) != 0;
  }

  static String traceparent(byte[] context) {
    StringBuilder result = new StringBuilder("00-");
    appendHex(result, context, 0, TRACE_ID_SIZE);
    result.append('-');
    appendHex(result, context, TRACE_ID_SIZE, SPAN_ID_SIZE);
    result.append("-0").append((context[FLAGS_OFFSET] & 1) == 0 ? '0' : '1');
    return result.toString();
  }

  private static void appendHex(StringBuilder result, byte[] bytes, int offset, int size) {
    for (int i = offset; i < offset + size; i++) {
      result.append(HEX[(bytes[i] & 0xff) >>> 4]).append(HEX[bytes[i] & 0xf]);
    }
  }
}
