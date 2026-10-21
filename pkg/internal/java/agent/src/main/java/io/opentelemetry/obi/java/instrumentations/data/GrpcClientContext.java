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
import io.opentelemetry.obi.java.instrumentations.util.NettyChannelExtractor;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class GrpcClientContext {
  // tp_info_t: trace ID, span ID, parent ID, timestamp, flags and padding.
  private static final int CONTEXT_SIZE = 48;
  private static final int CAPACITY = 4096;
  private static final ThreadLocal<GrpcClientContext> current = new ThreadLocal<>();
  private static final CappedConcurrentHashMap<Object, GrpcClientContext> calls =
      new CappedConcurrentHashMap<>(CAPACITY);
  private static final CappedConcurrentHashMap<Object, GrpcClientContext> pending =
      new CappedConcurrentHashMap<>(CAPACITY);
  private static final int MAX_METADATA_COPIES = 16;
  private final List<Object> copies = new ArrayList<>();
  private boolean closed;
  private Object metadata;
  private byte[] context;

  public static GrpcClientContext enter() {
    GrpcClientContext previous = current.get();
    current.set(new GrpcClientContext());
    return previous;
  }

  public static void exit(GrpcClientContext previous) {
    GrpcClientContext call = current.get();
    if (call != null) {
      synchronized (call) {
        call.closed = true;
        if (call.metadata != null) {
          calls.remove(call.metadata);
        }
        for (Object copy : call.copies) {
          calls.remove(copy);
          pending.remove(copy);
        }
        call.copies.clear();
      }
    }
    if (previous == null) {
      current.remove();
    } else {
      current.set(previous);
    }
  }

  public static void capture(Object headers) {
    GrpcClientContext call = current.get();
    if (call == null || call.metadata != null) {
      return;
    }
    NativeMemory packet = new NativeMemory(1 + CONTEXT_SIZE);
    packet.setByte(0, OperationType.GRPC_CONTEXT.code);
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
    byte[] context = readContext(packet);
    if (context == null) {
      return;
    }
    call.context = context;
    call.metadata = headers;
    calls.put(headers, call);
  }

  static byte[] readContext(NativeMemory packet) {
    // OBI clears the opcode only after successfully writing the complete reply.
    if (packet.getBuffer().get(0) != 0) {
      return null;
    }
    byte[] context = new byte[CONTEXT_SIZE];
    ((java.nio.Buffer) packet.getBuffer()).position(1);
    packet.getBuffer().get(context);
    boolean traceAvailable = false;
    boolean spanAvailable = false;
    for (int i = 0; i < 16; i++) {
      traceAvailable |= context[i] != 0;
    }
    for (int i = 16; i < 24; i++) {
      spanAvailable |= context[i] != 0;
    }
    return traceAvailable && spanAvailable ? context : null;
  }

  public static void copy(Object original, Object copy) {
    GrpcClientContext call = calls.get(original);
    if (call == null) {
      return;
    }
    synchronized (call) {
      if (call.closed || call.copies.size() >= MAX_METADATA_COPIES) {
        return;
      }
      call.copies.add(copy);
      calls.put(copy, call);
    }
  }

  public static GrpcClientContext prepare(Object headers) throws Exception {
    GrpcClientContext call = calls.remove(headers);
    if (call == null) {
      return null;
    }
    synchronized (call) {
      call.copies.remove(headers);
      if (call.closed) {
        return null;
      }
      inject(headers, call);
      return call;
    }
  }

  public static void bind(Object headers, GrpcClientContext call) {
    if (headers == null || call == null) {
      return;
    }
    synchronized (call) {
      if (call.closed || call.copies.size() >= MAX_METADATA_COPIES) {
        return;
      }
      call.copies.add(headers);
      pending.put(headers, call);
    }
  }

  static GrpcClientContext take(Object headers) {
    GrpcClientContext call = pending.remove(headers);
    if (call == null) {
      return null;
    }
    synchronized (call) {
      call.copies.remove(headers);
      return call.closed ? null : call;
    }
  }

  private static void inject(Object headers, GrpcClientContext call) throws Exception {
    Class<?> metadataClass = headers.getClass();
    Set<?> keys = (Set<?>) metadataClass.getMethod("keys").invoke(headers);
    if (keys.contains("traceparent")) {
      return;
    }
    ClassLoader loader = metadataClass.getClassLoader();
    Class<?> keyClass = Class.forName("io.grpc.Metadata$Key", false, loader);
    Class<?> marshallerClass = Class.forName("io.grpc.Metadata$AsciiMarshaller", false, loader);
    Object key =
        keyClass
            .getMethod("of", String.class, marshallerClass)
            .invoke(
                null, "traceparent", metadataClass.getField("ASCII_STRING_MARSHALLER").get(null));
    String traceparent =
        "00-"
            + hex(call.context, 0, 16)
            + "-"
            + hex(call.context, 16, 8)
            + "-"
            + hex(call.context, 40, 1);
    metadataClass.getMethod("put", keyClass, Object.class).invoke(headers, key, traceparent);
  }

  public static void publish(Object ctx, int streamId, Object headers) throws Exception {
    GrpcClientContext call = take(headers);
    if (call == null) {
      return;
    }
    Connection connection = NettyChannelExtractor.extractConnectionFromChannelHandlerContext(ctx);
    if (connection == null) {
      return;
    }
    NativeMemory packet =
        new NativeMemory(1 + (16 * 2 + Short.BYTES * 2) + Integer.BYTES + CONTEXT_SIZE);
    packet.setByte(0, OperationType.GRPC_STREAM.code);
    int offset = ConnectionInfo.writeSendConnectionInfo(packet, 1, connection);
    packet.setInt(offset, streamId);
    packet.write(offset + Integer.BYTES, call.context, 0, CONTEXT_SIZE);
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
  }

  private static String hex(byte[] bytes, int start, int length) {
    char[] digits = "0123456789abcdef".toCharArray();
    char[] result = new char[length * 2];
    for (int i = 0; i < length; i++) {
      result[2 * i] = digits[(bytes[start + i] & 0xff) >>> 4];
      result[2 * i + 1] = digits[bytes[start + i] & 15];
    }
    return new String(result);
  }
}
