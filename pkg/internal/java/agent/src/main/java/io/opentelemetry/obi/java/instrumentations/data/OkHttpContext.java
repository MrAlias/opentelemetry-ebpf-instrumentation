/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import java.lang.reflect.Method;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.net.ssl.SSLSocket;

public class OkHttpContext {
  private static final ThreadLocal<Boolean> synchronous = new ThreadLocal<>();
  private static final int TRACEPARENT_LENGTH = 55;

  public static boolean enter() {
    boolean previous = Boolean.TRUE.equals(synchronous.get());
    synchronous.set(true);
    return previous;
  }

  public static void restore(boolean previous) {
    if (previous) {
      synchronous.set(true);
    } else {
      synchronous.remove();
    }
  }

  public static Object inject(Object codec, Object request) throws Exception {
    if (!Boolean.TRUE.equals(synchronous.get())) {
      return request;
    }

    Method connectionMethod;
    try {
      connectionMethod = codec.getClass().getMethod("getConnection");
    } catch (NoSuchMethodException ignored) {
      connectionMethod = codec.getClass().getMethod("connection");
    }
    Object connection = connectionMethod.invoke(codec);
    Socket socket = (Socket) connection.getClass().getMethod("socket").invoke(connection);
    if (!(socket instanceof SSLSocket)) {
      return request;
    }

    List<?> values =
        (List<?>)
            request.getClass().getMethod("headers", String.class).invoke(request, "traceparent");
    if (values.size() > 1) {
      return request;
    }
    String supplied = values.isEmpty() ? null : (String) values.get(0);
    if (supplied != null && supplied.length() != TRACEPARENT_LENGTH) {
      return request;
    }

    NativeMemory packet = new NativeMemory(IOCTLPacket.packetPrefixSize + TRACEPARENT_LENGTH);
    int offset =
        IOCTLPacket.writePacketPrefix(packet, 0, OperationType.SEND, socket, TRACEPARENT_LENGTH);
    packet.setByte(0, OperationType.HTTP_TRACEPARENT.code);
    if (supplied != null) {
      byte[] bytes = supplied.getBytes(StandardCharsets.US_ASCII);
      packet.write(offset, bytes, 0, bytes.length);
    }
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
    byte first = packet.getBuffer().get(offset);
    if (supplied != null || first != '0') {
      return request;
    }

    byte[] bytes = new byte[TRACEPARENT_LENGTH];
    packet.getBuffer().position(offset);
    packet.getBuffer().get(bytes);
    return withTraceparent(request, new String(bytes, StandardCharsets.US_ASCII));
  }

  public static Object withTraceparent(Object request, String value) throws Exception {
    Object builder = request.getClass().getMethod("newBuilder").invoke(request);
    builder
        .getClass()
        .getMethod("header", String.class, String.class)
        .invoke(builder, "traceparent", value);
    return builder.getClass().getMethod("build").invoke(builder);
  }
}
