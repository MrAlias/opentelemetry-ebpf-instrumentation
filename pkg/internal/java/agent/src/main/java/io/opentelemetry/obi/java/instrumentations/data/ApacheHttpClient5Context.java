/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLSocket;

public class ApacheHttpClient5Context {
  private static final int TRACEPARENT_LENGTH = 55;

  public static final class Injection {
    final Object header;
    final NativeMemory packet;

    Injection(Object header, NativeMemory packet) {
      this.header = header;
      this.packet = packet;
    }
  }

  public static Injection inject(Object request, Object connection) throws Exception {
    ClassLoader loader = connection.getClass().getClassLoader();
    Class<?> managed =
        Class.forName("org.apache.hc.client5.http.io.ManagedHttpClientConnection", false, loader);
    if (!managed.isInstance(connection)) {
      return null;
    }
    Socket socket = (Socket) managed.getMethod("getSocket").invoke(connection);
    if (!(socket instanceof SSLSocket)) {
      return null;
    }

    Class<?> message = Class.forName("org.apache.hc.core5.http.HttpMessage", false, loader);
    Object version = message.getMethod("getVersion").invoke(request);
    if (version != null && !"HTTP/1.1".equals(version.toString())) {
      return null;
    }
    Class<?> headers = Class.forName("org.apache.hc.core5.http.MessageHeaders", false, loader);
    if ((Boolean)
        headers.getMethod("containsHeader", String.class).invoke(request, "traceparent")) {
      return null;
    }

    NativeMemory packet = new NativeMemory(IOCTLPacket.packetPrefixSize + TRACEPARENT_LENGTH);
    int offset =
        IOCTLPacket.writePacketPrefix(packet, 0, OperationType.SEND, socket, TRACEPARENT_LENGTH);
    packet.setByte(0, OperationType.HTTP_CLIENT_CONTEXT.code);
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
    if (packet.getBuffer().get(offset) != '0') {
      return null;
    }
    byte[] value = new byte[TRACEPARENT_LENGTH];
    for (int i = 0; i < value.length; i++) {
      value[i] = packet.getBuffer().get(offset + i);
    }
    try {
      Class<?> headerType = Class.forName("org.apache.hc.core5.http.Header", false, loader);
      Object header =
          Class.forName("org.apache.hc.core5.http.message.BasicHeader", false, loader)
              .getConstructor(String.class, Object.class)
              .newInstance("traceparent", new String(value, StandardCharsets.US_ASCII));
      Injection injection = new Injection(header, packet);
      message.getMethod("addHeader", headerType).invoke(request, header);
      return injection;
    } catch (Exception error) {
      release(packet);
      throw error;
    }
  }

  public static void finish(Object request, Injection injection) throws Exception {
    if (injection == null) {
      return;
    }
    try {
      remove(request, injection.header);
    } finally {
      release(injection.packet);
    }
  }

  private static void release(NativeMemory packet) {
    packet.setInt(IOCTLPacket.packetPrefixSize - Integer.BYTES, 0);
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
  }

  public static void remove(Object request, Object header) throws Exception {
    if (header == null) {
      return;
    }
    ClassLoader loader = request.getClass().getClassLoader();
    Class<?> message = Class.forName("org.apache.hc.core5.http.HttpMessage", false, loader);
    Class<?> headerType = Class.forName("org.apache.hc.core5.http.Header", false, loader);
    message.getMethod("removeHeader", headerType).invoke(request, header);
  }
}
