/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class SocketChannelRuntimeProbe {
  private SocketChannelRuntimeProbe() {}

  public static void main(String[] args) throws Exception {
    byte[] payload = "obi-socket-channel-fd".getBytes(StandardCharsets.UTF_8);
    ByteBuffer received = ByteBuffer.allocate(payload.length);
    int capturedSocketFileDescriptor;

    try (ServerSocketChannel listener = ServerSocketChannel.open()) {
      listener.bind(new InetSocketAddress("127.0.0.1", 0));
      try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
          SocketChannel server = listener.accept()) {
        ByteBuffer sent = ByteBuffer.wrap(payload);
        while (sent.hasRemaining()) {
          server.write(sent);
        }
        while (received.hasRemaining()) {
          if (client.read(received) < 0) {
            throw new IllegalStateException("socket closed before the probe payload arrived");
          }
        }

        if (!Arrays.equals(payload, received.array())) {
          throw new IllegalStateException("SocketChannel instrumentation changed the payload");
        }

        Object connection = capturedConnection(bufferKey(received));
        capturedSocketFileDescriptor = socketFileDescriptor(connection);
        int concreteSocketFileDescriptor = concreteSocketFileDescriptor(client);
        if (capturedSocketFileDescriptor != concreteSocketFileDescriptor) {
          throw new IllegalStateException(
              "SocketChannel instrumentation captured file descriptor "
                  + capturedSocketFileDescriptor
                  + " instead of "
                  + concreteSocketFileDescriptor);
        }
        assertEndpoint(connection, "Local", client.getLocalAddress());
        assertEndpoint(connection, "Remote", client.getRemoteAddress());
      }
    }

    if (capturedSocketFileDescriptor < 0) {
      throw new IllegalStateException(
          "SocketChannel instrumentation captured an invalid file descriptor");
    }

    System.out.println("socket-channel-agent-probe passed fd=" + capturedSocketFileDescriptor);
  }

  private static String bufferKey(ByteBuffer buffer) throws Exception {
    Class<?> extractor =
        Class.forName(
            "io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor", true, null);
    Method keyFromUsedBuffer = extractor.getMethod("keyFromUsedBuffer", ByteBuffer.class);
    return (String) keyFromUsedBuffer.invoke(null, buffer);
  }

  private static Object capturedConnection(String bufferKey) throws Exception {
    Class<?> storage =
        Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
    Method getConnection = storage.getMethod("getConnectionForBuf", String.class);
    Object connection = getConnection.invoke(null, bufferKey);
    if (connection == null) {
      throw new IllegalStateException("SocketChannel instrumentation did not capture a connection");
    }
    return connection;
  }

  private static int socketFileDescriptor(Object connection) throws Exception {
    Method getSocketFileDescriptor = connection.getClass().getMethod("getSocketFileDescriptor");
    return ((Number) getSocketFileDescriptor.invoke(connection)).intValue();
  }

  private static int concreteSocketFileDescriptor(SocketChannel channel) throws Exception {
    Field fdVal = channel.getClass().getDeclaredField("fdVal");
    fdVal.setAccessible(true);
    return fdVal.getInt(channel);
  }

  private static void assertEndpoint(Object connection, String prefix, SocketAddress expected)
      throws Exception {
    InetSocketAddress endpoint = (InetSocketAddress) expected;
    Method getAddress = connection.getClass().getMethod("get" + prefix + "Address");
    Method getPort = connection.getClass().getMethod("get" + prefix + "Port");
    InetAddress capturedAddress = (InetAddress) getAddress.invoke(connection);
    int capturedPort = ((Number) getPort.invoke(connection)).intValue();
    if (!endpoint.getAddress().equals(capturedAddress) || endpoint.getPort() != capturedPort) {
      throw new IllegalStateException(
          "SocketChannel instrumentation captured the wrong " + prefix.toLowerCase() + " endpoint");
    }
  }
}
