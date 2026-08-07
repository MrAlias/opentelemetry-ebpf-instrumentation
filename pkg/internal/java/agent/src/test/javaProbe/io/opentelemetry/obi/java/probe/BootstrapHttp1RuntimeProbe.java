/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;

/** Exercises the framed receive dependency closure from the bootstrap class loader. */
public final class BootstrapHttp1RuntimeProbe {
  private BootstrapHttp1RuntimeProbe() {}

  public static void main(String[] args) throws Exception {
    String prefix = "io.opentelemetry.obi.java.instrumentations.data.";
    String[] closure = {
      prefix + "SSLStorage$ConnectionOwner",
      prefix + "RemoteParentHttp1Framer",
      prefix + "RemoteParentHttp1Framer$Action",
      prefix + "RemoteParentHttp1Framer$ReceivePlan",
      prefix + "RemoteParentHttp1Framer$State",
      prefix + "RemoteParentHttp1Framer$BodyKind",
      prefix + "RemoteParentHttp1Framer$1",
      prefix + "RemoteParentHttp1Receive",
      prefix + "RemoteParentHttp1Receive$Emitter",
      prefix + "RemoteParentSocketContext$ReceiveContext",
      prefix + "RemoteParentSocketContext$ExtractionObserver"
    };
    for (String name : closure) {
      Class<?> helper = Class.forName(name, true, null);
      if (helper.getClassLoader() != null) {
        throw new IllegalStateException(name + " was not injected into bootstrap");
      }
    }

    try (ServerSocketChannel listener = ServerSocketChannel.open()) {
      listener.bind(new InetSocketAddress("127.0.0.1", 0));
      try (SocketChannel client = SocketChannel.open(listener.getLocalAddress());
          SocketChannel server = listener.accept()) {
        Class<?> connectionClass = Class.forName(prefix + "Connection", true, null);
        Class<?> storageClass = Class.forName(prefix + "SSLStorage", true, null);
        Constructor<?> connectionConstructor =
            connectionClass.getConstructor(
                java.net.InetAddress.class,
                int.class,
                java.net.InetAddress.class,
                int.class,
                int.class);
        InetSocketAddress local = (InetSocketAddress) server.getLocalAddress();
        InetSocketAddress remote = (InetSocketAddress) server.getRemoteAddress();
        Object connection =
            connectionConstructor.newInstance(
                local.getAddress(),
                local.getPort(),
                remote.getAddress(),
                remote.getPort(),
                fileDescriptor(server));

        // The packaged agent is deliberately started with native extraction disabled so this
        // closure test does not depend on a running OBI process. Explicitly enable the in-process
        // capability before exercising the injected receiver; provider teardown semantics are
        // covered separately by unit tests.
        Class<?> threadInfo =
            Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
        threadInfo.getMethod("setRemoteParentEnabled", boolean.class).invoke(null, true);

        Method associate =
            storageClass.getMethod("associateConnectionWithChannel", Object.class, connectionClass);
        if (associate.invoke(null, server, connection) == null) {
          throw new IllegalStateException("bootstrap SSLStorage did not create a ConnectionOwner");
        }

        Method emit =
            storageClass.getMethod(
                "emitRemoteParentHttp1", connectionClass, byte[].class, int.class, int.class);
        byte[] first = ascii("GET /bootstrap HTTP/1.1\r\nHo");
        byte[] second = ascii("st: localhost\r\n\r\n");
        assertStatus(0, emit.invoke(null, connection, first, 0, first.length), "DEFER");
        assertStatus(0, emit.invoke(null, connection, second, 0, second.length), "START");

        Class<?> receiveContext =
            Class.forName(prefix + "RemoteParentSocketContext$ReceiveContext", true, null);
        Object context = threadInfo.getMethod("takeRemoteParentReceiveContext").invoke(null);
        if (context == null) {
          throw new IllegalStateException("START did not publish its exact receive context");
        }
        threadInfo.getMethod("finishRemoteParentExtraction", receiveContext).invoke(null, context);

        byte[] http2 = ascii("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        assertStatus(
            0,
            emit.invoke(null, connection, http2, 0, http2.length),
            "terminal telemetry fallback");
        storageClass.getMethod("cleanupConnection", connectionClass).invoke(null, connection);
      }
    }

    System.out.println("bootstrap-http1-agent-probe passed");
  }

  private static int fileDescriptor(SocketChannel channel) throws Exception {
    Field field = channel.getClass().getDeclaredField("fdVal");
    field.setAccessible(true);
    return field.getInt(channel);
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static void assertStatus(int expected, Object actual, String operation) {
    if (((Number) actual).intValue() != expected) {
      throw new IllegalStateException(operation + " returned " + actual);
    }
  }
}
