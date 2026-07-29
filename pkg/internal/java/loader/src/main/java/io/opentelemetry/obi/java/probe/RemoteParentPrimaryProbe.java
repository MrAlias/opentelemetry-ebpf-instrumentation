/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/** Exercises the bootstrap remote-parent bridge against a single TCP socket. */
public final class RemoteParentPrimaryProbe {
  private static final int PACKET_SIZE = 64;

  private RemoteParentPrimaryProbe() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      throw new IllegalArgumentException("expected host, port, and process capability");
    }

    String host = args[0];
    int port = Integer.parseInt(args[1]);
    long processCapability = Long.parseUnsignedLong(args[2]);
    Class<?> bootstrap =
        Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBootstrap", true, null);
    Class<?> nativeBridge = Class.forName("io.opentelemetry.obi.java.BootstrapNative", true, null);
    initialize(bootstrap, processCapability);

    try (Socket socket = new Socket()) {
      socket.connect(new InetSocketAddress(host, port));
      int socketFileDescriptor =
          intValue(nativeBridge.getMethod("socketFileDescriptor", Socket.class).invoke(null, socket));
      if (socketFileDescriptor < 0) {
        throw new IllegalStateException("socket file descriptor is unavailable");
      }

      int tid = intValue(nativeBridge.getMethod("gettid").invoke(null));
      System.out.println("READY tid=" + tid + " fd=" + socketFileDescriptor);
      awaitGo();

      int emitResult = emitData(nativeBridge, socketFileDescriptor);
      Object record =
          Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", true, null)
              .getMethod("takeRemoteParent")
              .invoke(null);
      int status = intValue(record.getClass().getMethod("getStatus").invoke(record));
      String traceId = stringValue(record.getClass().getMethod("getTraceIdHex").invoke(record));
      String parentSpanId =
          stringValue(record.getClass().getMethod("getParentSpanIdHex").invoke(record));
      int socketFileDescriptorAfterTake =
          intValue(
              Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null)
                  .getMethod("remoteParentSocketFileDescriptor")
                  .invoke(null));
      System.out.println(
          "RESULT emit="
              + emitResult
              + " status="
              + status
              + " trace="
              + traceId
              + " span="
              + parentSpanId
              + " fdAfter="
              + socketFileDescriptorAfterTake);
    }
  }

  private static void initialize(Class<?> bootstrap, long processCapability) throws Exception {
    Method initialize =
        bootstrap.getMethod(
            "initialize", String.class, String.class, int.class, long.class, long.class);
    boolean ready =
        (Boolean) initialize.invoke(null, "getsockopt", "", 1_000, 0L, processCapability);
    if (!ready) {
      throw new IllegalStateException("remote-parent bridge is not ready");
    }
  }

  private static int emitData(Class<?> nativeBridge, int socketFileDescriptor) throws Exception {
    Class<?> nativeMemory = Class.forName("io.opentelemetry.obi.java.ebpf.NativeMemory", true, null);
    Object memory = nativeMemory.getConstructor(int.class).newInstance(PACKET_SIZE);
    long address = longValue(nativeMemory.getMethod("getAddress").invoke(memory));
    return intValue(
        nativeBridge
            .getMethod("emitData", int.class, long.class, boolean.class)
            .invoke(null, socketFileDescriptor, address, true));
  }

  private static void awaitGo() throws Exception {
    BufferedReader input =
        new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    if (!"GO".equals(input.readLine())) {
      throw new IllegalStateException("expected GO command");
    }
  }

  private static int intValue(Object value) {
    return ((Number) value).intValue();
  }

  private static long longValue(Object value) {
    return ((Number) value).longValue();
  }

  private static String stringValue(Object value) {
    return value == null ? "-" : value.toString();
  }
}
