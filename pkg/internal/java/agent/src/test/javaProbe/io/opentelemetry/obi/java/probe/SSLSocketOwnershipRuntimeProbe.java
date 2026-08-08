/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public final class SSLSocketOwnershipRuntimeProbe {
  private SSLSocketOwnershipRuntimeProbe() {}

  public static void main(String[] args) throws Exception {
    Class<?> nativeBridge = Class.forName("io.opentelemetry.obi.java.BootstrapNative", true, null);
    Method socketFileDescriptor = nativeBridge.getMethod("socketFileDescriptor", Socket.class);
    Method directSocketFileDescriptor =
        nativeBridge.getMethod("directSocketFileDescriptor", Socket.class);
    InetAddress loopback = InetAddress.getLoopbackAddress();

    try (ServerSocket server = new ServerSocket(0, 8, loopback)) {
      SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
      try (SSLSocket direct = (SSLSocket) factory.createSocket(loopback, server.getLocalPort())) {
        int descriptor = descriptor(socketFileDescriptor, direct);
        require(descriptor >= 0, "direct JSSE socket has no descriptor");
        require(
            descriptor(directSocketFileDescriptor, direct) == descriptor,
            "direct JSSE ownership was not accepted");
      }

      try (Socket raw = new Socket(loopback, server.getLocalPort());
          SSLSocket layered =
              (SSLSocket)
                  factory.createSocket(
                      raw, loopback.getHostAddress(), server.getLocalPort(), false)) {
        int descriptor = descriptor(socketFileDescriptor, layered);
        require(descriptor >= 0, "layered JSSE socket has no descriptor");
        require(
            descriptor(directSocketFileDescriptor, layered) == -1,
            "layered JSSE ownership was incorrectly accepted");
        require(
            descriptor(directSocketFileDescriptor, raw) == -1,
            "plain Socket was incorrectly accepted as direct JSSE");
      }
    }

    System.out.println("sslsocket-ownership-agent-probe passed");
  }

  private static int descriptor(Method method, Socket socket) throws Exception {
    return ((Integer) method.invoke(null, socket)).intValue();
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new IllegalStateException(message);
    }
  }
}
