/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import javax.net.ssl.SSLSocket;

public final class ApacheHttpClientPropagation {
  private static final byte[] HTTP11 = " HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII);
  private static final ThreadLocal<ApacheHttpClientPropagation> current = new ThreadLocal<>();

  private final JdkHttpClientPropagation propagation;
  private Socket socket;
  private boolean sending;
  private boolean written;

  private ApacheHttpClientPropagation(JdkHttpClientPropagation propagation) {
    this.propagation = propagation;
  }

  public static ApacheHttpClientPropagation enter() {
    if (current.get() != null) {
      return null;
    }
    JdkHttpClientPropagation propagation = JdkHttpClientPropagation.enter();
    if (propagation == null) {
      return null;
    }
    ApacheHttpClientPropagation scope = new ApacheHttpClientPropagation(propagation);
    current.set(scope);
    return scope;
  }

  public static void captureParent(ApacheHttpClientPropagation scope) {
    if (scope != null) {
      JdkHttpClientPropagation.captureParent(scope.propagation);
    }
  }

  public static void exit(ApacheHttpClientPropagation scope) {
    if (scope != null) {
      current.remove();
      JdkHttpClientPropagation.exit(scope.propagation);
    }
  }

  public static ApacheHttpClientPropagation beginAttempt(Object connection) throws Exception {
    ApacheHttpClientPropagation scope = current.get();
    if (scope == null || scope.sending) {
      return null;
    }
    Class<?> managedConnection =
        Class.forName(
            "org.apache.http.conn.ManagedHttpClientConnection",
            false,
            connection.getClass().getClassLoader());
    return beginAttempt((Socket) managedConnection.getMethod("getSocket").invoke(connection));
  }

  static ApacheHttpClientPropagation beginAttempt(Socket socket) {
    ApacheHttpClientPropagation scope = current.get();
    if (scope == null || scope.sending || !(socket instanceof SSLSocket)) {
      return null;
    }
    scope.socket = socket;
    scope.sending = true;
    scope.written = false;
    return scope;
  }

  public static void endAttempt(ApacheHttpClientPropagation scope) {
    if (scope != null) {
      scope.sending = false;
      scope.socket = null;
    }
  }

  public static byte[] inject(byte[] bytes, int offset, int length, Socket socket) {
    ApacheHttpClientPropagation scope = current.get();
    if (scope == null
        || !scope.sending
        || scope.written
        || socket != scope.socket
        || bytes == null
        || length <= 0) {
      return null;
    }
    // A later write can be a request body, even if it resembles HTTP headers.
    scope.written = true;
    try {
      ByteBuffer headers = prepareHeaders(bytes, offset, length);
      if (headers == null) {
        return null;
      }
      Connection connection =
          new Connection(
              socket.getLocalAddress(),
              socket.getLocalPort(),
              socket.getInetAddress(),
              socket.getPort());
      return JdkHttpClientPropagation.reserve(scope.propagation, connection, headers)
          ? headers.array()
          : null;
    } catch (Throwable ignored) {
      return null;
    }
  }

  static ByteBuffer prepareHeaders(byte[] bytes, int offset, int length) {
    if (offset < 0
        || length < HTTP11.length
        || offset > bytes.length - length
        || length > ByteBufferExtractor.MAX_SIZE) {
      return null;
    }
    int lineEnd = offset;
    while (lineEnd < offset + length - 1
        && !(bytes[lineEnd] == '\r' && bytes[lineEnd + 1] == '\n')) {
      lineEnd++;
    }
    int version = lineEnd + 2 - HTTP11.length;
    if (version <= offset) {
      return null;
    }
    for (int i = 0; i < HTTP11.length; i++) {
      if (version + i >= offset + length || bytes[version + i] != HTTP11[i]) {
        return null;
      }
    }
    for (int end = lineEnd; end <= offset + length - 4; end++) {
      if (bytes[end] != '\r'
          || bytes[end + 1] != '\n'
          || bytes[end + 2] != '\r'
          || bytes[end + 3] != '\n') {
        continue;
      }
      int headerLength = end + 4 - offset;
      ByteBuffer headers =
          JdkHttpClientPropagation.prepareHeaders(
              Collections.singletonList(ByteBuffer.wrap(bytes, offset, headerLength)));
      if (headers == null) {
        return null;
      }
      int added = headers.capacity() - headerLength;
      if (length > ByteBufferExtractor.MAX_SIZE - added) {
        return null;
      }
      byte[] result = new byte[length + added];
      System.arraycopy(headers.array(), 0, result, 0, headers.capacity());
      System.arraycopy(
          bytes, offset + headerLength, result, headers.capacity(), length - headerLength);
      ByteBuffer prepared = ByteBuffer.wrap(result);
      ((java.nio.Buffer) prepared).position(headers.position());
      return prepared;
    }
    return null;
  }
}
