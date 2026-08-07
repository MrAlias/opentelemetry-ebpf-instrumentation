// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

@Timeout(20)
class NettyHttpsServerTest {
  private static final String KEYSTORE_PASSWORD = "netty-test";
  private static final long TEST_PAIR_DEADLINE_MILLIS = 250;

  @TempDir static Path temporaryDirectory;

  private static Path keyStore;

  @BeforeAll
  static void createKeyStore() throws Exception {
    keyStore = temporaryDirectory.resolve("netty.p12");
    String executable =
        Path.of(
                System.getProperty("java.home"),
                "bin",
                isWindows() ? "keytool.exe" : "keytool")
            .toString();
    Process process =
        new ProcessBuilder(
                executable,
                "-genkeypair",
                "-alias",
                "netty",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-storetype",
                "PKCS12",
                "-keystore",
                keyStore.toString(),
                "-storepass",
                KEYSTORE_PASSWORD,
                "-keypass",
                KEYSTORE_PASSWORD,
                "-dname",
                "CN=localhost",
                "-ext",
                "SAN=ip:127.0.0.1",
                "-validity",
                "2",
                "-noprompt")
            .redirectErrorStream(true)
            .start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (InputStream input = process.getInputStream()) {
      input.transferTo(output);
    }
    assertTrue(process.waitFor(30, TimeUnit.SECONDS), "keytool timed out");
    assertEquals(0, process.exitValue(), output.toString(StandardCharsets.UTF_8));
  }

  @Test
  void servesValidatedRequestsOverTls() throws Exception {
    for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
      try (NettyHttpsServer server = start(protocol)) {
        String response = request(server, protocol, "netty-marker");

        assertTrue(response.startsWith("HTTP/1.1 200 "), response);
        assertTrue(response.contains("\"marker\":\"netty-marker\""), response);
        assertTrue(response.contains("\"secure\":true"), response);
        assertTrue(response.contains("\"tls_protocol\":\"" + protocol + "\""), response);
        assertTrue(response.contains("\"backend_kind\":\"netty\""), response);
        assertTrue(response.matches("(?s).*\"backend_connection_id\":[1-9][0-9]*.*"), response);
        assertTrue(response.matches("(?s).*\"backend_remote_port\":[1-9][0-9]*.*"), response);
      }
    }
  }

  @Test
  void observesTwoRequestsInOnePlaintextReceiveForBothTlsVersions() throws Exception {
    for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
      try (NettyHttpsServer server = start(protocol)) {
        String first = "coalesced-first-" + protocol.replace(".", "");
        String second = "coalesced-second-" + protocol.replace(".", "");
        byte[] plaintext = coalescedRequests(first, second);

        String response = coalescedRequest(server, protocol, plaintext);

        assertEquals(2, occurrences(response, "HTTP/1.1 200"), response);
        assertTrue(response.contains("\"marker\":\"" + first + "\""), response);
        assertTrue(response.contains("\"marker\":\"" + second + "\""), response);
        assertTrue(response.contains("\"backend_kind\":\"netty-coalesced-bridge\""), response);
        assertTrue(response.contains("\"plaintext_callback_count\":1"), response);
        assertTrue(response.contains("\"parser_request_count\":2"), response);
        assertTrue(response.contains("\"parser_callback_generations\":[1, 1]"), response);
        assertTrue(response.contains("\"traceparent_header_count\":0"), response);
        assertTrue(response.contains("\"request_markers_exact\":true"), response);
        assertTrue(response.contains("\"one_plaintext_receive\":true"), response);
        assertTrue(response.contains("\"passed\":true"), response);
        assertTrue(response.contains("\"failure_reason\":\"none\""), response);
        assertTrue(response.contains("\"plaintext_sha256\":\"" + sha256(plaintext) + "\""), response);
        assertEquals(1, occurrences(response, "X-OBI-Java-Diagnostics:"), response);
      }
    }
  }

  @Test
  void ordinaryRequestsReuseAKeepaliveConnection() throws Exception {
    for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
      try (NettyHttpsServer server = start(protocol);
          SSLSocket socket = newClientSocket(protocol)) {
        connect(server, socket, protocol);
        OutputStream output = socket.getOutputStream();
        InputStream input = new BufferedInputStream(socket.getInputStream());

        output.write(ordinaryRequest("keepalive-first", false));
        output.flush();
        String first = readResponse(input);
        output.write(ordinaryRequest("keepalive-second", true));
        output.flush();
        String second = readResponse(input);

        assertTrue(first.startsWith("HTTP/1.1 200 "), first);
        assertTrue(first.contains("\"marker\":\"keepalive-first\""), first);
        assertTrue(second.startsWith("HTTP/1.1 200 "), second);
        assertTrue(second.contains("\"marker\":\"keepalive-second\""), second);
        assertPeerClosed(input, "server did not close after the second ordinary request");
      }
    }
  }

  @Test
  void ordinaryRequestMaySpanMultiplePlaintextCallbacks() throws Exception {
    try (NettyHttpsServer server = start("TLSv1.3");
        SSLSocket socket = newClientSocket("TLSv1.3")) {
      connect(server, socket, "TLSv1.3");
      byte[] request = ordinaryRequest("fragmented-normal", true);
      int split = request.length / 2;
      OutputStream output = socket.getOutputStream();
      output.write(request, 0, split);
      output.flush();
      Thread.sleep(100);
      output.write(request, split, request.length - split);
      output.flush();

      String response = readResponse(new BufferedInputStream(socket.getInputStream()));

      assertTrue(response.startsWith("HTTP/1.1 200 "), response);
      assertTrue(response.contains("\"marker\":\"fragmented-normal\""), response);
    }
  }

  @Test
  void incompleteCoalescedPairClosesAtItsAbsoluteDeadline() throws Exception {
    try (NettyHttpsServer server =
            NettyHttpsServer.start(
                0,
                keyStore,
                KEYSTORE_PASSWORD,
                "TLSv1.3",
                TEST_PAIR_DEADLINE_MILLIS);
        SSLSocket socket = newClientSocket("TLSv1.3")) {
      connect(server, socket, "TLSv1.3");
      socket.setSoTimeout(2_000);
      socket.getOutputStream().write(coalescedRequest("incomplete-pair", 1, false));
      socket.getOutputStream().flush();

      assertPeerClosed(
          socket.getInputStream(), "incomplete coalesced pair outlived its absolute deadline");
    }
  }

  @Test
  void rejectsOutOfRangeCoalescedPairDeadlines() {
    assertThrows(
        IllegalArgumentException.class,
        () -> NettyHttpsServer.start(0, keyStore, KEYSTORE_PASSWORD, "TLSv1.3", 0));
    assertThrows(
        IllegalArgumentException.class,
        () -> NettyHttpsServer.start(0, keyStore, KEYSTORE_PASSWORD, "TLSv1.3", 10_001));
  }

  @Test
  void coalescedBridgeRejectsTraceparentShortcut() throws Exception {
    try (NettyHttpsServer server = start("TLSv1.3")) {
      String plaintext =
          new String(coalescedRequests("first", "second"), StandardCharsets.US_ASCII)
              .replace(
                  "X-OBI-Coalesced-Sequence: 1\r\n",
                  "X-OBI-Coalesced-Sequence: 1\r\n"
                      + "traceparent: 00-000102030405060708090a0b0c0d0e0f-1011121314151617-01\r\n");

      String response =
          coalescedRequest(server, "TLSv1.3", plaintext.getBytes(StandardCharsets.US_ASCII));

      assertEquals("", response);
    }
  }

  @Test
  void rejectsRequestsWithoutTheRequiredMarker() throws Exception {
    try (NettyHttpsServer server = start("TLSv1.3")) {
      String response = request(server, "TLSv1.3", null);

      assertTrue(response.startsWith("HTTP/1.1 400 "), response);
    }
  }

  @Test
  void rejectsRequestsWithAnInvalidMarker() throws Exception {
    try (NettyHttpsServer server = start("TLSv1.3")) {
      String response = request(server, "TLSv1.3", "not a valid marker");

      assertTrue(response.startsWith("HTTP/1.1 400 "), response);
    }
  }

  @Test
  void rejectsAClientThatOnlyOffersAnotherTlsVersion() throws Exception {
    try (NettyHttpsServer server = start("TLSv1.2")) {
      assertThrows(IOException.class, () -> connect(server, "TLSv1.3"));
    }
  }

  @Test
  void closeIsIdempotent() throws Exception {
    NettyHttpsServer server = start("TLSv1.3");

    server.close();
    server.close();

    assertTrue(server.isTerminated());
  }

  @Test
  void failedStartupShutsDownAllocatedEventLoops() throws Exception {
    Set<Long> eventLoopsBefore = nettyEventLoopThreadIDs();
    try (ServerSocket occupiedPort = new ServerSocket()) {
      occupiedPort.bind(new InetSocketAddress("127.0.0.1", 0));

      assertThrows(
          Exception.class,
          () ->
              NettyHttpsServer.start(
                  occupiedPort.getLocalPort(), keyStore, KEYSTORE_PASSWORD, "TLSv1.3"));
    }

    assertEquals(eventLoopsBefore, nettyEventLoopThreadIDs());
  }

  private static NettyHttpsServer start(String protocol) throws Exception {
    return NettyHttpsServer.start(0, keyStore, KEYSTORE_PASSWORD, protocol);
  }

  private static String request(NettyHttpsServer server, String protocol, String marker)
      throws Exception {
    try (SSLSocket socket = newClientSocket(protocol)) {
      connect(server, socket, protocol);
      OutputStream output = socket.getOutputStream();
      output.write(ordinaryRequest(marker, true));
      output.flush();
      return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static byte[] ordinaryRequest(String marker, boolean close) {
    String headers = marker == null ? "" : "X-OBI-Demo-ID: " + marker + "\r\n";
    String request =
        "GET "
            + NettyHttpsServer.API_PATH
            + " HTTP/1.1\r\nHost: localhost\r\n"
            + headers
            + "Connection: "
            + (close ? "close" : "keep-alive")
            + "\r\n\r\n";
    return request.getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] coalescedRequests(String first, String second) {
    byte[] firstRequest = coalescedRequest(first, 1, false);
    byte[] secondRequest = coalescedRequest(second, 2, true);
    byte[] pair = new byte[firstRequest.length + secondRequest.length];
    System.arraycopy(firstRequest, 0, pair, 0, firstRequest.length);
    System.arraycopy(secondRequest, 0, pair, firstRequest.length, secondRequest.length);
    return pair;
  }

  private static byte[] coalescedRequest(String marker, int sequence, boolean diagnostics) {
    String request =
        "GET "
            + NettyHttpsServer.COALESCED_BRIDGE_PATH
            + (diagnostics ? "?bridge_diagnostics=1" : "")
            + " HTTP/1.1\r\nHost: localhost\r\nX-OBI-Demo-ID: "
            + marker
            + "\r\nX-OBI-Coalesced-Sequence: "
            + sequence
            + "\r\nConnection: "
            + (sequence == 1 ? "keep-alive" : "close")
            + "\r\n\r\n";
    return request.getBytes(StandardCharsets.US_ASCII);
  }

  private static String coalescedRequest(
      NettyHttpsServer server, String protocol, byte[] plaintext) throws Exception {
    try (SSLSocket socket = newClientSocket(protocol)) {
      connect(server, socket, protocol);
      OutputStream output = socket.getOutputStream();
      output.write(plaintext);
      output.flush();
      return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static int occurrences(String value, String wanted) {
    int count = 0;
    int offset = 0;
    while ((offset = value.indexOf(wanted, offset)) >= 0) {
      count++;
      offset += wanted.length();
    }
    return count;
  }

  private static String sha256(byte[] value) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
  }

  private static void connect(NettyHttpsServer server, String protocol) throws Exception {
    try (SSLSocket socket = newClientSocket(protocol)) {
      connect(server, socket, protocol);
    }
  }

  private static SSLSocket newClientSocket(String protocol) throws Exception {
    TlsContextFactory.Contexts contexts =
        TlsContextFactory.load(keyStore, KEYSTORE_PASSWORD, protocol);
    return (SSLSocket) contexts.clientSocketFactory().createSocket();
  }

  private static void connect(NettyHttpsServer server, SSLSocket socket, String protocol)
      throws IOException {
    socket.setEnabledProtocols(new String[] {protocol});
    socket.connect(new InetSocketAddress("127.0.0.1", server.port()), 5_000);
    socket.setSoTimeout(10_000);
    socket.startHandshake();
  }

  private static String readResponse(InputStream input) throws IOException {
    ByteArrayOutputStream response = new ByteArrayOutputStream();
    int contentLength = -1;
    boolean headersComplete = false;
    for (int count = 0; count < 64; count++) {
      String line = readAsciiLine(input);
      if (line == null) {
        throw new EOFException("server closed before the response headers completed");
      }
      response.write(line.getBytes(StandardCharsets.US_ASCII));
      response.write('\r');
      response.write('\n');
      if (line.isEmpty()) {
        headersComplete = true;
        break;
      }
      if (line.regionMatches(true, 0, "Content-Length:", 0, "Content-Length:".length())) {
        contentLength = Integer.parseInt(line.substring("Content-Length:".length()).trim());
      }
    }
    if (!headersComplete || contentLength < 0 || contentLength > 64 * 1024) {
      throw new IOException("invalid bounded HTTP response");
    }
    byte[] body = input.readNBytes(contentLength);
    if (body.length != contentLength) {
      throw new EOFException("server closed before the response body completed");
    }
    response.write(body);
    return new String(response.toByteArray(), StandardCharsets.UTF_8);
  }

  private static String readAsciiLine(InputStream input) throws IOException {
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    for (int count = 0; count < 8 * 1024; count++) {
      int value = input.read();
      if (value < 0) {
        return line.size() == 0 ? null : new String(line.toByteArray(), StandardCharsets.US_ASCII);
      }
      if (value == '\n') {
        byte[] bytes = line.toByteArray();
        int length = bytes.length;
        if (length > 0 && bytes[length - 1] == '\r') {
          length--;
        }
        return new String(bytes, 0, length, StandardCharsets.US_ASCII);
      }
      line.write(value);
    }
    throw new IOException("HTTP response line exceeded the test bound");
  }

  private static void assertPeerClosed(InputStream input, String message) throws IOException {
    try {
      assertEquals(-1, input.read(), message);
    } catch (SocketTimeoutException timeout) {
      throw new AssertionError(message + ": read timed out", timeout);
    } catch (IOException closed) {
      // A TLS close or connection reset also proves that the peer released the socket.
    }
  }

  private static boolean isWindows() {
    return File.separatorChar == '\\';
  }

  private static Set<Long> nettyEventLoopThreadIDs() {
    return Thread.getAllStackTraces().keySet().stream()
        .filter(thread -> thread.getName().startsWith("nioEventLoopGroup-"))
        .map(Thread::getId)
        .collect(Collectors.toSet());
  }
}
