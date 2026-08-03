// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

@Timeout(30)
class TlsBoundaryHttpsServerTest {
  private static final String KEYSTORE_PASSWORD = "boundary-path-test";

  @TempDir static Path temporaryDirectory;

  private static Path keyStore;

  @BeforeAll
  static void createKeyStore() throws Exception {
    keyStore = temporaryDirectory.resolve("boundary-path.p12");
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
                "boundary-path",
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

  @RepeatedTest(2)
  void observesBoundarySensitiveHeadersOnTheServedRequest() throws Exception {
    for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
      try (TlsBoundaryHttpsServer server = start(protocol)) {
        String split = request(server, protocol, TlsBoundaryHttpsServer.Mode.SPLIT, "split-marker");
        String coalesced =
            request(
                server,
                protocol,
                TlsBoundaryHttpsServer.Mode.COALESCED,
                "coalesced-marker");

        assertBoundaryResponse(split, protocol, "split", "split-marker", false);
        assertBoundaryResponse(coalesced, protocol, "coalesced", "coalesced-marker", true);
      }
    }
  }

  @Test
  void isolatesConcurrentConnectionEvidence() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.3")) {
      ExecutorService executor = Executors.newFixedThreadPool(8);
      try {
        List<Callable<String>> requests = new ArrayList<>();
        for (int index = 0; index < 8; index++) {
          int sequence = index;
          TlsBoundaryHttpsServer.Mode mode =
              index % 2 == 0
                  ? TlsBoundaryHttpsServer.Mode.SPLIT
                  : TlsBoundaryHttpsServer.Mode.COALESCED;
          requests.add(
              () -> request(server, "TLSv1.3", mode, "parallel-marker-" + sequence));
        }
        List<Future<String>> responses = executor.invokeAll(requests);
        for (int index = 0; index < responses.size(); index++) {
          String response = responses.get(index).get(20, TimeUnit.SECONDS);
          boolean coalesced = index % 2 != 0;
          assertBoundaryResponse(
              response,
              "TLSv1.3",
              coalesced ? "coalesced" : "split",
              "parallel-marker-" + index,
              coalesced);
        }
      } finally {
        executor.shutdownNow();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
      }
    }
  }

  @Test
  void rejectsRequestsWithoutTheBoundedHeaderAndBodyShape() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.3")) {
      String response =
          requestBytes(
              server,
              "TLSv1.3",
              TlsBoundaryHttpsServer.Mode.SPLIT,
              "POST "
                  + TlsBoundaryHttpsServer.SPLIT_API_PATH
                  + " HTTP/1.1\r\nHost: localhost\r\nX-OBI-Demo-ID: short\r\n"
                  + "Content-Length: 0\r\nConnection: close\r\n\r\n",
              new byte[0]);

      assertTrue(response.startsWith("HTTP/1.1 400 "), response);
    }
  }

  @Test
  void rejectsAClientThatOnlyOffersAnotherTlsVersion() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.2")) {
      assertThrows(
          IOException.class,
          () ->
              request(
                  server,
                  "TLSv1.3",
                  TlsBoundaryHttpsServer.Mode.SPLIT,
                  "wrong-protocol"));
    }
  }

  @Test
  @Timeout(15)
  void absoluteRequestDeadlineClosesAConnectionDespitePeriodicBytes() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.3")) {
      TlsContextFactory.Contexts contexts =
          TlsContextFactory.load(keyStore, KEYSTORE_PASSWORD, "TLSv1.3");
      try (SSLSocket socket = (SSLSocket) contexts.clientSocketFactory().createSocket()) {
        socket.setEnabledProtocols(new String[] {"TLSv1.3"});
        socket.connect(
            new InetSocketAddress(
                "127.0.0.1", server.port(TlsBoundaryHttpsServer.Mode.SPLIT)),
            5_000);
        socket.setSoTimeout(2_000);
        socket.startHandshake();
        OutputStream output = socket.getOutputStream();
        boolean closed = false;
        for (int index = 0; index < 8 && !closed; index++) {
          try {
            output.write('P');
            output.flush();
            Thread.sleep(750);
          } catch (IOException expected) {
            closed = true;
          }
        }
        if (!closed) {
          try {
            closed = socket.getInputStream().read() == -1;
          } catch (IOException expected) {
            closed = true;
          }
        }
        assertTrue(closed, "periodic bytes kept the request alive past its absolute deadline");
      }
    }
  }

  @Test
  void closeIsIdempotentAndStopsAllExecutors() throws Exception {
    TlsBoundaryHttpsServer server = start("TLSv1.3");

    server.close();
    server.close();

    assertTrue(server.isTerminated());
  }

  @Test
  void failedStartupShutsDownAllocatedExecutors() throws Exception {
    Set<Long> threadsBefore = boundaryThreadIDs();
    try (ServerSocket splitReservation = new ServerSocket();
        ServerSocket occupiedCoalescedPort = new ServerSocket()) {
      splitReservation.bind(new InetSocketAddress("127.0.0.1", 0));
      occupiedCoalescedPort.bind(new InetSocketAddress("127.0.0.1", 0));
      int splitPort = splitReservation.getLocalPort();
      splitReservation.close();

      assertThrows(
          Exception.class,
          () ->
              TlsBoundaryHttpsServer.start(
                  splitPort,
                  occupiedCoalescedPort.getLocalPort(),
                  keyStore,
                  KEYSTORE_PASSWORD,
                  "TLSv1.3"));

      try (ServerSocket reboundSplitPort = new ServerSocket()) {
        reboundSplitPort.bind(new InetSocketAddress("127.0.0.1", splitPort));
      }
    }
    assertEquals(threadsBefore, boundaryThreadIDs());
  }

  private static TlsBoundaryHttpsServer start(String protocol) throws Exception {
    return TlsBoundaryHttpsServer.start(0, 0, keyStore, KEYSTORE_PASSWORD, protocol);
  }

  private static String request(
      TlsBoundaryHttpsServer server,
      String protocol,
      TlsBoundaryHttpsServer.Mode mode,
      String marker)
      throws Exception {
    StringBuilder headers = new StringBuilder();
    headers
        .append("POST ")
        .append(mode.path())
        .append(" HTTP/1.1\r\nHost: localhost\r\nX-OBI-Demo-ID: ")
        .append(marker)
        .append("\r\nContent-Type: application/octet-stream\r\nContent-Length: ")
        .append(TlsBoundaryHttpsServer.MIN_BODY_BYTES)
        .append("\r\nConnection: close\r\n");
    String padding = "p".repeat(TlsBoundaryHttpsServer.PADDING_HEADER_VALUE_BYTES);
    for (int index = 0; index < TlsBoundaryHttpsServer.PADDING_HEADER_COUNT; index++) {
      headers
          .append("Z-OBI-Boundary-Pad-")
          .append(index)
          .append(": ")
          .append(padding)
          .append("\r\n");
    }
    headers.append("\r\n");
    return requestBytes(
        server,
        protocol,
        mode,
        headers.toString(),
        new byte[TlsBoundaryHttpsServer.MIN_BODY_BYTES]);
  }

  private static String requestBytes(
      TlsBoundaryHttpsServer server,
      String protocol,
      TlsBoundaryHttpsServer.Mode mode,
      String headers,
      byte[] body)
      throws Exception {
    TlsContextFactory.Contexts contexts =
        TlsContextFactory.load(keyStore, KEYSTORE_PASSWORD, protocol);
    try (SSLSocket socket = (SSLSocket) contexts.clientSocketFactory().createSocket()) {
      socket.setEnabledProtocols(new String[] {protocol});
      socket.connect(new InetSocketAddress("127.0.0.1", server.port(mode)), 5_000);
      socket.setSoTimeout(10_000);
      socket.startHandshake();
      OutputStream output = socket.getOutputStream();
      output.write(headers.getBytes(StandardCharsets.US_ASCII));
      output.write(body);
      output.flush();
      byte[] response = socket.getInputStream().readAllBytes();
      assertTrue(response.length > 0, "server closed without a response");
      return new String(response, StandardCharsets.UTF_8);
    }
  }

  private static void assertBoundaryResponse(
      String response,
      String protocol,
      String mode,
      String marker,
      boolean coalesced) {
    assertTrue(response.startsWith("HTTP/1.1 200 "), response);
    assertTrue(response.contains("\"marker\":\"" + marker + "\""), response);
    assertTrue(response.contains("\"tls_protocol\":\"" + protocol + "\""), response);
    assertTrue(response.contains("\"backend_kind\":\"netty-tls-boundary\""), response);
    assertTrue(response.contains("\"mode\":\"" + mode + "\""), response);
    assertTrue(response.contains("\"passed\":true"), response);
    assertTrue(response.contains("\"failure_reason\":\"none\""), response);
    assertTrue(response.contains("\"request_complete\":true"), response);
    assertTrue(response.contains("\"header_spanned_records\":true"), response);
    assertTrue(response.contains("\"wire_decrypted_pairs_exact\":true"), response);
    assertTrue(response.contains("\"parser_shape_exact\":true"), response);
    assertTrue(response.contains("\"request_bytes_preserved\":true"), response);
    assertTrue(response.contains("\"handoff_before_parse\":true"), response);
    assertTrue(response.contains("\"response_forces_connection_close\":true"), response);
    assertTrue(
        response.contains("\"parser_facing_coalesced\":" + coalesced), response);
    assertTrue(
        response.matches("(?s).*\"header_bytes\":(?:1[7-9][0-9]{3}|[2-9][0-9]{4}).*"),
        response);
    assertTrue(
        response.matches("(?s).*\"decrypted_callbacks_before_request\":[2-9][0-9]*.*"),
        response);
    if (coalesced) {
      assertTrue(response.contains("\"parser_callbacks_before_request\":1"), response);
    } else {
      assertTrue(
          response.matches("(?s).*\"parser_callbacks_before_request\":[2-9][0-9]*.*"),
          response);
      assertTrue(response.contains("\"split_buffers_forwarded_unchanged\":true"), response);
    }
    assertFalse(response.contains("connection_closed"), response);
    assertFalse(response.contains("Z-OBI-Boundary-Pad"), response);
    assertFalse(response.contains("pppppppp"), response);
  }

  private static boolean isWindows() {
    return File.separatorChar == '\\';
  }

  private static Set<Long> boundaryThreadIDs() {
    return Thread.getAllStackTraces().keySet().stream()
        .filter(thread -> thread.getName().startsWith("obi-tls-boundary-"))
        .map(Thread::getId)
        .collect(Collectors.toSet());
  }
}
