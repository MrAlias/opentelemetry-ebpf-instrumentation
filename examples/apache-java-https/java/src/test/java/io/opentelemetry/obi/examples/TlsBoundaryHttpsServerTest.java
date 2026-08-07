// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
  private static final int MAX_RESPONSE_HEADERS = 64;
  private static final int MAX_RESPONSE_LINE_BYTES = 4096;
  private static final int MAX_RESPONSE_BODY_BYTES = 64 * 1024;
  private static final long SERIALIZED_TEST_GRACE_MILLIS = 25;
  private static final long RACE_TEST_GRACE_MILLIS = 1000;
  private static final Pattern JSON_FIELD_PATTERN =
      Pattern.compile("\\\"([a-z_]+)\\\":");
  private static final List<String> EVIDENCE_FIELDS =
      List.of(
          "mode",
          "delivery_shape",
          "evidence_phase",
          "fallback_reason",
          "coalescing_grace_millis",
          "coalescing_grace_expired",
          "passed",
          "failure_reason",
          "request_complete",
          "request_count",
          "request_header_bytes",
          "request_body_bytes",
          "request_total_bytes",
          "request_header_decrypted_callback_counts",
          "request_order",
          "emission_order",
          "emission_parser_callback_order",
          "response_order",
          "response_connection_close",
          "tls_application_record_legacy_versions",
          "tls_application_record_payload_lengths",
          "decrypted_callback_lengths",
          "parser_callback_lengths",
          "decrypted_total_bytes",
          "parser_total_bytes",
          "parser_callback_count",
          "verification_buffer_bytes",
          "verification_buffer_limit_bytes",
          "verification_pair_digest_exact",
          "wire_decrypted_pairs_exact",
          "headers_spanned_records",
          "parser_shape_exact",
          "parser_facing_coalesced",
          "requests_emitted_from_single_parser_callback",
          "request_bytes_preserved",
          "split_buffers_forwarded_unchanged",
          "handoff_before_parse",
          "first_response_keeps_alive",
          "response_forces_connection_close");

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
        RawResponse split = splitRequest(server, protocol, "split-marker");
        List<RawResponse> coalesced =
            coalescedPair(
                server, protocol, "coalesced-marker-1", "coalesced-marker-2");

        assertBoundaryResponse(split, protocol, "split", "split-marker", false);
        assertCoalescedPair(
            coalesced,
            protocol,
            "coalesced-marker-1",
            "coalesced-marker-2");
      }
    }
  }

  @RepeatedTest(2)
  void serializedProxyFallbackReturnsPartialThenFinalEvidence() throws Exception {
    for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
      try (TlsBoundaryHttpsServer server = start(protocol, SERIALIZED_TEST_GRACE_MILLIS)) {
        List<RawResponse> responses =
            serializedPair(
                server,
                protocol,
                "serialized-marker-1",
                "serialized-marker-2");

        assertSerializedPair(
            responses,
            protocol,
            "serialized-marker-1",
            "serialized-marker-2",
            SERIALIZED_TEST_GRACE_MILLIS);
      }
    }
  }

  @Test
  void secondRequestBeforeGraceCancelsFallbackAndUsesOneParserBuffer()
      throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.3", RACE_TEST_GRACE_MILLIS)) {
      List<RawResponse> responses =
          pairAcrossWritesBeforeGrace(
              server,
              "TLSv1.3",
              "grace-race-marker-1",
              "grace-race-marker-2");

      assertCoalescedPair(
          responses,
          "TLSv1.3",
          "grace-race-marker-1",
          "grace-race-marker-2");
      String evidence = extractEvidence(responses.get(0).body);
      assertTrue(evidence.contains("\"delivery_shape\":\"parser_coalesced\""), evidence);
      assertTrue(evidence.contains("\"coalescing_grace_expired\":false"), evidence);
      assertTrue(
          evidence.contains("\"coalescing_grace_millis\":" + RACE_TEST_GRACE_MILLIS),
          evidence);
    }
  }

  @Test
  void closeCancelsAPendingCoalescingGraceAndReleasesExecutors() throws Exception {
    TlsBoundaryHttpsServer server = start("TLSv1.3", RACE_TEST_GRACE_MILLIS);
    try (SSLSocket socket =
        connect(server, "TLSv1.3", TlsBoundaryHttpsServer.Mode.COALESCED)) {
      socket
          .getOutputStream()
          .write(
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED,
                  "close-pending-grace",
                  1,
                  false));
      socket.getOutputStream().flush();
      Thread.sleep(100);

      server.close();

      assertTrue(server.isTerminated());
      assertClosedWithoutResponse(socket.getInputStream());
    } finally {
      server.close();
    }
  }

  @Test
  void rejectsOutOfRangeCoalescingGraceBeforeAllocatingExecutors() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            TlsBoundaryHttpsServer.start(
                0, 0, keyStore, KEYSTORE_PASSWORD, "TLSv1.3", 0));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            TlsBoundaryHttpsServer.start(
                0, 0, keyStore, KEYSTORE_PASSWORD, "TLSv1.3", 1001));
  }

  @Test
  void isolatesConcurrentConnectionEvidence() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.3")) {
      ExecutorService executor = Executors.newFixedThreadPool(8);
      try {
        List<Callable<List<RawResponse>>> requests = new ArrayList<>();
        for (int index = 0; index < 8; index++) {
          int sequence = index;
          if (index % 2 == 0) {
            requests.add(
                () ->
                    List.of(
                        splitRequest(
                            server, "TLSv1.3", "parallel-marker-" + sequence)));
          } else {
            requests.add(
                () ->
                    coalescedPair(
                        server,
                        "TLSv1.3",
                        "parallel-marker-" + sequence + "-1",
                        "parallel-marker-" + sequence + "-2"));
          }
        }
        List<Future<List<RawResponse>>> responses = executor.invokeAll(requests);
        for (int index = 0; index < responses.size(); index++) {
          List<RawResponse> response = responses.get(index).get(20, TimeUnit.SECONDS);
          if (index % 2 == 0) {
            assertEquals(1, response.size());
            assertBoundaryResponse(
                response.get(0),
                "TLSv1.3",
                "split",
                "parallel-marker-" + index,
                false);
          } else {
            assertCoalescedPair(
                response,
                "TLSv1.3",
                "parallel-marker-" + index + "-1",
                "parallel-marker-" + index + "-2");
          }
        }
      } finally {
        executor.shutdownNow();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
      }
    }
  }

  @Test
  void rejectsRequestsWithoutTheBoundedHeaderAndBodyShape() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.3");
        SSLSocket socket = connect(server, "TLSv1.3", TlsBoundaryHttpsServer.Mode.SPLIT)) {
      byte[] invalid =
          ("POST "
                  + TlsBoundaryHttpsServer.SPLIT_API_PATH
                  + " HTTP/1.1\r\nHost: localhost\r\nX-OBI-Demo-ID: short\r\n"
                  + TlsBoundaryHttpsServer.SEQUENCE_HEADER
                  + ": 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
              .getBytes(StandardCharsets.US_ASCII);
      socket.getOutputStream().write(invalid);
      socket.getOutputStream().flush();
      assertClosedWithoutResponse(socket.getInputStream());
    }
  }

  @Test
  void coalescedPairRejectsDuplicateAndOutOfOrderSequences() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.3")) {
      assertCoalescedRejected(
          server,
          concat(
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "duplicate-1", 1, false),
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "duplicate-2", 1, false)));
      assertCoalescedRejected(
          server,
          concat(
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "out-of-order-1", 2, false),
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "out-of-order-2", 1, false)));
    }
  }

  @Test
  void coalescedPairRejectsDuplicateMarkersAndTrailingBytes() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.3")) {
      assertCoalescedRejected(
          server,
          concat(
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "duplicate-marker", 1, false),
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "duplicate-marker", 2, false)));
      assertCoalescedRejected(
          server,
          concat(
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "trailing-1", 1, false),
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "trailing-2", 2, false),
              new byte[] {'X'}));
    }
  }

  @Test
  void coalescedPairRejectsMalformedSecondRequest() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.3")) {
      byte[] malformed =
          ("POST "
                  + TlsBoundaryHttpsServer.COALESCED_API_PATH
                  + " HTTP/1.1\r\nHost: localhost\r\n"
                  + TlsBoundaryHttpsServer.SEQUENCE_HEADER
                  + ": 2\r\nContent-Length: invalid\r\nConnection: keep-alive\r\n\r\n")
              .getBytes(StandardCharsets.US_ASCII);
      assertCoalescedRejected(
          server,
          concat(
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "malformed-1", 1, false),
              malformed));
    }
  }

  @Test
  void serializedFallbackRejectsInvalidSecondRequestsWithoutFinalEvidence()
      throws Exception {
    try (TlsBoundaryHttpsServer server =
        start("TLSv1.3", SERIALIZED_TEST_GRACE_MILLIS)) {
      assertSerializedSecondRejected(
          server,
          "serialized-duplicate-marker",
          boundaryRequest(
              TlsBoundaryHttpsServer.Mode.COALESCED,
              "serialized-duplicate-marker",
              2,
              false));
      assertSerializedSecondRejected(
          server,
          "serialized-wrong-sequence-1",
          boundaryRequest(
              TlsBoundaryHttpsServer.Mode.COALESCED,
              "serialized-wrong-sequence-2",
              1,
              false));
      assertSerializedSecondRejected(
          server,
          "serialized-trailing-1",
          concat(
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED,
                  "serialized-trailing-2",
                  2,
                  false),
              new byte[] {'X'}));
      byte[] malformed =
          ("POST "
                  + TlsBoundaryHttpsServer.COALESCED_API_PATH
                  + " HTTP/1.1\r\nHost: localhost\r\n"
                  + TlsBoundaryHttpsServer.SEQUENCE_HEADER
                  + ": 2\r\nContent-Length: invalid\r\nConnection: keep-alive\r\n\r\n")
              .getBytes(StandardCharsets.US_ASCII);
      assertSerializedSecondRejected(server, "serialized-malformed-1", malformed);
    }
  }

  @Test
  @Timeout(15)
  void serializedFirstRequestReturnsPartialEvidenceThenTimesOut() throws Exception {
    try (TlsBoundaryHttpsServer server =
            start("TLSv1.3", SERIALIZED_TEST_GRACE_MILLIS);
        SSLSocket socket = connect(server, "TLSv1.3", TlsBoundaryHttpsServer.Mode.COALESCED)) {
      socket.setSoTimeout(8_000);
      OutputStream output = socket.getOutputStream();
      output.write(
          boundaryRequest(
              TlsBoundaryHttpsServer.Mode.COALESCED, "one-only", 1, false));
      output.flush();

      InputStream input = new BufferedInputStream(socket.getInputStream());
      RawResponse partial = readResponse(input);
      assertPartialSerializedEvidence(
          partial, "TLSv1.3", "one-only", SERIALIZED_TEST_GRACE_MILLIS);
      assertClosedWithoutResponse(input);
    }
  }

  @Test
  @Timeout(15)
  void secondRequestStartedBeforeGraceButTruncatedFailsClosed() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.3", 500);
        SSLSocket socket = connect(server, "TLSv1.3", TlsBoundaryHttpsServer.Mode.COALESCED)) {
      socket.setSoTimeout(8_000);
      byte[] first =
          boundaryRequest(
              TlsBoundaryHttpsServer.Mode.COALESCED, "truncated-start-1", 1, false);
      byte[] second =
          boundaryRequest(
              TlsBoundaryHttpsServer.Mode.COALESCED, "truncated-start-2", 2, false);
      socket
          .getOutputStream()
          .write(concat(first, Arrays.copyOf(second, 64)));
      socket.getOutputStream().flush();

      assertClosedWithoutResponse(socket.getInputStream());
    }
  }

  @Test
  @Timeout(15)
  void coalescedSequencesOnSeparateConnectionsNeverComplete() throws Exception {
    try (TlsBoundaryHttpsServer server =
            start("TLSv1.3", SERIALIZED_TEST_GRACE_MILLIS);
        SSLSocket first = connect(server, "TLSv1.3", TlsBoundaryHttpsServer.Mode.COALESCED);
        SSLSocket second = connect(server, "TLSv1.3", TlsBoundaryHttpsServer.Mode.COALESCED)) {
      first.setSoTimeout(8_000);
      second.setSoTimeout(8_000);
      first
          .getOutputStream()
          .write(
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "separate-1", 1, false));
      first.getOutputStream().flush();
      second
          .getOutputStream()
          .write(
              boundaryRequest(
                  TlsBoundaryHttpsServer.Mode.COALESCED, "separate-2", 2, false));
      second.getOutputStream().flush();

      RawResponse partial = readResponse(new BufferedInputStream(first.getInputStream()));
      assertPartialSerializedEvidence(
          partial, "TLSv1.3", "separate-1", SERIALIZED_TEST_GRACE_MILLIS);
      assertClosedWithoutResponse(second.getInputStream());
    }
  }

  @Test
  void rejectsAClientThatOnlyOffersAnotherTlsVersion() throws Exception {
    try (TlsBoundaryHttpsServer server = start("TLSv1.2")) {
      assertThrows(
          IOException.class,
          () ->
              splitRequest(server, "TLSv1.3", "wrong-protocol"));
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
          } catch (SocketTimeoutException timeout) {
            throw new AssertionError(
                "periodic bytes kept the request alive past its absolute deadline", timeout);
          } catch (IOException expected) {
            closed = true;
          }
        }
        assertTrue(closed, "periodic bytes kept the request alive past its absolute deadline");
      }
    }
  }

  @Test
  void closureOracleRejectsAReadTimeout() {
    InputStream timeout =
        new InputStream() {
          @Override
          public int read() throws IOException {
            throw new SocketTimeoutException("synthetic timeout");
          }
        };

    AssertionError failure =
        assertThrows(AssertionError.class, () -> assertClosedWithoutResponse(timeout));

    assertTrue(failure.getCause() instanceof SocketTimeoutException);
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

  private static TlsBoundaryHttpsServer start(String protocol, long coalescingGraceMillis)
      throws Exception {
    return TlsBoundaryHttpsServer.start(
        0,
        0,
        keyStore,
        KEYSTORE_PASSWORD,
        protocol,
        coalescingGraceMillis);
  }

  private static RawResponse splitRequest(
      TlsBoundaryHttpsServer server, String protocol, String marker) throws Exception {
    return exchangeSingle(
        server,
        protocol,
        TlsBoundaryHttpsServer.Mode.SPLIT,
        boundaryRequest(TlsBoundaryHttpsServer.Mode.SPLIT, marker, 1, true));
  }

  private static List<RawResponse> coalescedPair(
      TlsBoundaryHttpsServer server, String protocol, String firstMarker, String secondMarker)
      throws Exception {
    byte[] requests =
        concat(
            boundaryRequest(
                TlsBoundaryHttpsServer.Mode.COALESCED, firstMarker, 1, false),
            boundaryRequest(
                TlsBoundaryHttpsServer.Mode.COALESCED, secondMarker, 2, false));
    try (SSLSocket socket =
        connect(server, protocol, TlsBoundaryHttpsServer.Mode.COALESCED)) {
      OutputStream output = socket.getOutputStream();
      output.write(requests);
      output.flush();
      InputStream input = new BufferedInputStream(socket.getInputStream());
      RawResponse first = readResponse(input);
      RawResponse second = readResponse(input);
      assertEquals(-1, input.read(), "server did not close after the second response");
      return List.of(first, second);
    }
  }

  private static List<RawResponse> serializedPair(
      TlsBoundaryHttpsServer server, String protocol, String firstMarker, String secondMarker)
      throws Exception {
    try (SSLSocket socket =
        connect(server, protocol, TlsBoundaryHttpsServer.Mode.COALESCED)) {
      OutputStream output = socket.getOutputStream();
      InputStream input = new BufferedInputStream(socket.getInputStream());
      output.write(
          boundaryRequest(
              TlsBoundaryHttpsServer.Mode.COALESCED, firstMarker, 1, false));
      output.flush();
      RawResponse first = readResponse(input);

      output.write(
          boundaryRequest(
              TlsBoundaryHttpsServer.Mode.COALESCED, secondMarker, 2, false));
      output.flush();
      RawResponse second = readResponse(input);
      assertEquals(-1, input.read(), "server did not close after the serialized pair");
      return List.of(first, second);
    }
  }

  private static List<RawResponse> pairAcrossWritesBeforeGrace(
      TlsBoundaryHttpsServer server, String protocol, String firstMarker, String secondMarker)
      throws Exception {
    try (SSLSocket socket =
        connect(server, protocol, TlsBoundaryHttpsServer.Mode.COALESCED)) {
      OutputStream output = socket.getOutputStream();
      InputStream input = new BufferedInputStream(socket.getInputStream());
      output.write(
          boundaryRequest(
              TlsBoundaryHttpsServer.Mode.COALESCED, firstMarker, 1, false));
      output.flush();
      Thread.sleep(50);
      output.write(
          boundaryRequest(
              TlsBoundaryHttpsServer.Mode.COALESCED, secondMarker, 2, false));
      output.flush();

      RawResponse first = readResponse(input);
      RawResponse second = readResponse(input);
      assertEquals(-1, input.read(), "server did not close after the direct pair");
      return List.of(first, second);
    }
  }

  private static RawResponse exchangeSingle(
      TlsBoundaryHttpsServer server,
      String protocol,
      TlsBoundaryHttpsServer.Mode mode,
      byte[] request)
      throws Exception {
    try (SSLSocket socket = connect(server, protocol, mode)) {
      OutputStream output = socket.getOutputStream();
      output.write(request);
      output.flush();
      InputStream input = new BufferedInputStream(socket.getInputStream());
      RawResponse response = readResponse(input);
      assertEquals(-1, input.read(), "server did not close after the response");
      return response;
    }
  }

  private static SSLSocket connect(
      TlsBoundaryHttpsServer server, String protocol, TlsBoundaryHttpsServer.Mode mode)
      throws Exception {
    TlsContextFactory.Contexts contexts =
        TlsContextFactory.load(keyStore, KEYSTORE_PASSWORD, protocol);
    SSLSocket socket = (SSLSocket) contexts.clientSocketFactory().createSocket();
    try {
      socket.setEnabledProtocols(new String[] {protocol});
      socket.connect(new InetSocketAddress("127.0.0.1", server.port(mode)), 5_000);
      socket.setSoTimeout(10_000);
      socket.startHandshake();
      return socket;
    } catch (Exception failure) {
      try {
        socket.close();
      } catch (IOException ignored) {
        // Preserve the connection or handshake failure.
      }
      throw failure;
    }
  }

  private static byte[] boundaryRequest(
      TlsBoundaryHttpsServer.Mode mode, String marker, int sequence, boolean close)
      throws IOException {
    StringBuilder headers = new StringBuilder();
    headers
        .append("POST ")
        .append(mode.path())
        .append(" HTTP/1.1\r\nHost: localhost\r\nX-OBI-Demo-ID: ")
        .append(marker)
        .append("\r\n")
        .append(TlsBoundaryHttpsServer.SEQUENCE_HEADER)
        .append(": ")
        .append(sequence)
        .append("\r\nContent-Type: application/octet-stream\r\nContent-Length: ")
        .append(TlsBoundaryHttpsServer.MIN_BODY_BYTES)
        .append("\r\nConnection: ")
        .append(close ? "close" : "keep-alive")
        .append("\r\n");
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
    ByteArrayOutputStream request = new ByteArrayOutputStream();
    request.write(headers.toString().getBytes(StandardCharsets.US_ASCII));
    request.write(new byte[TlsBoundaryHttpsServer.MIN_BODY_BYTES]);
    return request.toByteArray();
  }

  private static byte[] concat(byte[]... values) throws IOException {
    ByteArrayOutputStream combined = new ByteArrayOutputStream();
    for (byte[] value : values) {
      combined.write(value);
    }
    return combined.toByteArray();
  }

  private static void assertCoalescedRejected(
      TlsBoundaryHttpsServer server, byte[] requests) throws Exception {
    try (SSLSocket socket =
        connect(server, "TLSv1.3", TlsBoundaryHttpsServer.Mode.COALESCED)) {
      OutputStream output = socket.getOutputStream();
      output.write(requests);
      output.flush();
      assertClosedWithoutResponse(socket.getInputStream());
    }
  }

  private static void assertSerializedSecondRejected(
      TlsBoundaryHttpsServer server, String firstMarker, byte[] secondRequest)
      throws Exception {
    try (SSLSocket socket =
        connect(server, "TLSv1.3", TlsBoundaryHttpsServer.Mode.COALESCED)) {
      OutputStream output = socket.getOutputStream();
      InputStream input = new BufferedInputStream(socket.getInputStream());
      output.write(
          boundaryRequest(
              TlsBoundaryHttpsServer.Mode.COALESCED, firstMarker, 1, false));
      output.flush();
      RawResponse partial = readResponse(input);
      assertPartialSerializedEvidence(
          partial, "TLSv1.3", firstMarker, SERIALIZED_TEST_GRACE_MILLIS);

      output.write(secondRequest);
      output.flush();
      assertClosedWithoutResponse(input);
    }
  }

  private static void assertClosedWithoutResponse(InputStream input) {
    boolean closed = false;
    try {
      closed = input.read() == -1;
    } catch (SocketTimeoutException timeout) {
      throw new AssertionError("server left the rejected connection open", timeout);
    } catch (IOException expected) {
      closed = true;
    }
    assertTrue(closed, "server returned bytes for a rejected coalesced request set");
  }

  private static RawResponse readResponse(InputStream input) throws IOException {
    String statusLine = readAsciiLine(input);
    if (statusLine == null) {
      throw new EOFException("server closed without an HTTP response");
    }
    Map<String, String> headers = new LinkedHashMap<>();
    boolean complete = false;
    for (int count = 0; count < MAX_RESPONSE_HEADERS; count++) {
      String line = readAsciiLine(input);
      if (line == null) {
        throw new EOFException("response headers ended early");
      }
      if (line.isEmpty()) {
        complete = true;
        break;
      }
      int colon = line.indexOf(':');
      if (colon <= 0) {
        throw new IOException("malformed response header");
      }
      headers.put(
          line.substring(0, colon).toLowerCase(Locale.ROOT),
          line.substring(colon + 1).trim());
    }
    if (!complete) {
      throw new IOException("response contains too many headers");
    }
    int contentLength;
    try {
      contentLength = Integer.parseInt(headers.getOrDefault("content-length", "-1"));
    } catch (NumberFormatException invalid) {
      throw new IOException("invalid response content length", invalid);
    }
    if (contentLength < 0 || contentLength > MAX_RESPONSE_BODY_BYTES) {
      throw new IOException("response body length is outside the test bound");
    }
    byte[] body = input.readNBytes(contentLength);
    if (body.length != contentLength) {
      throw new EOFException("response body ended early");
    }
    return new RawResponse(statusLine, headers, new String(body, StandardCharsets.UTF_8));
  }

  private static String readAsciiLine(InputStream input) throws IOException {
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    boolean carriageReturn = false;
    while (line.size() <= MAX_RESPONSE_LINE_BYTES) {
      int next = input.read();
      if (next < 0) {
        return line.size() == 0 && !carriageReturn
            ? null
            : throwEarlyResponseLine();
      }
      if (carriageReturn) {
        if (next == '\n') {
          return line.toString(StandardCharsets.US_ASCII);
        }
        line.write('\r');
        carriageReturn = false;
      }
      if (next == '\r') {
        carriageReturn = true;
      } else {
        line.write(next);
      }
    }
    throw new IOException("response line exceeds the test bound");
  }

  private static String throwEarlyResponseLine() throws EOFException {
    throw new EOFException("response line ended early");
  }

  private static void assertCoalescedPair(
      List<RawResponse> responses, String protocol, String firstMarker, String secondMarker) {
    assertEquals(2, responses.size());
    RawResponse first = responses.get(0);
    RawResponse second = responses.get(1);
    assertEquals("keep-alive", first.header("connection"));
    assertEquals("close", second.header("connection"));
    assertBoundaryResponse(first, protocol, "coalesced", firstMarker, true);
    assertBoundaryResponse(second, protocol, "coalesced", secondMarker, true);

    String firstEvidence = extractEvidence(first.body);
    String secondEvidence = extractEvidence(second.body);
    assertEquals(firstEvidence, secondEvidence, "coalesced responses carried different evidence");
    assertEquals(
        extractJsonLong(first.body, "backend_connection_id"),
        extractJsonLong(second.body, "backend_connection_id"));
    assertEquals(
        extractJsonLong(first.body, "backend_remote_port"),
        extractJsonLong(second.body, "backend_remote_port"));
    assertFalse(first.body.contains(secondMarker), first.body);
    assertFalse(second.body.contains(firstMarker), second.body);
    assertFalse(firstEvidence.contains(firstMarker), firstEvidence);
    assertFalse(firstEvidence.contains(secondMarker), firstEvidence);
  }

  private static void assertSerializedPair(
      List<RawResponse> responses,
      String protocol,
      String firstMarker,
      String secondMarker,
      long graceMillis) {
    assertEquals(2, responses.size());
    RawResponse first = responses.get(0);
    RawResponse second = responses.get(1);
    assertPartialSerializedEvidence(first, protocol, firstMarker, graceMillis);
    assertFinalSerializedEvidence(second, protocol, secondMarker, graceMillis);
    assertEquals(
        extractJsonLong(first.body, "backend_connection_id"),
        extractJsonLong(second.body, "backend_connection_id"));
    assertEquals(
        extractJsonLong(first.body, "backend_remote_port"),
        extractJsonLong(second.body, "backend_remote_port"));

    String firstEvidence = extractEvidence(first.body);
    String secondEvidence = extractEvidence(second.body);
    assertFalse(first.body.contains(secondMarker), first.body);
    assertFalse(second.body.contains(firstMarker), second.body);
    assertFalse(firstEvidence.contains(firstMarker), firstEvidence);
    assertFalse(firstEvidence.contains(secondMarker), firstEvidence);
    assertFalse(secondEvidence.contains(firstMarker), secondEvidence);
    assertFalse(secondEvidence.contains(secondMarker), secondEvidence);
  }

  private static void assertPartialSerializedEvidence(
      RawResponse response, String protocol, String marker, long graceMillis) {
    assertTrue(response.statusLine.startsWith("HTTP/1.1 200 "), response.statusLine);
    assertEquals("keep-alive", response.header("connection"));
    assertTrue(response.body.contains("\"marker\":\"" + marker + "\""), response.body);
    assertTrue(
        response.body.contains("\"tls_protocol\":\"" + protocol + "\""),
        response.body);
    String evidence = extractEvidence(response.body);
    assertEvidenceSchema(evidence);
    assertTrue(evidence.contains("\"mode\":\"coalesced\""), evidence);
    assertTrue(
        evidence.contains("\"delivery_shape\":\"serialized_proxy_fallback\""), evidence);
    assertTrue(evidence.contains("\"evidence_phase\":\"partial\""), evidence);
    assertTrue(
        evidence.contains("\"fallback_reason\":\"coalescing_grace_expired\""), evidence);
    assertTrue(evidence.contains("\"coalescing_grace_millis\":" + graceMillis), evidence);
    assertTrue(evidence.contains("\"coalescing_grace_expired\":true"), evidence);
    assertTrue(evidence.contains("\"passed\":false"), evidence);
    assertTrue(evidence.contains("\"failure_reason\":\"none\""), evidence);
    assertTrue(evidence.contains("\"request_complete\":false"), evidence);
    assertTrue(evidence.contains("\"request_count\":1"), evidence);
    assertTrue(evidence.contains("\"request_body_bytes\":[32768]"), evidence);
    assertTrue(evidence.contains("\"request_order\":[1]"), evidence);
    assertTrue(evidence.contains("\"emission_order\":[1]"), evidence);
    assertTrue(evidence.contains("\"emission_parser_callback_order\":[1]"), evidence);
    assertTrue(evidence.contains("\"response_order\":[1]"), evidence);
    assertTrue(evidence.contains("\"response_connection_close\":[false]"), evidence);
    assertTrue(evidence.contains("\"parser_callback_count\":1"), evidence);
    assertTrue(evidence.contains("\"parser_shape_exact\":true"), evidence);
    assertTrue(evidence.contains("\"parser_facing_coalesced\":false"), evidence);
    assertTrue(evidence.contains("\"split_buffers_forwarded_unchanged\":false"), evidence);
    assertTrue(
        evidence.contains("\"requests_emitted_from_single_parser_callback\":false"),
        evidence);
    assertTrue(evidence.contains("\"wire_decrypted_pairs_exact\":true"), evidence);
    assertTrue(evidence.contains("\"headers_spanned_records\":true"), evidence);
    assertTrue(evidence.contains("\"handoff_before_parse\":true"), evidence);
    assertTrue(evidence.contains("\"request_bytes_preserved\":false"), evidence);
    assertTrue(evidence.contains("\"verification_pair_digest_exact\":false"), evidence);
    assertTrue(evidence.contains("\"first_response_keeps_alive\":true"), evidence);
    assertTrue(evidence.contains("\"response_forces_connection_close\":false"), evidence);
    assertEquals(
        extractJsonLong(evidence, "decrypted_total_bytes"),
        extractJsonLong(evidence, "parser_total_bytes"));
    assertEquals(
        extractJsonLong(evidence, "decrypted_total_bytes"),
        extractJsonLong(evidence, "verification_buffer_bytes"));
    assertVerificationBound(evidence);
    assertFalse(evidence.contains(marker), evidence);
    assertFalse(evidence.contains("Z-OBI-Boundary-Pad"), evidence);
    assertFalse(evidence.contains("pppppppp"), evidence);
  }

  private static void assertFinalSerializedEvidence(
      RawResponse response, String protocol, String marker, long graceMillis) {
    assertTrue(response.statusLine.startsWith("HTTP/1.1 200 "), response.statusLine);
    assertEquals("close", response.header("connection"));
    assertTrue(response.body.contains("\"marker\":\"" + marker + "\""), response.body);
    assertTrue(
        response.body.contains("\"tls_protocol\":\"" + protocol + "\""),
        response.body);
    String evidence = extractEvidence(response.body);
    assertEvidenceSchema(evidence);
    assertTrue(evidence.contains("\"mode\":\"coalesced\""), evidence);
    assertTrue(
        evidence.contains("\"delivery_shape\":\"serialized_proxy_fallback\""), evidence);
    assertTrue(evidence.contains("\"evidence_phase\":\"final\""), evidence);
    assertTrue(
        evidence.contains("\"fallback_reason\":\"coalescing_grace_expired\""), evidence);
    assertTrue(evidence.contains("\"coalescing_grace_millis\":" + graceMillis), evidence);
    assertTrue(evidence.contains("\"coalescing_grace_expired\":true"), evidence);
    assertTrue(evidence.contains("\"passed\":true"), evidence);
    assertTrue(evidence.contains("\"failure_reason\":\"none\""), evidence);
    assertTrue(evidence.contains("\"request_complete\":true"), evidence);
    assertTrue(evidence.contains("\"request_count\":2"), evidence);
    assertTrue(evidence.contains("\"request_body_bytes\":[32768,32768]"), evidence);
    assertTrue(evidence.contains("\"request_order\":[1,2]"), evidence);
    assertTrue(evidence.contains("\"emission_order\":[1,2]"), evidence);
    assertTrue(evidence.contains("\"emission_parser_callback_order\":[1,2]"), evidence);
    assertTrue(evidence.contains("\"response_order\":[1,2]"), evidence);
    assertTrue(evidence.contains("\"response_connection_close\":[false,true]"), evidence);
    assertTrue(evidence.contains("\"parser_callback_count\":2"), evidence);
    assertTrue(evidence.contains("\"parser_shape_exact\":true"), evidence);
    assertTrue(evidence.contains("\"parser_facing_coalesced\":false"), evidence);
    assertTrue(evidence.contains("\"split_buffers_forwarded_unchanged\":false"), evidence);
    assertTrue(
        evidence.contains("\"requests_emitted_from_single_parser_callback\":false"),
        evidence);
    assertTrue(evidence.contains("\"wire_decrypted_pairs_exact\":true"), evidence);
    assertTrue(evidence.contains("\"headers_spanned_records\":true"), evidence);
    assertTrue(evidence.contains("\"handoff_before_parse\":true"), evidence);
    assertTrue(evidence.contains("\"request_bytes_preserved\":true"), evidence);
    assertTrue(evidence.contains("\"verification_pair_digest_exact\":true"), evidence);
    assertTrue(evidence.contains("\"first_response_keeps_alive\":true"), evidence);
    assertTrue(evidence.contains("\"response_forces_connection_close\":true"), evidence);
    assertEquals(
        extractJsonLong(evidence, "decrypted_total_bytes"),
        extractJsonLong(evidence, "parser_total_bytes"));
    assertEquals(
        extractJsonLong(evidence, "decrypted_total_bytes"),
        extractJsonLong(evidence, "verification_buffer_bytes"));
    List<Integer> requestTotals = extractJsonIntList(evidence, "request_total_bytes");
    assertEquals(2, requestTotals.size());
    assertEquals(
        (long) requestTotals.get(0) + requestTotals.get(1),
        extractJsonLong(evidence, "verification_buffer_bytes"));
    assertVerificationBound(evidence);
    assertFalse(evidence.contains(marker), evidence);
    assertFalse(evidence.contains("Z-OBI-Boundary-Pad"), evidence);
    assertFalse(evidence.contains("pppppppp"), evidence);
  }

  private static void assertBoundaryResponse(
      RawResponse response,
      String protocol,
      String mode,
      String marker,
      boolean coalesced) {
    assertTrue(response.statusLine.startsWith("HTTP/1.1 200 "), response.statusLine);
    String body = response.body;
    assertTrue(body.contains("\"marker\":\"" + marker + "\""), body);
    assertTrue(body.contains("\"tls_protocol\":\"" + protocol + "\""), body);
    assertTrue(body.contains("\"backend_kind\":\"netty-tls-boundary\""), body);
    String evidence = extractEvidence(body);
    assertEvidenceSchema(evidence);
    assertTrue(evidence.contains("\"mode\":\"" + mode + "\""), evidence);
    assertTrue(evidence.contains("\"evidence_phase\":\"final\""), evidence);
    assertTrue(evidence.contains("\"fallback_reason\":\"none\""), evidence);
    assertTrue(evidence.contains("\"coalescing_grace_expired\":false"), evidence);
    assertTrue(evidence.contains("\"passed\":true"), evidence);
    assertTrue(evidence.contains("\"failure_reason\":\"none\""), evidence);
    assertTrue(evidence.contains("\"request_complete\":true"), evidence);
    assertTrue(evidence.contains("\"headers_spanned_records\":true"), evidence);
    assertTrue(evidence.contains("\"wire_decrypted_pairs_exact\":true"), evidence);
    assertTrue(evidence.contains("\"parser_shape_exact\":true"), evidence);
    assertTrue(evidence.contains("\"request_bytes_preserved\":true"), evidence);
    assertTrue(evidence.contains("\"handoff_before_parse\":true"), evidence);
    assertTrue(evidence.contains("\"response_forces_connection_close\":true"), evidence);
    assertTrue(evidence.contains("\"parser_facing_coalesced\":" + coalesced), evidence);
    assertTrue(
        evidence.contains("\"request_body_bytes\":" + (coalesced ? "[32768,32768]" : "[32768]")),
        evidence);
    assertTrue(
        evidence.contains("\"request_order\":" + (coalesced ? "[1,2]" : "[1]")),
        evidence);
    assertTrue(
        evidence.contains("\"emission_order\":" + (coalesced ? "[1,2]" : "[1]")),
        evidence);
    assertTrue(
        evidence.contains("\"response_order\":" + (coalesced ? "[1,2]" : "[1]")),
        evidence);
    if (coalesced) {
      assertTrue(evidence.contains("\"delivery_shape\":\"parser_coalesced\""), evidence);
      assertTrue(evidence.contains("\"split_buffers_forwarded_unchanged\":false"), evidence);
      assertTrue(evidence.contains("\"request_count\":2"), evidence);
      assertTrue(evidence.contains("\"parser_callback_count\":1"), evidence);
      assertTrue(evidence.contains("\"emission_parser_callback_order\":[1,1]"), evidence);
      assertTrue(evidence.contains("\"response_connection_close\":[false,true]"), evidence);
      assertTrue(
          evidence.contains("\"requests_emitted_from_single_parser_callback\":true"),
          evidence);
      assertTrue(evidence.contains("\"first_response_keeps_alive\":true"), evidence);
      assertTrue(evidence.contains("\"verification_pair_digest_exact\":true"), evidence);
      assertEquals(
          extractJsonLong(evidence, "decrypted_total_bytes"),
          extractJsonLong(evidence, "verification_buffer_bytes"));
      assertVerificationBound(evidence);
    } else {
      assertTrue(evidence.contains("\"delivery_shape\":\"split\""), evidence);
      assertTrue(evidence.contains("\"coalescing_grace_millis\":0"), evidence);
      assertTrue(evidence.contains("\"request_count\":1"), evidence);
      assertTrue(evidence.contains("\"response_connection_close\":[true]"), evidence);
      assertTrue(evidence.contains("\"split_buffers_forwarded_unchanged\":true"), evidence);
      assertTrue(evidence.contains("\"first_response_keeps_alive\":false"), evidence);
      assertTrue(evidence.contains("\"verification_buffer_bytes\":0"), evidence);
      assertTrue(evidence.contains("\"verification_buffer_limit_bytes\":0"), evidence);
      assertTrue(evidence.contains("\"verification_pair_digest_exact\":false"), evidence);

      List<Integer> decryptedCallbackLengths =
          extractJsonIntList(evidence, "decrypted_callback_lengths");
      List<Integer> parserCallbackLengths =
          extractJsonIntList(evidence, "parser_callback_lengths");
      List<Integer> headerCallbackCounts =
          extractJsonIntList(evidence, "request_header_decrypted_callback_counts");
      List<Integer> emissionParserCallbackOrder =
          extractJsonIntList(evidence, "emission_parser_callback_order");
      assertEquals(decryptedCallbackLengths, parserCallbackLengths, evidence);
      assertEquals(
          decryptedCallbackLengths.size(),
          extractJsonLong(evidence, "parser_callback_count"),
          evidence);
      assertEquals(1, headerCallbackCounts.size(), evidence);
      assertEquals(1, emissionParserCallbackOrder.size(), evidence);
      int headerCompletionCallback = headerCallbackCounts.get(0);
      int emissionCallback = emissionParserCallbackOrder.get(0);
      assertTrue(headerCompletionCallback >= 2, evidence);
      assertTrue(headerCompletionCallback <= decryptedCallbackLengths.size(), evidence);
      assertTrue(emissionCallback >= headerCompletionCallback, evidence);
      assertTrue(emissionCallback <= decryptedCallbackLengths.size(), evidence);
    }
    assertFalse(evidence.contains(marker), evidence);
    assertFalse(evidence.contains("Z-OBI-Boundary-Pad"), evidence);
    assertFalse(evidence.contains("pppppppp"), evidence);
  }

  private static String extractEvidence(String body) {
    String field = "\"tls_boundary\":";
    int start = body.indexOf(field);
    int outerEnd = body.lastIndexOf('}');
    assertTrue(start >= 0 && outerEnd > start, body);
    return body.substring(start + field.length(), outerEnd);
  }

  private static long extractJsonLong(String body, String field) {
    String prefix = "\"" + field + "\":";
    int start = body.indexOf(prefix);
    assertTrue(start >= 0, body);
    start += prefix.length();
    int end = start;
    while (end < body.length() && Character.isDigit(body.charAt(end))) {
      end++;
    }
    assertTrue(end > start, body);
    return Long.parseLong(body.substring(start, end));
  }

  private static List<Integer> extractJsonIntList(String body, String field) {
    String prefix = "\"" + field + "\":[";
    int start = body.indexOf(prefix);
    assertTrue(start >= 0, body);
    start += prefix.length();
    int end = body.indexOf(']', start);
    assertTrue(end >= start, body);
    if (end == start) {
      return List.of();
    }
    List<Integer> values = new ArrayList<>();
    for (String value : body.substring(start, end).split(",")) {
      values.add(Integer.parseInt(value));
    }
    return List.copyOf(values);
  }

  private static void assertEvidenceSchema(String evidence) {
    Matcher matcher = JSON_FIELD_PATTERN.matcher(evidence);
    List<String> fields = new ArrayList<>();
    while (matcher.find()) {
      fields.add(matcher.group(1));
    }
    assertEquals(EVIDENCE_FIELDS, fields, evidence);
  }

  private static void assertVerificationBound(String evidence) {
    long bytes = extractJsonLong(evidence, "verification_buffer_bytes");
    long limit = extractJsonLong(evidence, "verification_buffer_limit_bytes");
    assertTrue(bytes > 0, evidence);
    assertTrue(bytes <= limit, evidence);
    assertEquals(2L * ((32 * 1024) + (40 * 1024)), limit, evidence);
  }

  private static final class RawResponse {
    private final String statusLine;
    private final Map<String, String> headers;
    private final String body;

    private RawResponse(String statusLine, Map<String, String> headers, String body) {
      this.statusLine = statusLine;
      this.headers = Map.copyOf(headers);
      this.body = body;
    }

    private String header(String name) {
      return headers.get(name.toLowerCase(Locale.ROOT));
    }
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
