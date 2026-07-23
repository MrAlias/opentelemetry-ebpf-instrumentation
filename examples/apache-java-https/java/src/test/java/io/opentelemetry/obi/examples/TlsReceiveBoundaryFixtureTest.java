// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

@Timeout(20)
class TlsReceiveBoundaryFixtureTest {
  private static final String KEYSTORE_PASSWORD = "boundary-test";

  @TempDir static Path temporaryDirectory;

  private static Path keyStore;

  @BeforeAll
  static void createKeyStore() throws Exception {
    keyStore = temporaryDirectory.resolve("boundary.p12");
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
                "boundary",
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

  @RepeatedTest(3)
  void splitModeRecordsTwoDecryptedCallbacksBeforeParsing() throws Exception {
    for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
      try (TlsReceiveBoundaryFixture fixture = newFixture(protocol)) {
        TlsReceiveBoundaryFixture.Evidence evidence =
            fixture.exercise(TlsReceiveBoundaryFixture.Mode.SPLIT, "split-secret-marker");

        assertTrue(evidence.passed(), protocol + ": " + evidence.toJson());
        assertTrue(evidence.shapeExact(), protocol + ": " + evidence.toJson());
        assertEquals(2, evidence.expectedPlaintextCallbackLengths().size());
        assertEquals(
            evidence.expectedPlaintextCallbackLengths(),
            evidence.actualPlaintextCallbackLengths());
        assertEquals(List.of(1), evidence.requestOrder());
        assertEquals(List.of(1), evidence.responseOrder());
        assertHandoffEvidence(evidence);
        assertFalse(evidence.toJson().contains("split-secret-marker"));
      }
    }
  }

  @RepeatedTest(3)
  void coalescedModeRecordsBothRequestsInOneDecryptedCallback() throws Exception {
    for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
      try (TlsReceiveBoundaryFixture fixture = newFixture(protocol)) {
        TlsReceiveBoundaryFixture.Evidence evidence =
            fixture.exercise(TlsReceiveBoundaryFixture.Mode.COALESCED, "coalesced-secret-marker");

        assertTrue(evidence.passed(), protocol + ": " + evidence.toJson());
        assertTrue(evidence.shapeExact(), protocol + ": " + evidence.toJson());
        assertEquals(1, evidence.expectedPlaintextCallbackLengths().size());
        assertEquals(
            evidence.expectedPlaintextCallbackLengths(),
            evidence.actualPlaintextCallbackLengths());
        assertEquals(List.of(1, 2), evidence.requestOrder());
        assertEquals(List.of(1, 2), evidence.responseOrder());
        assertHandoffEvidence(evidence);
        assertFalse(evidence.toJson().contains("coalesced-secret-marker"));
      }
    }
  }

  @Test
  void closeStopsAllFixtureExecutorsAndRejectsFurtherWork() throws Exception {
    TlsReceiveBoundaryFixture fixture = newFixture("TLSv1.3");

    fixture.close();
    fixture.close();

    assertTrue(fixture.isTerminated());
    assertThrows(
        IllegalStateException.class,
        () -> fixture.exercise(TlsReceiveBoundaryFixture.Mode.SPLIT, "closed"));
  }

  @Test
  void modeSelectionIsClosed() {
    assertEquals(
        TlsReceiveBoundaryFixture.Mode.SPLIT,
        TlsReceiveBoundaryFixture.Mode.parse("split"));
    assertEquals(
        TlsReceiveBoundaryFixture.Mode.COALESCED,
        TlsReceiveBoundaryFixture.Mode.parse("coalesced"));
    assertThrows(
        IllegalArgumentException.class,
        () -> TlsReceiveBoundaryFixture.Mode.parse("approximate"));
  }

  private static void assertHandoffEvidence(TlsReceiveBoundaryFixture.Evidence evidence) {
    assertTrue(evidence.buffersForwardedUnchanged(), evidence.toJson());
    assertTrue(evidence.handoffBeforeParse(), evidence.toJson());
    assertTrue(evidence.connectionClosed(), evidence.toJson());
    assertFalse(evidence.decryptThreadIDs().isEmpty());
    assertEquals(
        evidence.decryptThreadIDs().size(), evidence.parserThreadIDs().size());
    assertTrue(
        Collections.disjoint(evidence.decryptThreadIDs(), evidence.parserThreadIDs()),
        evidence.toJson());
  }

  private static TlsReceiveBoundaryFixture newFixture(String protocol) throws Exception {
    return TlsReceiveBoundaryFixture.start(keyStore, KEYSTORE_PASSWORD, protocol);
  }

  private static boolean isWindows() {
    return File.separatorChar == '\\';
  }
}
