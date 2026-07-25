// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.FutureTask;
import org.junit.jupiter.api.Test;

class ApacheJavaHttpsBackendTest {
  @Test
  void sharedResponseDiagnosticsRequireStrictOptIn() {
    assertEquals("X-OBI-Java-Diagnostics", ApacheJavaHttpsBackend.BRIDGE_DIAGNOSTICS_HEADER);
    assertEquals("bridge_diagnostics", ApacheJavaHttpsBackend.BRIDGE_DIAGNOSTICS_PARAMETER);
    String diagnostics = ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"1"});
    assertNotNull(diagnostics);
    assertFalse(diagnostics.contains("\r"));
    assertFalse(diagnostics.contains("\n"));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(null));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {""}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"0"}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"true"}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {" 1"}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"1 "}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"1", "1"}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"1", "0"}));
  }

  @Test
  void handoffCountIsBounded() {
    assertEquals(2, ApacheJavaHttpsBackend.parseHops(null));
    assertEquals(1, ApacheJavaHttpsBackend.parseHops("1"));
    assertEquals(8, ApacheJavaHttpsBackend.parseHops("8"));
    assertThrows(IllegalArgumentException.class, () -> ApacheJavaHttpsBackend.parseHops("0"));
    assertThrows(IllegalArgumentException.class, () -> ApacheJavaHttpsBackend.parseHops("9"));
    assertThrows(IllegalArgumentException.class, () -> ApacheJavaHttpsBackend.parseHops("many"));
  }

  @Test
  void dispatchCountIsBounded() {
    assertEquals(2, ApacheJavaHttpsBackend.parseDispatchRounds(null));
    assertEquals(1, ApacheJavaHttpsBackend.parseDispatchRounds("1"));
    assertEquals(8, ApacheJavaHttpsBackend.parseDispatchRounds("8"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseDispatchRounds("0"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseDispatchRounds("9"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseDispatchRounds("many"));
  }

  @Test
  void faultSelectionIsClosed() {
    assertEquals("none", ApacheJavaHttpsBackend.parseHandoffFault(null));
    assertEquals("cancel", ApacheJavaHttpsBackend.parseHandoffFault("cancel"));
    assertEquals("reject", ApacheJavaHttpsBackend.parseHandoffFault("reject"));
    assertEquals("timeout", ApacheJavaHttpsBackend.parseHandoffFault("timeout"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseHandoffFault("arbitrary"));
  }

  @Test
  void virtualThreadFlagsAreStrict() {
    assertTrue(ApacheJavaHttpsBackend.parseFlag(null, true, "mixed"));
    assertFalse(ApacheJavaHttpsBackend.parseFlag(null, false, "cancel"));
    assertTrue(ApacheJavaHttpsBackend.parseFlag("1", false, "mixed"));
    assertFalse(ApacheJavaHttpsBackend.parseFlag("0", true, "mixed"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseFlag("true", false, "mixed"));
  }

  @Test
  void cancellationResultIsPreserved() {
    FutureTask<Void> pending = new FutureTask<>(() -> null);
    assertTrue(ApacheJavaHttpsBackend.cancelTask(pending, true));

    CompletableFuture<Void> completed = CompletableFuture.completedFuture(null);
    assertFalse(ApacheJavaHttpsBackend.cancelTask(completed, true));
  }

  @Test
  void procSocketLineMatchesBothPortsAndEstablishedState() {
    String established =
        "7: 0100007F:480B 0100007F:C001 01 00000000:00000000 00:00000000"
            + " 00000000 0 0 424242 1 0000000000000000";

    assertEquals(
        424242, ApacheJavaHttpsBackend.socketInodeFromProcLine(established, 18443, 49153));
    assertEquals(
        -1, ApacheJavaHttpsBackend.socketInodeFromProcLine(established, 18443, 49154));
    assertEquals(
        -1,
        ApacheJavaHttpsBackend.socketInodeFromProcLine(
            established.replace(" 01 ", " 06 "), 18443, 49153));
    assertEquals(
        -1,
        ApacheJavaHttpsBackend.socketInodeFromProcLine("sl local_address", 18443, 49153));
  }

  @Test
  void connectionIdentifiersAreStableAndMonotonic() {
    Object first = new Object();
    Object second = new Object();

    long firstID = ApacheJavaHttpsBackend.connectionID(first);
    assertTrue(firstID > 0);
    assertEquals(firstID, ApacheJavaHttpsBackend.connectionID(first));
    assertTrue(ApacheJavaHttpsBackend.connectionID(second) > firstID);
    assertThrows(
        IllegalArgumentException.class, () -> ApacheJavaHttpsBackend.connectionID(null));
  }

  @Test
  void connectionIdentifiersUseObjectIdentity() {
    Object first = new EqualConnection();
    Object second = new EqualConnection();

    assertEquals(first, second);
    long firstID = ApacheJavaHttpsBackend.connectionID(first);
    long secondID = ApacheJavaHttpsBackend.connectionID(second);
    assertTrue(secondID > firstID);
  }

  private static final class EqualConnection {
    @Override
    public boolean equals(Object ignored) {
      return true;
    }

    @Override
    public int hashCode() {
      return 1;
    }
  }
}
