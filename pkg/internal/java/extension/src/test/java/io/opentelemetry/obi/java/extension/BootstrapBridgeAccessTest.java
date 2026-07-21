/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class BootstrapBridgeAccessTest {
  private static final String BRIDGE_AVAILABILITY_PROPERTY =
      "io.opentelemetry.obi.java.bridge.available";

  @AfterEach
  void resetDiagnostics() {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    System.clearProperty(BRIDGE_AVAILABILITY_PROPERTY);
  }

  @Test
  void missingBootstrapHelperIsDistinctFromAJavaRetrievalMiss() {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    BootstrapBridgeAccess bridge = new BootstrapBridgeAccess();

    assertEquals(BridgeResult.STATUS_MISSING, bridge.takeRemoteParent().status);

    String snapshot = BootstrapBridgeAccess.localDiagnosticsSnapshot();
    assertEquals(
        "bridge_lookup_missing=1,bridge_lookup_version_mismatch=0,bridge_lookup_error=0", snapshot);
    assertTrue(snapshot.matches("[a-z0-9_=,]+"));
  }

  @Test
  void helperAvailabilityBypassesTheNegativeLookupCache() {
    BootstrapBridgeAccess bridge = new BootstrapBridgeAccess();

    bridge.takeRemoteParent();
    bridge.takeRemoteParent();
    assertEquals(1L, BootstrapBridgeAccess.drainLocalCountersForTest()[0]);

    System.setProperty(BRIDGE_AVAILABILITY_PROPERTY, "1");
    bridge.takeRemoteParent();
    assertEquals(1L, BootstrapBridgeAccess.drainLocalCountersForTest()[0]);
  }

  @Test
  void flushedLookupCountersAreDrainedExactlyOnce() {
    new BootstrapBridgeAccess().takeRemoteParent();

    long[] first = BootstrapBridgeAccess.drainLocalCountersForTest();
    long[] second = BootstrapBridgeAccess.drainLocalCountersForTest();

    assertEquals(1L, first[0]);
    assertTrue(Arrays.stream(second).allMatch(value -> value == 0L));
  }
}
