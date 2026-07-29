/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
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

  @Test
  void lookupDiagnosticLoggingCannotInterruptMissingBridge() {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    Logger bridgeLogger = Logger.getLogger(BootstrapBridgeAccess.class.getName());
    boolean useParentHandlers = bridgeLogger.getUseParentHandlers();
    Level previousLevel = bridgeLogger.getLevel();
    Handler throwingHandler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            throw new AssertionError("broken application log handler");
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    throwingHandler.setLevel(Level.ALL);
    bridgeLogger.setUseParentHandlers(false);
    bridgeLogger.setLevel(Level.ALL);
    bridgeLogger.addHandler(throwingHandler);
    try {
      assertEquals(
          BridgeResult.STATUS_MISSING, new BootstrapBridgeAccess().takeRemoteParent().status);
    } finally {
      bridgeLogger.removeHandler(throwingHandler);
      bridgeLogger.setLevel(previousLevel);
      bridgeLogger.setUseParentHandlers(useParentHandlers);
    }
  }
}
