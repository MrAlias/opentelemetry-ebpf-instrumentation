/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RemoteParentTransportDiagnosticsV1Test {
  private static final String UNAVAILABLE =
      "version=2,status=6,requested=255,selected=255,attempted=0,getsockopt=0,unix=0";

  @BeforeEach
  @AfterEach
  void resetBridge() {
    RemoteParentBridge.resetForTest();
  }

  @Test
  void delegatesToTheCurrentBridgeGeneration() {
    assertEquals(
        "version=2,status=13,requested=3,selected=3,attempted=0,getsockopt=0,unix=0",
        RemoteParentTransportDiagnosticsV1.snapshot(RemoteParentBridge.class));
  }

  @Test
  void reportsVersionMismatchForPreviousBridgeGenerations() {
    assertEquals(
        UNAVAILABLE, RemoteParentTransportDiagnosticsV1.snapshot(PreviousGenerationBridge.class));
  }

  @Test
  void reportsVersionMismatchWhenTheBridgeThrows() {
    assertEquals(UNAVAILABLE, RemoteParentTransportDiagnosticsV1.snapshot(ThrowingBridge.class));
  }

  public static final class PreviousGenerationBridge {
    public static String diagnosticsSnapshot() {
      return "";
    }
  }

  public static final class ThrowingBridge {
    public static String transportConfigurationSnapshot() {
      throw new IllegalStateException("unavailable");
    }
  }
}
