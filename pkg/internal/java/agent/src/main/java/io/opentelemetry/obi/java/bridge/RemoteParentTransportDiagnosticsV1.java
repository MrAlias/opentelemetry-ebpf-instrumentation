/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

/** Versioned bootstrap facade for the remote-parent transport configuration snapshot. */
public final class RemoteParentTransportDiagnosticsV1 {
  private static final String BRIDGE_CLASS = "io.opentelemetry.obi.java.bridge.RemoteParentBridge";
  private static final String UNAVAILABLE_SNAPSHOT =
      "version=2,status=6,requested=255,selected=255,attempted=0,getsockopt=0,unix=0";

  private RemoteParentTransportDiagnosticsV1() {}

  public static String snapshot() {
    try {
      return snapshot(Class.forName(BRIDGE_CLASS, true, null));
    } catch (Throwable ignored) {
      return UNAVAILABLE_SNAPSHOT;
    }
  }

  static String snapshot(Class<?> bridgeClass) {
    try {
      Object snapshot = bridgeClass.getMethod("transportConfigurationSnapshot").invoke(null);
      return snapshot instanceof String ? (String) snapshot : UNAVAILABLE_SNAPSHOT;
    } catch (Throwable ignored) {
      return UNAVAILABLE_SNAPSHOT;
    }
  }
}
