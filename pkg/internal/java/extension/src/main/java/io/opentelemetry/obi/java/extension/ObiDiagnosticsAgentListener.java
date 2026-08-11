/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import io.opentelemetry.javaagent.extension.AgentListener;
import io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdk;

/** Initializes bridge diagnostics after the official agent installs its logging instrumentation. */
public final class ObiDiagnosticsAgentListener implements AgentListener {
  private final BootstrapBridgeAccess bridgeOverride;

  public ObiDiagnosticsAgentListener() {
    this(null);
  }

  ObiDiagnosticsAgentListener(BootstrapBridgeAccess bridge) {
    this.bridgeOverride = bridge;
  }

  @Override
  public void afterAgent(AutoConfiguredOpenTelemetrySdk autoConfiguredOpenTelemetrySdk) {
    BootstrapBridgeAccess requested =
        ObiConfigurablePropagatorProvider.diagnosticsLoggerInitializationTarget();
    if (requested != null) {
      BootstrapBridgeAccess bridge = bridgeOverride == null ? requested : bridgeOverride;
      bridge.initializeDiagnosticsLogger();
    }
  }
}
