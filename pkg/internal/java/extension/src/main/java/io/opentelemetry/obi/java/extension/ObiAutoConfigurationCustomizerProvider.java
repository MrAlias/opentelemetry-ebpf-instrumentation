/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizer;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider;

public final class ObiAutoConfigurationCustomizerProvider
    implements AutoConfigurationCustomizerProvider {
  @Override
  public void customize(AutoConfigurationCustomizer customizer) {
    customizer.addPropagatorCustomizer(
        (propagator, config) -> new ObiSelectionRecordingPropagator(propagator));
  }
}
