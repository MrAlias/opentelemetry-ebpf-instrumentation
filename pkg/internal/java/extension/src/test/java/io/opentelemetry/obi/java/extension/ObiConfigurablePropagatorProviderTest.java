/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigurablePropagatorProvider;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Test;

class ObiConfigurablePropagatorProviderTest {
  @Test
  void serviceLoaderFindsObiProvider() {
    boolean found = false;
    for (ConfigurablePropagatorProvider provider :
        ServiceLoader.load(ConfigurablePropagatorProvider.class)) {
      if (provider instanceof ObiConfigurablePropagatorProvider) {
        assertEquals("obi", provider.getName());
        found = true;
      }
    }
    assertTrue(found);
  }

  @Test
  void serviceLoaderFindsSelectionRecorder() {
    boolean found = false;
    for (AutoConfigurationCustomizerProvider provider :
        ServiceLoader.load(AutoConfigurationCustomizerProvider.class)) {
      if (provider instanceof ObiAutoConfigurationCustomizerProvider) {
        found = true;
      }
    }
    assertTrue(found);
  }
}
