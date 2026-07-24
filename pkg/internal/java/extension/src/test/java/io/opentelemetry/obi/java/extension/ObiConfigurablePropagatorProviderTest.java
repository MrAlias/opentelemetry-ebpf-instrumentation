/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigurablePropagatorProvider;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
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

  @Test
  void reportsOneLifecycleReasonForEveryConfigurationAndCompatibilityState() {
    AgentCompatibility supported = AgentCompatibility.evaluate("2.28.1", "1.62.0", "1.62.0", 21);
    AgentCompatibility unsupported = AgentCompatibility.evaluate("2.28.2", "1.62.0", "1.62.0", 21);

    assertLifecycleReason(
        providerMessages(false, supported),
        "OBI remote-parent propagator disabled by configuration");
    assertLifecycleReason(
        providerMessages(false, unsupported),
        "OBI remote-parent propagator disabled by configuration");
    assertLifecycleReason(
        providerMessages(true, supported), "OBI remote-parent propagator enabled");
    assertLifecycleReason(
        providerMessages(true, unsupported),
        "OBI remote-parent propagator disabled by compatibility gate");
  }

  private static List<String> providerMessages(boolean enabled, AgentCompatibility compatibility) {
    Logger logger = Logger.getLogger(ObiConfigurablePropagatorProvider.class.getName());
    boolean useParentHandlers = logger.getUseParentHandlers();
    Level level = logger.getLevel();
    List<String> messages = new ArrayList<>();
    Handler handler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            messages.add(record.getMessage());
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };

    logger.setUseParentHandlers(false);
    logger.setLevel(Level.ALL);
    handler.setLevel(Level.ALL);
    logger.addHandler(handler);
    try {
      new ObiConfigurablePropagatorProvider().getPropagator(enabled, compatibility);
    } finally {
      logger.removeHandler(handler);
      logger.setLevel(level);
      logger.setUseParentHandlers(useParentHandlers);
    }
    return messages;
  }

  private static void assertLifecycleReason(List<String> messages, String expected) {
    assertTrue(messages.contains(expected), messages.toString());
    for (String message :
        new String[] {
          "OBI remote-parent propagator enabled",
          "OBI remote-parent propagator disabled by compatibility gate",
          "OBI remote-parent propagator disabled by configuration"
        }) {
      if (!message.equals(expected)) {
        assertFalse(messages.contains(message), messages.toString());
      }
    }
  }
}
