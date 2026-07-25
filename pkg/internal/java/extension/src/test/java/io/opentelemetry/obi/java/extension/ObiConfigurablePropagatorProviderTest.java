/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigProperties;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigurablePropagatorProvider;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigurationException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ObiConfigurablePropagatorProviderTest {
  @BeforeEach
  void resetInvalidConfigurationWarning() {
    ObiConfigurablePropagatorProvider.resetInvalidEnabledPropertyWarningForTest();
  }

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
        providerMessages(null, supported),
        "OBI remote-parent propagator disabled by configuration");
    assertLifecycleReason(
        providerMessages("", supported), "OBI remote-parent propagator disabled by configuration");
    assertLifecycleReason(
        providerMessages("FALSE", unsupported),
        "OBI remote-parent propagator disabled by configuration");
    assertLifecycleReason(
        providerMessages("TrUe", supported), "OBI remote-parent propagator enabled");
    assertLifecycleReason(
        providerMessages("TRUE", unsupported),
        "OBI remote-parent propagator disabled by compatibility gate");
  }

  @Test
  void acceptsOnlyExplicitBooleanOptInValues() {
    assertEquals(Boolean.FALSE, ObiConfigurablePropagatorProvider.parseEnabled(null));
    assertEquals(Boolean.FALSE, ObiConfigurablePropagatorProvider.parseEnabled("false"));
    assertEquals(Boolean.FALSE, ObiConfigurablePropagatorProvider.parseEnabled("FALSE"));
    assertEquals(Boolean.FALSE, ObiConfigurablePropagatorProvider.parseEnabled(""));
    assertEquals(Boolean.TRUE, ObiConfigurablePropagatorProvider.parseEnabled("true"));
    assertEquals(Boolean.TRUE, ObiConfigurablePropagatorProvider.parseEnabled("TRUE"));
    assertNull(ObiConfigurablePropagatorProvider.parseEnabled(" true "));
    assertNull(ObiConfigurablePropagatorProvider.parseEnabled("enabled"));
  }

  @Test
  void invalidOptInFailsOpenWithOneNonEchoingWarning() {
    AgentCompatibility supported = AgentCompatibility.evaluate("2.28.1", "1.62.0", "1.62.0", 21);
    String invalidValue = "sensitive-invalid-value";
    List<LogRecord> records =
        providerRecords(
            () -> {
              ObiConfigurablePropagatorProvider provider = new ObiConfigurablePropagatorProvider();
              provider.getPropagator(invalidValue, supported);
              new ObiConfigurablePropagatorProvider().getPropagator(invalidValue, supported);
            });
    List<String> messages = messages(records);

    assertEquals(
        1,
        records.stream()
            .filter(
                record ->
                    record.getLevel() == Level.WARNING
                        && record
                            .getMessage()
                            .equals(
                                ObiConfigurablePropagatorProvider.INVALID_ENABLED_PROPERTY_MESSAGE))
            .count());
    assertTrue(
        messages.contains(ObiConfigurablePropagatorProvider.INVALID_ENABLED_PROPERTY_MESSAGE));
    assertFalse(messages.stream().anyMatch(message -> message.contains(invalidValue)));
    assertFalse(messages.contains("OBI remote-parent propagator enabled"));
    assertFalse(messages.contains("OBI remote-parent propagator disabled by compatibility gate"));
    assertFalse(messages.contains("OBI remote-parent propagator disabled by configuration"));
  }

  @Test
  void configurationReadFailureFailsOpenWithoutLeakingTheException() {
    String sensitiveFailure = "sensitive-configuration-failure";
    List<LogRecord> records =
        providerRecords(
            () ->
                new ObiConfigurablePropagatorProvider()
                    .getPropagator(new ThrowingConfigProperties(sensitiveFailure)));

    assertEquals(
        1,
        records.stream()
            .filter(
                record ->
                    record.getLevel() == Level.WARNING
                        && record
                            .getMessage()
                            .equals(
                                ObiConfigurablePropagatorProvider.INVALID_ENABLED_PROPERTY_MESSAGE))
            .count());
    for (LogRecord record : records) {
      assertFalse(record.getMessage().contains(sensitiveFailure));
      assertNull(record.getParameters());
      assertNull(record.getThrown());
    }
  }

  private static List<String> providerMessages(
      String configuredValue, AgentCompatibility compatibility) {
    return messages(
        providerRecords(
            () ->
                new ObiConfigurablePropagatorProvider()
                    .getPropagator(configuredValue, compatibility)));
  }

  private static List<LogRecord> providerRecords(Runnable action) {
    Logger logger = Logger.getLogger(ObiConfigurablePropagatorProvider.class.getName());
    boolean useParentHandlers = logger.getUseParentHandlers();
    Level level = logger.getLevel();
    List<LogRecord> records = new ArrayList<>();
    Handler handler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            records.add(record);
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
      action.run();
    } finally {
      logger.removeHandler(handler);
      logger.setLevel(level);
      logger.setUseParentHandlers(useParentHandlers);
    }
    return records;
  }

  private static List<String> messages(List<LogRecord> records) {
    List<String> messages = new ArrayList<>();
    for (LogRecord record : records) {
      messages.add(record.getMessage());
    }
    return messages;
  }

  private static void assertLifecycleReason(List<String> messages, String expected) {
    assertTrue(messages.contains(expected), messages.toString());
    for (String message :
        new String[] {
          "OBI remote-parent propagator enabled",
          "OBI remote-parent propagator disabled by compatibility gate",
          "OBI remote-parent propagator disabled by configuration",
          ObiConfigurablePropagatorProvider.INVALID_ENABLED_PROPERTY_MESSAGE
        }) {
      if (!message.equals(expected)) {
        assertFalse(messages.contains(message), messages.toString());
      }
    }
  }

  private static final class ThrowingConfigProperties implements ConfigProperties {
    private final String message;

    private ThrowingConfigProperties(String message) {
      this.message = message;
    }

    @Override
    public String getString(String name) {
      throw new ConfigurationException(message);
    }

    @Override
    public Boolean getBoolean(String name) {
      throw new AssertionError("unexpected boolean lookup");
    }

    @Override
    public Integer getInt(String name) {
      throw new AssertionError("unexpected integer lookup");
    }

    @Override
    public Long getLong(String name) {
      throw new AssertionError("unexpected long lookup");
    }

    @Override
    public Double getDouble(String name) {
      throw new AssertionError("unexpected double lookup");
    }

    @Override
    public Duration getDuration(String name) {
      throw new AssertionError("unexpected duration lookup");
    }

    @Override
    public List<String> getList(String name) {
      return Collections.emptyList();
    }

    @Override
    public Map<String, String> getMap(String name) {
      return Collections.emptyMap();
    }
  }
}
