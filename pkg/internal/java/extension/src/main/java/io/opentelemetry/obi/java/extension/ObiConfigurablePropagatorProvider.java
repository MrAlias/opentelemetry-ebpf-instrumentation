/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import io.opentelemetry.context.propagation.TextMapPropagator;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigProperties;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigurablePropagatorProvider;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigurationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

public final class ObiConfigurablePropagatorProvider implements ConfigurablePropagatorProvider {
  static final String ENABLED_PROPERTY = "otel.obi.remote.parent.enabled";
  static final String INVALID_ENABLED_PROPERTY_MESSAGE =
      "OBI remote-parent propagator disabled reason=invalid_configuration"
          + " property=otel.obi.remote.parent.enabled"
          + " environment=OTEL_OBI_REMOTE_PARENT_ENABLED expected=true|false";
  private static final Logger logger =
      Logger.getLogger(ObiConfigurablePropagatorProvider.class.getName());
  private static final AtomicBoolean invalidEnabledPropertyReported = new AtomicBoolean();
  private static final AtomicReference<BootstrapBridgeAccess>
      diagnosticsLoggerInitializationTarget = new AtomicReference<>();

  @Override
  public TextMapPropagator getPropagator(ConfigProperties config) {
    AgentCompatibility compatibility = AgentCompatibility.inspect();
    try {
      return getPropagator(config.getString(ENABLED_PROPERTY), compatibility);
    } catch (ConfigurationException ignored) {
      return getPropagator(false, compatibility, true);
    }
  }

  TextMapPropagator getPropagator(String configuredValue, AgentCompatibility compatibility) {
    Boolean configuredEnabled = parseEnabled(configuredValue);
    return getPropagator(
        Boolean.TRUE.equals(configuredEnabled), compatibility, configuredEnabled == null);
  }

  static Boolean parseEnabled(String configuredValue) {
    if (configuredValue == null
        || configuredValue.isEmpty()
        || "false".equalsIgnoreCase(configuredValue)) {
      return Boolean.FALSE;
    }
    if ("true".equalsIgnoreCase(configuredValue)) {
      return Boolean.TRUE;
    }
    return null;
  }

  private TextMapPropagator getPropagator(
      boolean configuredEnabled, AgentCompatibility compatibility, boolean invalidConfiguration) {
    logger.info("OBI remote-parent compatibility " + compatibility.snapshot());
    boolean enabled = configuredEnabled;
    if (invalidConfiguration) {
      if (invalidEnabledPropertyReported.compareAndSet(false, true)) {
        logger.warning(INVALID_ENABLED_PROPERTY_MESSAGE);
      }
    } else if (!configuredEnabled) {
      logger.info("OBI remote-parent propagator disabled by configuration");
    } else if (!compatibility.isSupported()) {
      logger.warning("OBI remote-parent propagator disabled by compatibility gate");
      enabled = false;
    } else {
      logger.info("OBI remote-parent propagator enabled");
    }
    BootstrapBridgeAccess bridge = new BootstrapBridgeAccess();
    diagnosticsLoggerInitializationTarget.set(enabled ? bridge : null);
    return new ObiRemoteParentPropagator(enabled, bridge);
  }

  static BootstrapBridgeAccess diagnosticsLoggerInitializationTarget() {
    return diagnosticsLoggerInitializationTarget.get();
  }

  static void resetInvalidEnabledPropertyWarningForTest() {
    invalidEnabledPropertyReported.set(false);
    diagnosticsLoggerInitializationTarget.set(null);
  }

  @Override
  public String getName() {
    return "obi";
  }
}
