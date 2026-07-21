/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import io.opentelemetry.context.propagation.TextMapPropagator;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigProperties;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigurablePropagatorProvider;
import java.util.logging.Logger;

public final class ObiConfigurablePropagatorProvider implements ConfigurablePropagatorProvider {
  static final String ENABLED_PROPERTY = "otel.obi.remote.parent.enabled";
  private static final Logger logger =
      Logger.getLogger(ObiConfigurablePropagatorProvider.class.getName());

  @Override
  public TextMapPropagator getPropagator(ConfigProperties config) {
    boolean enabled = config.getBoolean(ENABLED_PROPERTY, false);
    AgentCompatibility compatibility = AgentCompatibility.inspect();
    logger.info("OBI remote-parent compatibility " + compatibility.snapshot());
    if (enabled && !compatibility.isSupported()) {
      logger.warning("OBI remote-parent propagator disabled by compatibility gate");
      enabled = false;
    }
    if (enabled) {
      logger.info("OBI remote-parent propagator enabled");
    }
    return new ObiRemoteParentPropagator(enabled, new BootstrapBridgeAccess());
  }

  @Override
  public String getName() {
    return "obi";
  }
}
