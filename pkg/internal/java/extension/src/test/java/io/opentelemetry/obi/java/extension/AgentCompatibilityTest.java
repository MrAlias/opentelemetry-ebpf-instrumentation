/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AgentCompatibilityTest {
  @Test
  void acceptsOnlyDeclaredOpenTelemetryAndSplunkCells() {
    assertSupported("2.28.1", "1.62.0", "1.62.0", 8);
    assertSupported("2.28.1", "1.62.0", "1.62.0", 11);
    assertSupported("splunk-2.28.0-otel-2.28.1", "1.62.0", "1.62.0", 21);
    assertSupported("splunk-2.28.0-otel-2.28.1", "1.62.0", "1.62.0", 17);
  }

  @Test
  void rejectsEveryVersionBoundaryDeterministically() {
    assertRejected("2.27.99", "1.62.0", "1.62.0", 21, "unsupported_agent");
    assertRejected("2.28.0", "1.62.0", "1.62.0", 21, "unsupported_agent");
    assertRejected("2.28.2", "1.62.0", "1.62.0", 21, "unsupported_agent");
    assertRejected("2.29.0", "1.62.0", "1.62.0", 21, "unsupported_agent");
    assertRejected("splunk-2.28.0-otel-2.29.0", "1.62.0", "1.62.0", 21, "unsupported_agent");
    assertRejected("splunk-2.28.1-otel-2.28.1", "1.62.0", "1.62.0", 21, "unsupported_agent");
    assertRejected("vendor-2.28.0", "1.62.0", "1.62.0", 21, "unknown_agent");
    assertRejected("2.28.1", "1.61.99", "1.62.0", 21, "unsupported_api");
    assertRejected("2.28.1", "1.62.1", "1.62.0", 21, "unsupported_api");
    assertRejected("2.28.1", "1.62.0", "1.61.99", 21, "unsupported_spi");
    assertRejected("2.28.1", "1.62.0", "1.62.1", 21, "unsupported_spi");
    assertRejected("2.28.1", "1.62.0", "1.62.0", 7, "unsupported_java");
    assertRejected("2.28.1", "1.62.0", "1.62.0", 9, "unsupported_java");
    assertRejected("2.28.1", "1.62.0", "1.62.0", 16, "unsupported_java");
    assertRejected("2.28.1", "1.62.0", "1.62.0", 18, "unsupported_java");
    assertRejected("2.28.1", "1.62.0", "1.62.0", 27, "unsupported_java");
    assertRejected("2.28.1", "1.62.0", "1.62.0", 28, "unsupported_java");
  }

  @Test
  void diagnosticSnapshotIsMachineReadableAndComplete() {
    String snapshot = AgentCompatibility.evaluate("2.28.1", "1.62.0", "1.62.0", 21).snapshot();

    assertTrue(snapshot.contains("distribution=opentelemetry"), snapshot);
    assertTrue(snapshot.contains("agent_version=2.28.1"), snapshot);
    assertTrue(snapshot.contains("api_version=1.62.0"), snapshot);
    assertTrue(snapshot.contains("api_version_source=explicit"), snapshot);
    assertTrue(snapshot.contains("spi_version=1.62.0"), snapshot);
    assertTrue(snapshot.contains("provider=obi"), snapshot);
    assertTrue(snapshot.contains("supported=true"), snapshot);
    assertTrue(snapshot.contains("reason=compatible"), snapshot);
    assertFalse(snapshot.contains("@"), snapshot);
  }

  private static void assertSupported(String agent, String api, String spi, int javaFeature) {
    AgentCompatibility compatibility = AgentCompatibility.evaluate(agent, api, spi, javaFeature);
    assertTrue(compatibility.isSupported(), compatibility.snapshot());
  }

  private static void assertRejected(
      String agent, String api, String spi, int javaFeature, String reason) {
    AgentCompatibility compatibility = AgentCompatibility.evaluate(agent, api, spi, javaFeature);
    assertFalse(compatibility.isSupported(), compatibility.snapshot());
    assertTrue(compatibility.snapshot().contains("reason=" + reason), compatibility.snapshot());
  }
}
