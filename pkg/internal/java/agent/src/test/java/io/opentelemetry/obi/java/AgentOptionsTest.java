/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AgentOptionsTest {
  @Test
  void preservesEqualsInAnOptionValue() {
    Map<String, String> options =
        Agent.parseArgs("remoteParentTransport=unix,remoteParentSocket=/run/obi=a.sock");

    assertEquals("unix", options.get("remoteParentTransport"));
    assertEquals("/run/obi=a.sock", options.get("remoteParentSocket"));
  }

  @Test
  void acceptsRemoteParentTimeoutsLongerThanOneSecond() {
    Map<String, String> options = Agent.parseArgs("remoteParentTimeoutMillis=1500");

    assertEquals(
        1500,
        Agent.boundedIntOption(options, "remoteParentTimeoutMillis", 5, 1, Integer.MAX_VALUE));
  }

  @Test
  void acceptsAnUnsignedLinuxServerUid() {
    Map<String, String> options = Agent.parseArgs("remoteParentServerUid=4294967295");

    assertEquals(
        4294967295L,
        Agent.boundedLongOption(options, "remoteParentServerUid", 0L, 0L, 0xffff_ffffL));
    options.put("remoteParentServerUid", "-1");
    assertEquals(
        0L, Agent.boundedLongOption(options, "remoteParentServerUid", 0L, 0L, 0xffff_ffffL));
  }

  @Test
  void acceptsOnlyPositiveProcessCapabilities() {
    Map<String, String> options = Agent.parseArgs("processCapability=42");

    assertEquals(
        42L, Agent.boundedLongOption(options, "processCapability", 0L, 1L, Long.MAX_VALUE));
    options.put("processCapability", "0");
    assertEquals(0L, Agent.boundedLongOption(options, "processCapability", 0L, 1L, Long.MAX_VALUE));
  }

  @Test
  void failedInstallationCanBeClaimedAgain() {
    Agent.clearLocalInstallationClaim(false);

    assertTrue(Agent.claimLocalInstallation());
    Agent.clearLocalInstallationClaim(false);
    assertTrue(Agent.claimLocalInstallation());
    Agent.clearLocalInstallationClaim(true);
    assertFalse(Agent.claimLocalInstallation());

    Agent.clearLocalInstallationClaim(false);
  }

  @Test
  void onlyExplicitHelpersAreEligibleForBootstrapInjection() {
    assertTrue(Agent.isBootstrapHelperClassName(BootstrapNative.class.getName()));
    assertTrue(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.java.bridge.RemoteParentBridge$NoopProvider"));
    assertTrue(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.java.bridge.RemoteParentTransportConfiguration"));
    assertTrue(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.java.bridge.RemoteParentTransportDiagnosticsV1"));
    assertTrue(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$TlsConnectionMarkerAttempt"));
    assertTrue(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$BufferHandoff"));
    assertTrue(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$ConnectionOwner"));
    assertTrue(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$ExactConnection"));
    assertTrue(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext"));
    assertTrue(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityConcurrentMap"));
    assertTrue(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityConcurrentMap$IdentityWeakReference"));
    assertFalse(Agent.isBootstrapHelperClassName(UntrustedSamePackageClass.class.getName()));
    assertFalse(Agent.isBootstrapHelperClassName(Agent.class.getName()));
    assertFalse(
        Agent.isBootstrapHelperClassName(
            "io.opentelemetry.obi.net.bytebuddy.agent.builder.AgentBuilder"));
  }

  @Test
  void bootstrapHelpersDoNotReferenceUninjectedJava8AccessMarkers() throws Exception {
    assertNoAccessMarkerConstructor(
        "io.opentelemetry.obi.java.bridge.RemoteParentBridge$NoopProvider");
    assertNoAccessMarkerConstructor(
        "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityTaskMap$Bucket");
    assertNoAccessMarkerConstructor(
        "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityTaskMap$Entry");
    assertNoAccessMarkerConstructor(
        "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$TlsConnectionMarkerAttempt");
    assertNoAccessMarkerConstructor(
        "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$BufferHandoff");
    assertNoAccessMarkerConstructor(
        "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityConcurrentMap$IdentityWeakReference");
  }

  private static void assertNoAccessMarkerConstructor(String className) throws Exception {
    for (Constructor<?> constructor : Class.forName(className).getDeclaredConstructors()) {
      for (Class<?> parameterType : constructor.getParameterTypes()) {
        assertFalse(parameterType.getName().endsWith("$1"), constructor.toString());
      }
    }
  }

  private static final class UntrustedSamePackageClass {}
}
