/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class PidReuseProbeTest {
  @Test
  void disabledWhenAllFixtureVariablesAreAbsent() {
    assertNull(PidReuseProbe.parseConfig(Map.of()));
  }

  @Test
  void parsesOnlyTheExactClosedConfiguration() {
    Map<String, String> environment = validEnvironment();
    PidReuseProbe.Config config = PidReuseProbe.parseConfig(environment);
    assertEquals("A", config.phase());
    assertEquals(Path.of("/run/obi-demo/pid-reuse"), config.controlDirectory());
    assertEquals("", config.transport());
    assertEquals(198, config.socketFileDescriptor());

    for (String key : environment.keySet()) {
      Map<String, String> missing = new HashMap<>(environment);
      missing.remove(key);
      assertThrows(IllegalArgumentException.class, () -> PidReuseProbe.parseConfig(missing), key);
    }
    Map<String, String> invalidPhase = validEnvironment();
    invalidPhase.put("OBI_PID_REUSE_PHASE", "C");
    assertThrows(IllegalArgumentException.class, () -> PidReuseProbe.parseConfig(invalidPhase));
    Map<String, String> invalidDirectory = validEnvironment();
    invalidDirectory.put("OBI_PID_REUSE_CONTROL_DIR", "/run/../unsafe");
    assertThrows(
        IllegalArgumentException.class, () -> PidReuseProbe.parseConfig(invalidDirectory));
    Map<String, String> unknownField = validEnvironment();
    unknownField.put("OBI_PID_REUSE_TRANSPORT", "getsockopt");
    assertThrows(IllegalArgumentException.class, () -> PidReuseProbe.parseConfig(unknownField));
  }

  @Test
  void acceptsOnlyExactForcedTransportSnapshots() {
    assertEquals(
        "getsockopt",
        PidReuseProbe.forcedTransportFromSnapshot(
            "version=2,status=1,requested=1,selected=1,attempted=1,getsockopt=1,unix=0"));
    assertEquals(
        "unix",
        PidReuseProbe.forcedTransportFromSnapshot(
            "version=2,status=1,requested=2,selected=2,attempted=2,getsockopt=0,unix=1"));
    assertThrows(
        IllegalStateException.class,
        () ->
            PidReuseProbe.forcedTransportFromSnapshot(
                "version=2,status=1,requested=0,selected=1,attempted=1,getsockopt=1,unix=0"));

    PidReuseProbe.Config config = PidReuseProbe.parseConfig(validEnvironment());
    assertEquals("unix", config.withTransport("unix").transport());
    assertThrows(IllegalStateException.class, () -> config.withTransport("auto"));
    PidReuseProbe.Config selected = config.withTransport("getsockopt");
    assertThrows(IllegalStateException.class, () -> selected.withTransport("getsockopt"));
  }

  @Test
  void negativeResultSchemaIsTransportSpecificAndSanitized() {
    assertEquals(
        "schema=obi-pid-reuse-java-result-v1\nstatus=unsupported\nw3c_fail_open=true\n",
        PidReuseProbe.negativeResultPayload("getsockopt", 4, true));
    assertEquals(
        "schema=obi-pid-reuse-java-result-v1\nstatus=ambiguous\nw3c_fail_open=true\n",
        PidReuseProbe.negativeResultPayload("unix", 7, true));
    assertThrows(
        IllegalArgumentException.class,
        () -> PidReuseProbe.negativeResultPayload("getsockopt", 7, true));
    assertThrows(
        IllegalArgumentException.class,
        () -> PidReuseProbe.negativeResultPayload("unix", 7, false));
  }

  @Test
  void runtimePrivilegeAttestationIsPostExecExactAndMutationSensitive() {
    String status =
        "Name:\tjava\n"
            + "CapInh:\t0000000000000000\n"
            + "CapPrm:\t0000000000000000\n"
            + "CapEff:\t0000000000000000\n"
            + "CapBnd:\t0000000000000000\n"
            + "CapAmb:\t0000000000000000\n"
            + "NoNewPrivs:\t1\n";
    String stat = "4242 (java worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 200\n";
    PidReuseProbe.RuntimePrivilegeAttestation attestation =
        PidReuseProbe.runtimePrivilegeAttestation(status, stat, 4242);
    assertEquals(4242, attestation.pid());
    assertEquals(200, attestation.startTimeTicks());
    assertEquals(
        "schema=obi-pid-reuse-jvm-attestation-v1\n"
            + "pid=4242\n"
            + "start_time_ticks=200\n"
            + "cap_inh_zero=true\n"
            + "cap_prm_zero=true\n"
            + "cap_eff_zero=true\n"
            + "cap_bnd_zero=true\n"
            + "cap_amb_zero=true\n"
            + "no_new_privs=true\n",
        attestation.payload());

    for (String field : new String[] {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}) {
      String mutation = status.replace(field + ":\t0000000000000000", field + ":\t0000000000000001");
      assertThrows(
          IllegalStateException.class,
          () -> PidReuseProbe.runtimePrivilegeAttestation(mutation, stat, 4242),
          field);
    }
    assertThrows(
        IllegalStateException.class,
        () -> PidReuseProbe.runtimePrivilegeAttestation(status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), stat, 4242));
    assertThrows(
        IllegalStateException.class,
        () -> PidReuseProbe.runtimePrivilegeAttestation(status, stat, 4243));
    assertThrows(
        IllegalStateException.class,
        () -> PidReuseProbe.runtimePrivilegeAttestation(status.replace("CapAmb:\t0000000000000000\n", ""), stat, 4242));
  }

  @Test
  void validRecoveryRecordRequiresExactAbiAndPayload() {
    byte[] response = validRecord();
    PidReuseProbe.Record decoded = PidReuseProbe.decodeRecord(1, response);
    assertTrue(decoded.valid());
    assertEquals("22222222222222222222222222222222", decoded.traceId());
    assertEquals("bbbbbbbbbbbbbbbb", decoded.spanId());

    response[0] = 'X';
    assertFalse(PidReuseProbe.decodeRecord(1, response).valid());
    assertFalse(PidReuseProbe.decodeRecord(7, validRecord()).valid());
    response = validRecord();
    response[56] = 1;
    assertFalse(PidReuseProbe.decodeRecord(1, response).valid());
  }

  @Test
  void bridgeInitializationWaitsForLateBootstrapAttachAndFailsClosed() throws Exception {
    AtomicInteger attempts = new AtomicInteger();
    AtomicInteger sleeps = new AtomicInteger();
    AtomicLong now = new AtomicLong();
    PidReuseProbe.awaitBridgeInitialization(
        (name, initialize, loader) -> {
          assertEquals("io.opentelemetry.obi.java.ebpf.ThreadInfo", name);
          assertTrue(initialize);
          assertNull(loader);
          int current = attempts.incrementAndGet();
          if (current <= 2) {
            throw new ClassNotFoundException("bootstrap helper not attached yet");
          }
          LateBridge.enabled = true;
          LateBridge.incarnation = 42L;
          return LateBridge.class;
        },
        10L,
        now::get,
        milliseconds -> {
          assertEquals(10L, milliseconds);
          sleeps.incrementAndGet();
          now.incrementAndGet();
        });
    assertEquals(3, attempts.get());
    assertEquals(2, sleeps.get());

    AtomicInteger readinessAttempts = new AtomicInteger();
    AtomicInteger readinessSleeps = new AtomicInteger();
    AtomicLong readinessNow = new AtomicLong();
    PidReuseProbe.awaitBridgeInitialization(
        (name, initialize, loader) -> {
          int current = readinessAttempts.incrementAndGet();
          LateBridge.enabled = current >= 2;
          LateBridge.incarnation = current == 2 ? 0L : 43L;
          return LateBridge.class;
        },
        10L,
        readinessNow::get,
        milliseconds -> {
          readinessSleeps.incrementAndGet();
          readinessNow.incrementAndGet();
        });
    assertEquals(3, readinessAttempts.get());
    assertEquals(2, readinessSleeps.get());

    AtomicInteger missingAttempts = new AtomicInteger();
    AtomicInteger missingSleeps = new AtomicInteger();
    AtomicLong missingNow = new AtomicLong();
    assertThrows(
        IllegalStateException.class,
        () ->
            PidReuseProbe.awaitBridgeInitialization(
                (name, initialize, loader) -> {
                  missingAttempts.incrementAndGet();
                  throw new ClassNotFoundException("bootstrap helper remains absent");
                },
                2L,
                missingNow::get,
                milliseconds -> {
                  assertEquals(10L, milliseconds);
                  missingSleeps.incrementAndGet();
                  missingNow.incrementAndGet();
                }));
    assertEquals(3, missingAttempts.get());
    assertEquals(2, missingSleeps.get());

    AtomicInteger unexpectedSleeps = new AtomicInteger();
    assertThrows(
        NoSuchMethodException.class,
        () ->
            PidReuseProbe.awaitBridgeInitialization(
                (name, initialize, loader) -> String.class,
                10L,
                () -> 0L,
                milliseconds -> unexpectedSleeps.incrementAndGet()));
    assertEquals(0, unexpectedSleeps.get());
  }

  static final class LateBridge {
    static boolean enabled;
    static long incarnation;

    public static boolean isRemoteParentEnabled() {
      return enabled;
    }

    public static long processIncarnation() {
      return incarnation;
    }
  }

  private static Map<String, String> validEnvironment() {
    Map<String, String> environment = new HashMap<>();
    environment.put("OBI_PID_REUSE_PHASE", "A");
    environment.put("OBI_PID_REUSE_CONTROL_DIR", "/run/obi-demo/pid-reuse");
    environment.put("OBI_PID_REUSE_SOCKET_FD", "198");
    return environment;
  }

  private static byte[] validRecord() {
    byte[] response = new byte[64];
    response[0] = 'O';
    response[1] = 'B';
    response[2] = 'I';
    response[3] = 'J';
    ByteBuffer buffer = ByteBuffer.wrap(response).order(ByteOrder.LITTLE_ENDIAN);
    buffer.putShort(4, (short) 1);
    buffer.putShort(6, (short) 64);
    response[8] = 1;
    response[9] = 1;
    for (int index = 16; index < 32; index++) {
      response[index] = 0x22;
    }
    for (int index = 32; index < 40; index++) {
      response[index] = (byte) 0xbb;
    }
    buffer.putLong(40, 42L);
    buffer.putLong(48, 43L);
    return response;
  }
}
