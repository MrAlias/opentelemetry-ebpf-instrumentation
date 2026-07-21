/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLongArray;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RemoteParentBridgeTest {
  @BeforeEach
  void initialize() {
    RemoteParentBridge.resetForTest();
  }

  @AfterEach
  void reset() {
    RemoteParentBridge.resetForTest();
  }

  @Test
  void isNoopUntilAProviderRegisters() {
    assertEquals(RemoteParentStatus.MISSING, RemoteParentBridge.takeRemoteParent().getStatus());
    assertEquals(RemoteParentStatus.MISSING, RemoteParentBridge.discardRemoteParent().getStatus());
  }

  @Test
  void delegatesOneShotTakeAndDiscard() {
    FakeProvider provider = new FakeProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(provider));

    assertEquals(RemoteParentStatus.VALID, RemoteParentBridge.takeRemoteParent().getStatus());
    assertEquals(
        RemoteParentStatus.ALREADY_CONSUMED, RemoteParentBridge.takeRemoteParent().getStatus());
    assertEquals(RemoteParentStatus.MISSING, RemoteParentBridge.discardRemoteParent().getStatus());
  }

  @Test
  void rejectsVersionMismatchAndClosesReplacement() {
    FakeProvider first = new FakeProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(first));
    assertFalse(RemoteParentBridge.installProviderForTest(new WrongVersionProvider()));

    FakeProvider replacement = new FakeProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(replacement));
    assertTrue(first.closed.get());
    assertTrue(RemoteParentBridge.removeProvider(replacement));
    assertTrue(replacement.closed.get());

    String snapshot = RemoteParentBridge.diagnosticsSnapshot();
    assertTrue(snapshot.contains("provider_ok=2"));
    assertTrue(snapshot.contains("provider_ver=1"));
  }

  @Test
  void reportsFixedSanitizedTakeAndExtractionCounters() {
    FakeProvider provider = new FakeProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(provider));

    RemoteParentBridge.takeRemoteParent();
    RemoteParentBridge.takeRemoteParent();
    RemoteParentBridge.discardRemoteParent(RemoteParentDiagnostics.DISCARD_STANDARD_PARENT);
    RemoteParentBridge.recordExtractionFailure(RemoteParentDiagnostics.EXTRACTION_INVALID_CONTEXT);
    RemoteParentBridge.recordExtensionEvent(1, 1L);
    RemoteParentBridge.recordExtensionEvent(2, 1L);
    RemoteParentBridge.recordExtensionEvent(3, 2L);
    RemoteParentBridge.recordExtensionEvent(8, 1L);

    String snapshot = RemoteParentBridge.diagnosticsSnapshot();
    assertTrue(snapshot.matches("[a-z0-9_=,]+"));
    assertTrue(snapshot.length() < 1024);
    assertTrue(snapshot.contains("t_valid=1"));
    assertTrue(snapshot.contains("t_already_consumed=1"));
    assertTrue(snapshot.contains("d_missing=1"));
    assertTrue(snapshot.contains("discard_standard=2"));
    assertTrue(snapshot.contains("take_sampled=1"));
    assertTrue(snapshot.contains("take_unsampled=0"));
    assertTrue(snapshot.contains("extract_invalid=1"));
    assertTrue(snapshot.contains("extension_reg=1"));
    assertTrue(snapshot.contains("lookup_ready=1"));
    assertTrue(snapshot.contains("lookup_missing=2"));
    RemoteParentDiagnostics.registration(RemoteParentStatus.UNAUTHORIZED);
    RemoteParentDiagnostics.registration(RemoteParentStatus.VALID);
    snapshot = RemoteParentBridge.diagnosticsSnapshot();
    assertTrue(snapshot.contains("registration_ok=1"));
    assertTrue(snapshot.contains("registration_fail=1"));
  }

  @Test
  void diagnosticsSnapshotStaysBelowOneKilobyteAtSaturation() throws Exception {
    Field field = RemoteParentDiagnostics.class.getDeclaredField("counters");
    field.setAccessible(true);
    AtomicLongArray counters = (AtomicLongArray) field.get(null);
    for (int index = 0; index < counters.length(); index++) {
      counters.set(index, RemoteParentDiagnostics.MAX_COUNTER_VALUE);
    }

    String snapshot = RemoteParentBridge.diagnosticsSnapshot();

    assertTrue(snapshot.length() < 1024, snapshot);
    assertTrue(snapshot.matches("[a-z0-9_=,]+"));
  }

  private static final class FakeProvider implements RemoteParentProvider {
    private final AtomicInteger takes = new AtomicInteger();
    private final AtomicBoolean closed = new AtomicBoolean();

    @Override
    public int abiVersion() {
      return RemoteParentRecord.ABI_VERSION;
    }

    @Override
    public RemoteParentRecord takeRemoteParent() {
      int status =
          takes.getAndIncrement() == 0
              ? RemoteParentStatus.VALID
              : RemoteParentStatus.ALREADY_CONSUMED;
      if (status == RemoteParentStatus.VALID) {
        return RemoteParentRecord.decode(RemoteParentRecordTest.validRecord());
      }
      return RemoteParentRecord.statusOnly(status);
    }

    @Override
    public RemoteParentRecord discardRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public void close() {
      closed.set(true);
    }
  }

  private static final class WrongVersionProvider implements RemoteParentProvider {
    @Override
    public int abiVersion() {
      return RemoteParentRecord.ABI_VERSION + 1;
    }

    @Override
    public RemoteParentRecord takeRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public RemoteParentRecord discardRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public void close() {}
  }
}
