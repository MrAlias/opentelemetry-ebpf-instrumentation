/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLongArray;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RemoteParentBridgeTest {
  @BeforeEach
  void initialize() {
    RemoteParentBridge.resetForTest();
    ThreadInfo.setRemoteParentEnabled(true);
    ThreadInfo.revokeRemoteParentBridgeAuthority();
  }

  @AfterEach
  void reset() {
    ThreadInfo.setRemoteParentEnabled(false);
    ThreadInfo.revokeRemoteParentBridgeAuthority();
    RemoteParentBridge.resetForTest();
  }

  @Test
  void isNoopUntilAProviderRegisters() {
    assertEquals(RemoteParentStatus.MISSING, RemoteParentBridge.takeRemoteParent().getStatus());
    assertEquals(RemoteParentStatus.MISSING, RemoteParentBridge.discardRemoteParent().getStatus());
    assertEquals(
        "version=2,status=13,requested=3,selected=3,attempted=0,getsockopt=0,unix=0",
        RemoteParentBridge.transportConfigurationSnapshot());
  }

  @Test
  void delegatesOneShotTakeAndDiscard() {
    FakeProvider provider = new FakeProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(provider));

    assertEquals(RemoteParentStatus.VALID, RemoteParentBridge.takeRemoteParent().getStatus());
    assertEquals(
        RemoteParentStatus.ALREADY_CONSUMED, RemoteParentBridge.takeRemoteParent().getStatus());
    assertEquals(RemoteParentStatus.MISSING, RemoteParentBridge.discardRemoteParent().getStatus());
    assertEquals(
        "version=2,status=1,requested=0,selected=2,attempted=3,getsockopt=4,unix=1",
        RemoteParentBridge.transportConfigurationSnapshot());
  }

  @Test
  void frameworkTimingMissIsDistinctFromATransportMiss() {
    CountingMissingProvider provider = new CountingMissingProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(provider));

    ThreadInfo.beginRemoteParentReceiveAttempt();
    assertEquals(RemoteParentStatus.MISSING, RemoteParentBridge.takeRemoteParent().getStatus());
    assertEquals(0, provider.takes.get());

    ThreadInfo.markRemoteParentDirectLookup();
    assertEquals(RemoteParentStatus.MISSING, RemoteParentBridge.takeRemoteParent().getStatus());
    assertEquals(1, provider.takes.get());

    String diagnostics = RemoteParentBridge.diagnosticsSnapshot();
    assertTrue(diagnostics.contains("framework_depth=0"), diagnostics);
    assertTrue(diagnostics.contains("framework_cycle=0"), diagnostics);
    assertTrue(diagnostics.contains("framework_late=1"), diagnostics);
    assertTrue(diagnostics.contains("transport_missing=1"), diagnostics);
    assertTrue(diagnostics.contains("t_missing=2"), diagnostics);
  }

  @Test
  void disabledBridgeSkipsTakeAndDiscardAndRevokesCurrentJavaAuthority() {
    FakeProvider provider = new FakeProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(provider));

    ThreadInfo.markRemoteParentDirectLookup();
    ThreadInfo.setRemoteParentSocketFileDescriptor(81);
    ThreadInfo.setRemoteParentEnabled(false);

    assertEquals(RemoteParentStatus.MISSING, RemoteParentBridge.takeRemoteParent().getStatus());
    assertEquals(0, provider.takes.get());
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());

    ThreadInfo.markRemoteParentDirectLookup();
    ThreadInfo.setRemoteParentSocketFileDescriptor(82);

    assertEquals(RemoteParentStatus.MISSING, RemoteParentBridge.discardRemoteParent().getStatus());
    assertEquals(0, provider.discards.get());
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
  }

  @Test
  void disableDuringTakeSuppressesTheLatchedProviderResultAndRevokesAuthority() throws Exception {
    assertDisableDuringProviderCall(false);
  }

  @Test
  void disableDuringDiscardSuppressesTheLatchedProviderResultAndRevokesAuthority()
      throws Exception {
    assertDisableDuringProviderCall(true);
  }

  @Test
  void sameProviderRegistrationIsIdempotentWithoutRevalidation() {
    FakeProvider provider = new FakeProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(provider));
    assertTrue(RemoteParentBridge.installProviderForTest(provider));

    assertEquals(1, provider.abiCalls.get());
    assertFalse(provider.closed.get());
    assertTrue(RemoteParentBridge.diagnosticsSnapshot().contains("provider_ok=1"));
    assertTrue(RemoteParentBridge.diagnosticsSnapshot().contains("provider_reject=0"));
    assertTrue(RemoteParentBridge.removeProvider(provider));
    assertEquals(1, provider.closeCount.get());
  }

  @Test
  void defaultsTransportConfigurationForExistingProviders() {
    assertTrue(RemoteParentBridge.installProviderForTest(new DefaultConfigurationProvider()));

    assertEquals(
        "version=2,status=0,requested=255,selected=255,attempted=0,getsockopt=0,unix=0",
        RemoteParentBridge.transportConfigurationSnapshot());
  }

  @Test
  void sanitizesUnavailableProviderConfigurations() {
    FutureConfigurationProvider future = new FutureConfigurationProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(future));
    assertEquals(
        "version=2,status=6,requested=255,selected=255,attempted=0,getsockopt=0,unix=0",
        RemoteParentBridge.transportConfigurationSnapshot());
    assertTrue(RemoteParentBridge.removeProvider(future));

    ThrowingConfigurationProvider throwing = new ThrowingConfigurationProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(throwing));
    assertEquals(
        "version=2,status=12,requested=255,selected=255,attempted=0,getsockopt=0,unix=0",
        RemoteParentBridge.transportConfigurationSnapshot());
  }

  @Test
  void rejectsVersionMismatchAndRequiresExplicitReplacement() {
    FakeProvider first = new FakeProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(first));
    assertFalse(RemoteParentBridge.installProviderForTest(new WrongVersionProvider()));

    FakeProvider replacement = new FakeProvider();
    assertFalse(RemoteParentBridge.installProviderForTest(replacement));
    assertFalse(first.closed.get());
    assertFalse(replacement.closed.get());
    assertTrue(RemoteParentBridge.removeProvider(first));
    assertEquals(1, first.closeCount.get());
    assertTrue(RemoteParentBridge.installProviderForTest(replacement));
    assertFalse(RemoteParentBridge.removeProvider(first));
    assertTrue(RemoteParentBridge.removeProvider(replacement));
    assertEquals(1, replacement.closeCount.get());
    assertFalse(RemoteParentBridge.removeProvider(replacement));
    assertEquals(1, replacement.closeCount.get());

    String snapshot = RemoteParentBridge.diagnosticsSnapshot();
    assertTrue(snapshot.contains("provider_ok=2"));
    assertTrue(snapshot.contains("provider_reject=1"));
    assertTrue(snapshot.contains("provider_ver=1"));
  }

  @Test
  void concurrentSameProviderRegistrationIsIdempotent() throws Exception {
    FakeProvider shared = new FakeProvider();
    ExecutorService installers = Executors.newFixedThreadPool(8);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<Boolean>> results = new ArrayList<>();
    try {
      for (int index = 0; index < 8; index++) {
        results.add(
            installers.submit(
                () -> {
                  start.await();
                  return RemoteParentBridge.installProviderForTest(shared);
                }));
      }
      start.countDown();

      int installed = 0;
      for (Future<Boolean> result : results) {
        if (result.get(5, TimeUnit.SECONDS)) {
          installed++;
        }
      }
      assertEquals(8, installed);
      assertFalse(shared.closed.get());

      String snapshot = RemoteParentBridge.diagnosticsSnapshot();
      assertTrue(snapshot.contains("provider_ok=1"));
      assertTrue(snapshot.contains("provider_reject=0"));
      assertTrue(RemoteParentBridge.removeProvider(shared));
      assertEquals(1, shared.closeCount.get());
    } finally {
      start.countDown();
      installers.shutdownNow();
      assertTrue(installers.awaitTermination(5, TimeUnit.SECONDS));
    }
  }

  @Test
  void concurrentDifferentProvidersHaveOneWinner() throws Exception {
    ExecutorService installers = Executors.newFixedThreadPool(8);
    CountDownLatch start = new CountDownLatch(1);
    List<FakeProvider> candidates = new ArrayList<>();
    List<Future<Boolean>> results = new ArrayList<>();
    try {
      for (int index = 0; index < 8; index++) {
        FakeProvider candidate = new FakeProvider();
        candidates.add(candidate);
        results.add(
            installers.submit(
                () -> {
                  start.await();
                  return RemoteParentBridge.installProviderForTest(candidate);
                }));
      }
      start.countDown();

      int winnerIndex = -1;
      for (int index = 0; index < results.size(); index++) {
        if (results.get(index).get(5, TimeUnit.SECONDS)) {
          assertEquals(-1, winnerIndex);
          winnerIndex = index;
        }
      }
      assertTrue(winnerIndex >= 0);
      for (FakeProvider candidate : candidates) {
        assertFalse(candidate.closed.get());
      }

      String snapshot = RemoteParentBridge.diagnosticsSnapshot();
      assertTrue(snapshot.contains("provider_ok=1"));
      assertTrue(snapshot.contains("provider_reject=7"));

      FakeProvider winner = candidates.get(winnerIndex);
      assertTrue(RemoteParentBridge.removeProvider(winner));
      for (FakeProvider candidate : candidates) {
        if (candidate != winner) {
          candidate.close();
        }
        assertEquals(1, candidate.closeCount.get());
      }
    } finally {
      start.countDown();
      installers.shutdownNow();
      assertTrue(installers.awaitTermination(5, TimeUnit.SECONDS));
    }
  }

  @Test
  void reportsActionableDuplicateDiagnostic() {
    Logger diagnosticsLogger = Logger.getLogger(RemoteParentDiagnostics.class.getName());
    boolean useParentHandlers = diagnosticsLogger.getUseParentHandlers();
    Level previousLevel = diagnosticsLogger.getLevel();
    AtomicReference<String> message = new AtomicReference<>();
    Handler recordingHandler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            if (record.getMessage().contains("reason=provider_duplicate")) {
              message.compareAndSet(null, record.getMessage());
            }
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    recordingHandler.setLevel(Level.ALL);
    diagnosticsLogger.setUseParentHandlers(false);
    diagnosticsLogger.setLevel(Level.ALL);
    diagnosticsLogger.addHandler(recordingHandler);
    try {
      assertFalse(RemoteParentBridge.installProviderForTest(null));
      assertFalse(RemoteParentBridge.installProviderForTest(null));
      FakeProvider active = new FakeProvider();
      FakeProvider duplicate = new FakeProvider();
      assertTrue(RemoteParentBridge.installProviderForTest(active));
      assertFalse(RemoteParentBridge.installProviderForTest(duplicate));

      assertEquals(
          "OBI remote-parent diagnostics reason=provider_duplicate count=1", message.get());
      assertTrue(RemoteParentBridge.diagnosticsSnapshot().contains("provider_reject=3"));
      assertFalse(active.closed.get());
      assertFalse(duplicate.closed.get());
      duplicate.close();
      assertTrue(RemoteParentBridge.removeProvider(active));
    } finally {
      diagnosticsLogger.removeHandler(recordingHandler);
      diagnosticsLogger.setLevel(previousLevel);
      diagnosticsLogger.setUseParentHandlers(useParentHandlers);
    }
  }

  @Test
  void failureLoggingUsesABoundedSanitizedPowerOfTwoCadenceAcrossBatches() {
    Logger diagnosticsLogger = Logger.getLogger(RemoteParentDiagnostics.class.getName());
    boolean useParentHandlers = diagnosticsLogger.getUseParentHandlers();
    Level previousLevel = diagnosticsLogger.getLevel();
    List<LogRecord> records = new ArrayList<>();
    Handler recordingHandler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            if (record.getMessage().startsWith("OBI remote-parent diagnostics reason=")) {
              records.add(record);
            }
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    recordingHandler.setLevel(Level.ALL);
    diagnosticsLogger.setUseParentHandlers(false);
    diagnosticsLogger.setLevel(Level.ALL);
    diagnosticsLogger.addHandler(recordingHandler);
    try {
      assertTrue(RemoteParentBridge.installProviderForTest(new SensitiveFailureProvider()));
      for (int attempt = 0; attempt < 17; attempt++) {
        assertEquals(
            RemoteParentStatus.TRANSPORT_ERROR, RemoteParentBridge.takeRemoteParent().getStatus());
      }
      RemoteParentBridge.recordExtensionEvent(5, 3L);
      RemoteParentBridge.recordExtensionEvent(5, 3L);
      RemoteParentBridge.recordExtensionEvent(5, 1L);
      RemoteParentBridge.recordExtensionEvent(5, 10L);

      String[] expectedMessages = {
        "OBI remote-parent diagnostics reason=take_transport_error count=1",
        "OBI remote-parent diagnostics reason=take_transport_error count=2",
        "OBI remote-parent diagnostics reason=take_transport_error count=4",
        "OBI remote-parent diagnostics reason=take_transport_error count=8",
        "OBI remote-parent diagnostics reason=take_transport_error count=16",
        "OBI remote-parent diagnostics reason=bridge_lookup_error count=3",
        "OBI remote-parent diagnostics reason=bridge_lookup_error count=6",
        "OBI remote-parent diagnostics reason=bridge_lookup_error count=17"
      };
      assertEquals(expectedMessages.length, records.size());
      for (int index = 0; index < expectedMessages.length; index++) {
        LogRecord record = records.get(index);
        String message = record.getMessage();
        assertEquals(expectedMessages[index], message);
        assertEquals(Level.WARNING, record.getLevel());
        assertEquals(RemoteParentDiagnostics.class.getName(), record.getLoggerName());
        assertNull(record.getParameters());
        assertNull(record.getThrown());
        assertTrue(
            message.matches(
                "OBI remote-parent diagnostics reason=[a-z][a-z0-9_]{0,29}"
                    + " count=[1-9][0-9]{0,8}"));
        assertTrue(message.length() <= 83, message);
        for (String forbidden : SensitiveFailureProvider.FORBIDDEN_VALUES) {
          assertFalse(message.contains(forbidden), message);
        }
      }
      assertTrue(RemoteParentBridge.diagnosticsSnapshot().contains("t_transport_error=h"));
      assertTrue(RemoteParentBridge.diagnosticsSnapshot().contains("lookup_error=h"));
    } finally {
      diagnosticsLogger.removeHandler(recordingHandler);
      diagnosticsLogger.setLevel(previousLevel);
      diagnosticsLogger.setUseParentHandlers(useParentHandlers);
    }
  }

  @Test
  void localReceiveAmbiguityUsesStableDiscardSchemaWithoutInvokingProvider() {
    FakeProvider provider = new FakeProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(provider));
    Logger diagnosticsLogger = Logger.getLogger(RemoteParentDiagnostics.class.getName());
    boolean useParentHandlers = diagnosticsLogger.getUseParentHandlers();
    Level previousLevel = diagnosticsLogger.getLevel();
    List<String> messages = new ArrayList<>();
    Handler recordingHandler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            if (record.getMessage().contains("reason=receive_ambiguous")) {
              messages.add(record.getMessage());
            }
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    recordingHandler.setLevel(Level.ALL);
    diagnosticsLogger.setUseParentHandlers(false);
    diagnosticsLogger.setLevel(Level.ALL);
    diagnosticsLogger.addHandler(recordingHandler);
    try {
      RemoteParentBridge.recordReceiveFailure(RemoteParentStatus.AMBIGUOUS);
      RemoteParentBridge.recordReceiveFailure(RemoteParentStatus.AMBIGUOUS);
      RemoteParentBridge.recordReceiveFailure(RemoteParentStatus.AMBIGUOUS);
      RemoteParentBridge.recordReceiveFailure(RemoteParentStatus.UNSUPPORTED);
      RemoteParentBridge.recordReceiveFailure(RemoteParentStatus.STALE);

      assertEquals(0, provider.takes.get());
      assertEquals(0, provider.discards.get());
      assertTrue(RemoteParentBridge.diagnosticsSnapshot().contains("d_ambiguous=3"));
      assertTrue(RemoteParentBridge.diagnosticsSnapshot().contains("d_unsupported=1"));
      assertTrue(RemoteParentBridge.diagnosticsSnapshot().contains("d_stale=1"));
      assertEquals(
          java.util.Arrays.asList(
              "OBI remote-parent diagnostics reason=receive_ambiguous count=1",
              "OBI remote-parent diagnostics reason=receive_ambiguous count=2"),
          messages);
    } finally {
      diagnosticsLogger.removeHandler(recordingHandler);
      diagnosticsLogger.setLevel(previousLevel);
      diagnosticsLogger.setUseParentHandlers(useParentHandlers);
    }
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
    RemoteParentBridge.recordTlsRead(17);
    RemoteParentBridge.recordTlsRead(0);

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
    assertTrue(snapshot.contains("tls_reads=1"));
    assertTrue(snapshot.contains("tls_bytes=h"));
    assertEquals(1L, RemoteParentBridge.tlsReadEvents());
    assertEquals(17L, RemoteParentBridge.tlsReadBytes());
    RemoteParentDiagnostics.registration(RemoteParentStatus.UNAUTHORIZED);
    RemoteParentDiagnostics.registration(RemoteParentStatus.VALID);
    snapshot = RemoteParentBridge.diagnosticsSnapshot();
    assertTrue(snapshot.contains("registration_ok=1"));
    assertTrue(snapshot.contains("registration_fail=1"));
  }

  @Test
  void diagnosticsSnapshotStaysBoundedAtSaturation() throws Exception {
    Field field = RemoteParentDiagnostics.class.getDeclaredField("counters");
    field.setAccessible(true);
    AtomicLongArray counters = (AtomicLongArray) field.get(null);
    for (int index = 0; index < counters.length(); index++) {
      counters.set(index, RemoteParentDiagnostics.MAX_COUNTER_VALUE);
    }

    String snapshot = RemoteParentBridge.diagnosticsSnapshot();

    assertTrue(snapshot.length() < 1_200, snapshot);
    assertTrue(snapshot.matches("[a-z0-9_=,]+"));
  }

  @Test
  void diagnosticLoggingCannotInterruptBridgeOperations() {
    Logger diagnosticsLogger = Logger.getLogger(RemoteParentDiagnostics.class.getName());
    boolean useParentHandlers = diagnosticsLogger.getUseParentHandlers();
    Level previousLevel = diagnosticsLogger.getLevel();
    Handler throwingHandler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            throw new AssertionError("broken application log handler");
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    throwingHandler.setLevel(Level.ALL);
    diagnosticsLogger.setUseParentHandlers(false);
    diagnosticsLogger.setLevel(Level.ALL);
    diagnosticsLogger.addHandler(throwingHandler);
    try {
      UnauthorizedProvider provider = new UnauthorizedProvider();
      assertTrue(RemoteParentBridge.installProviderForTest(provider));
      assertFalse(RemoteParentBridge.installProviderForTest(new UnauthorizedProvider()));
      assertEquals(
          RemoteParentStatus.UNAUTHORIZED, RemoteParentBridge.takeRemoteParent().getStatus());
      assertEquals(
          RemoteParentStatus.UNAUTHORIZED, RemoteParentBridge.discardRemoteParent().getStatus());
    } finally {
      diagnosticsLogger.removeHandler(throwingHandler);
      diagnosticsLogger.setLevel(previousLevel);
      diagnosticsLogger.setUseParentHandlers(useParentHandlers);
    }
  }

  private static final class FakeProvider implements RemoteParentProvider {
    private final AtomicInteger takes = new AtomicInteger();
    private final AtomicInteger discards = new AtomicInteger();
    private final AtomicInteger abiCalls = new AtomicInteger();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicInteger closeCount = new AtomicInteger();

    @Override
    public int abiVersion() {
      abiCalls.incrementAndGet();
      return RemoteParentRecord.ABI_VERSION;
    }

    @Override
    public long transportConfiguration() {
      return 0x4f02010403020001L;
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
      discards.incrementAndGet();
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public void close() {
      closeCount.incrementAndGet();
      closed.set(true);
    }
  }

  private static final class CountingMissingProvider implements RemoteParentProvider {
    private final AtomicInteger takes = new AtomicInteger();

    @Override
    public int abiVersion() {
      return RemoteParentRecord.ABI_VERSION;
    }

    @Override
    public RemoteParentRecord takeRemoteParent() {
      takes.incrementAndGet();
      RemoteParentBridge.recordTransportMissing();
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public RemoteParentRecord discardRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public void close() {}
  }

  private void assertDisableDuringProviderCall(boolean discard) throws Exception {
    LatchedProvider provider = new LatchedProvider();
    assertTrue(RemoteParentBridge.installProviderForTest(provider));
    AtomicInteger status = new AtomicInteger(RemoteParentStatus.UNKNOWN);
    AtomicInteger descriptor = new AtomicInteger(Integer.MIN_VALUE);
    AtomicInteger lookupSource = new AtomicInteger(Integer.MIN_VALUE);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Thread caller =
        new Thread(
            () -> {
              try {
                ThreadInfo.markRemoteParentDirectLookup();
                ThreadInfo.setRemoteParentSocketFileDescriptor(83);
                RemoteParentRecord record =
                    discard
                        ? RemoteParentBridge.discardRemoteParent()
                        : RemoteParentBridge.takeRemoteParent();
                status.set(record.getStatus());
                descriptor.set(ThreadInfo.remoteParentSocketFileDescriptor());
                lookupSource.set(ThreadInfo.remoteParentLookupSource());
              } catch (Throwable thrown) {
                failure.set(thrown);
              }
            },
            discard ? "latched-discard" : "latched-take");

    caller.start();
    assertTrue(provider.entered.await(5, TimeUnit.SECONDS));
    ThreadInfo.setRemoteParentEnabled(false);
    provider.release.countDown();
    caller.join(TimeUnit.SECONDS.toMillis(5));

    assertFalse(caller.isAlive());
    assertNull(failure.get());
    assertEquals(RemoteParentStatus.MISSING, status.get());
    assertEquals(-1, descriptor.get());
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, lookupSource.get());
    assertEquals(discard ? 0 : 1, provider.takes.get());
    assertEquals(discard ? 1 : 0, provider.discards.get());
  }

  private static final class LatchedProvider implements RemoteParentProvider {
    private final CountDownLatch entered = new CountDownLatch(1);
    private final CountDownLatch release = new CountDownLatch(1);
    private final AtomicInteger takes = new AtomicInteger();
    private final AtomicInteger discards = new AtomicInteger();

    @Override
    public int abiVersion() {
      return RemoteParentRecord.ABI_VERSION;
    }

    @Override
    public RemoteParentRecord takeRemoteParent() {
      takes.incrementAndGet();
      return awaitAndReturnValid();
    }

    @Override
    public RemoteParentRecord discardRemoteParent() {
      discards.incrementAndGet();
      return awaitAndReturnValid();
    }

    private RemoteParentRecord awaitAndReturnValid() {
      entered.countDown();
      boolean interrupted = false;
      while (true) {
        try {
          release.await();
          break;
        } catch (InterruptedException ignored) {
          interrupted = true;
        }
      }
      if (interrupted) {
        Thread.currentThread().interrupt();
      }
      return RemoteParentRecord.decode(RemoteParentRecordTest.validRecord());
    }

    @Override
    public void close() {}
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

  private static final class UnauthorizedProvider implements RemoteParentProvider {
    @Override
    public int abiVersion() {
      return RemoteParentRecord.ABI_VERSION;
    }

    @Override
    public RemoteParentRecord takeRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.UNAUTHORIZED);
    }

    @Override
    public RemoteParentRecord discardRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.UNAUTHORIZED);
    }

    @Override
    public void close() {}
  }

  private static final class SensitiveFailureProvider implements RemoteParentProvider {
    private static final String[] FORBIDDEN_VALUES = {
      "4bf92f3577b34da6a3ce929d0e0e4736",
      "00f067aa0ba902b7",
      "Bearer-secret-credential",
      "private-request-body"
    };

    @Override
    public int abiVersion() {
      return RemoteParentRecord.ABI_VERSION;
    }

    @Override
    public RemoteParentRecord takeRemoteParent() {
      throw new IllegalStateException(
          "trace_id="
              + FORBIDDEN_VALUES[0]
              + " span_id="
              + FORBIDDEN_VALUES[1]
              + " authorization="
              + FORBIDDEN_VALUES[2]
              + " body="
              + FORBIDDEN_VALUES[3]);
    }

    @Override
    public RemoteParentRecord discardRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public void close() {}
  }

  private static class DefaultConfigurationProvider implements RemoteParentProvider {
    @Override
    public int abiVersion() {
      return RemoteParentRecord.ABI_VERSION;
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

  private static final class FutureConfigurationProvider extends DefaultConfigurationProvider {
    @Override
    public long transportConfiguration() {
      return 0x4f03000101010001L;
    }
  }

  private static final class ThrowingConfigurationProvider extends DefaultConfigurationProvider {
    @Override
    public long transportConfiguration() {
      throw new IllegalStateException("unavailable");
    }
  }
}
