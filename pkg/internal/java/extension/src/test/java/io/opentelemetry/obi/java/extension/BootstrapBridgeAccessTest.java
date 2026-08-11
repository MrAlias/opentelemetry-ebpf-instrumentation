/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
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
import org.junit.jupiter.api.Test;

class BootstrapBridgeAccessTest {
  private static final String BRIDGE_AVAILABILITY_PROPERTY =
      "io.opentelemetry.obi.java.bridge.available";

  @AfterEach
  void resetDiagnostics() {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    FakeRemoteParentBridge.reset();
    BlockingDiagnosticsRemoteParentBridge.reset();
    System.clearProperty(BRIDGE_AVAILABILITY_PROPERTY);
  }

  @Test
  void missingBootstrapHelperIsDistinctFromAJavaRetrievalMiss() {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    BootstrapBridgeAccess bridge = new BootstrapBridgeAccess();

    assertLookupFailure(
        bridge,
        "bridge_lookup_missing=1,bridge_lookup_version_mismatch=0,bridge_lookup_error=0",
        "bridge_lookup_missing",
        Level.INFO);
    assertTrue(BootstrapBridgeAccess.localDiagnosticsSnapshot().matches("[a-z0-9_=,]+"));
  }

  @Test
  void helperAvailabilityBypassesTheNegativeLookupCache() {
    BootstrapBridgeAccess bridge = new BootstrapBridgeAccess();

    bridge.takeRemoteParent();
    bridge.takeRemoteParent();
    assertEquals(1L, BootstrapBridgeAccess.drainLocalCountersForTest()[0]);

    System.setProperty(BRIDGE_AVAILABILITY_PROPERTY, "1");
    bridge.takeRemoteParent();
    assertEquals(1L, BootstrapBridgeAccess.drainLocalCountersForTest()[0]);
  }

  @Test
  void completedNegativeLookupDoesNotAcquireLookupMonitor() throws Exception {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    AtomicInteger resolverCalls = new AtomicInteger();
    BootstrapBridgeAccess bridge =
        new BootstrapBridgeAccess(
            () -> {
              resolverCalls.incrementAndGet();
              throw new ClassNotFoundException("lookup intentionally missing");
            });
    AtomicReference<Throwable> threadFailure = new AtomicReference<>();
    AtomicInteger callbackStatus = new AtomicInteger(-1);
    CountDownLatch callbackStarted = new CountDownLatch(1);
    Thread callback =
        new Thread(
            () -> {
              callbackStarted.countDown();
              try {
                callbackStatus.set(bridge.takeRemoteParent().status);
              } catch (Throwable failure) {
                threadFailure.compareAndSet(null, failure);
              }
            },
            "obi-bridge-negative-cache-callback");
    boolean callbackEntered;
    synchronized (bridge) {
      assertEquals(BridgeResult.STATUS_MISSING, bridge.takeRemoteParent().status);
      callback.start();
      callbackEntered = callbackStarted.await(5, TimeUnit.SECONDS);
      if (callbackEntered) {
        awaitCallback(callback, threadFailure, "negative cache hit acquired the lookup monitor");
      }
    }
    callback.join(TimeUnit.SECONDS.toMillis(5));

    assertTrue(callbackEntered, "negative-cache callback did not start");
    assertFalse(callback.isAlive(), "negative-cache callback did not finish");
    assertNull(threadFailure.get());
    assertEquals(BridgeResult.STATUS_MISSING, callbackStatus.get());
    assertEquals(1, resolverCalls.get());
  }

  @Test
  void flushedLookupCountersAreDrainedExactlyOnce() {
    new BootstrapBridgeAccess().takeRemoteParent();

    long[] first = BootstrapBridgeAccess.drainLocalCountersForTest();
    long[] second = BootstrapBridgeAccess.drainLocalCountersForTest();

    assertEquals(1L, first[0]);
    assertTrue(Arrays.stream(second).allMatch(value -> value == 0L));
  }

  @Test
  void versionMismatchIsClassifiedAndNegativelyCached() {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    AtomicInteger resolverCalls = new AtomicInteger();
    BootstrapBridgeAccess bridge =
        new BootstrapBridgeAccess(
            () -> {
              resolverCalls.incrementAndGet();
              return VersionMismatchedRemoteParentBridge.class;
            });

    assertLookupFailure(
        bridge,
        "bridge_lookup_missing=0,bridge_lookup_version_mismatch=1,bridge_lookup_error=0",
        "bridge_lookup_version_mismatch",
        Level.WARNING);
    assertEquals(1, resolverCalls.get());
  }

  @Test
  void reflectionErrorIsClassifiedAndNegativelyCached() {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    AtomicInteger resolverCalls = new AtomicInteger();
    BootstrapBridgeAccess bridge =
        new BootstrapBridgeAccess(
            () -> {
              resolverCalls.incrementAndGet();
              return BrokenRemoteParentBridge.class;
            });

    assertLookupFailure(
        bridge,
        "bridge_lookup_missing=0,bridge_lookup_version_mismatch=0,bridge_lookup_error=1",
        "bridge_lookup_error",
        Level.WARNING);
    assertEquals(1, resolverCalls.get());
  }

  @Test
  void concurrentColdLookupWaitsForTheInFlightAttempt() throws Exception {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    CountDownLatch lookupInProgress = new CountDownLatch(1);
    CountDownLatch releaseLookup = new CountDownLatch(1);
    AtomicReference<Throwable> threadFailure = new AtomicReference<>();
    AtomicReference<BootstrapBridgeAccess> bridgeReference = new AtomicReference<>();
    AtomicBoolean hookInvoked = new AtomicBoolean();
    AtomicInteger reentrantStatus = new AtomicInteger(-1);
    AtomicInteger firstStatus = new AtomicInteger(-1);
    AtomicInteger secondStatus = new AtomicInteger(-1);
    BootstrapBridgeAccess bridge =
        new BootstrapBridgeAccess(
            () -> {
              try {
                assertTrue(hookInvoked.compareAndSet(false, true), "duplicate lookup attempt");
                reentrantStatus.set(bridgeReference.get().takeRemoteParent().status);
                lookupInProgress.countDown();
                if (!releaseLookup.await(10, TimeUnit.SECONDS)) {
                  threadFailure.compareAndSet(null, new AssertionError("lookup release timed out"));
                }
              } catch (Throwable failure) {
                threadFailure.compareAndSet(null, failure);
              }
              return FakeRemoteParentBridge.class;
            });
    bridgeReference.set(bridge);
    Thread first = lookupThread(bridge, firstStatus, threadFailure, "obi-bridge-first-lookup");
    Thread second = lookupThread(bridge, secondStatus, threadFailure, "obi-bridge-second-lookup");
    try {
      first.start();
      assertTrue(lookupInProgress.await(5, TimeUnit.SECONDS), "cold lookup did not start");
      second.start();
      assertThreadBlocked(second);
    } finally {
      releaseLookup.countDown();
      first.join(TimeUnit.SECONDS.toMillis(5));
      second.join(TimeUnit.SECONDS.toMillis(5));
    }

    assertFalse(first.isAlive(), "first cold lookup did not finish");
    assertFalse(second.isAlive(), "concurrent cold lookup did not finish");
    assertNull(threadFailure.get());
    assertEquals(BridgeResult.STATUS_MISSING, reentrantStatus.get());
    assertEquals(BridgeResult.STATUS_VALID, firstStatus.get());
    assertTrue(
        secondStatus.get() == BridgeResult.STATUS_MISSING
            || secondStatus.get() == BridgeResult.STATUS_VALID,
        "concurrent lookup must either fail open during warmup or use the published bridge");
    int expectedTakeCalls = secondStatus.get() == BridgeResult.STATUS_VALID ? 2 : 1;
    assertEquals(expectedTakeCalls, FakeRemoteParentBridge.takeCalls.get());
    assertEquals(BridgeResult.STATUS_VALID, bridge.takeRemoteParent().status);
    assertEquals(expectedTakeCalls + 1, FakeRemoteParentBridge.takeCalls.get());
    assertTrue(
        Arrays.stream(BootstrapBridgeAccess.drainLocalCountersForTest())
            .allMatch(value -> value == 0L));
  }

  @Test
  void initializesDiagnosticsLoggerBeforePublishingOrUsingBridge() {
    BootstrapBridgeAccess bridge = new BootstrapBridgeAccess(() -> FakeRemoteParentBridge.class);

    bridge.initializeDiagnosticsLogger();
    bridge.initializeDiagnosticsLogger();

    assertEquals(1, FakeRemoteParentBridge.diagnosticsLoggerInitializations.get());
    assertEquals(1L, FakeRemoteParentBridge.eventCount(1));
    assertEquals(1L, FakeRemoteParentBridge.eventCount(2));
    assertEquals(0, FakeRemoteParentBridge.takeCalls.get());
    assertFalse(FakeRemoteParentBridge.bridgeUsedBeforeDiagnosticsInitialization.get());
    assertEquals(BridgeResult.STATUS_VALID, bridge.takeRemoteParent().status);
    assertEquals(1L, FakeRemoteParentBridge.eventCount(1));
    assertEquals(1L, FakeRemoteParentBridge.eventCount(2));
    assertFalse(FakeRemoteParentBridge.bridgeUsedBeforeDiagnosticsInitialization.get());
  }

  @Test
  void diagnosticsWarmupDoesNotNegativelyCacheAnAbsentHelper() {
    AtomicInteger resolverCalls = new AtomicInteger();
    BootstrapBridgeAccess bridge =
        new BootstrapBridgeAccess(
            () -> {
              if (resolverCalls.incrementAndGet() == 1) {
                throw new ClassNotFoundException("helper intentionally absent during warmup");
              }
              return FakeRemoteParentBridge.class;
            });

    bridge.initializeDiagnosticsLogger();

    assertEquals(1, resolverCalls.get());
    assertTrue(
        Arrays.stream(BootstrapBridgeAccess.drainLocalCountersForTest())
            .allMatch(value -> value == 0L));
    assertEquals(BridgeResult.STATUS_VALID, bridge.takeRemoteParent().status);
    assertEquals(2, resolverCalls.get());
    assertEquals(1L, FakeRemoteParentBridge.eventCount(1));
    assertEquals(1L, FakeRemoteParentBridge.eventCount(2));
    assertEquals(0L, FakeRemoteParentBridge.eventCount(3));
  }

  @Test
  void concurrentLazyLookupFailsOpenUntilDiagnosticsWarmupCompletes() throws Exception {
    BlockingDiagnosticsRemoteParentBridge.prepare();
    BootstrapBridgeAccess bridge =
        new BootstrapBridgeAccess(() -> BlockingDiagnosticsRemoteParentBridge.class);
    AtomicReference<Throwable> threadFailure = new AtomicReference<>();
    AtomicInteger firstStatus = new AtomicInteger(-1);
    AtomicInteger secondStatus = new AtomicInteger(-1);
    Thread first = lookupThread(bridge, firstStatus, threadFailure, "obi-bridge-warmup-owner");
    Thread second = lookupThread(bridge, secondStatus, threadFailure, "obi-bridge-warmup-peer");

    first.start();
    assertTrue(
        BlockingDiagnosticsRemoteParentBridge.initializationStarted.await(5, TimeUnit.SECONDS),
        "diagnostics warmup did not start");
    second.start();
    second.join(TimeUnit.SECONDS.toMillis(2));
    boolean secondCompletedBeforeRelease = !second.isAlive();
    int takesBeforeRelease = BlockingDiagnosticsRemoteParentBridge.takeCalls.get();
    boolean usedBeforeInitialization =
        BlockingDiagnosticsRemoteParentBridge.bridgeUsedBeforeInitialization.get();

    BlockingDiagnosticsRemoteParentBridge.releaseInitialization.countDown();
    first.join(TimeUnit.SECONDS.toMillis(5));
    second.join(TimeUnit.SECONDS.toMillis(5));

    assertTrue(secondCompletedBeforeRelease, "concurrent warmup lookup blocked on a JUL handler");
    assertFalse(first.isAlive(), "warmup owner did not finish");
    assertFalse(second.isAlive(), "warmup peer did not finish");
    assertNull(threadFailure.get());
    assertEquals(BridgeResult.STATUS_VALID, firstStatus.get());
    assertEquals(BridgeResult.STATUS_MISSING, secondStatus.get());
    assertEquals(0, takesBeforeRelease);
    assertFalse(usedBeforeInitialization);
    assertEquals(1, BlockingDiagnosticsRemoteParentBridge.takeCalls.get());
    assertEquals(BridgeResult.STATUS_VALID, bridge.takeRemoteParent().status);
    assertEquals(2, BlockingDiagnosticsRemoteParentBridge.takeCalls.get());
    assertFalse(BlockingDiagnosticsRemoteParentBridge.bridgeUsedBeforeInitialization.get());
  }

  @Test
  void diagnosticsInitializationFailureDoesNotDisableBridge() {
    FakeRemoteParentBridge.failDiagnosticsLoggerInitialization.set(true);
    BootstrapBridgeAccess bridge = new BootstrapBridgeAccess(() -> FakeRemoteParentBridge.class);

    bridge.initializeDiagnosticsLogger();

    assertEquals(1, FakeRemoteParentBridge.diagnosticsLoggerInitializations.get());
    assertEquals(BridgeResult.STATUS_VALID, bridge.takeRemoteParent().status);
    assertEquals(1L, FakeRemoteParentBridge.eventCount(1));
    assertEquals(1L, FakeRemoteParentBridge.eventCount(2));
  }

  @Test
  void bridgeWithoutDiagnosticsInitializerRemainsCompatible() {
    BootstrapBridgeAccess bridge = new BootstrapBridgeAccess(() -> LegacyRemoteParentBridge.class);

    bridge.initializeDiagnosticsLogger();

    assertEquals(BridgeResult.STATUS_VALID, bridge.takeRemoteParent().status);
    assertEquals(1L, FakeRemoteParentBridge.eventCount(1));
    assertEquals(1L, FakeRemoteParentBridge.eventCount(2));
  }

  @Test
  void lookupFailureLoggingDoesNotHoldLookupMonitor() throws Exception {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    AtomicInteger missingResolveCalls = new AtomicInteger();
    BootstrapBridgeAccess missingBridge =
        new BootstrapBridgeAccess(
            () -> {
              if (missingResolveCalls.incrementAndGet() == 1) {
                throw new ClassNotFoundException("first lookup intentionally missing");
              }
              return FakeRemoteParentBridge.class;
            });
    Logger bridgeLogger = Logger.getLogger(BootstrapBridgeAccess.class.getName());
    boolean useParentHandlers = bridgeLogger.getUseParentHandlers();
    Level previousLevel = bridgeLogger.getLevel();
    AtomicReference<Throwable> threadFailure = new AtomicReference<>();
    AtomicReference<Thread> callbackThread = new AtomicReference<>();
    AtomicInteger callbackStatus = new AtomicInteger(-1);
    Handler callbackHandler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            System.setProperty(BRIDGE_AVAILABILITY_PROPERTY, "available");
            Thread thread =
                lookupThread(
                    missingBridge, callbackStatus, threadFailure, "obi-bridge-missing-callback");
            callbackThread.set(thread);
            thread.start();
            awaitCallback(thread, threadFailure, "missing lookup diagnostics held the monitor");
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    callbackHandler.setLevel(Level.ALL);
    bridgeLogger.setUseParentHandlers(false);
    bridgeLogger.setLevel(Level.ALL);
    bridgeLogger.addHandler(callbackHandler);
    try {
      assertEquals(BridgeResult.STATUS_MISSING, missingBridge.takeRemoteParent().status);
    } finally {
      bridgeLogger.removeHandler(callbackHandler);
      bridgeLogger.setLevel(previousLevel);
      bridgeLogger.setUseParentHandlers(useParentHandlers);
      Thread thread = callbackThread.get();
      if (thread != null) {
        thread.join(TimeUnit.SECONDS.toMillis(5));
      }
    }

    assertNull(threadFailure.get());
    assertEquals(BridgeResult.STATUS_VALID, callbackStatus.get());
    assertEquals(2, missingResolveCalls.get());
    assertTrue(
        Arrays.stream(BootstrapBridgeAccess.drainLocalCountersForTest())
            .allMatch(value -> value == 0L));
  }

  @Test
  void successfulLookupFailsOpenDuringDiagnosticsWithoutHoldingMonitor() throws Exception {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    BootstrapBridgeAccess missingBridge =
        new BootstrapBridgeAccess(
            () -> {
              throw new ClassNotFoundException("lookup intentionally missing");
            });
    assertEquals(BridgeResult.STATUS_MISSING, missingBridge.takeRemoteParent().status);

    AtomicInteger successfulResolveCalls = new AtomicInteger();
    BootstrapBridgeAccess successfulBridge =
        new BootstrapBridgeAccess(
            () -> {
              successfulResolveCalls.incrementAndGet();
              return FakeRemoteParentBridge.class;
            });
    FakeRemoteParentBridge.lookupMonitor.set(successfulBridge);
    AtomicReference<Throwable> threadFailure = new AtomicReference<>();
    AtomicReference<Thread> callbackThread = new AtomicReference<>();
    AtomicInteger callbackStatus = new AtomicInteger(-1);
    FakeRemoteParentBridge.lookupMissingCallback.set(
        () -> {
          Thread thread =
              lookupThread(
                  successfulBridge, callbackStatus, threadFailure, "obi-bridge-success-callback");
          callbackThread.set(thread);
          thread.start();
          awaitCallback(thread, threadFailure, "successful lookup diagnostics held the monitor");
        });
    try {
      assertEquals(BridgeResult.STATUS_VALID, successfulBridge.takeRemoteParent().status);
    } finally {
      FakeRemoteParentBridge.lookupMissingCallback.set(null);
      Thread thread = callbackThread.get();
      if (thread != null) {
        thread.join(TimeUnit.SECONDS.toMillis(5));
      }
    }

    assertNull(threadFailure.get());
    assertEquals(BridgeResult.STATUS_MISSING, callbackStatus.get());
    assertEquals(1, successfulResolveCalls.get());
    assertEquals(1L, FakeRemoteParentBridge.eventCount(1));
    assertEquals(1L, FakeRemoteParentBridge.eventCount(2));
    assertEquals(1L, FakeRemoteParentBridge.eventCount(3));
    for (int event = 4; event < 9; event++) {
      assertEquals(0L, FakeRemoteParentBridge.eventCount(event));
    }
    assertEquals(1, FakeRemoteParentBridge.takeCalls.get());
    assertFalse(FakeRemoteParentBridge.diagnosticsHeldLookupMonitor.get());
    assertTrue(
        Arrays.stream(BootstrapBridgeAccess.drainLocalCountersForTest())
            .allMatch(value -> value == 0L));
  }

  @Test
  void diagnosticAccessIsPublishedBeforeItsFirstCounterDrain() throws Exception {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    BootstrapBridgeAccess preloadingFailure =
        new BootstrapBridgeAccess(
            () -> {
              throw new ClassNotFoundException("preload lookup intentionally missing");
            });
    assertEquals(BridgeResult.STATUS_MISSING, preloadingFailure.takeRemoteParent().status);

    AtomicInteger injectedResolveCalls = new AtomicInteger();
    BootstrapBridgeAccess injectedFailure =
        new BootstrapBridgeAccess(
            () -> {
              injectedResolveCalls.incrementAndGet();
              throw new ClassNotFoundException("injected lookup intentionally missing");
            });
    BootstrapBridgeAccess successfulBridge =
        new BootstrapBridgeAccess(() -> FakeRemoteParentBridge.class);
    AtomicBoolean failureInjected = new AtomicBoolean();
    AtomicReference<Throwable> threadFailure = new AtomicReference<>();
    AtomicReference<Thread> callbackThread = new AtomicReference<>();
    AtomicInteger callbackStatus = new AtomicInteger(-1);
    FakeRemoteParentBridge.lookupMissingCallback.set(
        () -> {
          if (!failureInjected.compareAndSet(false, true)) {
            return;
          }
          Thread thread =
              lookupThread(
                  injectedFailure,
                  callbackStatus,
                  threadFailure,
                  "obi-bridge-first-drain-callback");
          callbackThread.set(thread);
          thread.start();
          awaitCallback(thread, threadFailure, "injected lookup failure did not finish");
        });
    try {
      assertEquals(BridgeResult.STATUS_VALID, successfulBridge.takeRemoteParent().status);
    } finally {
      FakeRemoteParentBridge.lookupMissingCallback.set(null);
      Thread thread = callbackThread.get();
      if (thread != null) {
        thread.join(TimeUnit.SECONDS.toMillis(5));
      }
    }

    assertTrue(failureInjected.get(), "first diagnostic drain did not invoke the callback");
    assertNull(threadFailure.get());
    assertEquals(BridgeResult.STATUS_MISSING, callbackStatus.get());
    assertEquals(1, injectedResolveCalls.get());
    assertEquals(1L, FakeRemoteParentBridge.eventCount(1));
    assertEquals(1L, FakeRemoteParentBridge.eventCount(2));
    assertEquals(2L, FakeRemoteParentBridge.eventCount(3));
    assertTrue(
        Arrays.stream(BootstrapBridgeAccess.drainLocalCountersForTest())
            .allMatch(value -> value == 0L));
  }

  @Test
  void successfulDiagnosticAccessFlushesLaterFailures() {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    BootstrapBridgeAccess successfulBridge =
        new BootstrapBridgeAccess(() -> FakeRemoteParentBridge.class);
    assertEquals(BridgeResult.STATUS_VALID, successfulBridge.takeRemoteParent().status);
    assertEquals(1L, FakeRemoteParentBridge.eventCount(1));
    assertEquals(1L, FakeRemoteParentBridge.eventCount(2));
    assertEquals(0L, FakeRemoteParentBridge.eventCount(3));

    AtomicInteger failingResolveCalls = new AtomicInteger();
    BootstrapBridgeAccess failingBridge =
        new BootstrapBridgeAccess(
            () -> {
              failingResolveCalls.incrementAndGet();
              throw new ClassNotFoundException("lookup intentionally missing");
            });
    Logger bridgeLogger = Logger.getLogger(BootstrapBridgeAccess.class.getName());
    boolean useParentHandlers = bridgeLogger.getUseParentHandlers();
    Level previousLevel = bridgeLogger.getLevel();
    AtomicInteger localLogRecords = new AtomicInteger();
    Handler handler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            localLogRecords.incrementAndGet();
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    handler.setLevel(Level.ALL);
    bridgeLogger.setUseParentHandlers(false);
    bridgeLogger.setLevel(Level.ALL);
    bridgeLogger.addHandler(handler);
    try {
      assertEquals(BridgeResult.STATUS_MISSING, failingBridge.takeRemoteParent().status);
      assertEquals(BridgeResult.STATUS_MISSING, failingBridge.takeRemoteParent().status);
    } finally {
      bridgeLogger.removeHandler(handler);
      bridgeLogger.setLevel(previousLevel);
      bridgeLogger.setUseParentHandlers(useParentHandlers);
    }

    assertEquals(1, failingResolveCalls.get());
    assertEquals(0, localLogRecords.get());
    assertEquals(1L, FakeRemoteParentBridge.eventCount(3));
    assertTrue(
        Arrays.stream(BootstrapBridgeAccess.drainLocalCountersForTest())
            .allMatch(value -> value == 0L));
  }

  @Test
  void lookupDiagnosticLoggingCannotInterruptMissingBridge() {
    BootstrapBridgeAccess.resetLocalDiagnosticsForTest();
    Logger bridgeLogger = Logger.getLogger(BootstrapBridgeAccess.class.getName());
    boolean useParentHandlers = bridgeLogger.getUseParentHandlers();
    Level previousLevel = bridgeLogger.getLevel();
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
    bridgeLogger.setUseParentHandlers(false);
    bridgeLogger.setLevel(Level.ALL);
    bridgeLogger.addHandler(throwingHandler);
    try {
      assertEquals(
          BridgeResult.STATUS_MISSING, new BootstrapBridgeAccess().takeRemoteParent().status);
    } finally {
      bridgeLogger.removeHandler(throwingHandler);
      bridgeLogger.setLevel(previousLevel);
      bridgeLogger.setUseParentHandlers(useParentHandlers);
    }
  }

  private static void assertLookupFailure(
      BootstrapBridgeAccess bridge,
      String expectedSnapshot,
      String expectedReason,
      Level expectedLevel) {
    Logger bridgeLogger = Logger.getLogger(BootstrapBridgeAccess.class.getName());
    boolean useParentHandlers = bridgeLogger.getUseParentHandlers();
    Level previousLevel = bridgeLogger.getLevel();
    AtomicInteger matchingRecords = new AtomicInteger();
    AtomicReference<LogRecord> diagnostic = new AtomicReference<>();
    Handler handler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            if ("OBI remote-parent diagnostics reason={0} count={1}".equals(record.getMessage())) {
              matchingRecords.incrementAndGet();
              diagnostic.compareAndSet(null, record);
            }
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    handler.setLevel(Level.ALL);
    bridgeLogger.setUseParentHandlers(false);
    bridgeLogger.setLevel(Level.ALL);
    bridgeLogger.addHandler(handler);
    try {
      assertEquals(BridgeResult.STATUS_MISSING, bridge.takeRemoteParent().status);
      assertEquals(BridgeResult.STATUS_MISSING, bridge.takeRemoteParent().status);
    } finally {
      bridgeLogger.removeHandler(handler);
      bridgeLogger.setLevel(previousLevel);
      bridgeLogger.setUseParentHandlers(useParentHandlers);
    }

    assertEquals(expectedSnapshot, BootstrapBridgeAccess.localDiagnosticsSnapshot());
    assertEquals(1, matchingRecords.get());
    LogRecord record = diagnostic.get();
    assertNotNull(record);
    assertEquals(expectedLevel, record.getLevel());
    assertEquals(expectedReason, record.getParameters()[0]);
    assertEquals(1L, record.getParameters()[1]);
  }

  private static Thread lookupThread(
      BootstrapBridgeAccess bridge,
      AtomicInteger status,
      AtomicReference<Throwable> failure,
      String name) {
    return new Thread(
        () -> {
          try {
            status.set(bridge.takeRemoteParent().status);
          } catch (Throwable problem) {
            failure.compareAndSet(null, problem);
          }
        },
        name);
  }

  private static void awaitCallback(
      Thread thread, AtomicReference<Throwable> failure, String timeoutMessage) {
    try {
      thread.join(TimeUnit.SECONDS.toMillis(2));
      if (thread.isAlive()) {
        failure.compareAndSet(null, new AssertionError(timeoutMessage));
      }
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      failure.compareAndSet(null, interrupted);
    }
  }

  private static void assertThreadBlocked(Thread thread) {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (thread.getState() != Thread.State.BLOCKED
        && thread.isAlive()
        && System.nanoTime() - deadline < 0) {
      Thread.yield();
    }
    assertEquals(Thread.State.BLOCKED, thread.getState(), "lookup bypassed the in-flight attempt");
  }

  public static final class VersionMismatchedRemoteParentBridge {
    private VersionMismatchedRemoteParentBridge() {}

    public static int abiVersion() {
      return 2;
    }
  }

  public static final class BrokenRemoteParentBridge {
    private BrokenRemoteParentBridge() {}

    public static int abiVersion() {
      return 1;
    }
  }

  public static final class LegacyRemoteParentBridge {
    private LegacyRemoteParentBridge() {}

    public static int abiVersion() {
      return FakeRemoteParentBridge.abiVersion();
    }

    public static FakeRemoteParentRecord takeRemoteParent() {
      return FakeRemoteParentBridge.takeRemoteParent();
    }

    public static void discardRemoteParent(int reason) {
      FakeRemoteParentBridge.discardRemoteParent(reason);
    }

    public static void recordExtractionFailure(int reason) {
      FakeRemoteParentBridge.recordExtractionFailure(reason);
    }

    public static void recordExtensionEvent(int event, long count) {
      FakeRemoteParentBridge.recordExtensionEvent(event, count);
    }
  }

  public static final class BlockingDiagnosticsRemoteParentBridge {
    private static final AtomicInteger takeCalls = new AtomicInteger();
    private static final AtomicBoolean initialized = new AtomicBoolean();
    private static final AtomicBoolean bridgeUsedBeforeInitialization = new AtomicBoolean();
    private static volatile CountDownLatch initializationStarted = new CountDownLatch(0);
    private static volatile CountDownLatch releaseInitialization = new CountDownLatch(0);

    private BlockingDiagnosticsRemoteParentBridge() {}

    public static int abiVersion() {
      return 1;
    }

    public static FakeRemoteParentRecord takeRemoteParent() {
      if (!initialized.get()) {
        bridgeUsedBeforeInitialization.set(true);
      }
      takeCalls.incrementAndGet();
      return new FakeRemoteParentRecord();
    }

    public static void initializeDiagnosticsLogger() {
      initializationStarted.countDown();
      try {
        if (!releaseInitialization.await(10, TimeUnit.SECONDS)) {
          throw new AssertionError("diagnostics warmup release timed out");
        }
        initialized.set(true);
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        throw new AssertionError("diagnostics warmup interrupted", interrupted);
      }
    }

    public static void discardRemoteParent(int reason) {}

    public static void recordExtractionFailure(int reason) {}

    public static void recordExtensionEvent(int event, long count) {
      if (!initialized.get()) {
        bridgeUsedBeforeInitialization.set(true);
      }
    }

    private static void prepare() {
      reset();
      initializationStarted = new CountDownLatch(1);
      releaseInitialization = new CountDownLatch(1);
    }

    private static void reset() {
      releaseInitialization.countDown();
      initializationStarted = new CountDownLatch(0);
      releaseInitialization = new CountDownLatch(0);
      takeCalls.set(0);
      initialized.set(false);
      bridgeUsedBeforeInitialization.set(false);
    }
  }

  public static final class FakeRemoteParentBridge {
    private static final FakeRemoteParentRecord RECORD = new FakeRemoteParentRecord();
    private static final AtomicInteger takeCalls = new AtomicInteger();
    private static final AtomicLongArray extensionEvents = new AtomicLongArray(9);
    private static final AtomicReference<Runnable> lookupMissingCallback = new AtomicReference<>();
    private static final AtomicReference<Object> lookupMonitor = new AtomicReference<>();
    private static final AtomicBoolean diagnosticsHeldLookupMonitor = new AtomicBoolean();
    private static final AtomicInteger diagnosticsLoggerInitializations = new AtomicInteger();
    private static final AtomicBoolean failDiagnosticsLoggerInitialization = new AtomicBoolean();
    private static final AtomicBoolean bridgeUsedBeforeDiagnosticsInitialization =
        new AtomicBoolean();

    private FakeRemoteParentBridge() {}

    public static int abiVersion() {
      return 1;
    }

    public static FakeRemoteParentRecord takeRemoteParent() {
      if (diagnosticsLoggerInitializations.get() == 0) {
        bridgeUsedBeforeDiagnosticsInitialization.set(true);
      }
      takeCalls.incrementAndGet();
      return RECORD;
    }

    public static void initializeDiagnosticsLogger() {
      if (diagnosticsLoggerInitializations.compareAndSet(0, 1)
          && failDiagnosticsLoggerInitialization.get()) {
        throw new IllegalStateException("diagnostics initialization intentionally failed");
      }
    }

    public static void discardRemoteParent(int reason) {}

    public static void recordExtractionFailure(int reason) {}

    public static void recordExtensionEvent(int event, long count) {
      if (diagnosticsLoggerInitializations.get() == 0) {
        bridgeUsedBeforeDiagnosticsInitialization.set(true);
      }
      Object monitor = lookupMonitor.get();
      if (monitor != null && Thread.holdsLock(monitor)) {
        diagnosticsHeldLookupMonitor.set(true);
      }
      if (event >= 0 && event < extensionEvents.length() && count > 0L) {
        extensionEvents.addAndGet(event, count);
      }
      if (event != 3 || count <= 0L) {
        return;
      }
      Runnable callback = lookupMissingCallback.get();
      if (callback != null) {
        callback.run();
      }
    }

    private static long eventCount(int event) {
      return extensionEvents.get(event);
    }

    private static void reset() {
      takeCalls.set(0);
      for (int event = 0; event < extensionEvents.length(); event++) {
        extensionEvents.set(event, 0L);
      }
      lookupMissingCallback.set(null);
      lookupMonitor.set(null);
      diagnosticsHeldLookupMonitor.set(false);
      diagnosticsLoggerInitializations.set(0);
      failDiagnosticsLoggerInitialization.set(false);
      bridgeUsedBeforeDiagnosticsInitialization.set(false);
    }
  }

  public static final class FakeRemoteParentRecord {
    public int getAbiVersion() {
      return 1;
    }

    public int getStatus() {
      return BridgeResult.STATUS_VALID;
    }

    public int getTraceFlags() {
      return 1;
    }

    public String getTraceIdHex() {
      return "11111111111111111111111111111111";
    }

    public String getParentSpanIdHex() {
      return "2222222222222222";
    }
  }
}
