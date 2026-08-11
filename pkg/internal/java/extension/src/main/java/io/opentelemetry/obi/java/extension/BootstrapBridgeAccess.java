/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicLongArray;
import java.util.logging.Level;
import java.util.logging.Logger;

final class BootstrapBridgeAccess implements BridgeAccess {
  private static final int SUPPORTED_ABI_VERSION = 1;
  private static final long LOOKUP_RETRY_NANOS = 1_000_000_000L;
  private static final String BRIDGE_CLASS = "io.opentelemetry.obi.java.bridge.RemoteParentBridge";
  private static final String BRIDGE_AVAILABILITY_PROPERTY =
      "io.opentelemetry.obi.java.bridge.available";
  private static final int EVENT_EXTENSION_REGISTERED = 1;
  private static final int EVENT_LOOKUP_READY = 2;
  private static final int EVENT_LOOKUP_MISSING = 3;
  private static final int EVENT_LOOKUP_VERSION_MISMATCH = 4;
  private static final int EVENT_LOOKUP_ERROR = 5;
  private static final int EVENT_RECORD_VERSION_MISMATCH = 6;
  private static final int EVENT_INVOCATION_ERROR = 7;
  private static final int EVENT_STANDARD_PARENT_WON = 8;
  private static final int LOCAL_LOOKUP_MISSING = 0;
  private static final int LOCAL_LOOKUP_VERSION_MISMATCH = 1;
  private static final int LOCAL_LOOKUP_ERROR = 2;
  private static final long MAX_COUNTER_VALUE = 999_999_999L;
  private static final AtomicLongArray localCounters = new AtomicLongArray(3);
  private static final Logger logger = Logger.getLogger(BootstrapBridgeAccess.class.getName());
  private static volatile ReflectiveAccess diagnosticAccess;
  private static final BridgeClassResolver BOOTSTRAP_CLASS_RESOLVER =
      new BridgeClassResolver() {
        @Override
        public Class<?> resolve() throws ClassNotFoundException {
          return Class.forName(BRIDGE_CLASS, true, null);
        }
      };

  private final BridgeClassResolver bridgeClassResolver;
  private volatile ReflectiveAccess access;
  private volatile NegativeLookup negativeLookup;
  private volatile long nextLookupNanos;
  private Thread lookupOwner;

  BootstrapBridgeAccess() {
    this(BOOTSTRAP_CLASS_RESOLVER);
  }

  BootstrapBridgeAccess(BridgeClassResolver bridgeClassResolver) {
    this.bridgeClassResolver = bridgeClassResolver;
  }

  void initializeDiagnosticsLogger() {
    findBridge(false);
  }

  @Override
  public BridgeResult takeRemoteParent() {
    ReflectiveAccess current = access;
    if (current == null) {
      current = findBridge();
      if (current == null) {
        return BridgeResult.status(BridgeResult.STATUS_MISSING);
      }
    }
    return current.takeRemoteParent();
  }

  @Override
  public void discardRemoteParent(int reason) {
    ReflectiveAccess current = access;
    if (current == null) {
      current = findBridge();
      if (current == null) {
        return;
      }
    }
    current.discardRemoteParent(reason);
  }

  private ReflectiveAccess findBridge() {
    return findBridge(true);
  }

  private ReflectiveAccess findBridge(boolean recordFailure) {
    long failureCount = 0L;
    int failureCounter = -1;
    String failureReason = null;
    Level failureLevel = null;
    ReflectiveAccess found = null;
    Thread currentThread = Thread.currentThread();
    long now = System.nanoTime();
    String availability = bridgeAvailability();
    NegativeLookup currentNegative = negativeLookup;
    if (currentNegative != null && currentNegative.applies(now, availability)) {
      return null;
    }
    synchronized (this) {
      if (access != null) {
        return access;
      }
      if (lookupOwner != null) {
        return null;
      }
      now = System.nanoTime();
      availability = bridgeAvailability();
      currentNegative = negativeLookup;
      if (currentNegative != null && currentNegative.applies(now, availability)) {
        return null;
      }
      long retryAt = now + LOOKUP_RETRY_NANOS;
      negativeLookup = null;
      nextLookupNanos = 0L;
      lookupOwner = currentThread;
      try {
        Class<?> bridge = bridgeClassResolver.resolve();
        Method abiVersion = bridge.getMethod("abiVersion");
        if (((Number) abiVersion.invoke(null)).intValue() != SUPPORTED_ABI_VERSION) {
          failureCounter = LOCAL_LOOKUP_VERSION_MISMATCH;
          failureReason = "bridge_lookup_version_mismatch";
          failureLevel = Level.WARNING;
        } else {
          Method take = bridge.getMethod("takeRemoteParent");
          Method discard = bridge.getMethod("discardRemoteParent", int.class);
          Method extractionFailure = bridge.getMethod("recordExtractionFailure", int.class);
          Method extensionEvent = bridge.getMethod("recordExtensionEvent", int.class, long.class);
          Method initializeDiagnosticsLogger = diagnosticsLoggerInitializer(bridge);
          Class<?> record = take.getReturnType();
          found =
              new ReflectiveAccess(
                  take,
                  discard,
                  extractionFailure,
                  extensionEvent,
                  initializeDiagnosticsLogger,
                  record.getMethod("getAbiVersion"),
                  record.getMethod("getStatus"),
                  record.getMethod("getTraceFlags"),
                  record.getMethod("getTraceIdHex"),
                  record.getMethod("getParentSpanIdHex"));
        }
      } catch (ClassNotFoundException ignored) {
        failureCounter = LOCAL_LOOKUP_MISSING;
        failureReason = "bridge_lookup_missing";
        failureLevel = Level.INFO;
      } catch (Throwable ignored) {
        failureCounter = LOCAL_LOOKUP_ERROR;
        failureReason = "bridge_lookup_error";
        failureLevel = Level.WARNING;
      }
      if (found == null) {
        lookupOwner = null;
        if (recordFailure) {
          failureCount = incrementLocalCounter(failureCounter);
          nextLookupNanos = retryAt;
          negativeLookup = new NegativeLookup(availability, retryAt);
        }
      }
    }
    if (found != null) {
      try {
        found.initializeDiagnosticsLogger();
        found.recordExtensionEvent(EVENT_EXTENSION_REGISTERED, 1L);
        found.recordExtensionEvent(EVENT_LOOKUP_READY, 1L);
        diagnosticAccess = found;
        flushLocalCounters(found);
      } finally {
        synchronized (this) {
          // Keep arbitrary JUL handlers outside the lookup monitor, but do
          // not expose the bridge until post-agent warm-up and lifecycle
          // publication have returned.
          if (lookupOwner == currentThread) {
            access = found;
            lookupOwner = null;
          }
        }
      }
      return access;
    }
    if (recordFailure && !flushLocalCountersIfReady()) {
      logLocalFailure(failureReason, failureLevel, failureCount);
    }
    return null;
  }

  static String localDiagnosticsSnapshot() {
    return "bridge_lookup_missing="
        + localCounters.get(LOCAL_LOOKUP_MISSING)
        + ",bridge_lookup_version_mismatch="
        + localCounters.get(LOCAL_LOOKUP_VERSION_MISMATCH)
        + ",bridge_lookup_error="
        + localCounters.get(LOCAL_LOOKUP_ERROR);
  }

  static void resetLocalDiagnosticsForTest() {
    diagnosticAccess = null;
    for (int index = 0; index < localCounters.length(); index++) {
      localCounters.set(index, 0L);
    }
  }

  private static boolean flushLocalCountersIfReady() {
    ReflectiveAccess current = diagnosticAccess;
    if (current == null) {
      return false;
    }
    flushLocalCounters(current);
    return true;
  }

  private static void flushLocalCounters(ReflectiveAccess found) {
    long[] pending = drainLocalCounters();
    found.recordExtensionEvent(EVENT_LOOKUP_MISSING, pending[LOCAL_LOOKUP_MISSING]);
    found.recordExtensionEvent(
        EVENT_LOOKUP_VERSION_MISMATCH, pending[LOCAL_LOOKUP_VERSION_MISMATCH]);
    found.recordExtensionEvent(EVENT_LOOKUP_ERROR, pending[LOCAL_LOOKUP_ERROR]);
  }

  private static long[] drainLocalCounters() {
    long[] pending = new long[localCounters.length()];
    for (int index = 0; index < pending.length; index++) {
      pending[index] = localCounters.getAndSet(index, 0L);
    }
    return pending;
  }

  static long[] drainLocalCountersForTest() {
    return drainLocalCounters();
  }

  private static String bridgeAvailability() {
    try {
      return System.getProperty(BRIDGE_AVAILABILITY_PROPERTY);
    } catch (Throwable ignored) {
      return null;
    }
  }

  private static Method diagnosticsLoggerInitializer(Class<?> bridge) {
    try {
      return bridge.getMethod("initializeDiagnosticsLogger");
    } catch (Throwable ignored) {
      return null;
    }
  }

  private static boolean sameAvailability(String left, String right) {
    return left == null ? right == null : left.equals(right);
  }

  private static long incrementLocalCounter(int counter) {
    if (counter < 0 || counter >= localCounters.length()) {
      return 0L;
    }
    long current;
    long count;
    do {
      current = localCounters.get(counter);
      if (current == MAX_COUNTER_VALUE) {
        return 0L;
      }
      count = current + 1L;
    } while (!localCounters.compareAndSet(counter, current, count));
    return count;
  }

  private static void logLocalFailure(String reason, Level level, long count) {
    if (count <= 0L) {
      return;
    }
    if (count == 1L || (count & (count - 1L)) == 0L) {
      try {
        logger.log(
            level,
            "OBI remote-parent diagnostics reason={0} count={1}",
            new Object[] {reason, count});
      } catch (Throwable ignored) {
      }
    }
  }

  interface BridgeClassResolver {
    Class<?> resolve() throws ClassNotFoundException;
  }

  private static final class NegativeLookup {
    private final String availability;
    private final long retryAt;

    private NegativeLookup(String availability, long retryAt) {
      this.availability = availability;
      this.retryAt = retryAt;
    }

    private boolean applies(long now, String currentAvailability) {
      return now - retryAt < 0 && sameAvailability(currentAvailability, availability);
    }
  }

  private static final class ReflectiveAccess {
    private final Method take;
    private final Method discard;
    private final Method extractionFailure;
    private final Method extensionEvent;
    private final Method initializeDiagnosticsLogger;
    private final Method abiVersion;
    private final Method status;
    private final Method traceFlags;
    private final Method traceId;
    private final Method parentSpanId;

    private ReflectiveAccess(
        Method take,
        Method discard,
        Method extractionFailure,
        Method extensionEvent,
        Method initializeDiagnosticsLogger,
        Method abiVersion,
        Method status,
        Method traceFlags,
        Method traceId,
        Method parentSpanId) {
      this.take = take;
      this.discard = discard;
      this.extractionFailure = extractionFailure;
      this.extensionEvent = extensionEvent;
      this.initializeDiagnosticsLogger = initializeDiagnosticsLogger;
      this.abiVersion = abiVersion;
      this.status = status;
      this.traceFlags = traceFlags;
      this.traceId = traceId;
      this.parentSpanId = parentSpanId;
    }

    private void initializeDiagnosticsLogger() {
      if (initializeDiagnosticsLogger == null) {
        return;
      }
      try {
        initializeDiagnosticsLogger.invoke(null);
      } catch (Throwable ignored) {
      }
    }

    private BridgeResult takeRemoteParent() {
      try {
        Object record = take.invoke(null);
        if (record == null
            || ((Number) abiVersion.invoke(record)).intValue() != SUPPORTED_ABI_VERSION) {
          recordExtensionEvent(EVENT_RECORD_VERSION_MISMATCH, 1L);
          return BridgeResult.status(BridgeResult.STATUS_VERSION_MISMATCH);
        }

        int resultStatus = ((Number) status.invoke(record)).intValue();
        if (resultStatus != BridgeResult.STATUS_VALID) {
          return BridgeResult.status(resultStatus);
        }
        return new BridgeResult(
            resultStatus,
            ((Number) traceFlags.invoke(record)).intValue(),
            (String) traceId.invoke(record),
            (String) parentSpanId.invoke(record));
      } catch (Throwable ignored) {
        recordExtensionEvent(EVENT_INVOCATION_ERROR, 1L);
        return BridgeResult.status(BridgeResult.STATUS_TRANSPORT_ERROR);
      }
    }

    private void discardRemoteParent(int reason) {
      try {
        discard.invoke(null, reason);
      } catch (Throwable ignored) {
        recordExtensionEvent(EVENT_INVOCATION_ERROR, 1L);
      }
    }

    private void recordExtractionFailure(int reason) {
      try {
        extractionFailure.invoke(null, reason);
      } catch (Throwable ignored) {
        recordExtensionEvent(EVENT_INVOCATION_ERROR, 1L);
      }
    }

    private void recordExtensionEvent(int event, long count) {
      if (count <= 0) {
        return;
      }
      try {
        extensionEvent.invoke(null, event, count);
      } catch (Throwable ignored) {
      }
    }
  }

  @Override
  public void recordExtractionFailure(int reason) {
    ReflectiveAccess current = access;
    if (current == null) {
      current = findBridge();
      if (current == null) {
        return;
      }
    }
    current.recordExtractionFailure(reason);
  }

  @Override
  public void recordStandardParentWon() {
    ReflectiveAccess current = access;
    if (current == null) {
      current = findBridge();
      if (current == null) {
        return;
      }
    }
    current.recordExtensionEvent(EVENT_STANDARD_PARENT_WON, 1L);
  }
}
