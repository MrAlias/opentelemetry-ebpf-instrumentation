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

  private volatile ReflectiveAccess access;
  private volatile long nextLookupNanos;
  private volatile String observedAvailability;

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
    long now = System.nanoTime();
    String availability = bridgeAvailability();
    if (nextLookupNanos != 0
        && now - nextLookupNanos < 0
        && sameAvailability(availability, observedAvailability)) {
      return null;
    }

    synchronized (this) {
      if (access != null) {
        return access;
      }
      now = System.nanoTime();
      availability = bridgeAvailability();
      if (nextLookupNanos != 0
          && now - nextLookupNanos < 0
          && sameAvailability(availability, observedAvailability)) {
        return null;
      }
      observedAvailability = availability;
      nextLookupNanos = now + LOOKUP_RETRY_NANOS;
      try {
        Class<?> bridge = Class.forName(BRIDGE_CLASS, true, null);
        Method abiVersion = bridge.getMethod("abiVersion");
        if (((Number) abiVersion.invoke(null)).intValue() != SUPPORTED_ABI_VERSION) {
          recordLocal(
              LOCAL_LOOKUP_VERSION_MISMATCH, "bridge_lookup_version_mismatch", Level.WARNING);
          return null;
        }

        Method take = bridge.getMethod("takeRemoteParent");
        Method discard = bridge.getMethod("discardRemoteParent", int.class);
        Method extractionFailure = bridge.getMethod("recordExtractionFailure", int.class);
        Method extensionEvent = bridge.getMethod("recordExtensionEvent", int.class, long.class);
        Class<?> record = take.getReturnType();
        ReflectiveAccess found =
            new ReflectiveAccess(
                take,
                discard,
                extractionFailure,
                extensionEvent,
                record.getMethod("getAbiVersion"),
                record.getMethod("getStatus"),
                record.getMethod("getTraceFlags"),
                record.getMethod("getTraceIdHex"),
                record.getMethod("getParentSpanIdHex"));
        found.recordExtensionEvent(EVENT_EXTENSION_REGISTERED, 1L);
        found.recordExtensionEvent(EVENT_LOOKUP_READY, 1L);
        flushLocalCounters(found);
        access = found;
        return found;
      } catch (ClassNotFoundException ignored) {
        recordLocal(LOCAL_LOOKUP_MISSING, "bridge_lookup_missing", Level.INFO);
        return null;
      } catch (Throwable ignored) {
        recordLocal(LOCAL_LOOKUP_ERROR, "bridge_lookup_error", Level.WARNING);
        return null;
      }
    }
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
    for (int index = 0; index < localCounters.length(); index++) {
      localCounters.set(index, 0L);
    }
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

  private static boolean sameAvailability(String left, String right) {
    return left == null ? right == null : left.equals(right);
  }

  private static void recordLocal(int counter, String reason, Level level) {
    long current;
    long count;
    do {
      current = localCounters.get(counter);
      if (current == MAX_COUNTER_VALUE) {
        return;
      }
      count = current + 1L;
    } while (!localCounters.compareAndSet(counter, current, count));
    if (count == 1L || (count & (count - 1L)) == 0L) {
      logger.log(
          level,
          "OBI remote-parent diagnostics reason={0} count={1}",
          new Object[] {reason, count});
    }
  }

  private static final class ReflectiveAccess {
    private final Method take;
    private final Method discard;
    private final Method extractionFailure;
    private final Method extensionEvent;
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
        Method abiVersion,
        Method status,
        Method traceFlags,
        Method traceId,
        Method parentSpanId) {
      this.take = take;
      this.discard = discard;
      this.extractionFailure = extractionFailure;
      this.extensionEvent = extensionEvent;
      this.abiVersion = abiVersion;
      this.status = status;
      this.traceFlags = traceFlags;
      this.traceId = traceId;
      this.parentSpanId = parentSpanId;
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
