/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import java.util.concurrent.atomic.AtomicLongArray;
import java.util.logging.Logger;

/** Fixed-size, bootstrap-safe diagnostics for the remote-parent handoff. */
public final class RemoteParentDiagnostics {
  static final int EXTRACTION_MISSING_FIELDS = 1;
  static final int EXTRACTION_INVALID_CONTEXT = 2;
  static final int EXTRACTION_ERROR = 3;
  static final int DISCARD_STANDARD_PARENT = 1;

  private static final int CONFIG_ENABLED = 0;
  private static final int CONFIG_DISABLED = 1;
  private static final int PROVIDER_INSTALLED = 2;
  private static final int PROVIDER_REJECTED = 3;
  private static final int PROVIDER_VERSION_MISMATCH = 4;
  private static final int EXTENSION_REGISTERED = 5;
  private static final int BRIDGE_LOOKUP_READY = 6;
  private static final int BRIDGE_LOOKUP_MISSING = 7;
  private static final int BRIDGE_LOOKUP_VERSION_MISMATCH = 8;
  private static final int BRIDGE_LOOKUP_ERROR = 9;
  private static final int BRIDGE_RECORD_VERSION_MISMATCH = 10;
  private static final int BRIDGE_INVOCATION_ERROR = 11;
  private static final int DISCARD_STANDARD_PARENT_COUNTER = 12;
  private static final int EXTRACTION_MISSING_FIELDS_COUNTER = 13;
  private static final int EXTRACTION_INVALID_CONTEXT_COUNTER = 14;
  private static final int EXTRACTION_ERROR_COUNTER = 15;
  private static final int REGISTRATION_READY = 16;
  private static final int REGISTRATION_FAILED = 17;
  private static final int TAKE_SAMPLED = 18;
  private static final int TAKE_UNSAMPLED = 19;
  private static final int TLS_READ_EVENTS = 20;
  private static final int TLS_READ_BYTES = 21;
  private static final int TAKE_STATUS_BASE = 22;
  private static final int DISCARD_STATUS_BASE = TAKE_STATUS_BASE + RemoteParentStatus.DISABLED + 1;
  private static final int COUNTER_COUNT = DISCARD_STATUS_BASE + RemoteParentStatus.DISABLED + 1;
  static final long MAX_COUNTER_VALUE = 999_999_999L;
  private static final AtomicLongArray counters = new AtomicLongArray(COUNTER_COUNT);
  private static final Logger logger = Logger.getLogger(RemoteParentDiagnostics.class.getName());
  private static final String[] STATUS_NAMES = {
    "unknown",
    "valid",
    "missing",
    "stale",
    "unsupported",
    "malformed",
    "version_mismatch",
    "ambiguous",
    "unauthorized",
    "already_consumed",
    "timeout",
    "overload",
    "transport_error",
    "disabled"
  };

  private RemoteParentDiagnostics() {}

  static void configuration(boolean enabled) {
    increment(enabled ? CONFIG_ENABLED : CONFIG_DISABLED, null);
  }

  static void providerInstalled() {
    increment(PROVIDER_INSTALLED, null);
  }

  static void providerRejected() {
    increment(PROVIDER_REJECTED, "provider_rejected");
  }

  static void providerVersionMismatch() {
    increment(PROVIDER_VERSION_MISMATCH, "provider_version_mismatch");
  }

  static void takeStatus(int status) {
    int normalized = normalizeStatus(status);
    increment(TAKE_STATUS_BASE + normalized, failureReason("take", normalized));
  }

  static void takeFlags(int traceFlags) {
    increment((traceFlags & 1) != 0 ? TAKE_SAMPLED : TAKE_UNSAMPLED, null);
  }

  static void discardStatus(int status) {
    int normalized = normalizeStatus(status);
    increment(DISCARD_STATUS_BASE + normalized, failureReason("discard", normalized));
  }

  static void discardReason(int reason) {
    if (reason == DISCARD_STANDARD_PARENT) {
      increment(DISCARD_STANDARD_PARENT_COUNTER, null);
    }
  }

  static void extractionFailure(int reason) {
    switch (reason) {
      case EXTRACTION_MISSING_FIELDS:
        increment(EXTRACTION_MISSING_FIELDS_COUNTER, "extract_missing_fields");
        break;
      case EXTRACTION_INVALID_CONTEXT:
        increment(EXTRACTION_INVALID_CONTEXT_COUNTER, "extract_invalid_context");
        break;
      default:
        increment(EXTRACTION_ERROR_COUNTER, "extract_error");
        break;
    }
  }

  static void registration(int status) {
    int normalized = normalizeStatus(status);
    if (normalized == RemoteParentStatus.VALID) {
      increment(REGISTRATION_READY, null);
      return;
    }
    increment(REGISTRATION_FAILED, "registration_" + STATUS_NAMES[normalized]);
  }

  static void tlsRead(int bytes) {
    if (bytes <= 0) {
      return;
    }
    increment(TLS_READ_EVENTS, null);
    add(TLS_READ_BYTES, bytes, null);
  }

  static long tlsReadEvents() {
    return counters.get(TLS_READ_EVENTS);
  }

  static long tlsReadBytes() {
    return counters.get(TLS_READ_BYTES);
  }

  static void extensionEvent(int event, long count) {
    int counter;
    String failureReason = null;
    switch (event) {
      case 1:
        counter = EXTENSION_REGISTERED;
        break;
      case 2:
        counter = BRIDGE_LOOKUP_READY;
        break;
      case 3:
        counter = BRIDGE_LOOKUP_MISSING;
        failureReason = "bridge_lookup_missing";
        break;
      case 4:
        counter = BRIDGE_LOOKUP_VERSION_MISMATCH;
        failureReason = "bridge_lookup_version_mismatch";
        break;
      case 5:
        counter = BRIDGE_LOOKUP_ERROR;
        failureReason = "bridge_lookup_error";
        break;
      case 6:
        counter = BRIDGE_RECORD_VERSION_MISMATCH;
        failureReason = "bridge_record_version_mismatch";
        break;
      case 7:
        counter = BRIDGE_INVOCATION_ERROR;
        failureReason = "bridge_invocation_error";
        break;
      case 8:
        counter = DISCARD_STANDARD_PARENT_COUNTER;
        break;
      default:
        return;
    }
    add(counter, count, failureReason);
  }

  /** Returns fixed-name counters only; no trace, task, socket, or process data is included. */
  public static String snapshot() {
    StringBuilder snapshot = new StringBuilder(768);
    append(snapshot, "cfg_on", counters.get(CONFIG_ENABLED));
    append(snapshot, "cfg_off", counters.get(CONFIG_DISABLED));
    append(snapshot, "provider_ok", counters.get(PROVIDER_INSTALLED));
    append(snapshot, "provider_reject", counters.get(PROVIDER_REJECTED));
    append(snapshot, "provider_ver", counters.get(PROVIDER_VERSION_MISMATCH));
    append(snapshot, "extension_reg", counters.get(EXTENSION_REGISTERED));
    append(snapshot, "lookup_ready", counters.get(BRIDGE_LOOKUP_READY));
    append(snapshot, "lookup_missing", counters.get(BRIDGE_LOOKUP_MISSING));
    append(snapshot, "lookup_version", counters.get(BRIDGE_LOOKUP_VERSION_MISMATCH));
    append(snapshot, "lookup_error", counters.get(BRIDGE_LOOKUP_ERROR));
    append(snapshot, "record_version", counters.get(BRIDGE_RECORD_VERSION_MISMATCH));
    append(snapshot, "invoke_error", counters.get(BRIDGE_INVOCATION_ERROR));
    append(snapshot, "discard_standard", counters.get(DISCARD_STANDARD_PARENT_COUNTER));
    append(snapshot, "extract_fields", counters.get(EXTRACTION_MISSING_FIELDS_COUNTER));
    append(snapshot, "extract_invalid", counters.get(EXTRACTION_INVALID_CONTEXT_COUNTER));
    append(snapshot, "extract_error", counters.get(EXTRACTION_ERROR_COUNTER));
    append(snapshot, "registration_ok", counters.get(REGISTRATION_READY));
    append(snapshot, "registration_fail", counters.get(REGISTRATION_FAILED));
    append(snapshot, "take_sampled", counters.get(TAKE_SAMPLED));
    append(snapshot, "take_unsampled", counters.get(TAKE_UNSAMPLED));
    append(snapshot, "tls_reads", counters.get(TLS_READ_EVENTS));
    append(snapshot, "tls_bytes", counters.get(TLS_READ_BYTES));
    for (int status = RemoteParentStatus.UNKNOWN; status <= RemoteParentStatus.DISABLED; status++) {
      append(snapshot, "t_" + STATUS_NAMES[status], counters.get(TAKE_STATUS_BASE + status));
      append(snapshot, "d_" + STATUS_NAMES[status], counters.get(DISCARD_STATUS_BASE + status));
    }
    return snapshot.toString();
  }

  static void resetForTest() {
    for (int index = 0; index < COUNTER_COUNT; index++) {
      counters.set(index, 0L);
    }
  }

  private static int normalizeStatus(int status) {
    return RemoteParentStatus.isKnown(status) ? status : RemoteParentStatus.UNKNOWN;
  }

  private static String failureReason(String operation, int status) {
    if (status == RemoteParentStatus.VALID
        || status == RemoteParentStatus.MISSING
        || status == RemoteParentStatus.DISABLED) {
      return null;
    }
    return operation + "_" + STATUS_NAMES[status];
  }

  private static void increment(int index, String failureReason) {
    add(index, 1L, failureReason);
  }

  private static void add(int index, long amount, String failureReason) {
    if (amount <= 0) {
      return;
    }
    long current;
    long next;
    do {
      current = counters.get(index);
      if (current == MAX_COUNTER_VALUE) {
        return;
      }
      next = Math.min(MAX_COUNTER_VALUE, current + Math.min(amount, MAX_COUNTER_VALUE));
    } while (!counters.compareAndSet(index, current, next));

    if (failureReason != null && (next == 1L || (next & (next - 1L)) == 0L)) {
      try {
        logger.warning("OBI remote-parent diagnostics reason=" + failureReason + " count=" + next);
      } catch (Throwable ignored) {
      }
    }
  }

  private static void append(StringBuilder snapshot, String name, long value) {
    if (snapshot.length() != 0) {
      snapshot.append(',');
    }
    snapshot.append(name).append('=').append(Long.toString(value, Character.MAX_RADIX));
  }
}
