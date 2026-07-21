/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

final class BridgeResult {
  static final int STATUS_VALID = 1;
  static final int STATUS_MISSING = 2;
  static final int STATUS_MALFORMED = 5;
  static final int STATUS_VERSION_MISMATCH = 6;
  static final int STATUS_TRANSPORT_ERROR = 12;
  private static final int STATUS_DISABLED = 13;
  private static final BridgeResult[] STATUS_RESULTS = statusResults();

  final int status;
  final int traceFlags;
  final String traceId;
  final String parentSpanId;

  BridgeResult(int status, int traceFlags, String traceId, String parentSpanId) {
    this.status = status;
    this.traceFlags = traceFlags;
    this.traceId = traceId;
    this.parentSpanId = parentSpanId;
  }

  static BridgeResult status(int status) {
    int normalized = status >= 0 && status <= STATUS_DISABLED ? status : STATUS_MALFORMED;
    return STATUS_RESULTS[normalized];
  }

  private static BridgeResult[] statusResults() {
    BridgeResult[] results = new BridgeResult[STATUS_DISABLED + 1];
    for (int status = 0; status <= STATUS_DISABLED; status++) {
      results[status] = new BridgeResult(status, 0, null, null);
    }
    return results;
  }
}
