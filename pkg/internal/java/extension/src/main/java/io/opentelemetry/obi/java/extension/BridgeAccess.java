/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

interface BridgeAccess {
  int DISCARD_STANDARD_PARENT = 1;
  int EXTRACTION_MISSING_FIELDS = 1;
  int EXTRACTION_INVALID_CONTEXT = 2;
  int EXTRACTION_ERROR = 3;

  BridgeResult takeRemoteParent();

  default void discardRemoteParent(int reason) {
    takeRemoteParent();
  }

  default void recordExtractionFailure(int reason) {}

  default void recordStandardParentWon() {}
}
