/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

/** Status values used by the OBI-to-Java remote-parent ABI. */
public final class RemoteParentStatus {
  public static final int UNKNOWN = 0;
  public static final int VALID = 1;
  public static final int MISSING = 2;
  public static final int STALE = 3;
  public static final int UNSUPPORTED = 4;
  public static final int MALFORMED = 5;
  public static final int VERSION_MISMATCH = 6;
  public static final int AMBIGUOUS = 7;
  public static final int UNAUTHORIZED = 8;
  public static final int ALREADY_CONSUMED = 9;
  public static final int TIMEOUT = 10;
  public static final int OVERLOAD = 11;
  public static final int TRANSPORT_ERROR = 12;
  public static final int DISABLED = 13;

  private RemoteParentStatus() {}

  public static boolean isKnown(int status) {
    return status >= UNKNOWN && status <= DISABLED;
  }
}
