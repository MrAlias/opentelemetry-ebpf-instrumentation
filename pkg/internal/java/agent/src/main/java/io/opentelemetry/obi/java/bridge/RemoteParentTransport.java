/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

/** Native transport selections for the OBI remote-parent bridge. */
public final class RemoteParentTransport {
  public static final int AUTO = 0;
  public static final int GETSOCKOPT = 1;
  public static final int UNIX = 2;
  public static final int DISABLED = 3;

  private RemoteParentTransport() {}

  public static int parse(String value) {
    if ("auto".equalsIgnoreCase(value)) {
      return AUTO;
    }
    if ("getsockopt".equalsIgnoreCase(value)) {
      return GETSOCKOPT;
    }
    if ("unix".equalsIgnoreCase(value)) {
      return UNIX;
    }
    if (value == null || value.isEmpty() || "disabled".equalsIgnoreCase(value)) {
      return DISABLED;
    }
    return DISABLED;
  }
}
