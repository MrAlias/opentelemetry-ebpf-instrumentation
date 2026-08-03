/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

/** Test-only access to NativeMemory's current-thread JNI bypass. */
public final class NativeMemoryTestAccess {
  private NativeMemoryTestAccess() {}

  public static void setSyntheticAddress(boolean enabled) {
    NativeMemory.setSyntheticAddressForTest(enabled);
  }
}
