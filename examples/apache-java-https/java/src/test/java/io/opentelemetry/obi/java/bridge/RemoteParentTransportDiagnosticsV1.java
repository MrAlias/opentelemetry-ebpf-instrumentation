// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.java.bridge;

public final class RemoteParentTransportDiagnosticsV1 {
  private RemoteParentTransportDiagnosticsV1() {}

  public static String snapshot() {
    return "version=2,status=1,requested=2,selected=2,attempted=2,getsockopt=0,unix=1";
  }
}
