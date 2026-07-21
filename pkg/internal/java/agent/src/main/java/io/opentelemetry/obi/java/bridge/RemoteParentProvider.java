/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

/** Provider installed into the bootstrap bridge by the dynamically attached OBI helper. */
public interface RemoteParentProvider {
  int abiVersion();

  RemoteParentRecord takeRemoteParent();

  RemoteParentRecord discardRemoteParent();

  void close();
}
