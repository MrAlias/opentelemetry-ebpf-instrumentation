/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

/** Loaded without an application or agent class-loader parent by the late-attach probe. */
public final class IsolatedBridgeConsumer {
  private IsolatedBridgeConsumer() {}

  public static int remoteParentStatus() throws Exception {
    try {
      Class<?> bridge =
          Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", true, null);
      Object record = bridge.getMethod("takeRemoteParent").invoke(null);
      return (Integer) record.getClass().getMethod("getStatus").invoke(record);
    } catch (ClassNotFoundException unavailable) {
      return -1;
    }
  }
}
