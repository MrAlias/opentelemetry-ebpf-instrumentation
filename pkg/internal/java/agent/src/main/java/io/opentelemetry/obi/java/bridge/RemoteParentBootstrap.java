/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;

/** Initializes the native provider on the bootstrap copy of the bridge classes. */
public final class RemoteParentBootstrap {
  private static final String BRIDGE_AVAILABILITY_PROPERTY =
      "io.opentelemetry.obi.java.bridge.available";
  private static final int INSTALLATION_IDLE = 0;
  private static final int INSTALLATION_STARTED = 1;
  private static final int INSTALLATION_COMPLETE = 2;

  private static RemoteParentProvider installed;
  private static int installationState;

  private RemoteParentBootstrap() {}

  public static synchronized boolean beginInstrumentationInstallation() {
    if (installationState != INSTALLATION_IDLE) {
      return false;
    }
    installationState = INSTALLATION_STARTED;
    return true;
  }

  public static synchronized void completeInstrumentationInstallation() {
    if (installationState == INSTALLATION_STARTED) {
      installationState = INSTALLATION_COMPLETE;
    }
  }

  public static synchronized void cancelInstrumentationInstallation() {
    if (installationState == INSTALLATION_STARTED) {
      installationState = INSTALLATION_IDLE;
      clearProvider();
    }
  }

  public static synchronized boolean instrumentationInstallationClaimed() {
    return installationState != INSTALLATION_IDLE;
  }

  public static synchronized boolean initialize(
      String transport,
      String unixSocketPath,
      int timeoutMillis,
      long serverUid,
      long processCapability) {
    signalBridgeAvailability();
    clearProvider();
    if (processCapability <= 0L) {
      RemoteParentDiagnostics.configuration(false);
      return false;
    }
    ThreadInfo.setProcessIncarnation(processCapability);
    ThreadInfo.registerProcessIncarnation();
    NativeRemoteParentProvider next =
        new NativeRemoteParentProvider(
            RemoteParentTransport.parse(transport), unixSocketPath, timeoutMillis, serverUid);
    RemoteParentDiagnostics.configuration(next.isEnabled());
    if (!next.isEnabled()) {
      next.close();
      return false;
    }
    boolean ready = next.isReady();
    if (!RemoteParentBridge.installProvider(next)) {
      next.close();
      return false;
    }
    installed = next;
    ThreadInfo.setRemoteParentEnabled(true);
    return ready;
  }

  public static synchronized String diagnosticsSnapshot() {
    return RemoteParentBridge.diagnosticsSnapshot();
  }

  private static void clearProvider() {
    ThreadInfo.setRemoteParentEnabled(false);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    if (installed != null) {
      RemoteParentBridge.removeProvider(installed);
      installed = null;
    }
  }

  private static void signalBridgeAvailability() {
    try {
      System.setProperty(BRIDGE_AVAILABILITY_PROPERTY, "1");
    } catch (Throwable ignored) {
    }
  }
}
