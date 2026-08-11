/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import java.util.concurrent.atomic.AtomicReference;

/** Bootstrap-visible handoff between the late-attached OBI helper and agent extensions. */
public final class RemoteParentBridge {
  private static final RemoteParentProvider NOOP = new NoopProvider();
  private static final AtomicReference<RemoteParentProvider> provider = new AtomicReference<>(NOOP);

  private RemoteParentBridge() {}

  public static int abiVersion() {
    return RemoteParentRecord.ABI_VERSION;
  }

  public static RemoteParentRecord takeRemoteParent() {
    long bridgeEpoch = ThreadInfo.captureRemoteParentBridgeCapability();
    if (bridgeEpoch == 0L) {
      ThreadInfo.revokeRemoteParentBridgeAuthority();
      RemoteParentRecord missing = RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
      RemoteParentDiagnostics.takeStatus(missing.getStatus());
      return missing;
    }
    int frameworkMissReason = ThreadInfo.takeRemoteParentFrameworkMissReason();
    if (frameworkMissReason != ThreadInfo.REMOTE_PARENT_FRAMEWORK_MISS_NONE) {
      ThreadInfo.revokeRemoteParentBridgeAuthority();
      RemoteParentRecord missing = RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
      RemoteParentDiagnostics.frameworkMiss(frameworkMissReason);
      RemoteParentDiagnostics.takeStatus(missing.getStatus());
      return missing;
    }
    RemoteParentProvider selected = provider.get();
    RemoteParentRecord record;
    try {
      record = selected.takeRemoteParent();
    } catch (Throwable ignored) {
      record = RemoteParentRecord.statusOnly(RemoteParentStatus.TRANSPORT_ERROR);
    }
    if (record == null) {
      record = RemoteParentRecord.statusOnly(RemoteParentStatus.MALFORMED);
    }
    if (selected != provider.get()
        || !ThreadInfo.isCurrentRemoteParentBridgeCapability(bridgeEpoch)) {
      ThreadInfo.revokeRemoteParentBridgeAuthority();
      record = RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }
    RemoteParentDiagnostics.takeStatus(record.getStatus());
    if (record.getStatus() == RemoteParentStatus.VALID) {
      RemoteParentDiagnostics.takeFlags(record.getTraceFlags());
    }
    return record;
  }

  public static RemoteParentRecord discardRemoteParent() {
    return discardRemoteParent(0);
  }

  public static RemoteParentRecord discardRemoteParent(int reason) {
    RemoteParentDiagnostics.discardReason(reason);
    long bridgeEpoch = ThreadInfo.captureRemoteParentBridgeCapability();
    if (bridgeEpoch == 0L) {
      ThreadInfo.revokeRemoteParentBridgeAuthority();
      RemoteParentRecord missing = RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
      RemoteParentDiagnostics.discardStatus(missing.getStatus());
      return missing;
    }
    RemoteParentProvider selected = provider.get();
    RemoteParentRecord record;
    try {
      record = selected.discardRemoteParent();
    } catch (Throwable ignored) {
      record = RemoteParentRecord.statusOnly(RemoteParentStatus.TRANSPORT_ERROR);
    }
    if (record == null) {
      record = RemoteParentRecord.statusOnly(RemoteParentStatus.MALFORMED);
    }
    if (selected != provider.get()
        || !ThreadInfo.isCurrentRemoteParentBridgeCapability(bridgeEpoch)) {
      ThreadInfo.revokeRemoteParentBridgeAuthority();
      record = RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }
    RemoteParentDiagnostics.discardStatus(record.getStatus());
    return record;
  }

  /**
   * Installs a compatible provider when the bridge is empty.
   *
   * <p>Reinstalling the exact active instance is an idempotent success. A different provider is
   * rejected until the active provider is explicitly removed.
   */
  public static boolean installProvider(RemoteParentProvider next) {
    return installProvider(next, false);
  }

  static boolean installProviderForTest(RemoteParentProvider next) {
    return installProvider(next, true);
  }

  private static boolean installProvider(RemoteParentProvider next, boolean allowNonBootstrap) {
    if (next == null) {
      RemoteParentDiagnostics.providerRejected();
      return false;
    }
    if (provider.get() == next) {
      return true;
    }
    try {
      if (next.abiVersion() != RemoteParentRecord.ABI_VERSION) {
        RemoteParentDiagnostics.providerVersionMismatch();
        return false;
      }
    } catch (Throwable ignored) {
      RemoteParentDiagnostics.providerRejected();
      return false;
    }
    if (!allowNonBootstrap && next.getClass().getClassLoader() != null) {
      RemoteParentDiagnostics.providerRejected();
      return false;
    }

    while (true) {
      RemoteParentProvider current = provider.get();
      if (current == next) {
        return true;
      }
      if (current != NOOP) {
        RemoteParentDiagnostics.providerDuplicate();
        return false;
      }
      if (provider.compareAndSet(NOOP, next)) {
        RemoteParentDiagnostics.providerInstalled();
        return true;
      }
    }
  }

  public static void recordExtractionFailure(int reason) {
    RemoteParentDiagnostics.extractionFailure(reason);
  }

  /**
   * Records a local receive drop without invoking the provider.
   *
   * <p>The existing {@code d_<status>} schema covers both native discard outcomes and local
   * fail-closed drops. This keeps ambiguity reason-coded while avoiding a destructive provider
   * lookup whose only purpose would be accounting.
   */
  public static void recordReceiveFailure(int status) {
    RemoteParentDiagnostics.receiveFailure(status);
  }

  /** Records a provider lookup that reached its native transport and found no parent. */
  public static void recordTransportMissing() {
    RemoteParentDiagnostics.transportMissing();
  }

  public static void recordExtensionEvent(int event, long count) {
    RemoteParentDiagnostics.extensionEvent(event, count);
  }

  public static void recordTlsRead(int bytes) {
    RemoteParentDiagnostics.tlsRead(bytes);
  }

  public static long tlsReadEvents() {
    return RemoteParentDiagnostics.tlsReadEvents();
  }

  public static long tlsReadBytes() {
    return RemoteParentDiagnostics.tlsReadBytes();
  }

  public static String diagnosticsSnapshot() {
    return RemoteParentDiagnostics.snapshot();
  }

  /** Initializes diagnostics logging before concurrent bridge use. */
  public static void initializeDiagnosticsLogger() {
    RemoteParentDiagnostics.initializeLogger();
  }

  public static String transportConfigurationSnapshot() {
    long configuration;
    try {
      configuration = provider.get().transportConfiguration();
    } catch (Throwable ignored) {
      configuration =
          RemoteParentTransportConfiguration.failure(
              RemoteParentTransportConfiguration.NONE, RemoteParentStatus.TRANSPORT_ERROR);
    }
    return RemoteParentTransportConfiguration.snapshot(configuration);
  }

  public static boolean removeProvider(RemoteParentProvider expected) {
    if (expected == null || !provider.compareAndSet(expected, NOOP)) {
      return false;
    }
    try {
      expected.close();
    } catch (Throwable ignored) {
    }
    return true;
  }

  static void resetForTest() {
    RemoteParentProvider previous = provider.getAndSet(NOOP);
    if (previous != NOOP) {
      previous.close();
    }
    RemoteParentDiagnostics.resetForTest();
  }

  private static final class NoopProvider implements RemoteParentProvider {
    NoopProvider() {}

    @Override
    public int abiVersion() {
      return RemoteParentRecord.ABI_VERSION;
    }

    @Override
    public long transportConfiguration() {
      return RemoteParentTransportConfiguration.disabled();
    }

    @Override
    public RemoteParentRecord takeRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public RemoteParentRecord discardRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public void close() {}
  }
}
