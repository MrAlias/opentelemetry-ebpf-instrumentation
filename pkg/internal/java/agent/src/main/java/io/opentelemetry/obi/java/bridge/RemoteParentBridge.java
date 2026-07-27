/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

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
    RemoteParentRecord record;
    try {
      record = provider.get().takeRemoteParent();
    } catch (Throwable ignored) {
      record = RemoteParentRecord.statusOnly(RemoteParentStatus.TRANSPORT_ERROR);
    }
    if (record == null) {
      record = RemoteParentRecord.statusOnly(RemoteParentStatus.MALFORMED);
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
    RemoteParentRecord record;
    try {
      record = provider.get().discardRemoteParent();
    } catch (Throwable ignored) {
      record = RemoteParentRecord.statusOnly(RemoteParentStatus.TRANSPORT_ERROR);
    }
    if (record == null) {
      record = RemoteParentRecord.statusOnly(RemoteParentStatus.MALFORMED);
    }
    RemoteParentDiagnostics.discardStatus(record.getStatus());
    return record;
  }

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

    RemoteParentProvider previous = provider.getAndSet(next);
    if (previous != NOOP && previous != next) {
      try {
        previous.close();
      } catch (Throwable ignored) {
      }
    }
    RemoteParentDiagnostics.providerInstalled();
    return true;
  }

  public static void recordExtractionFailure(int reason) {
    RemoteParentDiagnostics.extractionFailure(reason);
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
