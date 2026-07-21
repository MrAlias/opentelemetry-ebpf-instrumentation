/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.logging.Logger;

public final class NativeRemoteParentProvider implements RemoteParentProvider {
  private static final int BUFFER_POOL_SIZE = 64;
  private static final long RETRY_NANOS = 1_000_000_000L;
  private static final Logger logger = Logger.getLogger(NativeRemoteParentProvider.class.getName());

  private final AtomicReferenceArray<byte[]> buffers = new AtomicReferenceArray<>(BUFFER_POOL_SIZE);
  private final Object configurationLock = new Object();
  private final int transport;
  private final String unixSocketPath;
  private final int timeoutMillis;
  private final long serverUid;
  private final TransportConfigurer transportConfigurer;
  private final ProcessRegistrar processRegistrar;

  private volatile int transportStatus;
  private volatile long nextConfigurationAttemptNanos;
  private volatile boolean closed;

  NativeRemoteParentProvider(
      int transport, String unixSocketPath, int timeoutMillis, long serverUid) {
    this(
        transport,
        unixSocketPath,
        timeoutMillis,
        serverUid,
        BootstrapNative::configureRemoteParentTransport,
        ThreadInfo::registerProcessIncarnation);
  }

  NativeRemoteParentProvider(
      int transport,
      String unixSocketPath,
      int timeoutMillis,
      long serverUid,
      TransportConfigurer transportConfigurer,
      ProcessRegistrar processRegistrar) {
    this.transport = transport;
    this.unixSocketPath = unixSocketPath == null ? "" : unixSocketPath;
    this.timeoutMillis = timeoutMillis;
    this.serverUid = serverUid;
    this.transportConfigurer = transportConfigurer;
    this.processRegistrar = processRegistrar;
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
      buffers.set(i, new byte[RemoteParentRecord.RECORD_SIZE]);
    }
    configureTransport();
  }

  @Override
  public int abiVersion() {
    return RemoteParentRecord.ABI_VERSION;
  }

  boolean isReady() {
    return transportStatus == RemoteParentStatus.VALID;
  }

  boolean isEnabled() {
    return transport != RemoteParentTransport.DISABLED;
  }

  @Override
  public RemoteParentRecord takeRemoteParent() {
    return callAndClearSocket(true);
  }

  @Override
  public RemoteParentRecord discardRemoteParent() {
    return callAndClearSocket(false);
  }

  private RemoteParentRecord callAndClearSocket(boolean take) {
    try {
      if (!ensureReady()) {
        return RemoteParentRecord.statusOnly(transportStatus);
      }
      return call(take);
    } finally {
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
    }
  }

  private RemoteParentRecord call(boolean take) {
    int start = ((int) Thread.currentThread().getId()) & (BUFFER_POOL_SIZE - 1);
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
      int slot = (start + i) & (BUFFER_POOL_SIZE - 1);
      byte[] response = buffers.getAndSet(slot, null);
      if (response == null) {
        continue;
      }
      try {
        int socketFileDescriptor = ThreadInfo.remoteParentSocketFileDescriptor();
        if (take) {
          BootstrapNative.takeRemoteParent(socketFileDescriptor, response);
        } else {
          BootstrapNative.discardRemoteParent(socketFileDescriptor, response);
        }
        RemoteParentRecord record = RemoteParentRecord.decode(response);
        if (requiresReconfiguration(record.getStatus())) {
          markUnavailable(record.getStatus());
        }
        return record;
      } catch (Throwable ignored) {
        markUnavailable(RemoteParentStatus.TRANSPORT_ERROR);
        return RemoteParentRecord.statusOnly(RemoteParentStatus.TRANSPORT_ERROR);
      } finally {
        buffers.set(slot, response);
      }
    }
    return RemoteParentRecord.statusOnly(RemoteParentStatus.OVERLOAD);
  }

  private boolean ensureReady() {
    if (closed || !isEnabled()) {
      return false;
    }
    if (isReady()) {
      return true;
    }

    long now = System.nanoTime();
    if (nextConfigurationAttemptNanos != 0 && now - nextConfigurationAttemptNanos < 0) {
      return false;
    }

    synchronized (configurationLock) {
      if (closed || isReady()) {
        return !closed;
      }
      now = System.nanoTime();
      if (nextConfigurationAttemptNanos != 0 && now - nextConfigurationAttemptNanos < 0) {
        return false;
      }
      if (configureTransport() == RemoteParentStatus.VALID) {
        logger.info("OBI remote-parent provider ready");
        return true;
      }
      return false;
    }
  }

  private int configureTransport() {
    int status;
    try {
      if (isEnabled() && !processRegistrar.register()) {
        status = RemoteParentStatus.UNAUTHORIZED;
      } else {
        status =
            transportConfigurer.configure(
                transport,
                unixSocketPath,
                timeoutMillis,
                serverUid,
                ThreadInfo.processIncarnation());
      }
    } catch (Throwable ignored) {
      status = RemoteParentStatus.TRANSPORT_ERROR;
    }
    if (isEnabled()) {
      RemoteParentDiagnostics.registration(status);
    }
    transportStatus = status;
    nextConfigurationAttemptNanos =
        status == RemoteParentStatus.VALID ? 0 : System.nanoTime() + RETRY_NANOS;
    return status;
  }

  private void markUnavailable(int status) {
    if (closed) {
      return;
    }
    transportStatus = status;
    nextConfigurationAttemptNanos = System.nanoTime() + RETRY_NANOS;
  }

  static boolean requiresReconfiguration(int status) {
    return status == RemoteParentStatus.UNKNOWN
        || status == RemoteParentStatus.UNSUPPORTED
        || status == RemoteParentStatus.MALFORMED
        || status == RemoteParentStatus.VERSION_MISMATCH
        || status == RemoteParentStatus.UNAUTHORIZED
        || status == RemoteParentStatus.TIMEOUT
        || status == RemoteParentStatus.OVERLOAD
        || status == RemoteParentStatus.TRANSPORT_ERROR
        || status == RemoteParentStatus.DISABLED;
  }

  @Override
  public void close() {
    synchronized (configurationLock) {
      closed = true;
      transportStatus = RemoteParentStatus.DISABLED;
      nextConfigurationAttemptNanos = Long.MAX_VALUE;
      try {
        BootstrapNative.closeRemoteParentTransport();
      } catch (Throwable ignored) {
      }
    }
  }

  interface TransportConfigurer {
    int configure(
        int transport,
        String unixSocketPath,
        int timeoutMillis,
        long serverUid,
        long processIncarnation);
  }

  interface ProcessRegistrar {
    boolean register();
  }
}
