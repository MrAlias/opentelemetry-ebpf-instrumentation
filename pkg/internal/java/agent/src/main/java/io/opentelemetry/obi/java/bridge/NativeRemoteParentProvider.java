/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.ReceiveContext;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;
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
  private final SocketCaller socketCaller;

  private volatile int transportStatus;
  private volatile long transportConfiguration;
  private volatile long nextConfigurationAttemptNanos;
  private volatile boolean closed;

  NativeRemoteParentProvider(
      int transport, String unixSocketPath, int timeoutMillis, long serverUid) {
    this(
        transport,
        unixSocketPath,
        timeoutMillis,
        serverUid,
        NativeRemoteParentProvider::configureNativeTransport,
        ThreadInfo::registerProcessIncarnation,
        NativeRemoteParentProvider::callNative);
  }

  NativeRemoteParentProvider(
      int transport,
      String unixSocketPath,
      int timeoutMillis,
      long serverUid,
      TransportConfigurer transportConfigurer,
      ProcessRegistrar processRegistrar) {
    this(
        transport,
        unixSocketPath,
        timeoutMillis,
        serverUid,
        transportConfigurer,
        processRegistrar,
        NativeRemoteParentProvider::callNative);
  }

  NativeRemoteParentProvider(
      int transport,
      String unixSocketPath,
      int timeoutMillis,
      long serverUid,
      TransportConfigurer transportConfigurer,
      ProcessRegistrar processRegistrar,
      SocketCaller socketCaller) {
    this.transport = transport;
    this.unixSocketPath = unixSocketPath == null ? "" : unixSocketPath;
    this.timeoutMillis = timeoutMillis;
    this.serverUid = serverUid;
    this.transportConfigurer = transportConfigurer;
    this.processRegistrar = processRegistrar;
    this.socketCaller = socketCaller;
    this.transportConfiguration = RemoteParentTransportConfiguration.unknown(transport);
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
      buffers.set(i, new byte[RemoteParentRecord.RECORD_SIZE]);
    }
    configureTransport();
  }

  @Override
  public int abiVersion() {
    return RemoteParentRecord.ABI_VERSION;
  }

  @Override
  public long transportConfiguration() {
    return transportConfiguration;
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
    int lookupSource = ThreadInfo.remoteParentLookupSource();
    boolean taskScoped = lookupSource == ThreadInfo.REMOTE_PARENT_LOOKUP_TASK;
    RemoteParentSocketContext context = ThreadInfo.takeRemoteParentSocketContext();
    ReceiveContext receiveContext = ThreadInfo.takeRemoteParentReceiveContext();
    Lifecycle.Lease lifecycleLease = null;
    RemoteParentRecord result;
    boolean receiveContextValid;
    try {
      if (lookupSource == ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED) {
        result = RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
      } else if (receiveContext != null
          && !ThreadInfo.isCurrentRemoteParentBridgeCapability(receiveContext.bridgeEpoch())) {
        result = RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
      } else if (!ensureReady()) {
        result = RemoteParentRecord.statusOnly(transportStatus);
      } else {
        Lifecycle lifecycle = ThreadInfo.remoteParentLookupLifecycle();
        if (lifecycle != null) {
          lifecycleLease = lifecycle.acquireLookupLease();
        }
        result =
            lifecycle != null && lifecycleLease == null
                ? RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING)
                : call(take, taskScoped, context);
        if (receiveContext != null
            && !ThreadInfo.isCurrentRemoteParentBridgeCapability(receiveContext.bridgeEpoch())) {
          result = RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
        }
      }
    } finally {
      if (lifecycleLease != null) {
        lifecycleLease.close();
      }
      receiveContextValid = ThreadInfo.finishRemoteParentExtractionAndValidate(receiveContext);
      if (context != null) {
        context.discard();
      }
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
    }
    return receiveContextValid ? result : RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
  }

  private RemoteParentRecord call(
      boolean take, boolean taskScoped, RemoteParentSocketContext context) {
    int start = ((int) Thread.currentThread().getId()) & (BUFFER_POOL_SIZE - 1);
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
      int slot = (start + i) & (BUFFER_POOL_SIZE - 1);
      byte[] response = buffers.getAndSet(slot, null);
      if (response == null) {
        continue;
      }
      try {
        int status = callNative(take, taskScoped, context, response);
        RemoteParentRecord record = recordFromNativeResponse(status, response);
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

  private int callNative(
      boolean take, boolean taskScoped, RemoteParentSocketContext context, byte[] response) {
    RemoteParentSocketContext.Lookup lookup = null;
    try {
      if (context != null) {
        lookup = context.takeForRemoteParentLookup();
        if (lookup == null) {
          return RemoteParentStatus.MISSING;
        }
      }
      int status =
          socketCaller.call(
              take,
              taskScoped,
              usesPrimarySocketLookup() && lookup != null ? lookup.socketFileDescriptor() : -1,
              response);
      if (take && status == RemoteParentStatus.MISSING) {
        RemoteParentDiagnostics.transportMissing();
      }
      return status;
    } finally {
      if (lookup != null) {
        lookup.close();
      }
    }
  }

  private boolean usesPrimarySocketLookup() {
    return RemoteParentTransportConfiguration.selected(transportConfiguration)
        == RemoteParentTransport.GETSOCKOPT;
  }

  private static int callNative(
      boolean take, boolean taskScoped, int socketFileDescriptor, byte[] response) {
    if (taskScoped) {
      return take
          ? BootstrapNative.takeRemoteParentTask(socketFileDescriptor, response)
          : BootstrapNative.discardRemoteParentTask(socketFileDescriptor, response);
    }
    return take
        ? BootstrapNative.takeRemoteParent(socketFileDescriptor, response)
        : BootstrapNative.discardRemoteParent(socketFileDescriptor, response);
  }

  static RemoteParentRecord recordFromNativeResponse(int status, byte[] response) {
    if (!RemoteParentStatus.isKnown(status) || status == RemoteParentStatus.UNKNOWN) {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MALFORMED);
    }
    if (status != RemoteParentStatus.VALID) {
      return RemoteParentRecord.statusOnly(status);
    }

    RemoteParentRecord record = RemoteParentRecord.decode(response);
    return record.getStatus() == RemoteParentStatus.VALID
        ? record
        : RemoteParentRecord.statusOnly(RemoteParentStatus.MALFORMED);
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
        logInfo("OBI remote-parent provider ready");
        return true;
      }
      return false;
    }
  }

  private int configureTransport() {
    long configuration;
    try {
      if (isEnabled() && !processRegistrar.register()) {
        configuration =
            RemoteParentTransportConfiguration.failure(transport, RemoteParentStatus.UNAUTHORIZED);
      } else {
        configuration =
            transportConfigurer.configure(
                transport,
                unixSocketPath,
                timeoutMillis,
                serverUid,
                ThreadInfo.processIncarnation());
      }
    } catch (Throwable ignored) {
      configuration =
          RemoteParentTransportConfiguration.failure(transport, RemoteParentStatus.TRANSPORT_ERROR);
    }
    configuration = RemoteParentTransportConfiguration.normalize(configuration, transport);
    int status = RemoteParentTransportConfiguration.status(configuration);
    if (isEnabled()) {
      RemoteParentDiagnostics.registration(status);
    }
    boolean changed = configuration != transportConfiguration;
    transportConfiguration = configuration;
    transportStatus = status;
    nextConfigurationAttemptNanos =
        status == RemoteParentStatus.VALID ? 0 : System.nanoTime() + RETRY_NANOS;
    if (changed) {
      logTransportConfiguration(configuration);
    }
    return status;
  }

  private static void logTransportConfiguration(long configuration) {
    logInfo(
        "OBI remote-parent transport configuration "
            + RemoteParentTransportConfiguration.snapshot(configuration));
  }

  private static void logInfo(String message) {
    try {
      logger.info(message);
    } catch (Throwable ignored) {
    }
  }

  private static long configureNativeTransport(
      int transport,
      String unixSocketPath,
      int timeoutMillis,
      long serverUid,
      long processIncarnation) {
    return configureNativeTransport(
        transport,
        () ->
            BootstrapNative.configureRemoteParentTransportV2(
                transport, unixSocketPath, timeoutMillis, serverUid, processIncarnation),
        () ->
            BootstrapNative.configureRemoteParentTransport(
                transport, unixSocketPath, timeoutMillis, serverUid, processIncarnation));
  }

  static long configureNativeTransport(
      int transport, LongSupplier versionTwoConfigurer, IntSupplier legacyConfigurer) {
    try {
      return versionTwoConfigurer.getAsLong();
    } catch (NoSuchMethodError | UnsatisfiedLinkError unavailable) {
      return RemoteParentTransportConfiguration.legacy(transport, legacyConfigurer.getAsInt());
    }
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
    long configure(
        int transport,
        String unixSocketPath,
        int timeoutMillis,
        long serverUid,
        long processIncarnation);
  }

  interface ProcessRegistrar {
    boolean register();
  }

  @FunctionalInterface
  interface SocketCaller {
    int call(boolean take, boolean taskScoped, int socketFileDescriptor, byte[] response);
  }
}
