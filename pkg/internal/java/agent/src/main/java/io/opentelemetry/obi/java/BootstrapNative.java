/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import io.opentelemetry.obi.java.bridge.RemoteParentBridge;
import io.opentelemetry.obi.java.bridge.RemoteParentStatus;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.net.Socket;
import java.util.function.BiFunction;
import java.util.function.LongBinaryOperator;
import java.util.function.ToIntFunction;
import javax.net.ssl.SSLEngine;

/** Bootstrap-safe JNI entry points used by instrumented JDK classes. */
public final class BootstrapNative {
  public static final int IOCTL_CMD = 0x0b10b1;
  private static boolean nativeLibraryLoaded;
  private static volatile LongBinaryOperator emitDataOnSocketForTest;
  private static volatile BiFunction<Integer, NativeMemory, Integer> emitTelemetryReceiveForTest;
  private static volatile ToIntFunction<Socket> socketFileDescriptorForTest;

  private BootstrapNative() {}

  public static native int ioctl(int fd, int cmd, long argp);

  public static native int gettid();

  public static native int socketFileDescriptor(Socket socket);

  public static int emitData(Socket socket, long argp, boolean receive) {
    long receiveBridgeEpoch = 0L;
    if (receive) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
      receiveBridgeEpoch = ThreadInfo.captureRemoteParentBridgeCapability();
    }
    Lifecycle lifecycle = asLifecycle(SSLStorage.prepareRemoteParentSocketLifecycle(socket));
    if (lifecycle == null) {
      failClosedSocketEmission(socket, receive);
      return -1;
    }

    Lifecycle.Lease lease = lifecycle.acquireLookupLease();
    if (lease == null) {
      if (receive) {
        ThreadInfo.clearRemoteParentSocketFileDescriptor();
        ThreadInfo.blockRemoteParentLookup();
      }
      return -1;
    }

    int socketFileDescriptor;
    int result;
    try {
      socketFileDescriptor = resolveSocketFileDescriptor(socket);
      result = socketFileDescriptor < 0 ? -1 : callEmitDataOnSocket(socketFileDescriptor, argp);
    } catch (Throwable failure) {
      lease.close();
      if (receive) {
        invalidateRemoteParentSocketFileDescriptor(socket, lifecycle);
      }
      throw failure;
    }
    lease.close();

    int emitted =
        finishEmitData(socketFileDescriptor, result, receive, lifecycle, receiveBridgeEpoch);
    if (receive && (result < 0 || !lifecycle.active())) {
      invalidateRemoteParentSocketFileDescriptor(socket, lifecycle);
    }
    return emitted;
  }

  public static int emitData(Connection connection, long argp, boolean receive) {
    long receiveBridgeEpoch = 0L;
    if (receive) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
      receiveBridgeEpoch = ThreadInfo.captureRemoteParentBridgeCapability();
    }
    return emitConnectionData(connection, argp, receive, receiveBridgeEpoch);
  }

  /** Emits using the eligibility captured by a caller before it selected a receive wire path. */
  public static int emitData(
      Connection connection, long argp, boolean receive, long receiveBridgeEpoch) {
    if (receive) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
    }
    return emitConnectionData(connection, argp, receive, receiveBridgeEpoch);
  }

  private static int emitConnectionData(
      Connection connection, long argp, boolean receive, long receiveBridgeEpoch) {
    Lifecycle lifecycle = asLifecycle(SSLStorage.remoteParentSocketLifecycle(connection));
    if (connection == null || lifecycle == null) {
      if (receive) {
        ThreadInfo.blockRemoteParentLookup();
        if (connection == null) {
          ThreadInfo.invalidateRemoteParentSocketFileDescriptor(null);
        } else {
          // A late engine callback must not retain a descriptor after its exact owner has closed.
          ThreadInfo.clearRemoteParentSocketFileDescriptor();
        }
      }
      return -1;
    }

    Lifecycle.Lease lease = lifecycle.acquireLookupLease();
    if (lease == null) {
      if (receive) {
        ThreadInfo.clearRemoteParentSocketFileDescriptor();
        ThreadInfo.blockRemoteParentLookup();
      }
      return -1;
    }

    int socketFileDescriptor = connection.getSocketFileDescriptor();
    int result;
    try {
      result = socketFileDescriptor < 0 ? -1 : callEmitDataOnSocket(socketFileDescriptor, argp);
    } catch (Throwable failure) {
      lease.close();
      finishEmitDataFailure(receive, lifecycle);
      throw failure;
    }
    lease.close();
    return finishEmitData(socketFileDescriptor, result, receive, lifecycle, receiveBridgeEpoch);
  }

  /** Emits one framed HTTP/1 receive operation without creating a generation on continuations. */
  public static int emitHttp1Data(
      Connection connection, long argp, OperationType operation, boolean primaryAcknowledged) {
    return emitHttp1Data(
        connection,
        argp,
        operation,
        primaryAcknowledged,
        ThreadInfo.captureRemoteParentBridgeCapability());
  }

  /** Emits framed HTTP/1 data under the exact provider epoch that authorized its wire identity. */
  public static int emitHttp1Data(
      Connection connection,
      long argp,
      OperationType operation,
      boolean primaryAcknowledged,
      long receiveBridgeEpoch) {
    if (operation == OperationType.HTTP1_RECEIVE_START) {
      return emitData(connection, argp, true, receiveBridgeEpoch);
    }
    if (operation != OperationType.HTTP1_RECEIVE_CONTINUE
        && operation != OperationType.HTTP1_RECEIVE_RESET) {
      throw new IllegalArgumentException("not an HTTP/1 receive operation: " + operation);
    }
    return emitReceiveDataWithoutAcknowledgement(
        connection, argp, operation, primaryAcknowledged, receiveBridgeEpoch);
  }

  /** Emits generic receive telemetry without negotiating or staging remote-parent authority. */
  public static int emitTelemetryReceiveData(Connection connection, long argp) {
    return emitReceiveDataWithoutAcknowledgement(
        connection, argp, OperationType.TELEMETRY_RECEIVE, false, 0L);
  }

  /**
   * Emits unsupported {@link Socket} plaintext as telemetry without granting bridge authority.
   *
   * <p>The exact lifecycle captured before the application read fences descriptor reuse for every
   * fragment. Unlike the legacy receive operation, telemetry never stages a parent or retains a
   * descriptor. The callback is split at the fixed wire ceiling without overlap or loss.
   */
  public static int emitTelemetryReceiveData(
      Socket socket, Object expectedLifecycle, byte[] plaintext, int offset, int length) {
    if (plaintext == null) {
      throw new NullPointerException("plaintext");
    }
    if (offset < 0 || length <= 0 || offset > plaintext.length - length) {
      throw new IndexOutOfBoundsException("invalid plaintext range");
    }

    ThreadInfo.beginRemoteParentReceiveAttempt();
    long bridgeEpoch = ThreadInfo.remoteParentBridgeEpoch();
    boolean recordUnsupported = ThreadInfo.isRemoteParentEnabled();
    Lifecycle lifecycle = asLifecycle(expectedLifecycle);
    Lifecycle.Lease lease = null;
    boolean terminalFailure = false;
    try {
      if (socket == null
          || lifecycle == null
          || SSLStorage.currentRemoteParentSocketLifecycle(socket) != lifecycle) {
        return -1;
      }
      lease = lifecycle.acquireLookupLease();
      if (lease == null) {
        return -1;
      }

      int socketFileDescriptor = resolveSocketFileDescriptor(socket);
      if (socketFileDescriptor < 0) {
        terminalFailure = true;
        return -1;
      }

      int sourceOffset = offset;
      int remaining = length;
      int result = 0;
      while (remaining > 0) {
        int fragmentLength = Math.min(remaining, IOCTLPacket.http1MaxPayloadSize);
        NativeMemory packet = new NativeMemory(IOCTLPacket.packetPrefixSize + fragmentLength);
        int writeOffset =
            IOCTLPacket.writeTelemetryReceivePacketPrefix(packet, 0, socket, fragmentLength);
        IOCTLPacket.writePacketBuffer(packet, writeOffset, plaintext, sourceOffset, fragmentLength);
        BiFunction<Integer, NativeMemory, Integer> testEmitter = emitTelemetryReceiveForTest;
        int status =
            testEmitter == null
                ? callEmitDataOnSocket(socketFileDescriptor, packet.getAddress())
                : testEmitter.apply(socketFileDescriptor, packet);
        if (status < 0) {
          terminalFailure = true;
          return status;
        }
        result = Math.max(result, status);
        sourceOffset += fragmentLength;
        remaining -= fragmentLength;
      }
      return result;
    } catch (Throwable failure) {
      terminalFailure = true;
      throw failure;
    } finally {
      if (lease != null) {
        lease.close();
      }
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.blockRemoteParentLookup();
      if (terminalFailure && lifecycle != null) {
        invalidateRemoteParentSocketFileDescriptor(socket, lifecycle);
      }
      if (recordUnsupported
          || ThreadInfo.isRemoteParentEnabled()
          || !ThreadInfo.isCurrentRemoteParentBridgeEpoch(bridgeEpoch)) {
        try {
          RemoteParentBridge.recordReceiveFailure(RemoteParentStatus.UNSUPPORTED);
        } catch (Throwable ignored) {
        }
      }
    }
  }

  private static int emitReceiveDataWithoutAcknowledgement(
      Connection connection,
      long argp,
      OperationType operation,
      boolean primaryAcknowledged,
      long receiveBridgeEpoch) {
    ThreadInfo.beginRemoteParentReceiveAttempt();
    Lifecycle lifecycle = asLifecycle(SSLStorage.remoteParentSocketLifecycle(connection));
    if (connection == null || lifecycle == null) {
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.blockRemoteParentLookup();
      return -1;
    }

    Lifecycle.Lease lease = lifecycle.acquireLookupLease();
    if (lease == null) {
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.blockRemoteParentLookup();
      return -1;
    }

    int socketFileDescriptor = connection.getSocketFileDescriptor();
    int result;
    try {
      result = socketFileDescriptor < 0 ? -1 : callEmitDataOnSocket(socketFileDescriptor, argp);
    } catch (Throwable failure) {
      lease.close();
      ThreadInfo.invalidateRemoteParentSocketFileDescriptor(lifecycle);
      throw failure;
    }
    lease.close();

    if (result < 0 || !lifecycle.active()) {
      ThreadInfo.invalidateRemoteParentSocketFileDescriptor(lifecycle);
      return result < 0 ? result : -1;
    }
    if (operation == OperationType.HTTP1_RECEIVE_RESET
        || operation == OperationType.TELEMETRY_RECEIVE) {
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.blockRemoteParentLookup();
      return result;
    }

    if (!ThreadInfo.markRemoteParentDirectLookupIfCurrent(lifecycle, receiveBridgeEpoch)) {
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.blockRemoteParentLookup();
      return result;
    }
    if (!primaryAcknowledged) {
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      return result;
    }
    if (!ThreadInfo.setRemoteParentSocketFileDescriptor(socketFileDescriptor, lifecycle)) {
      ThreadInfo.invalidateRemoteParentSocketFileDescriptor(lifecycle);
      return -1;
    }
    if (!ThreadInfo.isCurrentRemoteParentBridgeCapability(receiveBridgeEpoch)) {
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.blockRemoteParentLookup();
    }
    return result;
  }

  public static int emitData(int socketFileDescriptor, long argp, boolean receive) {
    long receiveBridgeEpoch = 0L;
    if (receive) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
      receiveBridgeEpoch = ThreadInfo.captureRemoteParentBridgeCapability();
    }
    return emitDataWithoutLease(socketFileDescriptor, argp, receive, null, receiveBridgeEpoch);
  }

  private static int emitDataWithoutLease(
      int socketFileDescriptor,
      long argp,
      boolean receive,
      Object lifecycle,
      long receiveBridgeEpoch) {
    try {
      int result = socketFileDescriptor < 0 ? -1 : callEmitDataOnSocket(socketFileDescriptor, argp);
      return finishEmitData(socketFileDescriptor, result, receive, lifecycle, receiveBridgeEpoch);
    } catch (Throwable failure) {
      finishEmitDataFailure(receive, lifecycle);
      throw failure;
    }
  }

  private static int callEmitDataOnSocket(int socketFileDescriptor, long argp) {
    LongBinaryOperator testEmitter = emitDataOnSocketForTest;
    return testEmitter == null
        ? emitDataOnSocket(socketFileDescriptor, argp)
        : (int) testEmitter.applyAsLong(socketFileDescriptor, argp);
  }

  private static int resolveSocketFileDescriptor(Socket socket) {
    ToIntFunction<Socket> testResolver = socketFileDescriptorForTest;
    return testResolver == null ? socketFileDescriptor(socket) : testResolver.applyAsInt(socket);
  }

  private static int finishEmitData(
      int socketFileDescriptor,
      int result,
      boolean receive,
      Object lifecycle,
      long receiveBridgeEpoch) {
    boolean keepSocketFileDescriptor = false;
    boolean authorityEstablished = false;
    boolean terminalFailure = false;
    try {
      if (socketFileDescriptor < 0) {
        terminalFailure = receive;
        return -1;
      }
      if (receive && result >= 0) {
        authorityEstablished =
            ThreadInfo.markRemoteParentDirectLookupIfCurrent(lifecycle, receiveBridgeEpoch);
      }
      if (receive && result == 1 && authorityEstablished) {
        if (lifecycle instanceof Lifecycle) {
          keepSocketFileDescriptor =
              ThreadInfo.setRemoteParentSocketFileDescriptor(
                  socketFileDescriptor, (Lifecycle) lifecycle);
        } else {
          // Retain the established raw-descriptor API for callers that cannot supply a concrete
          // socket/connection identity, such as the primary remote-parent probe.
          ThreadInfo.setRemoteParentSocketFileDescriptor(socketFileDescriptor);
          keepSocketFileDescriptor = true;
        }
        terminalFailure = !keepSocketFileDescriptor;
      } else if (receive && result < 0) {
        terminalFailure = true;
      }
      if (keepSocketFileDescriptor
          && !ThreadInfo.isCurrentRemoteParentBridgeCapability(receiveBridgeEpoch)) {
        keepSocketFileDescriptor = false;
        authorityEstablished = false;
      }
      return result;
    } catch (Throwable failure) {
      terminalFailure = receive;
      throw failure;
    } finally {
      if (receive && !keepSocketFileDescriptor) {
        if (terminalFailure) {
          ThreadInfo.invalidateRemoteParentSocketFileDescriptor(lifecycle);
        } else {
          ThreadInfo.clearRemoteParentSocketFileDescriptor();
        }
        if (!authorityEstablished
            || !ThreadInfo.isCurrentRemoteParentBridgeCapability(receiveBridgeEpoch)) {
          ThreadInfo.blockRemoteParentLookup();
        }
      }
    }
  }

  private static void finishEmitDataFailure(boolean receive, Object lifecycle) {
    if (receive) {
      ThreadInfo.blockRemoteParentLookup();
      ThreadInfo.invalidateRemoteParentSocketFileDescriptor(lifecycle);
    }
  }

  private static Lifecycle asLifecycle(Object lifecycle) {
    return lifecycle instanceof Lifecycle ? (Lifecycle) lifecycle : null;
  }

  private static void failClosedSocketEmission(Socket socket, boolean receive) {
    if (!receive) {
      return;
    }
    ThreadInfo.blockRemoteParentLookup();
    if (socket == null) {
      ThreadInfo.invalidateRemoteParentSocketFileDescriptor(null);
    } else if (socket.isClosed()) {
      // A closed socket cannot safely use a later generation. Invalidate the current mapping
      // so any queued task aliases of an older receive fail closed as well.
      invalidateRemoteParentSocketFileDescriptor(socket);
    } else {
      // A live tombstone, map-capacity failure, or delayed null snapshot must only detach this
      // thread: revoking an unknown lifecycle here could clobber a newer valid generation.
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
    }
  }

  /** Clears a receive-side descriptor that can no longer be tied to a request. */
  public static void clearRemoteParentSocketFileDescriptor() {
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
  }

  /** Invalidates a terminal receive lifecycle, including queued task aliases. */
  public static void invalidateRemoteParentSocketFileDescriptor(Object lifecycle) {
    ThreadInfo.invalidateRemoteParentSocketFileDescriptor(lifecycle);
  }

  /** Invalidates a terminal SSL socket lifecycle without relying on its numeric descriptor. */
  public static void invalidateRemoteParentSocketFileDescriptor(Socket socket) {
    invalidateRemoteParentSocketFileDescriptor(
        socket, SSLStorage.currentRemoteParentSocketLifecycle(socket));
  }

  /**
   * Invalidates the exact lifecycle observed at read entry, preventing a late callback from
   * revoking a fresh retry lifecycle for the same socket object.
   */
  public static void invalidateRemoteParentSocketFileDescriptor(Socket socket, Object lifecycle) {
    if (socket == null) {
      ThreadInfo.invalidateRemoteParentSocketFileDescriptor(lifecycle);
      return;
    }
    if (!(lifecycle instanceof Lifecycle)) {
      // A terminal callback with no captured socket generation must not revoke a generation
      // created after it entered. It can still leave an unrelated descriptor staged on this
      // thread, so detach that local state.
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.blockRemoteParentLookup();
      return;
    }
    Object invalidated = SSLStorage.invalidateRemoteParentSocketLifecycle(socket, lifecycle);
    if (invalidated != null) {
      ThreadInfo.invalidateRemoteParentSocketFileDescriptor(invalidated);
    }
  }

  /** Marks a socket closing while retaining an inactive tombstone until close returns. */
  public static Object beginRemoteParentSocketClose(Socket socket) {
    Object lifecycle = SSLStorage.beginRemoteParentSocketClose(socket);
    if (lifecycle != null) {
      ThreadInfo.invalidateRemoteParentSocketFileDescriptor(lifecycle);
    } else if (socket == null) {
      ThreadInfo.invalidateRemoteParentSocketFileDescriptor(null);
    } else {
      // A live socket that could not obtain a tombstone (for example because the capped weak map
      // is full) must not block close or revoke an unknown generation. Detach only this thread.
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.blockRemoteParentLookup();
    }
    return lifecycle;
  }

  /** Releases a temporary close tombstone after the socket close method returns. */
  public static void finishRemoteParentSocketClose(Socket socket, Object lifecycle) {
    SSLStorage.finishRemoteParentSocketClose(socket, lifecycle);
  }

  /** Captures an existing socket lifecycle for a later terminal read callback. */
  public static Object currentRemoteParentSocketLifecycle(Socket socket) {
    return SSLStorage.currentRemoteParentSocketLifecycle(socket);
  }

  /** Captures or creates the exact live socket lifecycle before an application read. */
  public static Object prepareRemoteParentSocketLifecycle(Socket socket) {
    return SSLStorage.prepareRemoteParentSocketLifecycle(socket);
  }

  public static void markTlsConnection(Connection connection) {
    if (connection == null || connection.getSocketFileDescriptor() < 0) {
      return;
    }
    Lifecycle lifecycle = asLifecycle(SSLStorage.remoteParentSocketLifecycle(connection));
    if (lifecycle == null) {
      return;
    }
    Lifecycle.Lease lease = lifecycle.acquireLookupLease();
    if (lease == null) {
      return;
    }
    try {
      NativeMemory packet = new NativeMemory(IOCTLPacket.tlsConnectionMarkerSize);
      IOCTLPacket.writeTlsConnectionMarker(packet, 0, connection);
      ioctl(connection.getSocketFileDescriptor(), IOCTL_CMD, packet.getAddress());
    } finally {
      lease.close();
    }
  }

  public static void markTlsConnectionIfDue(SSLEngine engine, Connection connection) {
    if (!ThreadInfo.isRemoteParentEnabled()) {
      return;
    }
    long processIncarnation = ThreadInfo.processIncarnation();
    if (!SSLStorage.claimTlsConnectionMarkerAttempt(engine, connection, processIncarnation)) {
      return;
    }
    markTlsConnection(connection);
  }

  private static native int emitDataOnSocket(int socketFileDescriptor, long argp);

  public static native int emitVirtualThreadOp(byte operation, long value);

  public static native int emitTaskContextOp(byte operation, long value, long token);

  public static native int configureRemoteParentTransport(
      int transport,
      String unixSocketPath,
      int timeoutMillis,
      long serverUid,
      long processIncarnation);

  public static native long configureRemoteParentTransportV2(
      int transport,
      String unixSocketPath,
      int timeoutMillis,
      long serverUid,
      long processIncarnation);

  public static native int takeRemoteParent(int socketFileDescriptor, byte[] response);

  public static native int discardRemoteParent(int socketFileDescriptor, byte[] response);

  public static native int takeRemoteParentTask(int socketFileDescriptor, byte[] response);

  public static native int discardRemoteParentTask(int socketFileDescriptor, byte[] response);

  public static native void closeRemoteParentTransport();

  static synchronized void loadNativeLibrary(String path) {
    if (nativeLibraryLoaded) {
      return;
    }
    System.load(path);
    nativeLibraryLoaded = true;
  }

  static synchronized boolean isNativeLibraryLoaded() {
    return nativeLibraryLoaded;
  }

  static void setEmitDataOnSocketForTest(LongBinaryOperator emitter) {
    emitDataOnSocketForTest = emitter;
  }

  static void setEmitTelemetryReceiveForTest(BiFunction<Integer, NativeMemory, Integer> emitter) {
    emitTelemetryReceiveForTest = emitter;
  }

  static void setSocketFileDescriptorForTest(ToIntFunction<Socket> resolver) {
    socketFileDescriptorForTest = resolver;
  }
}
