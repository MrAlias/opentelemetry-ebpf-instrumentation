/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

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
  private static volatile ToIntFunction<Socket> directSocketFileDescriptorForTest;

  private BootstrapNative() {}

  public static native int ioctl(int fd, int cmd, long argp);

  public static native int gettid();

  public static native int socketFileDescriptor(Socket socket);

  /** Returns a descriptor only when a JSSE socket directly owns its physical transport. */
  public static native int directSocketFileDescriptor(Socket socket);

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
   * Checks whether an exact socket generation directly owns the descriptor fenced by its close
   * advice. Layered JSSE sockets are deliberately rejected because their caller-owned underlying
   * {@link Socket} can close and reuse the descriptor outside this lifecycle.
   */
  public static boolean isDirectRemoteParentSocket(Socket socket, Object expectedLifecycle) {
    Lifecycle lifecycle = exactSocketLifecycle(socket, expectedLifecycle);
    if (lifecycle == null) {
      return false;
    }
    Lifecycle.Lease lease = lifecycle.acquireLookupLease();
    if (lease == null) {
      return false;
    }
    try {
      return resolveDirectSocketFileDescriptor(socket) >= 0;
    } finally {
      lease.close();
    }
  }

  /** Frames application-visible plaintext only for an exact, directly owned JSSE socket. */
  public static int emitRemoteParentSocketReceive(
      Socket socket, Object expectedLifecycle, byte[] plaintext, int offset, int length) {
    if (!isDirectRemoteParentSocket(socket, expectedLifecycle)) {
      rejectUnsupportedRemoteParentSocket(socket, expectedLifecycle);
      return -1;
    }
    return SSLStorage.emitRemoteParentSocketReceive(
        socket, expectedLifecycle, plaintext, offset, length);
  }

  /** Emits one framed HTTP/1 operation for an exact direct-JSSE socket generation. */
  public static int emitHttp1Data(
      Socket socket,
      Object expectedLifecycle,
      long argp,
      OperationType operation,
      boolean primaryAcknowledged,
      long receiveBridgeEpoch) {
    if (operation == OperationType.HTTP1_RECEIVE_START) {
      return emitDirectSocketData(socket, expectedLifecycle, argp, true, receiveBridgeEpoch);
    }
    if (operation != OperationType.HTTP1_RECEIVE_CONTINUE
        && operation != OperationType.HTTP1_RECEIVE_RESET) {
      throw new IllegalArgumentException("not an HTTP/1 receive operation: " + operation);
    }
    return emitDirectSocketDataWithoutAcknowledgement(
        socket, expectedLifecycle, argp, operation, primaryAcknowledged, receiveBridgeEpoch);
  }

  /** Emits direct-socket telemetry without negotiating or retaining parent authority. */
  public static int emitTelemetryReceiveData(Socket socket, Object expectedLifecycle, long argp) {
    return emitDirectSocketDataWithoutAcknowledgement(
        socket, expectedLifecycle, argp, OperationType.TELEMETRY_RECEIVE, false, 0L);
  }

  /**
   * Emits directly owned {@link Socket} plaintext as telemetry without granting bridge authority.
   *
   * <p>A layered JSSE socket is rejected because its outer lifecycle cannot fence the caller-owned
   * raw socket against close and descriptor reuse. Direct telemetry is split at the fixed wire
   * ceiling without overlap or loss and never stages a parent or retains a descriptor.
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

      int socketFileDescriptor = resolveDirectSocketFileDescriptor(socket);
      if (socketFileDescriptor < 0) {
        // Unsupported layered/custom ownership is nonterminal for the outer lifecycle. Retain it
        // so diagnostics stay bounded and later callbacks continue to fail closed without ever
        // resolving or emitting through the caller-owned raw descriptor.
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
      if (recordUnsupported
          || ThreadInfo.isRemoteParentEnabled()
          || !ThreadInfo.isCurrentRemoteParentBridgeEpoch(bridgeEpoch)) {
        try {
          SSLStorage.recordUnsupportedSocketReceive(socket, lifecycle);
        } catch (Throwable ignored) {
        }
      }
      if (terminalFailure && lifecycle != null) {
        invalidateRemoteParentSocketFileDescriptor(socket, lifecycle);
      }
    }
  }

  /** Rejects plaintext whose physical socket owner is not fenced by the supplied lifecycle. */
  public static void rejectUnsupportedRemoteParentSocket(Socket socket, Object expectedLifecycle) {
    ThreadInfo.beginRemoteParentReceiveAttempt();
    long bridgeEpoch = ThreadInfo.remoteParentBridgeEpoch();
    boolean recordUnsupported = ThreadInfo.isRemoteParentEnabled();
    Lifecycle lifecycle = exactSocketLifecycle(socket, expectedLifecycle);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    ThreadInfo.blockRemoteParentLookup();
    if (lifecycle == null) {
      return;
    }
    if (recordUnsupported
        || ThreadInfo.isRemoteParentEnabled()
        || !ThreadInfo.isCurrentRemoteParentBridgeEpoch(bridgeEpoch)) {
      try {
        SSLStorage.recordUnsupportedSocketReceive(socket, lifecycle);
      } catch (Throwable ignored) {
      }
    }
  }

  private static int emitDirectSocketData(
      Socket socket,
      Object expectedLifecycle,
      long argp,
      boolean receive,
      long receiveBridgeEpoch) {
    if (receive) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
    }
    Lifecycle lifecycle = exactSocketLifecycle(socket, expectedLifecycle);
    if (lifecycle == null) {
      finishEmitDataFailure(receive, expectedLifecycle);
      return -1;
    }
    Lifecycle.Lease lease = lifecycle.acquireLookupLease();
    if (lease == null) {
      finishEmitDataFailure(receive, lifecycle);
      return -1;
    }
    int socketFileDescriptor;
    int result;
    try {
      socketFileDescriptor = resolveDirectSocketFileDescriptor(socket);
      result = socketFileDescriptor < 0 ? -1 : callEmitDataOnSocket(socketFileDescriptor, argp);
    } catch (Throwable failure) {
      lease.close();
      finishEmitDataFailure(receive, lifecycle);
      throw failure;
    }
    lease.close();
    return finishEmitData(socketFileDescriptor, result, receive, lifecycle, receiveBridgeEpoch);
  }

  private static int emitDirectSocketDataWithoutAcknowledgement(
      Socket socket,
      Object expectedLifecycle,
      long argp,
      OperationType operation,
      boolean primaryAcknowledged,
      long receiveBridgeEpoch) {
    ThreadInfo.beginRemoteParentReceiveAttempt();
    Lifecycle lifecycle = exactSocketLifecycle(socket, expectedLifecycle);
    if (lifecycle == null) {
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
    int socketFileDescriptor;
    int result;
    try {
      socketFileDescriptor = resolveDirectSocketFileDescriptor(socket);
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

  private static int resolveDirectSocketFileDescriptor(Socket socket) {
    ToIntFunction<Socket> testResolver = directSocketFileDescriptorForTest;
    return testResolver == null
        ? directSocketFileDescriptor(socket)
        : testResolver.applyAsInt(socket);
  }

  private static Lifecycle exactSocketLifecycle(Socket socket, Object expectedLifecycle) {
    Lifecycle lifecycle = asLifecycle(expectedLifecycle);
    return socket != null
            && lifecycle != null
            && SSLStorage.currentRemoteParentSocketLifecycle(socket) == lifecycle
        ? lifecycle
        : null;
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

  /** Enters a socket read and captures its exact lifecycle before application I/O. */
  public static Object beginRemoteParentSocketRead(Socket socket) {
    Object scope = SSLStorage.beginRemoteParentSocketRead();
    try {
      return new Object[] {scope, SSLStorage.prepareRemoteParentSocketLifecycle(socket)};
    } catch (Throwable failure) {
      SSLStorage.endRemoteParentSocketRead(scope);
      throw failure;
    }
  }

  /** Returns the exact lifecycle captured by {@link #beginRemoteParentSocketRead(Socket)}. */
  public static Object remoteParentSocketReadLifecycle(Object readState) {
    if (!(readState instanceof Object[])) {
      return null;
    }
    Object[] state = (Object[]) readState;
    return state.length == 2 ? state[1] : null;
  }

  /** Claims a read only when it is the application-visible outermost callback. */
  public static boolean claimRemoteParentSocketRead(
      Object readState, Socket socket, Object lifecycle) {
    if (!(readState instanceof Object[])) {
      return false;
    }
    Object[] state = (Object[]) readState;
    return state.length == 2 && SSLStorage.claimRemoteParentSocketRead(state[0], socket, lifecycle);
  }

  /** Poisons any successful inner owner before an enclosing read reports failure or EOF. */
  public static void abortRemoteParentSocketRead(Object readState) {
    if (!(readState instanceof Object[])) {
      return;
    }
    Object[] state = (Object[]) readState;
    if (state.length == 2) {
      SSLStorage.abortRemoteParentSocketRead(state[0]);
    }
  }

  /** Balances {@link #beginRemoteParentSocketRead(Socket)} on every read exit. */
  public static void endRemoteParentSocketRead(Object readState) {
    if (!(readState instanceof Object[])) {
      return;
    }
    Object[] state = (Object[]) readState;
    if (state.length == 2) {
      SSLStorage.endRemoteParentSocketRead(state[0]);
    }
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
   * Poisons the exact lifecycle observed at read entry, preventing a late callback from revoking a
   * different lifecycle and preventing a later read from resuming mid-request with a fresh framer.
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
    Object poisoned = SSLStorage.poisonRemoteParentSocketLifecycle(socket, lifecycle);
    ThreadInfo.invalidateRemoteParentSocketFileDescriptor(poisoned == null ? lifecycle : poisoned);
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

  static void setDirectSocketFileDescriptorForTest(ToIntFunction<Socket> resolver) {
    directSocketFileDescriptorForTest = resolver;
  }
}
