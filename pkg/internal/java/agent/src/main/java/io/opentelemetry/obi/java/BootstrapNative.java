/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.net.Socket;
import java.util.function.LongBinaryOperator;
import javax.net.ssl.SSLEngine;

/** Bootstrap-safe JNI entry points used by instrumented JDK classes. */
public final class BootstrapNative {
  public static final int IOCTL_CMD = 0x0b10b1;
  private static boolean nativeLibraryLoaded;
  private static volatile LongBinaryOperator emitDataOnSocketForTest;

  private BootstrapNative() {}

  public static native int ioctl(int fd, int cmd, long argp);

  public static native int gettid();

  public static native int socketFileDescriptor(Socket socket);

  public static int emitData(Socket socket, long argp, boolean receive) {
    if (receive) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
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
      socketFileDescriptor = socketFileDescriptor(socket);
      result = socketFileDescriptor < 0 ? -1 : callEmitDataOnSocket(socketFileDescriptor, argp);
    } catch (Throwable failure) {
      lease.close();
      if (receive) {
        invalidateRemoteParentSocketFileDescriptor(socket, lifecycle);
      }
      throw failure;
    }
    lease.close();

    int emitted = finishEmitData(socketFileDescriptor, result, receive, lifecycle);
    if (receive && (result < 0 || !lifecycle.active())) {
      invalidateRemoteParentSocketFileDescriptor(socket, lifecycle);
    }
    return emitted;
  }

  public static int emitData(Connection connection, long argp, boolean receive) {
    if (receive) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
    }
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
    return finishEmitData(socketFileDescriptor, result, receive, lifecycle);
  }

  public static int emitData(int socketFileDescriptor, long argp, boolean receive) {
    if (receive) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
    }
    return emitDataWithoutLease(socketFileDescriptor, argp, receive, null);
  }

  private static int emitDataWithoutLease(
      int socketFileDescriptor, long argp, boolean receive, Object lifecycle) {
    try {
      int result = socketFileDescriptor < 0 ? -1 : callEmitDataOnSocket(socketFileDescriptor, argp);
      return finishEmitData(socketFileDescriptor, result, receive, lifecycle);
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

  private static int finishEmitData(
      int socketFileDescriptor, int result, boolean receive, Object lifecycle) {
    boolean keepSocketFileDescriptor = false;
    boolean terminalFailure = false;
    try {
      if (socketFileDescriptor < 0) {
        terminalFailure = receive;
        return -1;
      }
      if (receive && result >= 0) {
        ThreadInfo.markRemoteParentDirectLookup(lifecycle);
      }
      if (receive && result == 1) {
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
}
