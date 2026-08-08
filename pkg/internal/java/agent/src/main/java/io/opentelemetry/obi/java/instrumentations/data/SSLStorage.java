/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.bridge.RemoteParentBridge;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.util.CappedConcurrentHashMap;
import io.opentelemetry.obi.java.instrumentations.util.NettyChannelExtractor;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.IdentityHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;

public class SSLStorage {
  public static final int SUBMISSION_NESTED = 0;
  public static final int SUBMISSION_OWNER = 1;
  public static final int REJECTION_NONE = 0;
  public static final int REJECTION_CLEAN_TASK = 1;
  public static final int REJECTION_DISCARD_OLDEST = 2;
  public static Method bootExtractMethod = null;
  public static Field bootNettyConnectionField = null;

  public static boolean debugOn = false;

  public static Field bootDebugOn = null;

  private static volatile boolean bootExtractMethodLookupComplete;
  private static volatile boolean bootNettyConnectionFieldLookupComplete;
  private static volatile boolean bootDebugOnLookupComplete;
  private static final AtomicBoolean nettyFailureLogged = new AtomicBoolean();

  static final int MAX_CONCURRENT = 10_000;
  private static final int CHANNEL_LIFECYCLE_LOCK_STRIPES = 64;
  private static final int CHANNEL_LIFECYCLE_LOCK_MASK = CHANNEL_LIFECYCLE_LOCK_STRIPES - 1;
  private static final String NETTY_ABSTRACT_CHANNEL_CLASS_NAME =
      "io.netty.channel.AbstractChannel";
  static final int TLS_CONNECTION_MARKER_BURST_ATTEMPTS = 8;
  static final long TLS_CONNECTION_MARKER_RETRY_NANOS = 1_000_000_000L;
  private static final WeakIdentityConcurrentMap<ConnectionOwner> sslConnections =
      new WeakIdentityConcurrentMap<>(MAX_CONCURRENT);
  private static final WeakIdentityConcurrentMap<TlsConnectionMarkerAttempt> tlsConnectionMarkers =
      new WeakIdentityConcurrentMap<>(MAX_CONCURRENT);
  private static final CappedConcurrentHashMap<String, BytesWithLen> bufToBuf =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);

  private static final int BUFFER_HANDOFF_AVAILABLE = 0;
  static final int BUFFER_HANDOFF_CLAIMING = 1;
  private static final int BUFFER_HANDOFF_CONSUMED = 2;
  private static final int BUFFER_HANDOFF_AMBIGUOUS = 3;
  private static final WeakIdentityConcurrentMap<BufferHandoff> readBufferConnections =
      new WeakIdentityConcurrentMap<>(MAX_CONCURRENT);
  private static final WeakIdentityConcurrentMap<ChannelState> channelStates =
      new WeakIdentityConcurrentMap<>(MAX_CONCURRENT);
  private static final WeakIdentityConcurrentMap<Object> nettyCloseHookLoaders =
      new WeakIdentityConcurrentMap<>(MAX_CONCURRENT);
  private static final WeakIdentityConcurrentMap<SocketOwner> socketRemoteParentOwners =
      new WeakIdentityConcurrentMap<>(MAX_CONCURRENT);
  private static final CappedConcurrentHashMap<ExactConnection, ConnectionOwner> activeConnections =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT, new ActiveConnectionEvictionListener());

  private static final WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(MAX_CONCURRENT);
  private static final ThreadLocal<IdentityHashMap<Object, Integer>> activeTaskSubmissions =
      new ThreadLocal<>();
  private static final ThreadLocal<ArrayDeque<Object>> discardOldestQueues = new ThreadLocal<>();
  private static final ThreadLocal<Integer> executorHookDepth = new ThreadLocal<>();
  private static final ThreadLocal<ArrayDeque<Boolean>> executorTaskScopes = new ThreadLocal<>();
  private static final ThreadLocal<Boolean> virtualThreadTaskScope = new ThreadLocal<>();
  private static final ThreadLocal<Integer> remoteParentUnwrapDepth = new ThreadLocal<>();
  private static final ThreadLocal<Object[]> remoteParentSocketReadScope = new ThreadLocal<>();
  private static volatile LongSupplier threadIdProviderForTest;
  private static volatile LongSupplier tlsConnectionMarkerClockForTest;
  private static volatile Runnable beforeLegacyReceiveEmitForTest;
  private static final Object NO_NETTY_CONNECTION = new Object();
  private static final Object NETTY_CLOSE_HOOK_AVAILABLE = new Object();
  private static final AtomicBoolean channelStateCapacityExhausted = new AtomicBoolean();
  private static final AtomicBoolean channelStateCapacityLogged = new AtomicBoolean();
  private static final AtomicBoolean bootstrapNettyCloseHookAvailable = new AtomicBoolean();
  // Agent-owned locks avoid taking monitors held by application or JDK socket code.
  private static final Object[] channelLifecycleLocks = channelLifecycleLocks();
  private static final ThreadLocal<ArrayDeque<Object>> nettyConnectionScopes = new ThreadLocal<>();
  private static final ThreadLocal<ArrayDeque<NettyHandlerScope>> nettyHandlerScopes =
      new ThreadLocal<>();

  public static final ThreadLocal<BytesWithLen> unencrypted = new ThreadLocal<>();

  public static final ThreadLocal<Object> nettyConnection = new ThreadLocal<>();

  public static void beginNettyConnectionScope() {
    ArrayDeque<Object> scopes = nettyConnectionScopes.get();
    boolean nested = scopes != null;
    if (scopes == null) {
      scopes = new ArrayDeque<>();
      nettyConnectionScopes.set(scopes);
    }
    Object previous = nested ? nettyConnection.get() : null;
    scopes.push(previous == null ? NO_NETTY_CONNECTION : previous);
    nettyConnection.remove();
  }

  public static void endNettyConnectionScope() {
    ArrayDeque<Object> scopes = nettyConnectionScopes.get();
    if (scopes == null || scopes.isEmpty()) {
      return;
    }
    Object previous = scopes.pop();
    nettyConnection.remove();
    if (previous != NO_NETTY_CONNECTION) {
      nettyConnection.set(previous);
    }
    if (scopes.isEmpty()) {
      nettyConnectionScopes.remove();
    }
  }

  public static void beginNettyHandlerScope(Object context) {
    // Retained for already transformed callers. Unknown direction cannot authorize a receive-side
    // task capture and therefore enters a non-receive scope.
    beginNettyHandlerScope(context, false);
  }

  public static void beginNettyHandlerScope(Object context, boolean receiving) {
    try {
      NettyHandlerScope scope = new NettyHandlerScope();
      ArrayDeque<NettyHandlerScope> scopes = nettyHandlerScopes.get();
      if (scopes == null) {
        scopes = new ArrayDeque<>();
        nettyHandlerScopes.set(scopes);
      }
      scopes.push(scope);
      beginNettyConnectionScope();
      scope.started = true;
      if (receiving) {
        ThreadInfo.beginRemoteParentReceiveScope();
        scope.receiving = true;
      }
    } catch (Throwable failure) {
      logNettyHandlerScopeFailure("begin Netty SSL handler scope", failure);
      return;
    }

    try {
      if (debugOn) {
        System.err.println("[NettySSLHandlerInst] Netty SSL handler scope");
      }
      if (context != null) {
        setCurrentNettyConnection(
            NettyChannelExtractor.extractConnectionFromChannelHandlerContext(context));
      }
    } catch (Throwable failure) {
      logNettyHandlerScopeFailure("enter Netty SSL handler scope", failure);
    }
  }

  public static void endNettyHandlerScope() {
    try {
      ArrayDeque<NettyHandlerScope> scopes = nettyHandlerScopes.get();
      if (scopes == null || scopes.isEmpty()) {
        return;
      }
      NettyHandlerScope scope = scopes.pop();
      if (scopes.isEmpty()) {
        nettyHandlerScopes.remove();
      }
      if (scope.started) {
        try {
          if (scope.receiving) {
            ThreadInfo.endRemoteParentReceiveScope();
          }
        } finally {
          endNettyConnectionScope();
        }
      }
    } catch (Throwable failure) {
      logNettyHandlerScopeFailure("end Netty SSL handler scope", failure);
    }
  }

  private static void logNettyHandlerScopeFailure(String operation, Throwable failure) {
    try {
      logNettyAdviceFailure(operation, failure);
    } catch (Throwable ignored) {
    }
  }

  public static boolean setCurrentNettyConnection(Object connection) {
    if (!(connection instanceof Connection)
        || ((Connection) connection).getSocketFileDescriptor() < 0) {
      return false;
    }

    ConnectionOwner owner = asConnectionOwner(((Connection) connection).getOwnerToken());
    if (!isActive(owner) || owner.connection != connection) {
      return false;
    }

    nettyConnection.set(new NettyConnectionScope(owner));
    return true;
  }

  /**
   * Enters a TLS unwrap scope and returns whether this is the outermost instrumented overload.
   *
   * <p>JDK convenience overloads delegate to other {@code unwrap} overloads. Only the outermost
   * advice may correlate or emit plaintext; nested advice must remain a no-op to avoid duplicate
   * remote-parent staging.
   */
  public static boolean beginRemoteParentUnwrap() {
    ThreadInfo.beginRemoteParentReceiveScope();
    Integer depth = remoteParentUnwrapDepth.get();
    if (depth == null) {
      remoteParentUnwrapDepth.set(1);
      return true;
    }
    remoteParentUnwrapDepth.set(depth + 1);
    return false;
  }

  /** Balances {@link #beginRemoteParentUnwrap()} without retaining state on a reused worker. */
  public static void endRemoteParentUnwrap() {
    try {
      Integer depth = remoteParentUnwrapDepth.get();
      if (depth == null || depth <= 1) {
        remoteParentUnwrapDepth.remove();
        return;
      }
      remoteParentUnwrapDepth.set(depth - 1);
    } finally {
      ThreadInfo.endRemoteParentReceiveScope();
    }
  }

  static void clearRemoteParentUnwrapDepthForTest() {
    remoteParentUnwrapDepth.remove();
  }

  /**
   * Enters one possibly nested {@code SSLSocket} stream read.
   *
   * <p>The shared scope lets only the outermost successful callback process plaintext. An inner
   * default-JSSE read can fill a buffer that an enclosing proxy subsequently truncates or
   * transforms, so it must not publish authority before the application-visible read completes.
   */
  public static Object beginRemoteParentSocketRead() {
    ThreadInfo.beginRemoteParentReceiveScope();
    Object[] scope = remoteParentSocketReadScope.get();
    if (scope == null) {
      // depth, deferred socket, deferred lifecycle, ambiguous nested ownership
      scope = new Object[] {Integer.valueOf(1), null, null, Boolean.FALSE};
      remoteParentSocketReadScope.set(scope);
      return scope;
    }
    scope[0] = Integer.valueOf(((Integer) scope[0]).intValue() + 1);
    return scope;
  }

  /**
   * Claims only the application-visible, outermost callback across nested stream wrappers.
   *
   * <p>A successful inner callback records its exact socket generation but emits nothing. The
   * outermost callback either consumes that same owner and processes its own returned bytes, or
   * poisons both generations when a different socket is visible. Multiple nested owners are
   * ambiguous and are all failed closed.
   */
  public static boolean claimRemoteParentSocketRead(
      Object candidate, Socket socket, Object lifecycle) {
    if (!(candidate instanceof Object[])) {
      return false;
    }
    Object[] scope = (Object[]) candidate;
    if (remoteParentSocketReadScope.get() != scope) {
      return false;
    }

    int depth = ((Integer) scope[0]).intValue();
    if (depth <= 1) {
      Socket deferredSocket = scope[1] instanceof Socket ? (Socket) scope[1] : null;
      Object deferredLifecycle = scope[2];
      if (Boolean.TRUE.equals(scope[3])) {
        poisonDeferredRemoteParentSocketRead(scope);
        poisonRemoteParentSocketRead(socket, lifecycle);
        return false;
      }
      if (deferredSocket == null) {
        return true;
      }
      if (deferredSocket == socket && deferredLifecycle == lifecycle) {
        scope[1] = null;
        scope[2] = null;
        return true;
      }
      poisonDeferredRemoteParentSocketRead(scope);
      poisonRemoteParentSocketRead(socket, lifecycle);
      scope[3] = Boolean.TRUE;
      return false;
    }

    if (!(lifecycle instanceof Lifecycle) || socket == null) {
      scope[3] = Boolean.TRUE;
      return false;
    }
    if (Boolean.TRUE.equals(scope[3])) {
      poisonRemoteParentSocketRead(socket, lifecycle);
      return false;
    }

    Socket deferredSocket = scope[1] instanceof Socket ? (Socket) scope[1] : null;
    Object deferredLifecycle = scope[2];
    if (deferredSocket == null) {
      scope[1] = socket;
      scope[2] = lifecycle;
      return false;
    }
    if (deferredSocket == socket && deferredLifecycle == lifecycle) {
      return false;
    }

    poisonDeferredRemoteParentSocketRead(scope);
    poisonRemoteParentSocketRead(socket, lifecycle);
    scope[3] = Boolean.TRUE;
    return false;
  }

  /** Poisons any successful inner owner when an enclosing read fails or reaches EOF. */
  public static void abortRemoteParentSocketRead(Object candidate) {
    if (!(candidate instanceof Object[])) {
      return;
    }
    Object[] scope = (Object[]) candidate;
    if (remoteParentSocketReadScope.get() == scope) {
      poisonDeferredRemoteParentSocketRead(scope);
      scope[3] = Boolean.TRUE;
    }
  }

  /** Balances {@link #beginRemoteParentSocketRead()} on every application and advice exit. */
  public static void endRemoteParentSocketRead(Object candidate) {
    try {
      if (!(candidate instanceof Object[])) {
        return;
      }
      Object[] scope = (Object[]) candidate;
      if (remoteParentSocketReadScope.get() != scope) {
        return;
      }
      int depth = ((Integer) scope[0]).intValue();
      if (depth <= 1) {
        poisonDeferredRemoteParentSocketRead(scope);
        remoteParentSocketReadScope.remove();
      } else {
        scope[0] = Integer.valueOf(depth - 1);
      }
    } finally {
      ThreadInfo.endRemoteParentReceiveScope();
    }
  }

  private static void poisonDeferredRemoteParentSocketRead(Object[] scope) {
    Socket socket = scope[1] instanceof Socket ? (Socket) scope[1] : null;
    Object lifecycle = scope[2];
    scope[1] = null;
    scope[2] = null;
    poisonRemoteParentSocketRead(socket, lifecycle);
  }

  private static void poisonRemoteParentSocketRead(Socket socket, Object lifecycle) {
    if (socket == null || !(lifecycle instanceof Lifecycle)) {
      return;
    }
    try {
      Object poisoned = poisonRemoteParentSocketLifecycle(socket, lifecycle);
      ThreadInfo.invalidateRemoteParentSocketFileDescriptor(
          poisoned == null ? lifecycle : poisoned);
    } catch (Throwable ignored) {
      // Nested-read bookkeeping must never replace the application's result or exception.
    }
  }

  /** Returns an existing lifecycle for a socket without allocating one on a terminal path. */
  public static Object currentRemoteParentSocketLifecycle(Socket socket) {
    SocketOwner owner = socket == null ? null : socketRemoteParentOwners.get(socket);
    Lifecycle lifecycle = owner == null ? null : owner.lifecycle;
    return lifecycle != null && lifecycle.active() ? lifecycle : null;
  }

  /**
   * Returns the live lifecycle for a socket receive, creating one only for an open socket.
   *
   * <p>The weak, capped owner map prevents a closed socket from being rebound to a reused numeric
   * descriptor. Capacity exhaustion fails closed by returning {@code null}.
   */
  public static Object prepareRemoteParentSocketLifecycle(Socket socket) {
    if (socket == null || socket.isClosed()) {
      return null;
    }

    Lifecycle current = (Lifecycle) currentRemoteParentSocketLifecycle(socket);
    if (current != null) {
      return current;
    }
    if (socketRemoteParentOwners.get(socket) != null) {
      return null;
    }

    SocketOwner candidate = new SocketOwner(socket);
    if (socketRemoteParentOwners.putIfAbsent(socket, candidate)) {
      return candidate.lifecycle;
    }
    return currentRemoteParentSocketLifecycle(socket);
  }

  /**
   * Explicitly invalidates and removes a socket lifecycle.
   *
   * <p>This removable path is intended for deterministic cleanup and tests. Production terminal
   * receive paths use {@link #poisonRemoteParentSocketLifecycle(Socket, Object)} so another read
   * cannot resurrect a fresh parser on the same still-open socket.
   */
  public static Object invalidateRemoteParentSocketLifecycle(Socket socket, Object expected) {
    if (!(expected instanceof Lifecycle)) {
      return null;
    }

    Lifecycle expectedLifecycle = (Lifecycle) expected;
    if (socket == null) {
      expectedLifecycle.invalidate();
      return expectedLifecycle;
    }

    SocketOwner owner = socketRemoteParentOwners.get(socket);
    if (owner != null && owner.lifecycle == expectedLifecycle) {
      owner.close(socket);
    }
    expectedLifecycle.invalidate();
    if (owner != null && owner.lifecycle == expectedLifecycle) {
      socketRemoteParentOwners.remove(socket, owner);
    }
    return expectedLifecycle;
  }

  /**
   * Retires an exact socket lifecycle while retaining its inactive weak-map owner until close.
   *
   * <p>The retained owner is a fail-closed tombstone: subsequent reads cannot allocate a fresh
   * framer and reinterpret continuation bytes as a new request. A delayed callback for an older
   * lifecycle never closes or invalidates a newer exact owner.
   */
  public static Object poisonRemoteParentSocketLifecycle(Socket socket, Object expected) {
    if (!(expected instanceof Lifecycle)) {
      return null;
    }

    Lifecycle expectedLifecycle = (Lifecycle) expected;
    if (socket == null) {
      expectedLifecycle.invalidate();
      return expectedLifecycle;
    }

    SocketOwner owner = socketRemoteParentOwners.get(socket);
    if (owner == null || owner.lifecycle != expectedLifecycle) {
      expectedLifecycle.invalidate();
      return null;
    }
    try {
      owner.close(socket);
    } catch (Throwable ignored) {
      // Poisoning is terminal even when best-effort framer/native cleanup fails.
    }
    expectedLifecycle.invalidate();
    return socketRemoteParentOwners.get(socket) == owner ? expectedLifecycle : null;
  }

  /**
   * Creates an inactive close tombstone so no concurrent receive can restage this socket before its
   * close method completes.
   */
  public static Object beginRemoteParentSocketClose(Socket socket) {
    if (socket == null) {
      return null;
    }

    while (true) {
      SocketOwner current = socketRemoteParentOwners.get(socket);
      if (current != null && current.lifecycle.retainCloseTombstoneIfOpen()) {
        return current.lifecycle;
      }

      SocketOwner tombstone = new SocketOwner(Lifecycle.newCloseTombstone());
      if (current == null) {
        if (socketRemoteParentOwners.putIfAbsent(socket, tombstone)) {
          return tombstone.lifecycle;
        }
        // putIfAbsent also returns false when the capped weak map has no room. Do not spin in a
        // close path in that case: another thread can be observed on the next get, while a still
        // absent socket must fail locally without revoking an unrelated lifecycle.
        if (socketRemoteParentOwners.get(socket) == null) {
          return null;
        }
        continue;
      }

      current.close(socket);
      current.lifecycle.invalidate();
      if (socketRemoteParentOwners.replace(socket, current, tombstone)) {
        return tombstone.lifecycle;
      }
    }
  }

  /** Removes the temporary close tombstone after the socket close method returns. */
  public static void finishRemoteParentSocketClose(Socket socket, Object lifecycle) {
    if (socket == null || !(lifecycle instanceof Lifecycle)) {
      return;
    }
    Lifecycle expected = (Lifecycle) lifecycle;
    SocketOwner owner = socketRemoteParentOwners.get(socket);
    if (owner != null
        && owner.lifecycle == expected
        && expected.isCloseTombstone()
        && expected.releaseCloseTombstone()) {
      socketRemoteParentOwners.remove(socket, owner);
    }
  }

  /** Frames and emits plaintext for one exact direct-JSSE socket generation. */
  public static int emitRemoteParentSocketReceive(
      Socket socket, Object expectedLifecycle, byte[] plaintext, int offset, int length) {
    SocketOwner owner = socket == null ? null : socketRemoteParentOwners.get(socket);
    if (owner == null
        || owner.lifecycle != expectedLifecycle
        || owner.receive == null
        || !owner.lifecycle.active()) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.blockRemoteParentLookup();
      return -1;
    }
    int status;
    try {
      status = owner.receive.emit(socket, plaintext, offset, length);
    } catch (Throwable failure) {
      poisonSocketOwner(socket, owner);
      throw failure;
    }
    if (status < 0) {
      poisonSocketOwner(socket, owner);
    } else {
      RemoteParentBridge.recordTlsRead(length);
    }
    return status;
  }

  /** Records unsupported socket plaintext at most once for one exact socket generation. */
  public static void recordUnsupportedSocketReceive(Socket socket, Object expectedLifecycle) {
    SocketOwner owner = socket == null ? null : socketRemoteParentOwners.get(socket);
    if (owner != null
        && owner.lifecycle == expectedLifecycle
        && owner.unsupportedRecorded.compareAndSet(false, true)) {
      RemoteParentBridge.recordReceiveFailure(
          io.opentelemetry.obi.java.bridge.RemoteParentStatus.UNSUPPORTED);
    }
  }

  private static void poisonSocketOwner(Socket socket, SocketOwner owner) {
    if (owner == null) {
      return;
    }
    Object poisoned = poisonRemoteParentSocketLifecycle(socket, owner.lifecycle);
    ThreadInfo.invalidateRemoteParentSocketFileDescriptor(
        poisoned == null ? owner.lifecycle : poisoned);
  }

  /** Returns the exact active connection-owner lifecycle for an engine receive. */
  public static Object remoteParentSocketLifecycle(Connection connection) {
    ConnectionOwner owner =
        connection == null ? null : asConnectionOwner(connection.getOwnerToken());
    return isActive(owner) && owner.connection == connection && owner.remoteParentLifecycle.active()
        ? owner.remoteParentLifecycle
        : null;
  }

  /** Frames and emits plaintext against the exact active physical connection owner. */
  public static int emitRemoteParentHttp1(
      Connection connection, byte[] source, int offset, int length) {
    ConnectionOwner owner =
        connection == null ? null : asConnectionOwner(connection.getOwnerToken());
    if (!isActive(owner) || owner.connection != connection) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      return -1;
    }
    return owner.remoteParentHttp1Receive.emit(connection, source, offset, length);
  }

  /** Emits plaintext from an SSLEngine receive while preserving disabled-mode legacy behavior. */
  public static int emitRemoteParentReceive(
      SSLEngine engine, Connection connection, byte[] plaintext, int offset, int length) {
    try {
      BootstrapNative.markTlsConnectionIfDue(engine, connection);
    } catch (Throwable failure) {
      if (debugOn) {
        System.err.println("[SSLStorage] failed to mark TLS connection: " + failure);
      }
    }

    int status;
    long receiveBridgeEpoch = ThreadInfo.captureRemoteParentBridgeCapability();
    if (receiveBridgeEpoch != 0L) {
      status = emitRemoteParentHttp1(connection, plaintext, offset, length);
    } else {
      ConnectionOwner owner =
          connection == null ? null : asConnectionOwner(connection.getOwnerToken());
      if (isActive(owner) && owner.connection == connection) {
        // The current fragment must still take the exact legacy path below. First retire any
        // framing/capability issued by the previous provider epoch so later re-enablement cannot
        // resume across plaintext that this framer never observed.
        owner.remoteParentHttp1Receive.beforeLegacyReceive(connection);
      }
      NativeMemory packet = new NativeMemory(IOCTLPacket.packetPrefixSize + length);
      int writeOffset =
          IOCTLPacket.writePacketPrefix(packet, 0, OperationType.RECEIVE, connection, length);
      IOCTLPacket.writePacketBuffer(packet, writeOffset, plaintext, offset, length);
      Runnable beforeEmit = beforeLegacyReceiveEmitForTest;
      if (beforeEmit != null) {
        beforeEmit.run();
      }
      status = BootstrapNative.emitData(connection, packet.getAddress(), true, receiveBridgeEpoch);
    }
    if (status >= 0) {
      RemoteParentBridge.recordTlsRead(length);
    }
    return status;
  }

  /** Resets local framing before invalidating the exact engine lifecycle. */
  public static void invalidateRemoteParent(SSLEngine engine, Object expectedLifecycle) {
    try {
      closeRemoteParentHttp1(engine, expectedLifecycle);
    } finally {
      BootstrapNative.invalidateRemoteParentSocketFileDescriptor(expectedLifecycle);
    }
  }

  /** Resets and releases framing state only for the exact still-current engine lifecycle. */
  public static void closeRemoteParentHttp1(SSLEngine engine, Object expectedLifecycle) {
    ConnectionOwner owner = connectionOwnerForSession(engine);
    if (owner != null && owner.remoteParentLifecycle == expectedLifecycle && isActive(owner)) {
      owner.remoteParentHttp1Receive.close(owner.connection);
    }
  }

  /** Resets and releases framing state only for the exact still-current connection lifecycle. */
  public static void closeRemoteParentHttp1(Connection connection, Object expectedLifecycle) {
    ConnectionOwner owner =
        connection == null ? null : asConnectionOwner(connection.getOwnerToken());
    if (owner != null
        && owner.connection == connection
        && owner.remoteParentLifecycle == expectedLifecycle
        && isActive(owner)) {
      owner.remoteParentHttp1Receive.close(owner.connection);
    }
  }

  /** Returns the exact active connection-owner lifecycle already associated with an engine. */
  public static Object remoteParentSocketLifecycle(SSLEngine engine) {
    ConnectionOwner owner = connectionOwnerForSession(engine);
    return isActive(owner) && owner.remoteParentLifecycle.active()
        ? owner.remoteParentLifecycle
        : null;
  }

  public static Connection getConnectionForSession(SSLEngine session) {
    ConnectionOwner owner = connectionOwnerForSession(session);
    return owner == null ? null : owner.connection;
  }

  public static void setConnectionForSession(SSLEngine session, Connection c) {
    if (session == null || c == null || c.getSocketFileDescriptor() < 0) {
      return;
    }
    ConnectionOwner owner = activeConnectionOwner(c);
    if (owner != null) {
      sslConnections.put(session, owner);
    }
  }

  public static Connection resolveConnectionForUnwrap(SSLEngine session, Object handoff) {
    if (session == null) {
      return null;
    }

    ConnectionOwner cachedOwner = connectionOwnerForSession(session);
    Connection cached = cachedOwner == null ? null : cachedOwner.connection;
    Object scopedValue = nettyConnection.get();
    Connection scoped = currentScopedConnection();

    if (hasInvalidFdScopedConnection(scopedValue)) {
      return null;
    }

    if (scoped != null) {
      if (scoped.getSocketFileDescriptor() >= 0) {
        ConnectionOwner scopedOwner = currentScopedConnectionOwner(scopedValue);
        if (scopedOwner == null) {
          return null;
        }
        sslConnections.put(session, scopedOwner);
        return connectionOwnerForSession(session) == scopedOwner ? scopedOwner.connection : null;
      }
      if (cached != null && cached.getSocketFileDescriptor() >= 0 && cached.equals(scoped)) {
        return cached;
      }
      return null;
    }

    if (!hasEstablishedSession(session)) {
      return cached != null && cached.getSocketFileDescriptor() >= 0 ? cached : null;
    }

    if (cached != null && cached.getSocketFileDescriptor() >= 0) {
      BufferHandoff correlated = asBufferHandoff(handoff);
      if ((correlated != null && correlated.state == BUFFER_HANDOFF_AMBIGUOUS)
          || (correlated != null && correlated.state == BUFFER_HANDOFF_CLAIMING)
          || (correlated != null
              && (!isActive(correlated.owner)
                  || !sameExactConnection(cached, correlated.owner.connection)))) {
        return null;
      }
      return cached;
    }

    return null;
  }

  public static Connection claimConnectionForUnwrap(
      SSLEngine session,
      ByteBuffer buffer,
      Object handoff,
      Connection expected,
      Object expectedOwnerToken,
      Connection scopedAtEntry,
      int bytesConsumed,
      int plaintextLength) {
    if (session == null || plaintextLength <= 0) {
      return null;
    }

    if (!hasEstablishedSession(session)) {
      return null;
    }

    ConnectionOwner expectedOwner = asConnectionOwner(expectedOwnerToken);
    Object scopedValue = nettyConnection.get();
    Connection scopedNow = currentScopedConnection();
    if (hasInvalidFdScopedConnection(scopedValue)) {
      return null;
    }
    if (scopedAtEntry != null || scopedNow != null) {
      if (scopedAtEntry == null
          || scopedNow == null
          || expected == null
          || expectedOwner == null
          || scopedAtEntry != scopedNow
          || !scopedConnectionMatchesExpected(expected, scopedAtEntry)
          || !isActive(expectedOwner)
          || expectedOwner.connection != expected
          || connectionOwnerForSession(session) != expectedOwner) {
        return null;
      }
      consumeScopedBufferHandoff(buffer, handoff, expectedOwner);
      return connectionOwnerForSession(session) == expectedOwner ? expected : null;
    }

    if (expected != null
        && (expectedOwner == null
            || !isActive(expectedOwner)
            || expectedOwner.connection != expected
            || connectionOwnerForSession(session) != expectedOwner)) {
      return null;
    }

    if (bytesConsumed <= 0) {
      return expected;
    }

    BufferHandoff candidate = asBufferHandoff(handoff);
    if (candidate == null) {
      return expected;
    }
    if (candidate.state == BUFFER_HANDOFF_AMBIGUOUS || buffer == null) {
      return null;
    }

    if (candidate.state == BUFFER_HANDOFF_CLAIMING) {
      makeCurrentBufferHandoffAmbiguous(buffer, candidate);
      return null;
    }

    if (candidate.state == BUFFER_HANDOFF_CONSUMED) {
      return expectedOwner != null
              && candidate.owner == expectedOwner
              && readBufferConnections.get(buffer) == candidate
              && connectionOwnerForSession(session) == expectedOwner
          ? expected
          : null;
    }

    if (candidate.state != BUFFER_HANDOFF_AVAILABLE
        || !isActive(candidate.owner)
        || (expectedOwner != null && candidate.owner != expectedOwner)) {
      return null;
    }

    if (expectedOwner == null) {
      ConnectionOwner currentOwner = connectionOwnerForSession(session);
      if (currentOwner != null && currentOwner != candidate.owner) {
        return null;
      }
    }

    return claimAvailableBufferHandoff(session, buffer, candidate, expectedOwner);
  }

  private static Connection claimAvailableBufferHandoff(
      SSLEngine session,
      ByteBuffer buffer,
      BufferHandoff candidate,
      ConnectionOwner expectedOwner) {
    BufferHandoff claiming = new BufferHandoff(candidate, BUFFER_HANDOFF_CLAIMING);
    if (!readBufferConnections.replace(buffer, candidate, claiming)) {
      makeFailedTakeAmbiguous(buffer, candidate);
      return null;
    }

    boolean accepted = false;
    boolean installedSessionOwner = false;
    try {
      if (!isActive(candidate.owner)) {
        return null;
      }

      if (expectedOwner != null) {
        if (candidate.owner != expectedOwner
            || connectionOwnerForSession(session) != expectedOwner) {
          return null;
        }
      } else {
        while (true) {
          if (!isActive(candidate.owner)) {
            return null;
          }
          if (sslConnections.putIfAbsent(session, candidate.owner)) {
            installedSessionOwner = true;
            break;
          }
          ConnectionOwner cachedOwner = sslConnections.get(session);
          if (cachedOwner == null) {
            return null;
          }
          if (!isActive(cachedOwner)) {
            sslConnections.remove(session, cachedOwner);
            if (cachedOwner == candidate.owner) {
              return null;
            }
            continue;
          }
          if (cachedOwner != candidate.owner) {
            return null;
          }
          break;
        }
      }

      if (connectionOwnerForSession(session) != candidate.owner) {
        return null;
      }

      BufferHandoff consumed = new BufferHandoff(claiming, BUFFER_HANDOFF_CONSUMED);
      if (!readBufferConnections.replace(buffer, claiming, consumed)) {
        return null;
      }
      if (connectionOwnerForSession(session) != candidate.owner) {
        return null;
      }

      accepted = true;
      return candidate.owner.connection;
    } finally {
      if (!accepted) {
        makeCurrentBufferHandoffAmbiguous(buffer, claiming);
        if (installedSessionOwner) {
          sslConnections.remove(session, candidate.owner);
        }
      }
    }
  }

  private static boolean sameExactConnection(Connection first, Connection second) {
    return first.equals(second)
        && first.getSocketFileDescriptor() == second.getSocketFileDescriptor();
  }

  private static boolean scopedConnectionMatchesExpected(Connection expected, Connection scoped) {
    if (scoped.getSocketFileDescriptor() >= 0) {
      return sameExactConnection(expected, scoped);
    }
    return expected.getSocketFileDescriptor() >= 0 && expected.equals(scoped);
  }

  private static boolean hasEstablishedSession(SSLEngine session) {
    try {
      SSLSession established = session.getSession();
      return established != null && established.getId().length != 0;
    } catch (Throwable ignored) {
      return false;
    }
  }

  public static boolean claimTlsConnectionMarkerAttempt(
      SSLEngine session, Connection connection, long processIncarnation) {
    if (session == null
        || connection == null
        || connection.getSocketFileDescriptor() < 0
        || processIncarnation <= 0) {
      return false;
    }
    ConnectionOwner owner = connectionOwnerForSession(session);
    if (owner == null || owner.connection != connection) {
      return false;
    }

    long now = tlsConnectionMarkerNanos();
    while (true) {
      if (!isActive(owner) || connectionOwnerForSession(session) != owner) {
        return false;
      }

      TlsConnectionMarkerAttempt current = tlsConnectionMarkers.get(session);
      boolean matching = current != null && current.matches(owner, processIncarnation);
      if (matching
          && current.attempts >= TLS_CONNECTION_MARKER_BURST_ATTEMPTS
          && now - current.nextAttemptNanos < 0) {
        return false;
      }

      int attempts =
          matching
              ? current.attempts == Integer.MAX_VALUE ? Integer.MAX_VALUE : current.attempts + 1
              : 1;
      TlsConnectionMarkerAttempt next =
          new TlsConnectionMarkerAttempt(
              owner, processIncarnation, attempts, now + TLS_CONNECTION_MARKER_RETRY_NANOS);
      boolean reserved;
      if (current == null) {
        reserved = tlsConnectionMarkers.putIfAbsent(session, next);
        if (!reserved && tlsConnectionMarkers.get(session) == null) {
          return false;
        }
      } else {
        reserved = tlsConnectionMarkers.replace(session, current, next);
      }
      if (!reserved) {
        continue;
      }

      if (isActive(owner) && connectionOwnerForSession(session) == owner) {
        return true;
      }
      tlsConnectionMarkers.remove(session, next);
      return false;
    }
  }

  private static long tlsConnectionMarkerNanos() {
    LongSupplier clock = tlsConnectionMarkerClockForTest;
    return clock == null ? System.nanoTime() : clock.getAsLong();
  }

  public static Object captureReadBufferHandoff(ByteBuffer buffer) {
    return readBufferConnections.get(buffer);
  }

  public static Connection getConnectionForReadBuffer(ByteBuffer buffer) {
    BufferHandoff handoff = asBufferHandoff(captureReadBufferHandoff(buffer));
    return handoff == null || handoff.state != BUFFER_HANDOFF_AVAILABLE || !isActive(handoff.owner)
        ? null
        : handoff.owner.connection;
  }

  public static void setConnectionForReadBuffer(ByteBuffer buffer, Connection connection) {
    setConnectionForReadBuffer(buffer, connection, false);
  }

  public static void setConnectionForReadBuffer(
      ByteBuffer buffer, Connection connection, boolean freshFillAtReadEntry) {
    if (buffer == null || connection == null || connection.getSocketFileDescriptor() < 0) {
      return;
    }

    ConnectionOwner owner = activeConnectionOwner(connection);
    if (owner == null) {
      return;
    }

    BufferHandoff candidate = new BufferHandoff(owner, BUFFER_HANDOFF_AVAILABLE);
    while (true) {
      BufferHandoff observed = readBufferConnections.get(buffer);
      if (observed == null) {
        if (readBufferConnections.putIfAbsent(buffer, candidate)) {
          return;
        }
        observed = readBufferConnections.get(buffer);
        if (observed == null) {
          return;
        }
      }
      BufferHandoff replacement;
      if (observed.state == BUFFER_HANDOFF_CLAIMING) {
        replacement = new BufferHandoff(candidate, BUFFER_HANDOFF_AMBIGUOUS);
      } else if (freshFillAtReadEntry) {
        replacement = candidate;
      } else if (observed.state == BUFFER_HANDOFF_AMBIGUOUS) {
        replacement = new BufferHandoff(candidate, BUFFER_HANDOFF_AMBIGUOUS);
      } else if (observed.owner == owner) {
        replacement = candidate;
      } else {
        replacement = new BufferHandoff(candidate, BUFFER_HANDOFF_AMBIGUOUS);
      }
      if (readBufferConnections.replace(buffer, observed, replacement)) {
        return;
      }
    }
  }

  public static Connection associateConnectionWithChannel(Object channel, Connection connection) {
    if (connection == null || connection.getSocketFileDescriptor() < 0) {
      return null;
    }
    if (channel == null) {
      return connection;
    }

    synchronized (channelLifecycleLock(channel)) {
      ChannelState state = channelStates.get(channel);
      if (state == null) {
        if (channelStateCapacityExhausted.get()) {
          return null;
        }
        state = new ChannelState();
        if (!channelStates.putIfAbsent(channel, state)) {
          state = channelStates.get(channel);
          if (state == null) {
            markChannelStateCapacityExhausted();
            return null;
          }
        }
      }
      if (state.closed) {
        return null;
      }

      if (state.owner != null) {
        return isActive(state.owner) && sameExactConnection(state.owner.connection, connection)
            ? state.owner.connection
            : null;
      }

      ConnectionOwner owner = newChannelConnectionOwner(channel, connection);
      if (owner == null || !isActive(owner)) {
        state.closed = true;
        return null;
      }
      state.owner = owner;
      return owner.connection;
    }
  }

  public static Connection getConnectionForChannel(Object channel) {
    if (channel == null) {
      return null;
    }

    synchronized (channelLifecycleLock(channel)) {
      ChannelState state = channelStates.get(channel);
      return state == null || state.closed || !isActive(state.owner)
          ? null
          : state.owner.connection;
    }
  }

  public static Connection associateConnectionWithSocketChannel(
      Object channel, Connection connection) {
    return associateConnectionWithChannel(channel, connection);
  }

  /** Test-only owner association that exercises the same connection-generation path. */
  static Connection associateConnectionWithPhysicalOwnerForTest(
      Object physicalOwner, Connection connection) {
    if (physicalOwner == null || connection == null || connection.getSocketFileDescriptor() < 0) {
      return null;
    }
    ConnectionOwner owner = newChannelConnectionOwner(physicalOwner, connection);
    return owner == null ? null : owner.connection;
  }

  static Object physicalOwnerForTest(Connection connection) {
    ConnectionOwner owner =
        connection == null ? null : asConnectionOwner(connection.getOwnerToken());
    return owner == null || owner.connection != connection ? null : owner.physicalOwner.get();
  }

  static void clearPhysicalOwnerForTest(Connection connection) {
    ConnectionOwner owner =
        connection == null ? null : asConnectionOwner(connection.getOwnerToken());
    if (owner != null && owner.connection == connection) {
      owner.physicalOwner.clear();
    }
  }

  public static Connection getConnectionForSocketChannel(Object channel) {
    return getConnectionForChannel(channel);
  }

  public static void cleanupConnection(Connection connection) {
    cleanupConnection(null, connection);
  }

  public static void cleanupConnection(Object channel, Connection connection) {
    cleanupConnection(channel, connection, true);
  }

  public static void cleanupConnection(Object channel, Connection connection, boolean terminal) {
    if (!terminal) {
      return;
    }

    if (channel != null) {
      closeChannel(channel, connection);
      return;
    }

    if (connection != null && connection.getSocketFileDescriptor() >= 0) {
      cleanupConnectionOwnerFor(connection);
    }
  }

  /**
   * Blocks new descriptor operations before a channel close whose terminal result is not yet known.
   *
   * <p>{@code SocketChannelImpl.tryClose()} may close its descriptor before returning its boolean
   * result. The returned fence therefore must be finished from method exit on both normal and
   * exceptional paths.
   */
  public static Object beginRemoteParentConnectionClose(Object channel, Connection connection) {
    ConnectionOwner owner = connectionOwnerForClose(channel, connection);
    if (owner == null) {
      return null;
    }
    // Drain bounded pre-START plaintext and reset an active request before tryClose can make the
    // descriptor unusable. cleanupConnection repeats local release safely after the close exits.
    owner.remoteParentHttp1Receive.close(owner.connection);
    return owner.remoteParentLifecycle.beginCloseFence();
  }

  /**
   * Finishes a {@code SocketChannelImpl.tryClose()} fence and permanently retires its owner.
   *
   * <p>The JDK invokes {@code tryClose()} only after logical channel closure has started. A {@code
   * false} result merely defers the physical descriptor close, so reopening correlation at that
   * point could select a pre-closed or later-reused descriptor.
   */
  public static void finishRemoteParentConnectionClose(
      Object channel, Connection connection, Object fence) {
    if (fence instanceof Lifecycle.CloseFence) {
      ((Lifecycle.CloseFence) fence).finish(true);
    }
    cleanupConnection(channel, connection);
  }

  public static void closeNettyChannel(Object channel) {
    try {
      closeChannel(NettyChannelExtractor.channelLifecycleKey(channel), null);
    } catch (Throwable failure) {
      logNettyHandlerScopeFailure("close Netty channel", failure);
    }
  }

  public static void registerNettyCloseHook(Object channel) {
    try {
      Class<?> abstractChannelClass = nettyAbstractChannelClass(channel);
      if (abstractChannelClass == null) {
        return;
      }
      ClassLoader loader = abstractChannelClass.getClassLoader();
      if (loader == null) {
        bootstrapNettyCloseHookAvailable.set(true);
        return;
      }
      if (!nettyCloseHookLoaders.putIfAbsent(loader, NETTY_CLOSE_HOOK_AVAILABLE)
          && nettyCloseHookLoaders.get(loader) == null) {
        logNettyAdviceFailure(
            "register Netty terminal close hook",
            new IllegalStateException("Netty close-hook loader capacity exhausted"));
      }
    } catch (Throwable failure) {
      logNettyAdviceFailure("register Netty terminal close hook", failure);
    }
  }

  public static boolean isNettyCloseHookAvailable(Object channel) {
    try {
      Class<?> abstractChannelClass = nettyAbstractChannelClass(channel);
      if (abstractChannelClass == null) {
        return false;
      }
      ClassLoader loader = abstractChannelClass.getClassLoader();
      return loader == null
          ? bootstrapNettyCloseHookAvailable.get()
          : nettyCloseHookLoaders.get(loader) != null;
    } catch (Throwable failure) {
      logNettyAdviceFailure("resolve Netty terminal close hook", failure);
      return false;
    }
  }

  private static Class<?> nettyAbstractChannelClass(Object channel) {
    if (channel == null) {
      return null;
    }
    Class<?> channelClass = channel.getClass();
    for (Class<?> type = channelClass; type != null; type = type.getSuperclass()) {
      if (NETTY_ABSTRACT_CHANNEL_CLASS_NAME.equals(type.getName())) {
        return type;
      }
    }
    return null;
  }

  private static void closeChannel(Object channel, Connection connection) {
    if (channel == null) {
      return;
    }

    synchronized (channelLifecycleLock(channel)) {
      ChannelState state = channelStates.get(channel);
      if (state == null) {
        ChannelState closedState = new ChannelState();
        closedState.closed = true;
        if (channelStates.putIfAbsent(channel, closedState)) {
          cleanupCanonicalConnectionOwner(connection);
          return;
        }
        state = channelStates.get(channel);
        if (state == null) {
          markChannelStateCapacityExhausted();
          cleanupCanonicalConnectionOwner(connection);
          return;
        }
      }
      if (state.closed) {
        return;
      }
      state.closed = true;
      cleanupConnectionOwner(state.owner);
    }
  }

  private static void cleanupConnectionOwnerFor(Connection connection) {
    ConnectionOwner knownOwner = asConnectionOwner(connection.getOwnerToken());
    if (knownOwner != null) {
      cleanupConnectionOwner(knownOwner);
      return;
    }

    ExactConnection key = new ExactConnection(connection);
    ConnectionOwner owner = activeConnections.get(key);
    if (owner != null) {
      cleanupConnectionOwner(owner);
    }
  }

  private static void cleanupCanonicalConnectionOwner(Connection connection) {
    if (connection == null) {
      return;
    }
    ConnectionOwner owner = asConnectionOwner(connection.getOwnerToken());
    if (owner != null && owner.connection == connection) {
      cleanupConnectionOwner(owner);
    }
  }

  private static ConnectionOwner connectionOwnerForClose(Object channel, Connection connection) {
    if (channel != null) {
      synchronized (channelLifecycleLock(channel)) {
        ChannelState state = channelStates.get(channel);
        if (state == null || state.owner == null) {
          return null;
        }
        if (state.owner != null) {
          if (connection == null || sameExactConnection(state.owner.connection, connection)) {
            // A concurrent close may have already raised closePending. It is still essential that
            // this closer enters beginCloseFence(), which waits for any in-flight native lease
            // before the JDK can pre-close or recycle the descriptor.
            return isRegistered(state.owner) ? state.owner : null;
          }
          return null;
        }
      }
    }

    if (connection == null || connection.getSocketFileDescriptor() < 0) {
      return null;
    }
    ConnectionOwner owner = asConnectionOwner(connection.getOwnerToken());
    if (owner != null && owner.connection == connection) {
      return isRegistered(owner) ? owner : null;
    }
    owner = activeConnections.get(new ExactConnection(connection));
    return owner != null && isRegistered(owner) ? owner : null;
  }

  private static void markChannelStateCapacityExhausted() {
    channelStateCapacityExhausted.set(true);
    if (channelStateCapacityLogged.compareAndSet(false, true)) {
      System.err.println(
          "[SSLStorage] Netty channel correlation capacity exhausted; new TLS correlations will"
              + " fail closed");
    }
  }

  private static ConnectionOwner activeConnectionOwner(Connection connection) {
    ConnectionOwner knownOwner = asConnectionOwner(connection.getOwnerToken());
    if (knownOwner != null && knownOwner.connection == connection) {
      return isActive(knownOwner) ? knownOwner : null;
    }
    return null;
  }

  private static ConnectionOwner newChannelConnectionOwner(Object channel, Connection connection) {
    ConnectionOwner knownOwner = asConnectionOwner(connection.getOwnerToken());
    if (knownOwner != null) {
      if (knownOwner.connection == connection
          && knownOwner.hasPhysicalOwner(channel)
          && isActive(knownOwner)) {
        return knownOwner;
      }
      cleanupConnectionOwner(knownOwner);
    }

    ExactConnection key = new ExactConnection(connection);
    while (true) {
      ConnectionOwner owner = activeConnections.get(key);
      if (owner != null) {
        if (owner.connection == connection && owner.hasPhysicalOwner(channel) && isActive(owner)) {
          return owner;
        }
        cleanupConnectionOwner(owner);
        continue;
      }
      ConnectionOwner candidate = new ConnectionOwner(key, channel);
      owner = activeConnections.putIfAbsent(key, candidate);
      if (owner == null) {
        return isActive(candidate) ? candidate : null;
      }
    }
  }

  private static void cleanupConnectionOwner(ConnectionOwner owner) {
    if (owner != null) {
      owner.remoteParentHttp1Receive.close(owner.connection);
      owner.remoteParentLifecycle.invalidate();
      if (owner.connection.getOwnerToken() == owner) {
        owner.connection.setOwnerToken(null);
      }
    }
    if (owner != null && activeConnections.remove(owner.key, owner)) {
      owner.active = false;
    }
  }

  private static Object[] channelLifecycleLocks() {
    Object[] locks = new Object[CHANNEL_LIFECYCLE_LOCK_STRIPES];
    for (int index = 0; index < locks.length; index++) {
      locks[index] = new Object();
    }
    return locks;
  }

  private static Object channelLifecycleLock(Object channel) {
    return channelLifecycleLocks[System.identityHashCode(channel) & CHANNEL_LIFECYCLE_LOCK_MASK];
  }

  private static boolean isActive(ConnectionOwner owner) {
    return isRegistered(owner) && owner.remoteParentLifecycle.active();
  }

  private static boolean isRegistered(ConnectionOwner owner) {
    return owner != null && owner.active && activeConnections.get(owner.key) == owner;
  }

  private static ConnectionOwner connectionOwnerForSession(SSLEngine session) {
    if (session == null) {
      return null;
    }
    ConnectionOwner owner = sslConnections.get(session);
    if (isActive(owner)) {
      return owner;
    }
    if (owner != null) {
      sslConnections.remove(session, owner);
    }
    return null;
  }

  private static BufferHandoff asBufferHandoff(Object handoff) {
    return handoff instanceof BufferHandoff ? (BufferHandoff) handoff : null;
  }

  public static Object captureConnectionOwnerForUnwrap(SSLEngine session, Connection connection) {
    ConnectionOwner owner = connectionOwnerForSession(session);
    return owner != null && owner.connection == connection ? owner : null;
  }

  public static Connection currentScopedConnection() {
    Object value = nettyConnection.get();
    if (value instanceof NettyConnectionScope) {
      ConnectionOwner owner = ((NettyConnectionScope) value).owner;
      return isActive(owner) ? owner.connection : null;
    }
    if (!(value instanceof Connection)) {
      return null;
    }
    Connection connection = (Connection) value;
    if (connection.getSocketFileDescriptor() < 0) {
      return connection;
    }
    ConnectionOwner owner = asConnectionOwner(connection.getOwnerToken());
    return isActive(owner) && owner.connection == connection ? connection : null;
  }

  private static ConnectionOwner currentScopedConnectionOwner(Object value) {
    if (value instanceof NettyConnectionScope) {
      ConnectionOwner owner = ((NettyConnectionScope) value).owner;
      return isActive(owner) ? owner : null;
    }
    if (!(value instanceof Connection) || ((Connection) value).getSocketFileDescriptor() < 0) {
      return null;
    }
    Connection connection = (Connection) value;
    ConnectionOwner owner = asConnectionOwner(connection.getOwnerToken());
    return isActive(owner) && owner.connection == connection ? owner : null;
  }

  private static boolean hasInvalidFdScopedConnection(Object value) {
    if (value instanceof NettyConnectionScope) {
      return !isActive(((NettyConnectionScope) value).owner);
    }
    if (!(value instanceof Connection)) {
      return false;
    }
    Connection connection = (Connection) value;
    return connection.getSocketFileDescriptor() >= 0
        && currentScopedConnectionOwner(connection) == null;
  }

  private static void consumeScopedBufferHandoff(
      ByteBuffer buffer, Object handoff, ConnectionOwner owner) {
    BufferHandoff captured = asBufferHandoff(handoff);
    while (buffer != null) {
      BufferHandoff current = readBufferConnections.get(buffer);
      if (current == null
          || current.state == BUFFER_HANDOFF_AMBIGUOUS
          || captured == null
          || current.generation != captured.generation) {
        return;
      }
      if (current == captured
          && current.owner == owner
          && current.state == BUFFER_HANDOFF_CONSUMED) {
        return;
      }
      if (current.state == BUFFER_HANDOFF_CONSUMED
          && current.owner == owner
          && captured.owner == owner) {
        return;
      }
      if (current == captured
          && current.owner == owner
          && current.state == BUFFER_HANDOFF_AVAILABLE) {
        BufferHandoff consumed = new BufferHandoff(current, BUFFER_HANDOFF_CONSUMED);
        if (readBufferConnections.replace(buffer, current, consumed)) {
          return;
        }
      } else if (readBufferConnections.replace(
          buffer, current, new BufferHandoff(current, BUFFER_HANDOFF_AMBIGUOUS))) {
        return;
      }
    }
  }

  private static void makeFailedTakeAmbiguous(ByteBuffer buffer, BufferHandoff candidate) {
    while (buffer != null) {
      BufferHandoff current = readBufferConnections.get(buffer);
      if (current == null || current.state == BUFFER_HANDOFF_AMBIGUOUS) {
        return;
      }
      if (current.generation != candidate.generation) {
        return;
      }
      if (current.state == BUFFER_HANDOFF_CONSUMED && current.owner == candidate.owner) {
        return;
      }
      if (readBufferConnections.replace(
          buffer, current, new BufferHandoff(current, BUFFER_HANDOFF_AMBIGUOUS))) {
        return;
      }
    }
  }

  private static void makeCurrentBufferHandoffAmbiguous(
      ByteBuffer buffer, BufferHandoff candidate) {
    while (buffer != null) {
      BufferHandoff current = readBufferConnections.get(buffer);
      if (current == null
          || current.state == BUFFER_HANDOFF_AMBIGUOUS
          || current.generation != candidate.generation) {
        return;
      }
      if (current.state == BUFFER_HANDOFF_CONSUMED && current.owner == candidate.owner) {
        return;
      }
      if (readBufferConnections.replace(
          buffer, current, new BufferHandoff(current, BUFFER_HANDOFF_AMBIGUOUS))) {
        return;
      }
    }
  }

  private static ConnectionOwner asConnectionOwner(Object owner) {
    return owner instanceof ConnectionOwner ? (ConnectionOwner) owner : null;
  }

  public static void setBufferMapping(String encrypted, BytesWithLen plain) {
    bufToBuf.put(encrypted, plain);
  }

  public static BytesWithLen getUnencryptedBuffer(String encrypted) {
    return bufToBuf.get(encrypted);
  }

  public static void removeBufferMapping(String encrypted) {
    bufToBuf.remove(encrypted);
  }

  // These boot finder methods are here to help us find the version of the methods/classes that are
  // loaded
  // on the boot class loader. Since we use multiple class loaders, we need to be able to find a
  // specific version
  // of the class.
  public static Method getBootExtractMethod() {
    if (bootExtractMethod == null && !bootExtractMethodLookupComplete) {
      synchronized (SSLStorage.class) {
        if (bootExtractMethod != null || bootExtractMethodLookupComplete) {
          return bootExtractMethod;
        }
        try {
          Class<?> extractorClass =
              Class.forName(
                  "io.opentelemetry.obi.java.instrumentations.util.NettyChannelExtractor",
                  true,
                  null); // null for bootstrap loader
          bootExtractMethod =
              extractorClass.getMethod("extractConnectionFromChannelHandlerContext", Object.class);
        } catch (Throwable failure) {
          logNettyAdviceFailure("resolve channel extractor", failure);
        } finally {
          bootExtractMethodLookupComplete = true;
        }
      }
    }
    return bootExtractMethod;
  }

  public static Field getBootNettyConnectionField() {
    if (bootNettyConnectionField == null && !bootNettyConnectionFieldLookupComplete) {
      synchronized (SSLStorage.class) {
        if (bootNettyConnectionField != null || bootNettyConnectionFieldLookupComplete) {
          return bootNettyConnectionField;
        }
        try {
          Class<?> sslStorageClass =
              Class.forName(
                  "io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
          bootNettyConnectionField = sslStorageClass.getDeclaredField("nettyConnection");
        } catch (Throwable failure) {
          logNettyAdviceFailure("resolve Netty connection storage", failure);
        } finally {
          bootNettyConnectionFieldLookupComplete = true;
        }
      }
    }

    return bootNettyConnectionField;
  }

  public static Field getBootDebugOn() {
    if (bootDebugOn == null && !bootDebugOnLookupComplete) {
      synchronized (SSLStorage.class) {
        if (bootDebugOn != null || bootDebugOnLookupComplete) {
          return bootDebugOn;
        }
        try {
          Class<?> sslStorageClass =
              Class.forName(
                  "io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
          bootDebugOn = sslStorageClass.getDeclaredField("debugOn");
        } catch (Throwable failure) {
          logNettyAdviceFailure("resolve debug state", failure);
        } finally {
          bootDebugOnLookupComplete = true;
        }
      }
    }

    return bootDebugOn;
  }

  public static Object bootDebugOn() {
    try {
      Field debugOn = getBootDebugOn();
      if (debugOn == null) {
        return false;
      }
      return debugOn.get(null);
    } catch (Throwable failure) {
      logNettyAdviceFailure("read debug state", failure);
    }

    return false;
  }

  public static void logNettyAdviceFailure(String operation, Throwable failure) {
    if (debugOn) {
      System.err.println("[SSLStorage] Failed to " + operation + ": " + failure);
    } else if (nettyFailureLogged.compareAndSet(false, true)) {
      System.err.println("[SSLStorage] Netty helper unavailable; TLS correlation will fail open");
    }
  }

  static void resetNettyFailureLoggingForTest() {
    nettyFailureLogged.set(false);
  }

  private static Lifecycle activeTaskLifecycle() {
    try {
      if (ThreadInfo.remoteParentLookupSource() == ThreadInfo.REMOTE_PARENT_LOOKUP_TASK) {
        Lifecycle relayed = ThreadInfo.remoteParentLookupLifecycle();
        return relayed != null && relayed.active() ? relayed : null;
      }
      if (!ThreadInfo.hasRemoteParentDirectReceiveAuthority()) {
        return null;
      }
      ArrayDeque<NettyHandlerScope> handlerScopes = nettyHandlerScopes.get();
      if (handlerScopes == null
          || handlerScopes.isEmpty()
          || !handlerScopes.peek().started
          || !handlerScopes.peek().receiving) {
        return null;
      }
      Object scoped = nettyConnection.get();
      if (!(scoped instanceof NettyConnectionScope)) {
        return null;
      }
      ConnectionOwner owner = ((NettyConnectionScope) scoped).owner;
      return isActive(owner) && owner.remoteParentLifecycle.active()
          ? owner.remoteParentLifecycle
          : null;
    } catch (Throwable ignored) {
      return null;
    }
  }

  public static void trackTask(long threadId, Object task) {
    if (task == null) {
      return;
    }
    tasks.track(task, ThreadInfo.captureTaskContext(threadId, activeTaskLifecycle()));
  }

  public static void untrackTask(Object task) {
    if (task == null) {
      return;
    }
    tasks.untrack(task);
  }

  public static void trackTaskCancellation(Object task, Object cancellationOwner) {
    if (task == null || cancellationOwner == null) {
      return;
    }
    tasks.trackCancellationOwner(task, cancellationOwner);
  }

  public static boolean transferTaskContext(Object source, Object target) {
    if (source == null || target == null) {
      return false;
    }
    return tasks.transfer(source, target);
  }

  public static int beginRejectedExecution(Object handler, Object queue) {
    String name = handler == null ? "" : handler.getClass().getName();
    if ("java.util.concurrent.ThreadPoolExecutor$DiscardOldestPolicy".equals(name)) {
      ArrayDeque<Object> queues = discardOldestQueues.get();
      if (queues == null) {
        queues = new ArrayDeque<>();
        discardOldestQueues.set(queues);
      }
      queues.push(queue);
      return REJECTION_DISCARD_OLDEST;
    }
    if ("java.util.concurrent.ThreadPoolExecutor$AbortPolicy".equals(name)
        || "java.util.concurrent.ThreadPoolExecutor$CallerRunsPolicy".equals(name)
        || "java.util.concurrent.ThreadPoolExecutor$DiscardPolicy".equals(name)) {
      return REJECTION_CLEAN_TASK;
    }
    return REJECTION_NONE;
  }

  public static void endRejectedExecution(int rejection, Object task, boolean executorShutdown) {
    if (rejection == REJECTION_CLEAN_TASK) {
      untrackTask(task);
      return;
    }
    if (rejection != REJECTION_DISCARD_OLDEST) {
      return;
    }

    ArrayDeque<Object> queues = discardOldestQueues.get();
    if (queues != null && !queues.isEmpty()) {
      queues.pop();
      if (queues.isEmpty()) {
        discardOldestQueues.remove();
      }
    }
    if (executorShutdown) {
      untrackTask(task);
    }
  }

  public static void onRejectedQueuePoll(Object queue, Object task) {
    ArrayDeque<Object> queues = discardOldestQueues.get();
    if (task != null && queues != null && !queues.isEmpty() && queues.peek() == queue) {
      untrackTask(task);
    }
  }

  public static boolean beginExecutorHook() {
    Integer depth = executorHookDepth.get();
    executorHookDepth.set(depth == null ? 1 : depth + 1);
    return depth == null;
  }

  public static void endExecutorBeforeHook(boolean outermost, Object task, boolean completed) {
    endExecutorHook();
    if (!outermost) {
      return;
    }
    if (!completed) {
      untrackTask(task);
      return;
    }

    ArrayDeque<Boolean> scopes = executorTaskScopes.get();
    if (scopes == null) {
      scopes = new ArrayDeque<>();
      executorTaskScopes.set(scopes);
    }
    scopes.push(Boolean.FALSE);

    TaskContext context = takeTaskContext(task);
    if (context == null) {
      return;
    }
    long threadId = currentThreadId();
    boolean linked =
        ThreadInfo.enterTaskParentThreadContext(
            threadId,
            context.getParentThreadId(),
            context.getHandoffToken(),
            context.getRemoteParentSocketContext(),
            context.getRemoteParentSocketLifecycle(),
            context.getRemoteParentReceiveContext(),
            context.getRemoteParentBridgeEpoch());
    if (linked) {
      scopes.pop();
      scopes.push(Boolean.TRUE);
    }
  }

  public static void endExecutorAfterHook(boolean outermost) {
    try {
      if (!outermost) {
        return;
      }
      ArrayDeque<Boolean> scopes = executorTaskScopes.get();
      if (scopes == null || scopes.isEmpty()) {
        return;
      }
      boolean linked = scopes.pop();
      if (scopes.isEmpty()) {
        executorTaskScopes.remove();
      }
      if (linked) {
        ThreadInfo.restoreTaskParentThreadContext();
      }
    } finally {
      endExecutorHook();
    }
  }

  private static void endExecutorHook() {
    Integer depth = executorHookDepth.get();
    if (depth == null || depth <= 1) {
      executorHookDepth.remove();
    } else {
      executorHookDepth.set(depth - 1);
    }
  }

  public static TaskContext taskContext(Object task) {
    if (task == null) {
      return null;
    }

    return tasks.get(task);
  }

  public static TaskContext takeTaskContext(Object task) {
    if (task == null) {
      return null;
    }

    return tasks.take(task);
  }

  public static boolean enterTaskScope(Object task) {
    TaskContext context = takeTaskContext(task);
    if (context == null) {
      return false;
    }

    long threadId = currentThreadId();
    long parentThreadId = context.getParentThreadId();
    if (parentThreadId != threadId || context.getHandoffToken() != 0L) {
      return ThreadInfo.enterTaskParentThreadContext(
          threadId,
          parentThreadId,
          context.getHandoffToken(),
          context.getRemoteParentSocketContext(),
          context.getRemoteParentSocketLifecycle(),
          context.getRemoteParentReceiveContext(),
          context.getRemoteParentBridgeEpoch());
    }
    ThreadInfo.cancelTaskContext(context);
    return false;
  }

  public static void captureVirtualThread(Object virtualThread) {
    if (ThreadInfo.isRemoteParentEnabled()) {
      trackTask(currentThreadId(), virtualThread);
    }
  }

  public static void enterVirtualThreadScope(Object virtualThread) {
    if (virtualThreadTaskScope.get() != null) {
      return;
    }
    TaskContext context = takeTaskContext(virtualThread);
    if (context == null) {
      return;
    }
    boolean linked =
        ThreadInfo.enterTaskParentThreadContext(
            currentThreadId(),
            context.getParentThreadId(),
            context.getHandoffToken(),
            context.getRemoteParentSocketContext(),
            context.getRemoteParentSocketLifecycle(),
            context.getRemoteParentReceiveContext(),
            context.getRemoteParentBridgeEpoch());
    virtualThreadTaskScope.set(linked);
  }

  public static void exitVirtualThreadScope(Object virtualThread) {
    untrackTask(virtualThread);
    Boolean linked = virtualThreadTaskScope.get();
    virtualThreadTaskScope.remove();
    if (Boolean.TRUE.equals(linked)) {
      ThreadInfo.restoreTaskParentThreadContext();
    }
  }

  public static int beginTaskSubmission(long threadId, Object task) {
    if (task == null) {
      return SUBMISSION_NESTED;
    }

    IdentityHashMap<Object, Integer> submissions = activeTaskSubmissions.get();
    if (submissions == null) {
      submissions = new IdentityHashMap<>();
      activeTaskSubmissions.set(submissions);
    }
    Integer depth = submissions.get(task);
    if (depth != null) {
      submissions.put(task, depth + 1);
      return SUBMISSION_NESTED;
    }

    submissions.put(task, 1);
    trackTask(threadId, task);
    return SUBMISSION_OWNER;
  }

  public static void endTaskSubmission(Object task) {
    IdentityHashMap<Object, Integer> submissions = activeTaskSubmissions.get();
    if (submissions == null || task == null) {
      return;
    }
    Integer depth = submissions.get(task);
    if (depth == null) {
      return;
    }
    if (depth > 1) {
      submissions.put(task, depth - 1);
      return;
    }
    submissions.remove(task);
    if (submissions.isEmpty()) {
      activeTaskSubmissions.remove();
    }
  }

  public static long currentThreadId() {
    LongSupplier provider = threadIdProviderForTest;
    return provider == null
        ? io.opentelemetry.obi.java.BootstrapNative.gettid()
        : provider.getAsLong();
  }

  static void setThreadIdProviderForTest(LongSupplier provider) {
    threadIdProviderForTest = provider;
  }

  static void setTlsConnectionMarkerClockForTest(LongSupplier clock) {
    tlsConnectionMarkerClockForTest = clock;
  }

  static void setBeforeLegacyReceiveEmitForTest(Runnable callback) {
    beforeLegacyReceiveEmitForTest = callback;
  }

  static final class TlsConnectionMarkerAttempt {
    private final ConnectionOwner owner;
    private final long processIncarnation;
    private final int attempts;
    private final long nextAttemptNanos;

    TlsConnectionMarkerAttempt(
        ConnectionOwner owner, long processIncarnation, int attempts, long nextAttemptNanos) {
      this.owner = owner;
      this.processIncarnation = processIncarnation;
      this.attempts = attempts;
      this.nextAttemptNanos = nextAttemptNanos;
    }

    private boolean matches(ConnectionOwner candidate, long candidateIncarnation) {
      return owner == candidate && processIncarnation == candidateIncarnation;
    }
  }

  static final class BufferHandoff {
    private final ConnectionOwner owner;
    private final int state;
    private final BufferHandoff generation;

    BufferHandoff(ConnectionOwner owner, int state) {
      this.owner = owner;
      this.state = state;
      this.generation = this;
    }

    BufferHandoff(BufferHandoff handoff, int state) {
      this.owner = handoff.owner;
      this.state = state;
      this.generation = handoff.generation;
    }
  }

  static final class ConnectionOwner implements Lifecycle.ActiveCheck {
    private final ExactConnection key;
    private final Connection connection;
    private final WeakReference<Object> physicalOwner;
    private final Lifecycle remoteParentLifecycle;
    private final long remoteParentBridgeEpoch;
    private final RemoteParentHttp1Receive remoteParentHttp1Receive;
    private volatile boolean active = true;

    ConnectionOwner(ExactConnection key, Object physicalOwner) {
      this.key = key;
      this.connection = key.connection;
      this.physicalOwner = new WeakReference<Object>(physicalOwner);
      this.remoteParentLifecycle = new Lifecycle(this.physicalOwner, this);
      this.remoteParentBridgeEpoch = ThreadInfo.remoteParentBridgeEpoch();
      this.remoteParentHttp1Receive =
          new RemoteParentHttp1Receive(this.remoteParentLifecycle, this.remoteParentBridgeEpoch);
      this.connection.setOwnerToken(this);
    }

    boolean hasPhysicalOwner(Object candidate) {
      return candidate != null && physicalOwner.get() == candidate;
    }

    @Override
    public boolean active() {
      return isRegistered(this);
    }
  }

  static final class SocketOwner {
    private final Lifecycle lifecycle;
    private final RemoteParentHttp1Receive receive;
    private final AtomicBoolean unsupportedRecorded = new AtomicBoolean();

    SocketOwner(Socket socket) {
      this.lifecycle = new Lifecycle(socket);
      this.receive =
          new RemoteParentHttp1Receive(this.lifecycle, ThreadInfo.remoteParentBridgeEpoch());
    }

    SocketOwner(Lifecycle tombstone) {
      this.lifecycle = tombstone;
      this.receive = null;
    }

    void close(Socket socket) {
      if (receive != null) {
        receive.close(socket);
      }
    }
  }

  static final class ActiveConnectionEvictionListener
      implements CappedConcurrentHashMap.EvictionListener<ConnectionOwner> {
    @Override
    public void onEviction(ConnectionOwner owner) {
      cleanupConnectionOwner(owner);
    }
  }

  private static final class ChannelState {
    private ConnectionOwner owner;
    private boolean closed;

    ChannelState() {}
  }

  private static final class NettyConnectionScope {
    private final ConnectionOwner owner;

    NettyConnectionScope(ConnectionOwner owner) {
      this.owner = owner;
    }
  }

  private static final class NettyHandlerScope {
    private boolean started;
    private boolean receiving;

    NettyHandlerScope() {}
  }

  static final class ExactConnection {
    private final Connection connection;
    private final int hash;

    ExactConnection(Connection connection) {
      this.connection = connection;
      this.hash = 31 * connection.hashCode() + connection.getSocketFileDescriptor();
    }

    @Override
    public int hashCode() {
      return hash;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      if (!(other instanceof ExactConnection)) {
        return false;
      }
      return sameExactConnection(connection, ((ExactConnection) other).connection);
    }
  }
}
