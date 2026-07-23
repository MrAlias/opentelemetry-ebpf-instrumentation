/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.util.CappedConcurrentHashMap;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
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

  private static final int MAX_CONCURRENT = 10_000;
  static final int TLS_CONNECTION_MARKER_BURST_ATTEMPTS = 8;
  static final long TLS_CONNECTION_MARKER_RETRY_NANOS = 1_000_000_000L;
  private static final WeakIdentityConcurrentMap<ConnectionOwner> sslConnections =
      new WeakIdentityConcurrentMap<>(MAX_CONCURRENT);
  private static final WeakIdentityConcurrentMap<TlsConnectionMarkerAttempt> tlsConnectionMarkers =
      new WeakIdentityConcurrentMap<>(MAX_CONCURRENT);
  private static final CappedConcurrentHashMap<String, BytesWithLen> bufToBuf =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);

  private static final int BUFFER_HANDOFF_AVAILABLE = 0;
  private static final int BUFFER_HANDOFF_CLAIMING = 1;
  private static final int BUFFER_HANDOFF_CONSUMED = 2;
  private static final int BUFFER_HANDOFF_AMBIGUOUS = 3;
  private static final BufferHandoff AMBIGUOUS_BUFFER_HANDOFF =
      new BufferHandoff(null, BUFFER_HANDOFF_AMBIGUOUS);
  private static final WeakIdentityConcurrentMap<BufferHandoff> readBufferConnections =
      new WeakIdentityConcurrentMap<>(MAX_CONCURRENT);
  private static final CappedConcurrentHashMap<ExactConnection, ConnectionOwner> activeConnections =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);

  private static final WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(MAX_CONCURRENT);
  private static final ThreadLocal<IdentityHashMap<Object, Integer>> activeTaskSubmissions =
      new ThreadLocal<>();
  private static final ThreadLocal<ArrayDeque<Object>> discardOldestQueues = new ThreadLocal<>();
  private static final ThreadLocal<Integer> executorHookDepth = new ThreadLocal<>();
  private static final ThreadLocal<ArrayDeque<Boolean>> executorTaskScopes = new ThreadLocal<>();
  private static final ThreadLocal<Boolean> virtualThreadTaskScope = new ThreadLocal<>();
  private static volatile LongSupplier threadIdProviderForTest;
  private static volatile LongSupplier tlsConnectionMarkerClockForTest;
  private static final Object NO_NETTY_CONNECTION = new Object();
  private static final ThreadLocal<ArrayDeque<Object>> nettyConnectionScopes = new ThreadLocal<>();

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
    Connection scoped = scopedValue instanceof Connection ? (Connection) scopedValue : null;

    if (scoped != null) {
      if (scoped.getSocketFileDescriptor() >= 0) {
        ConnectionOwner scopedOwner = activeConnectionOwner(scoped);
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
      if (correlated == AMBIGUOUS_BUFFER_HANDOFF
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
    Connection scopedNow = currentScopedConnection();
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
    if (candidate == AMBIGUOUS_BUFFER_HANDOFF || buffer == null) {
      return null;
    }

    if (candidate.state == BUFFER_HANDOFF_CLAIMING) {
      makeCurrentBufferHandoffAmbiguous(buffer);
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
    BufferHandoff claiming = new BufferHandoff(candidate.owner, BUFFER_HANDOFF_CLAIMING);
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

      BufferHandoff consumed = new BufferHandoff(candidate.owner, BUFFER_HANDOFF_CONSUMED);
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
        makeCurrentBufferHandoffAmbiguous(buffer);
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
      if (observed == AMBIGUOUS_BUFFER_HANDOFF) {
        return;
      }
      BufferHandoff replacement =
          observed.state != BUFFER_HANDOFF_CLAIMING
                  && (observed.owner == owner || !isActive(observed.owner))
              ? candidate
              : AMBIGUOUS_BUFFER_HANDOFF;
      if (readBufferConnections.replace(buffer, observed, replacement)) {
        return;
      }
    }
  }

  public static void cleanupConnection(Connection connection) {
    if (connection == null || connection.getSocketFileDescriptor() < 0) {
      return;
    }
    ExactConnection key = new ExactConnection(connection);
    ConnectionOwner owner = activeConnections.get(key);
    if (owner != null && activeConnections.remove(key, owner)) {
      owner.active = false;
    }
  }

  private static ConnectionOwner activeConnectionOwner(Connection connection) {
    ExactConnection key = new ExactConnection(connection);
    while (true) {
      ConnectionOwner owner = activeConnections.get(key);
      if (owner != null) {
        return owner;
      }
      ConnectionOwner candidate = new ConnectionOwner(key);
      owner = activeConnections.putIfAbsent(key, candidate);
      if (owner != null) {
        return owner;
      }
      return activeConnections.get(key) == candidate ? candidate : null;
    }
  }

  private static boolean isActive(ConnectionOwner owner) {
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
    return value instanceof Connection ? (Connection) value : null;
  }

  private static void consumeScopedBufferHandoff(
      ByteBuffer buffer, Object handoff, ConnectionOwner owner) {
    BufferHandoff captured = asBufferHandoff(handoff);
    while (buffer != null) {
      BufferHandoff current = readBufferConnections.get(buffer);
      if (current == null || current == AMBIGUOUS_BUFFER_HANDOFF) {
        return;
      }
      if (current == captured
          && current.owner == owner
          && current.state == BUFFER_HANDOFF_CONSUMED) {
        return;
      }
      if (current == captured
          && current.owner == owner
          && current.state == BUFFER_HANDOFF_AVAILABLE) {
        BufferHandoff consumed = new BufferHandoff(owner, BUFFER_HANDOFF_CONSUMED);
        if (readBufferConnections.replace(buffer, current, consumed)) {
          return;
        }
      } else if (readBufferConnections.replace(buffer, current, AMBIGUOUS_BUFFER_HANDOFF)) {
        return;
      }
    }
  }

  private static void makeFailedTakeAmbiguous(ByteBuffer buffer, BufferHandoff candidate) {
    while (buffer != null) {
      BufferHandoff current = readBufferConnections.get(buffer);
      if (current == null || current == AMBIGUOUS_BUFFER_HANDOFF) {
        return;
      }
      if (current.state == BUFFER_HANDOFF_CONSUMED && current.owner == candidate.owner) {
        return;
      }
      if (readBufferConnections.replace(buffer, current, AMBIGUOUS_BUFFER_HANDOFF)) {
        return;
      }
    }
  }

  private static void makeCurrentBufferHandoffAmbiguous(ByteBuffer buffer) {
    while (buffer != null) {
      BufferHandoff current = readBufferConnections.get(buffer);
      if (current == null || current == AMBIGUOUS_BUFFER_HANDOFF) {
        return;
      }
      if (readBufferConnections.replace(buffer, current, AMBIGUOUS_BUFFER_HANDOFF)) {
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

  public static void trackTask(long threadId, Object task) {
    if (task == null) {
      return;
    }
    tasks.track(task, ThreadInfo.captureTaskContext(threadId));
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
            threadId, context.getParentThreadId(), context.getHandoffToken());
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
          threadId, parentThreadId, context.getHandoffToken());
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
            currentThreadId(), context.getParentThreadId(), context.getHandoffToken());
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

    BufferHandoff(ConnectionOwner owner, int state) {
      this.owner = owner;
      this.state = state;
    }
  }

  static final class ConnectionOwner {
    private final ExactConnection key;
    private final Connection connection;
    private volatile boolean active = true;

    ConnectionOwner(ExactConnection key) {
      this.key = key;
      this.connection = key.connection;
    }
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
