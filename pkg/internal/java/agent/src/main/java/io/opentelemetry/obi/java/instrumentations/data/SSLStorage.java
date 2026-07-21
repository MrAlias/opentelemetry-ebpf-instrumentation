/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.util.CappedConcurrentHashMap;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayDeque;
import java.util.IdentityHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;
import javax.net.ssl.SSLEngine;

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
  private static final CappedConcurrentHashMap<SSLEngine, Connection> sslConnections =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);
  private static final CappedConcurrentHashMap<String, BytesWithLen> bufToBuf =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);

  private static final CappedConcurrentHashMap<String, Connection> bufConn =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);

  private static final CappedConcurrentHashMap<Connection, Connection> activeConnections =
      new CappedConcurrentHashMap<>(MAX_CONCURRENT);

  private static final WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(MAX_CONCURRENT);
  private static final ThreadLocal<IdentityHashMap<Object, Integer>> activeTaskSubmissions =
      new ThreadLocal<>();
  private static final ThreadLocal<ArrayDeque<Object>> discardOldestQueues = new ThreadLocal<>();
  private static final ThreadLocal<Integer> executorHookDepth = new ThreadLocal<>();
  private static final ThreadLocal<ArrayDeque<Boolean>> executorTaskScopes = new ThreadLocal<>();
  private static final ThreadLocal<Boolean> virtualThreadTaskScope = new ThreadLocal<>();
  private static volatile LongSupplier threadIdProviderForTest;
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
    return sslConnections.get(session);
  }

  public static void setConnectionForSession(SSLEngine session, Connection c) {
    sslConnections.put(session, c);
  }

  public static Connection getConnectionForBuf(String buf) {
    return bufConn.get(buf);
  }

  public static boolean connectionUntracked(Connection c) {
    return activeConnections.get(c) == null;
  }

  public static Connection getActiveConnection(Connection c) {
    return activeConnections.get(c);
  }

  public static void setConnectionForBuf(String buf, Connection c) {
    c.setBufferKey(buf);
    bufConn.put(buf, c);
    activeConnections.put(c, c);
  }

  public static void cleanupConnectionBufMapping(Connection c) {
    bufConn.remove(c.getBufferKey());
    activeConnections.remove(c);
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
}
