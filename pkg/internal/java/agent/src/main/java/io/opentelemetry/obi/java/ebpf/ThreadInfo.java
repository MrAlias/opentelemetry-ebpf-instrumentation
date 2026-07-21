/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

public class ThreadInfo {
  static final long NO_TASK_RELAY_CHANGE = -1L;
  static final int MAX_TASK_RELAY_DEPTH = 64;

  private static final ThreadLocal<TaskRelayState> taskRelayState = new ThreadLocal<>();
  private static final ThreadLocal<Integer> remoteParentSocketFileDescriptor = new ThreadLocal<>();
  private static final AtomicLong nextTaskToken = new AtomicLong(initialTaskToken());
  private static volatile LongSupplier processIncarnationSource = ThreadInfo::newProcessIncarnation;
  private static volatile long processIncarnation = initialProcessIncarnation();
  private static volatile boolean remoteParentEnabled;
  private static volatile TaskContextEmitter taskContextEmitterForTest;

  public static int writeThreadContext(NativeMemory mem, int off, long parentId) {
    mem.setLong(off, parentId);
    off += Long.BYTES;
    return off;
  }

  public static void sendParentThreadContext(long parentId) {
    TaskContextEmitter testEmitter = taskContextEmitterForTest;
    if (testEmitter != null) {
      testEmitter.emit(OperationType.THREAD, parentId, 0L);
      return;
    }
    NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize);
    IOCTLPacket.writePacket(p, 0, OperationType.THREAD, parentId);
    BootstrapNative.ioctl(0, BootstrapNative.IOCTL_CMD, p.getAddress());
  }

  public static TaskContext captureTaskContext(long parentThreadId) {
    if (!remoteParentEnabled) {
      return new TaskContext(onVirtualThread() ? 0L : parentThreadId, 0L);
    }

    long token = newTaskToken();
    emitTaskContextOp(OperationType.TASK_CAPTURE, token, 0L);
    return new TaskContext(parentThreadId, token);
  }

  public static void cancelTaskContext(TaskContext context) {
    if (context != null) {
      cancelTaskHandoff(context.getHandoffToken());
    }
  }

  private static void cancelTaskHandoff(long token) {
    if (token != 0L) {
      emitTaskContextOp(OperationType.TASK_CANCEL, token, 0L);
    }
  }

  // Legacy emit variant retained for callers without an exact handoff token.
  public static boolean enterTaskParentThreadContext(long threadId, long parentId) {
    return enterTaskParentThreadContext(threadId, parentId, 0L);
  }

  public static boolean enterTaskParentThreadContext(
      long threadId, long parentId, long handoffToken) {
    if (onVirtualThread() && handoffToken == 0L) {
      cancelTaskHandoff(handoffToken);
      return false;
    }

    TaskRelayState state = taskRelayState.get();
    if (parentId <= 0 || (parentId == threadId && handoffToken == 0L)) {
      cancelTaskHandoff(handoffToken);
      return false;
    }
    if (!remoteParentEnabled && state == null) {
      cancelTaskHandoff(handoffToken);
      sendParentThreadContext(parentId);
      return false;
    }

    if (state != null && state.hasParent(parentId) && handoffToken == 0L) {
      failClosedTaskEntry(handoffToken, 0L);
      return false;
    }

    if (state == null) {
      state = new TaskRelayState();
      taskRelayState.set(state);
    }

    long restoreToken = state.isEmpty() ? 0L : captureRelayToken();
    long target = state.enter(threadId, parentId, restoreToken, handoffToken != 0L);
    if (target == NO_TASK_RELAY_CHANGE) {
      failClosedTaskEntry(handoffToken, restoreToken);
      if (state.isEmpty()) {
        taskRelayState.remove();
      }
      return false;
    }

    try {
      emitTaskContextOp(OperationType.TASK_LINK, target, handoffToken);
      return true;
    } catch (Throwable failure) {
      state.exit();
      cancelTaskHandoff(handoffToken);
      cancelTaskHandoff(restoreToken);
      if (state.isEmpty()) {
        taskRelayState.remove();
      }
      throw failure;
    }
  }

  public static void restoreTaskParentThreadContext() {
    TaskRelayState state = taskRelayState.get();
    if (state == null) {
      return;
    }

    long threadId = state.threadId();
    long target = state.exit();
    long restoreToken = state.exitToken();
    if (state.isEmpty()) {
      taskRelayState.remove();
    }
    if (target != NO_TASK_RELAY_CHANGE) {
      emitTaskContextOp(OperationType.TASK_LINK, target, restoreToken);
    }
  }

  public static void setRemoteParentEnabled(boolean enabled) {
    remoteParentEnabled = enabled;
  }

  public static boolean isRemoteParentEnabled() {
    return remoteParentEnabled;
  }

  public static void setRemoteParentSocketFileDescriptor(int socketFileDescriptor) {
    if (socketFileDescriptor >= 0) {
      remoteParentSocketFileDescriptor.set(socketFileDescriptor);
    } else {
      remoteParentSocketFileDescriptor.remove();
    }
  }

  public static int remoteParentSocketFileDescriptor() {
    Integer socketFileDescriptor = remoteParentSocketFileDescriptor.get();
    return socketFileDescriptor == null ? -1 : socketFileDescriptor;
  }

  public static void clearRemoteParentSocketFileDescriptor() {
    remoteParentSocketFileDescriptor.remove();
  }

  public static boolean registerProcessIncarnation() {
    long incarnation = processIncarnation();
    if (incarnation == 0L) {
      return false;
    }
    emitVirtualThreadOp(OperationType.PROCESS_REGISTER, incarnation);
    return true;
  }

  public static synchronized void setProcessIncarnation(long capability) {
    if (capability <= 0L) {
      throw new IllegalArgumentException("process capability must be positive");
    }
    processIncarnation = capability;
  }

  public static long processIncarnation() {
    long incarnation = processIncarnation;
    if (incarnation != 0L) {
      return incarnation;
    }
    synchronized (ThreadInfo.class) {
      if (processIncarnation == 0L) {
        processIncarnation = initialProcessIncarnation();
      }
      return processIncarnation;
    }
  }

  static boolean hasTaskRelayState() {
    return taskRelayState.get() != null;
  }

  static void setTaskContextEmitterForTest(TaskContextEmitter emitter) {
    taskContextEmitterForTest = emitter;
  }

  static void setProcessIncarnationSourceForTest(LongSupplier source) {
    synchronized (ThreadInfo.class) {
      processIncarnationSource = source == null ? ThreadInfo::newProcessIncarnation : source;
      processIncarnation = 0L;
    }
  }

  // Cheap virtual-thread check that compiles on Java 8 (no Thread.isVirtual()
  // in the agent's compile target): java.lang.VirtualThread is final, so the
  // class-name comparison is exact.
  public static boolean onVirtualThread() {
    return "java.lang.VirtualThread".equals(Thread.currentThread().getClass().getName());
  }

  // True for Loom scheduler-internal task objects: the per-VT runContinuation
  // lambda (hidden class named "java.lang.VirtualThread$$Lambda/0x...") and
  // the VirtualThread$VThreadContinuation wrappers. They pass through the
  // instrumented Executor surface on every unpark, submitted from platform
  // threads, so a current-thread check cannot filter them.
  public static boolean loomTask(Object task) {
    return task != null && task.getClass().getName().startsWith("java.lang.VirtualThread");
  }

  // Called at VirtualThread.mount() EXIT, when Thread.currentThread() is
  // already the virtual thread. Thread.getId() (same value as threadId())
  // keeps the agent compatible with its Java 8 compile target.
  public static void onVirtualThreadMount() {
    onVirtualThreadMount(Thread.currentThread().getId());
  }

  public static void onVirtualThreadMount(long virtualThreadId) {
    emitVirtualThreadOp(OperationType.VT_MOUNT, virtualThreadId);
  }

  // Called at VirtualThread.unmount() EXIT. Deletes java_vt_threads[carrier]
  // so a carrier with no mounted VT is never translated. No compare-and-delete
  // is needed: mount and unmount for a given carrier always execute on that
  // carrier OS thread, so its map entry is written and deleted in program
  // order.
  public static void onVirtualThreadUnmount() {
    emitVirtualThreadOp(OperationType.VT_UNMOUNT, 0L);
  }

  public static void onVirtualThreadTerminate(long virtualThreadId) {
    emitVirtualThreadOp(OperationType.VT_TERMINATE, virtualThreadId);
  }

  private static long captureRelayToken() {
    long token = newTaskToken();
    emitTaskContextOp(OperationType.TASK_RELAY_CAPTURE, token, 0L);
    return token;
  }

  private static long newTaskToken() {
    long token;
    do {
      token = nextTaskToken.getAndIncrement();
    } while (token == 0L);
    return token;
  }

  private static long initialTaskToken() {
    long seed = System.nanoTime() ^ System.currentTimeMillis();
    seed ^= (long) System.identityHashCode(ThreadInfo.class) << 32;
    return seed == 0L ? 1L : seed;
  }

  private static long initialProcessIncarnation() {
    try {
      long value = processIncarnationSource.getAsLong();
      return value;
    } catch (Throwable ignored) {
      return 0L;
    }
  }

  private static long newProcessIncarnation() {
    return new SecureRandom().nextLong();
  }

  private static void failClosedTaskEntry(long handoffToken, long restoreToken) {
    try {
      emitTaskContextOp(OperationType.TASK_UNLINK, 0L, 0L);
    } finally {
      cancelTaskHandoff(handoffToken);
      cancelTaskHandoff(restoreToken);
    }
  }

  private static void emitTaskContextOp(OperationType operation, long value, long token) {
    TaskContextEmitter testEmitter = taskContextEmitterForTest;
    if (testEmitter != null) {
      testEmitter.emit(operation, value, token);
      return;
    }
    BootstrapNative.emitTaskContextOp(operation.code, value, token);
  }

  private static void emitVirtualThreadOp(OperationType operation, long value) {
    TaskContextEmitter testEmitter = taskContextEmitterForTest;
    if (testEmitter != null) {
      testEmitter.emit(operation, value, 0L);
      return;
    }
    BootstrapNative.emitVirtualThreadOp(operation.code, value);
  }

  static final class TaskRelayState {
    private long threadId;
    private long currentParent;
    private long[] previousParents = new long[4];
    private long[] previousTokens = new long[4];
    private long exitToken;
    private int depth;

    long enter(long currentThreadId, long parentId, long restoreToken, boolean exactTokenHandoff) {
      if (parentId <= 0
          || depth >= MAX_TASK_RELAY_DEPTH
          || (!exactTokenHandoff && hasParent(parentId))) {
        return NO_TASK_RELAY_CHANGE;
      }

      if (depth == 0) {
        threadId = currentThreadId;
      }
      if (depth == previousParents.length) {
        long[] expanded = new long[previousParents.length * 2];
        System.arraycopy(previousParents, 0, expanded, 0, previousParents.length);
        previousParents = expanded;
        long[] expandedTokens = new long[previousTokens.length * 2];
        System.arraycopy(previousTokens, 0, expandedTokens, 0, previousTokens.length);
        previousTokens = expandedTokens;
      }
      previousParents[depth] = currentParent;
      previousTokens[depth] = restoreToken;
      depth++;
      currentParent = parentId;
      return parentId;
    }

    long exit() {
      if (depth == 0) {
        return NO_TASK_RELAY_CHANGE;
      }

      long previous = previousParents[--depth];
      exitToken = previousTokens[depth];
      previousParents[depth] = 0L;
      previousTokens[depth] = 0L;
      currentParent = previous;
      return previous == 0 ? threadId : previous;
    }

    boolean isEmpty() {
      return depth == 0;
    }

    boolean requiresReset() {
      return depth > 1;
    }

    long threadId() {
      return threadId;
    }

    boolean hasParent(long parentId) {
      if (currentParent == parentId) {
        return true;
      }
      for (int i = 0; i < depth; i++) {
        if (previousParents[i] == parentId) {
          return true;
        }
      }
      return false;
    }

    long exitToken() {
      return exitToken;
    }
  }

  interface TaskContextEmitter {
    void emit(OperationType operation, long value, long token);
  }
}
