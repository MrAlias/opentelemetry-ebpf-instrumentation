/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

public class ThreadInfo {
  static final long NO_TASK_RELAY_CHANGE = -1L;
  static final int MAX_TASK_RELAY_DEPTH = 64;
  private static final byte LOOKUP_DEFAULT = 0;
  private static final byte LOOKUP_DIRECT = 1;
  private static final byte LOOKUP_TASK = 2;
  private static final byte LOOKUP_BLOCKED = 3;

  public static final int REMOTE_PARENT_LOOKUP_DIRECT = 1;
  public static final int REMOTE_PARENT_LOOKUP_TASK = 2;
  public static final int REMOTE_PARENT_LOOKUP_BLOCKED = 3;

  private static final ThreadLocal<TaskRelayState> taskRelayState = new ThreadLocal<>();
  private static final ThreadLocal<RemoteParentSocketContext> remoteParentSocketContext =
      new ThreadLocal<>();
  private static final ThreadLocal<Byte> remoteParentLookupOverride = new ThreadLocal<>();
  private static final ThreadLocal<RemoteParentSocketContext.Lifecycle>
      remoteParentLookupLifecycle = new ThreadLocal<>();
  private static final ThreadLocal<Integer> remoteParentReceiveDepth = new ThreadLocal<>();
  private static final ThreadLocal<Long> remoteParentReceiveEpoch = new ThreadLocal<>();
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
    // Preserve binary compatibility for older instrumentations without letting an unscoped caller
    // acquire a strict BPF generation alias.
    return captureTaskContext(parentThreadId, null);
  }

  /**
   * Captures a strict remote-parent handoff only for an exact active transport scope.
   *
   * <p>Tasks submitted outside the TLS handler keep ordinary parent-thread propagation without
   * acquiring a BPF generation alias. Unix transport has no Java descriptor context, so an active
   * lifecycle permits a capture attempt; BPF still requires a generation staged directly by the
   * current receive. A descriptor context is copied only when it belongs to that same lifecycle.
   */
  public static TaskContext captureTaskContext(
      long parentThreadId, RemoteParentSocketContext.Lifecycle lifecycle) {
    if (!remoteParentEnabled
        || lifecycle == null
        || !lifecycle.active()
        || !hasRemoteParentDirectReceiveAuthority()
        || remoteParentLookupLifecycle.get() != lifecycle
        || onVirtualThread()) {
      return new TaskContext(onVirtualThread() ? 0L : parentThreadId, 0L);
    }

    RemoteParentSocketContext socketContext = remoteParentSocketContext.get();
    if (socketContext != null && !socketContext.hasLifecycle(lifecycle)) {
      // A descriptorless receive can be a Unix transport, but a present socket context is
      // positive evidence about the BPF generation currently owned by this execution. Never let
      // a different lifecycle authorize an alias of that generation.
      return new TaskContext(parentThreadId, 0L);
    }
    if (socketContext != null && socketContext.peek() < 0) {
      // The one-shot descriptor may already have been claimed while the exact lifecycle remains
      // active. Further task aliases for that same generation are still valid.
      socketContext = null;
    }
    long token = newTaskToken();
    emitTaskContextOp(OperationType.TASK_CAPTURE, token, 0L);
    return new TaskContext(parentThreadId, token, socketContext, lifecycle);
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
    return enterTaskParentThreadContext(threadId, parentId, handoffToken, null, null);
  }

  public static boolean enterTaskParentThreadContext(
      long threadId, long parentId, long handoffToken, RemoteParentSocketContext socketContext) {
    return enterTaskParentThreadContext(
        threadId,
        parentId,
        handoffToken,
        socketContext,
        socketContext == null ? null : socketContext.lifecycle());
  }

  public static boolean enterTaskParentThreadContext(
      long threadId,
      long parentId,
      long handoffToken,
      RemoteParentSocketContext socketContext,
      RemoteParentSocketContext.Lifecycle socketLifecycle) {
    if (onVirtualThread() && handoffToken == 0L) {
      rejectTaskEntry(handoffToken);
      return false;
    }

    TaskRelayState state = taskRelayState.get();
    if (parentId <= 0 || (parentId == threadId && handoffToken == 0L)) {
      rejectTaskEntry(handoffToken);
      return false;
    }
    if (handoffToken != 0L
        && (socketLifecycle != null && !socketLifecycle.active()
            || socketContext != null
                && socketLifecycle != null
                && !socketContext.hasLifecycle(socketLifecycle))) {
      rejectTaskEntry(handoffToken);
      return false;
    }
    if (!remoteParentEnabled && state == null) {
      try {
        cancelTaskHandoff(handoffToken);
        sendParentThreadContext(parentId);
      } finally {
        remoteParentSocketContext.remove();
        blockRemoteParentLookup();
      }
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

    boolean exactTokenHandoff = handoffToken != 0L;
    long restoreToken = state.isEmpty() || !state.currentExact() ? 0L : captureRelayToken();
    byte previousLookupOverride = currentRemoteParentLookupOverride();
    long previousReceiveEpoch = currentRemoteParentReceiveEpoch();
    RemoteParentSocketContext.Lifecycle previousLookupLifecycle = remoteParentLookupLifecycle.get();
    long target =
        state.enter(
            threadId,
            parentId,
            restoreToken,
            exactTokenHandoff,
            remoteParentSocketContext.get(),
            previousLookupOverride,
            previousReceiveEpoch,
            previousLookupLifecycle);
    if (target == NO_TASK_RELAY_CHANGE) {
      failClosedTaskEntry(handoffToken, restoreToken);
      if (state.isEmpty()) {
        taskRelayState.remove();
      }
      return false;
    }

    if (exactTokenHandoff) {
      remoteParentLookupOverride.set(LOOKUP_TASK);
      setRemoteParentLookupLifecycle(socketLifecycle);
    } else {
      blockRemoteParentLookup();
    }
    try {
      emitTaskParentContext(target, handoffToken, exactTokenHandoff);
      setRemoteParentSocketContext(socketContext);
      return true;
    } catch (Throwable failure) {
      remoteParentSocketContext.remove();
      state.exit();
      blockRemoteParentLookup();
      bestEffortUnlinkTask(failure);
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
    boolean restoreExact = state.exitExact();
    RemoteParentSocketContext previousSocketContext = state.exitSocketContext();
    byte previousLookupOverride = state.exitLookupOverride();
    long previousReceiveEpoch = state.exitReceiveEpoch();
    RemoteParentSocketContext.Lifecycle previousLookupLifecycle = state.exitLookupLifecycle();
    if (state.isEmpty()) {
      taskRelayState.remove();
    }
    boolean restoreSucceeded = false;
    try {
      if (target != NO_TASK_RELAY_CHANGE) {
        emitTaskParentContext(target, restoreToken, restoreExact);
      }
      restoreSucceeded = true;
    } catch (Throwable failure) {
      bestEffortUnlinkTask(failure);
      throw failure;
    } finally {
      if (restoreSucceeded
          && restoreRemoteParentLookup(
              previousLookupOverride, previousReceiveEpoch, previousLookupLifecycle)) {
        setRemoteParentSocketContext(previousSocketContext);
      } else {
        if (previousSocketContext != null) {
          previousSocketContext.discard();
        }
        remoteParentSocketContext.remove();
        blockRemoteParentLookup();
      }
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
      remoteParentSocketContext.set(new RemoteParentSocketContext(socketFileDescriptor));
    } else {
      remoteParentSocketContext.remove();
    }
  }

  /**
   * Stages a descriptor only while the exact socket or connection lifecycle remains live.
   *
   * <p>The lifecycle is shared with queued task handoffs, so its invalidation makes every alias
   * fail closed without changing ordinary detach-only cleanup semantics.
   */
  public static boolean setRemoteParentSocketFileDescriptor(
      int socketFileDescriptor, RemoteParentSocketContext.Lifecycle lifecycle) {
    if (socketFileDescriptor < 0 || lifecycle == null || !lifecycle.active()) {
      remoteParentSocketContext.remove();
      return false;
    }
    remoteParentSocketContext.set(new RemoteParentSocketContext(socketFileDescriptor, lifecycle));
    return true;
  }

  public static int remoteParentSocketFileDescriptor() {
    RemoteParentSocketContext context = remoteParentSocketContext.get();
    return context == null ? -1 : context.peek();
  }

  public static int takeRemoteParentSocketFileDescriptor() {
    RemoteParentSocketContext context = takeRemoteParentSocketContext();
    return context == null ? -1 : context.take();
  }

  /** Atomically detaches the current one-shot socket context for a native remote-parent lookup. */
  public static RemoteParentSocketContext takeRemoteParentSocketContext() {
    RemoteParentSocketContext context = remoteParentSocketContext.get();
    remoteParentSocketContext.remove();
    return context;
  }

  public static void clearRemoteParentSocketFileDescriptor() {
    remoteParentSocketContext.remove();
  }

  /** Marks a successful receive as the direct authority for the current execution scope. */
  public static void markRemoteParentDirectLookup() {
    markRemoteParentDirectLookup(null);
  }

  /** Marks a successful receive and retains its physical lifecycle as a revocation fence. */
  public static void markRemoteParentDirectLookup(Object lifecycle) {
    if (lifecycle instanceof RemoteParentSocketContext.Lifecycle) {
      RemoteParentSocketContext.Lifecycle exact = (RemoteParentSocketContext.Lifecycle) lifecycle;
      if (!exact.active()) {
        blockRemoteParentLookup();
        return;
      }
      remoteParentLookupLifecycle.set(exact);
    } else {
      remoteParentLookupLifecycle.remove();
    }
    remoteParentLookupOverride.set(LOOKUP_DIRECT);
  }

  /** Returns positive evidence that this execution completed the current inbound receive. */
  public static boolean hasRemoteParentDirectReceiveAuthority() {
    return currentRemoteParentLookupOverride() == LOOKUP_DIRECT;
  }

  /** Prevents an uncertain receive from falling back to either a task or a direct owner. */
  public static void blockRemoteParentLookup() {
    remoteParentLookupOverride.set(LOOKUP_BLOCKED);
    remoteParentLookupLifecycle.remove();
  }

  /** Returns the most recent positively established execution source, or fail-closed BLOCKED. */
  public static int remoteParentLookupSource() {
    byte lookupOverride = currentRemoteParentLookupOverride();
    if (lookupOverride == LOOKUP_BLOCKED) {
      return REMOTE_PARENT_LOOKUP_BLOCKED;
    }
    if (lookupOverride == LOOKUP_TASK) {
      TaskRelayState state = taskRelayState.get();
      return state != null && state.currentExact()
          ? REMOTE_PARENT_LOOKUP_TASK
          : REMOTE_PARENT_LOOKUP_BLOCKED;
    }
    return REMOTE_PARENT_LOOKUP_DIRECT;
  }

  /** Resets the ambient source override during process/test cleanup. */
  public static void clearRemoteParentLookupSource() {
    remoteParentLookupOverride.remove();
    remoteParentLookupLifecycle.remove();
  }

  /** Returns the lifecycle that must remain live for a direct or task lookup. */
  public static RemoteParentSocketContext.Lifecycle remoteParentLookupLifecycle() {
    return remoteParentLookupLifecycle.get();
  }

  /** Begins a receive attempt that may not have an explicit surrounding unwrap scope. */
  public static void beginRemoteParentReceiveAttempt() {
    if (remoteParentReceiveDepth.get() == null) {
      advanceRemoteParentReceiveEpoch();
    }
    blockRemoteParentLookup();
  }

  /** Enters an inbound TLS boundary that must never fall back to a task alias. */
  public static void beginRemoteParentReceiveScope() {
    Integer depth = remoteParentReceiveDepth.get();
    advanceRemoteParentReceiveEpoch();
    blockRemoteParentLookup();
    remoteParentReceiveDepth.set(depth == null ? 1 : depth + 1);
  }

  /** Balances {@link #beginRemoteParentReceiveScope()} on every exit path. */
  public static void endRemoteParentReceiveScope() {
    Integer depth = remoteParentReceiveDepth.get();
    if (depth == null || depth <= 1) {
      remoteParentReceiveDepth.remove();
    } else {
      remoteParentReceiveDepth.set(depth - 1);
    }
  }

  /**
   * Invalidates the shared lifecycle for a terminal receive path.
   *
   * <p>Unlike {@link #clearRemoteParentSocketFileDescriptor()}, this consumes ownership held by
   * queued task aliases as well as the current thread.
   */
  public static void invalidateRemoteParentSocketFileDescriptor(Object lifecycle) {
    advanceRemoteParentReceiveEpoch();
    blockRemoteParentLookup();
    if (lifecycle instanceof RemoteParentSocketContext.Lifecycle) {
      ((RemoteParentSocketContext.Lifecycle) lifecycle).invalidate();
      RemoteParentSocketContext current = remoteParentSocketContext.get();
      if (current != null && current.hasLifecycle(lifecycle)) {
        remoteParentSocketContext.remove();
      }
      return;
    }

    RemoteParentSocketContext current = remoteParentSocketContext.get();
    remoteParentSocketContext.remove();
    if (current != null) {
      current.take();
    }
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
      remoteParentSocketContext.remove();
      blockRemoteParentLookup();
      cancelTaskHandoff(handoffToken);
      cancelTaskHandoff(restoreToken);
    }
  }

  private static void rejectTaskEntry(long handoffToken) {
    try {
      cancelTaskHandoff(handoffToken);
    } finally {
      remoteParentSocketContext.remove();
      blockRemoteParentLookup();
    }
  }

  private static byte currentRemoteParentLookupOverride() {
    Byte lookupOverride = remoteParentLookupOverride.get();
    return lookupOverride == null ? LOOKUP_DEFAULT : lookupOverride;
  }

  private static long currentRemoteParentReceiveEpoch() {
    Long epoch = remoteParentReceiveEpoch.get();
    return epoch == null ? 0L : epoch;
  }

  private static void advanceRemoteParentReceiveEpoch() {
    long next = currentRemoteParentReceiveEpoch() + 1L;
    remoteParentReceiveEpoch.set(next == 0L ? 1L : next);
  }

  private static boolean restoreRemoteParentLookup(
      byte lookupOverride, long receiveEpoch, RemoteParentSocketContext.Lifecycle lookupLifecycle) {
    if (currentRemoteParentReceiveEpoch() != receiveEpoch) {
      blockRemoteParentLookup();
      return false;
    } else if (lookupLifecycle != null && !lookupLifecycle.active()) {
      blockRemoteParentLookup();
      return false;
    } else if (lookupOverride == LOOKUP_DIRECT
        || lookupOverride == LOOKUP_TASK
        || lookupOverride == LOOKUP_BLOCKED) {
      remoteParentLookupOverride.set(lookupOverride);
    } else {
      remoteParentLookupOverride.remove();
    }
    setRemoteParentLookupLifecycle(lookupLifecycle);
    return true;
  }

  private static void setRemoteParentLookupLifecycle(
      RemoteParentSocketContext.Lifecycle lifecycle) {
    if (lifecycle == null) {
      remoteParentLookupLifecycle.remove();
    } else {
      remoteParentLookupLifecycle.set(lifecycle);
    }
  }

  private static void bestEffortUnlinkTask(Throwable failure) {
    try {
      emitTaskContextOp(OperationType.TASK_UNLINK, 0L, 0L);
    } catch (Throwable unlinkFailure) {
      failure.addSuppressed(unlinkFailure);
    }
  }

  private static void setRemoteParentSocketContext(RemoteParentSocketContext context) {
    if (context == null || context.peek() < 0) {
      remoteParentSocketContext.remove();
    } else {
      remoteParentSocketContext.set(context);
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

  private static void emitTaskParentContext(long parentId, long token, boolean exactTokenHandoff) {
    if (exactTokenHandoff) {
      emitTaskContextOp(OperationType.TASK_LINK, parentId, token);
    } else {
      sendParentThreadContext(parentId);
    }
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
    private boolean[] previousExact = new boolean[4];
    private byte[] previousLookupOverrides = new byte[4];
    private long[] previousReceiveEpochs = new long[4];
    private RemoteParentSocketContext.Lifecycle[] previousLookupLifecycles =
        new RemoteParentSocketContext.Lifecycle[4];
    private RemoteParentSocketContext[] previousSocketContexts = new RemoteParentSocketContext[4];
    private long exitToken;
    private boolean currentExact;
    private boolean exitExact;
    private byte exitLookupOverride;
    private long exitReceiveEpoch;
    private RemoteParentSocketContext.Lifecycle exitLookupLifecycle;
    private RemoteParentSocketContext exitSocketContext;
    private int depth;

    long enter(long currentThreadId, long parentId, long restoreToken, boolean exactTokenHandoff) {
      return enter(
          currentThreadId,
          parentId,
          restoreToken,
          exactTokenHandoff,
          null,
          LOOKUP_DEFAULT,
          0L,
          null);
    }

    long enter(
        long currentThreadId,
        long parentId,
        long restoreToken,
        boolean exactTokenHandoff,
        RemoteParentSocketContext previousSocketContext,
        byte previousLookupOverride,
        long previousReceiveEpoch,
        RemoteParentSocketContext.Lifecycle previousLookupLifecycle) {
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
        boolean[] expandedExact = new boolean[previousExact.length * 2];
        System.arraycopy(previousExact, 0, expandedExact, 0, previousExact.length);
        previousExact = expandedExact;
        byte[] expandedLookupOverrides = new byte[previousLookupOverrides.length * 2];
        System.arraycopy(
            previousLookupOverrides, 0, expandedLookupOverrides, 0, previousLookupOverrides.length);
        previousLookupOverrides = expandedLookupOverrides;
        long[] expandedReceiveEpochs = new long[previousReceiveEpochs.length * 2];
        System.arraycopy(
            previousReceiveEpochs, 0, expandedReceiveEpochs, 0, previousReceiveEpochs.length);
        previousReceiveEpochs = expandedReceiveEpochs;
        RemoteParentSocketContext.Lifecycle[] expandedLookupLifecycles =
            new RemoteParentSocketContext.Lifecycle[previousLookupLifecycles.length * 2];
        System.arraycopy(
            previousLookupLifecycles,
            0,
            expandedLookupLifecycles,
            0,
            previousLookupLifecycles.length);
        previousLookupLifecycles = expandedLookupLifecycles;
        RemoteParentSocketContext[] expandedSocketContexts =
            new RemoteParentSocketContext[previousSocketContexts.length * 2];
        System.arraycopy(
            previousSocketContexts, 0, expandedSocketContexts, 0, previousSocketContexts.length);
        previousSocketContexts = expandedSocketContexts;
      }
      previousParents[depth] = currentParent;
      previousTokens[depth] = restoreToken;
      previousExact[depth] = currentExact;
      previousLookupOverrides[depth] = previousLookupOverride;
      previousReceiveEpochs[depth] = previousReceiveEpoch;
      previousLookupLifecycles[depth] = previousLookupLifecycle;
      previousSocketContexts[depth] = previousSocketContext;
      depth++;
      currentParent = parentId;
      currentExact = exactTokenHandoff;
      return parentId;
    }

    long exit() {
      if (depth == 0) {
        return NO_TASK_RELAY_CHANGE;
      }

      long previous = previousParents[--depth];
      exitToken = previousTokens[depth];
      exitExact = previousExact[depth];
      exitLookupOverride = previousLookupOverrides[depth];
      exitReceiveEpoch = previousReceiveEpochs[depth];
      exitLookupLifecycle = previousLookupLifecycles[depth];
      exitSocketContext = previousSocketContexts[depth];
      previousParents[depth] = 0L;
      previousTokens[depth] = 0L;
      previousExact[depth] = false;
      previousLookupOverrides[depth] = LOOKUP_DEFAULT;
      previousReceiveEpochs[depth] = 0L;
      previousLookupLifecycles[depth] = null;
      previousSocketContexts[depth] = null;
      currentParent = previous;
      currentExact = exitExact;
      return previous == 0 ? threadId : previous;
    }

    boolean isEmpty() {
      return depth == 0;
    }

    boolean requiresReset() {
      return depth > 1;
    }

    boolean currentExact() {
      return currentExact;
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

    boolean exitExact() {
      return exitExact;
    }

    byte exitLookupOverride() {
      return exitLookupOverride;
    }

    long exitReceiveEpoch() {
      return exitReceiveEpoch;
    }

    RemoteParentSocketContext.Lifecycle exitLookupLifecycle() {
      return exitLookupLifecycle;
    }

    RemoteParentSocketContext exitSocketContext() {
      return exitSocketContext;
    }
  }

  interface TaskContextEmitter {
    void emit(OperationType operation, long value, long token);
  }
}
