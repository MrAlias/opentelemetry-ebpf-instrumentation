/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.instrumentations.JavaExecutorInst;
import io.opentelemetry.obi.java.instrumentations.VirtualThreadInst;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import io.opentelemetry.obi.java.instrumentations.data.WeakIdentityTaskMapTestAccess;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ThreadInfoTest {
  @AfterEach
  void disableRemoteParent() {
    ThreadInfo.setRemoteParentEnabled(false);
    ThreadInfo.setTaskContextEmitterForTest(null);
    ThreadInfo.setProcessIncarnationSourceForTest(null);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    setStorageThreadIdProvider(null);
  }

  @Test
  void processIncarnationGenerationFailsClosedAndRetries() {
    AtomicInteger attempts = new AtomicInteger();
    ThreadInfo.setProcessIncarnationSourceForTest(
        () -> {
          if (attempts.getAndIncrement() == 0) {
            throw new IllegalStateException("randomness unavailable");
          }
          return 77L;
        });
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));

    assertEquals(0L, ThreadInfo.processIncarnation());
    assertEquals(77L, ThreadInfo.processIncarnation());
    assertTrue(ThreadInfo.registerProcessIncarnation());
    assertEquals(1, emitted.size());
    assertEquals(OperationType.PROCESS_REGISTER, emitted.get(0).operation);
    assertEquals(77L, emitted.get(0).value);
  }

  @Test
  void userspaceCapabilityRotatesTheProcessIncarnation() {
    ThreadInfo.setProcessIncarnation(11L);
    assertEquals(11L, ThreadInfo.processIncarnation());

    ThreadInfo.setProcessIncarnation(22L);
    assertEquals(22L, ThreadInfo.processIncarnation());
  }

  @Test
  void remoteParentSocketDescriptorCanBeClearedAfterUse() {
    ThreadInfo.setRemoteParentSocketFileDescriptor(17);
    assertEquals(17, ThreadInfo.remoteParentSocketFileDescriptor());

    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void terminalLifecycleInvalidatesACapturedSocketAcrossThreads() throws Exception {
    enableRemoteParentWithNoopEmitter();
    RemoteParentSocketContext.Lifecycle lifecycle = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(71, lifecycle);
    TaskContext context = ThreadInfo.captureTaskContext(101L);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();

    Thread closer =
        new Thread(() -> ThreadInfo.invalidateRemoteParentSocketFileDescriptor(lifecycle));
    closer.start();
    closer.join(TimeUnit.SECONDS.toMillis(5));

    assertFalse(closer.isAlive());
    assertEquals(-1, context.getRemoteParentSocketContext().peek());

    AtomicInteger claimed = new AtomicInteger(Integer.MIN_VALUE);
    Thread worker =
        new Thread(
            () -> {
              boolean entered =
                  ThreadInfo.enterTaskParentThreadContext(
                      900L,
                      context.getParentThreadId(),
                      context.getHandoffToken(),
                      context.getRemoteParentSocketContext());
              try {
                claimed.set(ThreadInfo.takeRemoteParentSocketFileDescriptor());
              } finally {
                if (entered) {
                  ThreadInfo.restoreTaskParentThreadContext();
                }
              }
            });
    worker.start();
    worker.join(TimeUnit.SECONDS.toMillis(5));

    assertFalse(worker.isAlive());
    assertEquals(-1, claimed.get());
  }

  @Test
  void terminalLifecycleDoesNotInvalidateADifferentSocketOwnership() {
    enableRemoteParentWithNoopEmitter();
    RemoteParentSocketContext.Lifecycle live = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(72, live);
    TaskContext liveContext = ThreadInfo.captureTaskContext(101L);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();

    RemoteParentSocketContext.Lifecycle terminal = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(73, terminal);
    ThreadInfo.invalidateRemoteParentSocketFileDescriptor(terminal);

    assertEquals(72, liveContext.getRemoteParentSocketContext().peek());
  }

  @Test
  void delayedOldLifecycleInvalidationDoesNotRevokeAReusedDescriptor() {
    enableRemoteParentWithNoopEmitter();
    RemoteParentSocketContext.Lifecycle oldLifecycle = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(74, oldLifecycle);
    TaskContext oldContext = ThreadInfo.captureTaskContext(101L);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    ThreadInfo.invalidateRemoteParentSocketFileDescriptor(oldLifecycle);

    RemoteParentSocketContext.Lifecycle freshLifecycle = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(74, freshLifecycle);
    TaskContext freshContext = ThreadInfo.captureTaskContext(102L);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();

    ThreadInfo.invalidateRemoteParentSocketFileDescriptor(oldLifecycle);

    assertEquals(-1, oldContext.getRemoteParentSocketContext().peek());
    assertEquals(74, freshContext.getRemoteParentSocketContext().peek());
  }

  @Test
  void stagingRejectsALifecycleInvalidatedDuringReceive() {
    RemoteParentSocketContext.Lifecycle lifecycle = new RemoteParentSocketContext.Lifecycle();
    lifecycle.invalidate();

    assertFalse(ThreadInfo.setRemoteParentSocketFileDescriptor(75, lifecycle));
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void taskSocketDescriptorIsClaimedOnceAndNotRestored() {
    enableRemoteParentWithNoopEmitter();
    ThreadInfo.setRemoteParentSocketFileDescriptor(18);
    TaskContext context = ThreadInfo.captureTaskContext(101L);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();

    assertEquals(18, context.getRemoteParentSocketContext().peek());
    assertTrue(
        ThreadInfo.enterTaskParentThreadContext(
            900L,
            context.getParentThreadId(),
            context.getHandoffToken(),
            context.getRemoteParentSocketContext()));
    assertEquals(18, ThreadInfo.takeRemoteParentSocketFileDescriptor());
    assertEquals(-1, ThreadInfo.takeRemoteParentSocketFileDescriptor());

    ThreadInfo.restoreTaskParentThreadContext();

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, context.getRemoteParentSocketContext().peek());
  }

  @Test
  void nestedTaskScopesRestoreOnlyUnconsumedSocketOwnership() {
    enableRemoteParentWithNoopEmitter();
    ThreadInfo.setRemoteParentSocketFileDescriptor(99);
    RemoteParentSocketContext outer = new RemoteParentSocketContext(19);
    RemoteParentSocketContext inner = new RemoteParentSocketContext(20);

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 11L, outer));
    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 202L, 22L, inner));
    assertEquals(20, ThreadInfo.takeRemoteParentSocketFileDescriptor());

    ThreadInfo.restoreTaskParentThreadContext();
    assertEquals(19, ThreadInfo.takeRemoteParentSocketFileDescriptor());
    ThreadInfo.restoreTaskParentThreadContext();

    assertEquals(99, ThreadInfo.takeRemoteParentSocketFileDescriptor());
  }

  @Test
  void nestedAliasesDoNotResurrectConsumedSocketOwnership() {
    enableRemoteParentWithNoopEmitter();
    ThreadInfo.setRemoteParentSocketFileDescriptor(99);
    RemoteParentSocketContext shared = new RemoteParentSocketContext(20);

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 11L, shared));
    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 202L, 22L, shared));
    assertEquals(20, ThreadInfo.takeRemoteParentSocketFileDescriptor());

    ThreadInfo.restoreTaskParentThreadContext();
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    ThreadInfo.restoreTaskParentThreadContext();

    assertEquals(99, ThreadInfo.takeRemoteParentSocketFileDescriptor());
  }

  @Test
  void taskWithoutSocketOwnershipCannotInheritAWorkerDescriptor() {
    enableRemoteParentWithNoopEmitter();
    ThreadInfo.setRemoteParentSocketFileDescriptor(99);

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 11L, null));
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    ThreadInfo.restoreTaskParentThreadContext();

    assertEquals(99, ThreadInfo.takeRemoteParentSocketFileDescriptor());
  }

  @Test
  void concurrentTaskAliasesCanClaimSocketOwnershipOnlyOnce() throws Exception {
    enableRemoteParentWithNoopEmitter();
    RemoteParentSocketContext socketContext = new RemoteParentSocketContext(21);
    CountDownLatch ready = new CountDownLatch(2);
    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch complete = new CountDownLatch(2);
    AtomicInteger linked = new AtomicInteger();
    AtomicInteger claimed = new AtomicInteger();
    AtomicInteger unexpected = new AtomicInteger();

    Thread first =
        socketClaimingTask(
            901L, 31L, socketContext, ready, start, complete, linked, claimed, unexpected);
    Thread second =
        socketClaimingTask(
            902L, 32L, socketContext, ready, start, complete, linked, claimed, unexpected);
    first.start();
    second.start();

    assertTrue(ready.await(5, TimeUnit.SECONDS));
    start.countDown();
    assertTrue(complete.await(5, TimeUnit.SECONDS));
    first.join(TimeUnit.SECONDS.toMillis(5));
    second.join(TimeUnit.SECONDS.toMillis(5));

    assertFalse(first.isAlive());
    assertFalse(second.isAlive());
    assertEquals(2, linked.get());
    assertEquals(1, claimed.get());
    assertEquals(0, unexpected.get());
    assertEquals(-1, socketContext.peek());
  }

  @Test
  void taskCancellationDetachesWithoutInvalidatingAnotherAlias() {
    enableRemoteParentWithNoopEmitter();
    ThreadInfo.setRemoteParentSocketFileDescriptor(22);
    TaskContext context = ThreadInfo.captureTaskContext(101L);

    ThreadInfo.cancelTaskContext(context);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();

    assertEquals(22, context.getRemoteParentSocketContext().take());
  }

  @Test
  void reusedNumericDescriptorCreatesIndependentOwnership() {
    enableRemoteParentWithNoopEmitter();
    ThreadInfo.setRemoteParentSocketFileDescriptor(23);
    TaskContext first = ThreadInfo.captureTaskContext(101L);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    ThreadInfo.setRemoteParentSocketFileDescriptor(23);
    TaskContext second = ThreadInfo.captureTaskContext(101L);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();

    assertNotSame(first.getRemoteParentSocketContext(), second.getRemoteParentSocketContext());
    assertEquals(23, first.getRemoteParentSocketContext().take());
    assertEquals(23, second.getRemoteParentSocketContext().take());
    ThreadInfo.cancelTaskContext(first);
    ThreadInfo.cancelTaskContext(second);
  }

  @Test
  void failClosedNestedEntryDetachesOuterSocketOwnership() {
    enableRemoteParentWithNoopEmitter();
    RemoteParentSocketContext socketContext = new RemoteParentSocketContext(24);
    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 11L, socketContext));

    assertFalse(ThreadInfo.enterTaskParentThreadContext(900L, 101L));
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());

    ThreadInfo.restoreTaskParentThreadContext();
  }

  @Test
  void disabledCleanupDoesNotReachJniOrAllocateState() {
    ThreadInfo.setRemoteParentEnabled(false);

    assertFalse(ThreadInfo.hasTaskRelayState());
    ThreadInfo.restoreTaskParentThreadContext();
    assertFalse(ThreadInfo.hasTaskRelayState());
  }

  @Test
  void nestedTaskScopesRestoreTheOuterRelayBeforeUnlinking() {
    ThreadInfo.TaskRelayState state = new ThreadInfo.TaskRelayState();

    assertEquals(101L, state.enter(900L, 101L, 0L, false));
    assertFalse(state.requiresReset());
    assertEquals(202L, state.enter(900L, 202L, 77L, true));
    assertTrue(state.requiresReset());
    assertEquals(101L, state.exit());
    assertEquals(77L, state.exitToken());
    assertEquals(900L, state.exit());
    assertEquals(0L, state.exitToken());
    assertTrue(state.isEmpty());
  }

  @Test
  void nestedScopeWithTheSameParentLeavesTheOuterRelayUntouched() {
    ThreadInfo.TaskRelayState state = new ThreadInfo.TaskRelayState();

    assertEquals(101L, state.enter(900L, 101L, 0L, false));
    assertEquals(ThreadInfo.NO_TASK_RELAY_CHANGE, state.enter(900L, 101L, 0L, false));
    assertEquals(900L, state.exit());
    assertTrue(state.isEmpty());
  }

  @Test
  void exactTokenForTheSameNumericParentStillCreatesANestedScope() {
    ThreadInfo.TaskRelayState state = new ThreadInfo.TaskRelayState();

    assertEquals(101L, state.enter(900L, 101L, 0L, true));
    assertEquals(101L, state.enter(900L, 101L, 77L, true));
    assertEquals(101L, state.exit());
    assertEquals(77L, state.exitToken());
    assertEquals(900L, state.exit());
    assertTrue(state.isEmpty());
  }

  @Test
  void legacyTaskScopesRejectAncestorCycles() {
    ThreadInfo.TaskRelayState state = new ThreadInfo.TaskRelayState();

    assertEquals(101L, state.enter(900L, 101L, 0L, false));
    assertEquals(202L, state.enter(900L, 202L, 0L, false));
    assertEquals(ThreadInfo.NO_TASK_RELAY_CHANGE, state.enter(900L, 101L, 0L, false));
    assertEquals(101L, state.exit());
    assertEquals(900L, state.exit());
    assertTrue(state.isEmpty());
  }

  @Test
  void taskRelayNestingIsBoundedAtAFixedDepth() {
    ThreadInfo.TaskRelayState state = new ThreadInfo.TaskRelayState();

    for (int i = 0; i < ThreadInfo.MAX_TASK_RELAY_DEPTH; i++) {
      assertEquals(1_000L + i, state.enter(900L, 1_000L + i, 0L, true));
    }
    assertEquals(
        ThreadInfo.NO_TASK_RELAY_CHANGE,
        state.enter(900L, 1_000L + ThreadInfo.MAX_TASK_RELAY_DEPTH, 0L, true));

    for (int i = 0; i < ThreadInfo.MAX_TASK_RELAY_DEPTH; i++) {
      state.exit();
    }
    assertTrue(state.isEmpty());
  }

  @Test
  void taskRelayDepthLimitUnlinksTheCurrentContext() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);

    for (int i = 0; i < ThreadInfo.MAX_TASK_RELAY_DEPTH; i++) {
      assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 1_000L + i, i + 1L));
    }
    assertFalse(
        ThreadInfo.enterTaskParentThreadContext(
            900L, 1_000L + ThreadInfo.MAX_TASK_RELAY_DEPTH, 999L));

    assertTrue(ThreadInfo.hasTaskRelayState());
    int rejected = emitted.size() - 4;
    assertEquals(OperationType.TASK_RELAY_CAPTURE, emitted.get(rejected).operation);
    assertEquals(OperationType.TASK_UNLINK, emitted.get(rejected + 1).operation);
    assertEquals(OperationType.TASK_CANCEL, emitted.get(rejected + 2).operation);
    assertEquals(999L, emitted.get(rejected + 2).value);
    assertEquals(OperationType.TASK_CANCEL, emitted.get(rejected + 3).operation);

    for (int i = 0; i < ThreadInfo.MAX_TASK_RELAY_DEPTH; i++) {
      ThreadInfo.restoreTaskParentThreadContext();
    }
    assertFalse(ThreadInfo.hasTaskRelayState());
  }

  @Test
  void legacyAncestorCycleUnlinksTheCurrentContext() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L));
    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 202L));
    assertFalse(ThreadInfo.enterTaskParentThreadContext(900L, 101L));

    assertEquals(OperationType.TASK_UNLINK, emitted.get(emitted.size() - 1).operation);
    ThreadInfo.restoreTaskParentThreadContext();
    ThreadInfo.restoreTaskParentThreadContext();
  }

  @Test
  void nestedScopeUsesStrictRelayCaptureAndSingleAtomicLinks() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 11L));
    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 202L, 22L));
    ThreadInfo.restoreTaskParentThreadContext();
    ThreadInfo.restoreTaskParentThreadContext();

    assertEquals(5, emitted.size());
    assertEquals(OperationType.TASK_LINK, emitted.get(0).operation);
    assertEquals(11L, emitted.get(0).token);
    assertEquals(OperationType.TASK_RELAY_CAPTURE, emitted.get(1).operation);
    long restoreToken = emitted.get(1).value;
    assertTrue(restoreToken != 0L);
    assertEquals(OperationType.TASK_LINK, emitted.get(2).operation);
    assertEquals(22L, emitted.get(2).token);
    assertEquals(OperationType.TASK_LINK, emitted.get(3).operation);
    assertEquals(restoreToken, emitted.get(3).token);
    assertEquals(OperationType.TASK_LINK, emitted.get(4).operation);
    assertEquals(0L, emitted.get(4).token);
  }

  @Test
  void scopeEnteredBeforeDisableStillUnlinksOnTheWorker() throws Exception {
    List<Long> emitted = Collections.synchronizedList(new ArrayList<>());
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch disabled = new CountDownLatch(1);
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> {
          if (operation == OperationType.TASK_LINK) {
            emitted.add(value);
          }
        });
    ThreadInfo.setRemoteParentEnabled(true);

    Thread worker =
        new Thread(
            () -> {
              assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L));
              entered.countDown();
              try {
                assertTrue(disabled.await(5, TimeUnit.SECONDS));
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new AssertionError(interrupted);
              }
              ThreadInfo.restoreTaskParentThreadContext();
              assertFalse(ThreadInfo.hasTaskRelayState());
            });
    worker.start();

    assertTrue(entered.await(5, TimeUnit.SECONDS));
    ThreadInfo.setRemoteParentEnabled(false);
    disabled.countDown();
    worker.join(TimeUnit.SECONDS.toMillis(5));

    assertFalse(worker.isAlive());
    assertEquals(java.util.Arrays.asList(101L, 900L), emitted);
  }

  @Test
  void delayedTaskUsesItsSubmissionTokenAfterAnotherParentStages() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    Object taskA = new Object();
    Object taskB = new Object();

    SSLStorage.trackTask(101L, taskA);
    TaskContext contextA = SSLStorage.taskContext(taskA);
    SSLStorage.trackTask(101L, taskB);
    TaskContext contextB = SSLStorage.taskContext(taskB);
    assertTrue(contextA.getHandoffToken() != contextB.getHandoffToken());

    TaskContext delayed = SSLStorage.takeTaskContext(taskA);
    assertTrue(
        ThreadInfo.enterTaskParentThreadContext(
            900L, delayed.getParentThreadId(), delayed.getHandoffToken()));
    ThreadInfo.restoreTaskParentThreadContext();
    SSLStorage.untrackTask(taskB);

    EmittedOp link =
        emitted.stream()
            .filter(operation -> operation.operation == OperationType.TASK_LINK)
            .filter(operation -> operation.token != 0L)
            .findFirst()
            .orElseThrow(AssertionError::new);
    assertEquals(contextA.getHandoffToken(), link.token);
    assertFalse(contextB.getHandoffToken() == link.token);
  }

  @Test
  void sameTidDifferentSubmissionTokensBecomeAmbiguous() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    Object reusedTask = new Object();

    SSLStorage.trackTask(101L, reusedTask);
    SSLStorage.trackTask(101L, reusedTask);

    assertEquals(
        2, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
    assertEquals(
        2, emitted.stream().filter(op -> op.operation == OperationType.TASK_CANCEL).count());
    assertTrue(SSLStorage.taskContext(reusedTask) == null);
    assertTrue(SSLStorage.takeTaskContext(reusedTask) == null);
  }

  @Test
  void delayedTaskOnItsSubmitterTidStillLinksTheExactToken() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);

    TaskContext delayed = ThreadInfo.captureTaskContext(900L);
    TaskContext newerDirectContext = ThreadInfo.captureTaskContext(900L);
    assertTrue(
        ThreadInfo.enterTaskParentThreadContext(
            900L, delayed.getParentThreadId(), delayed.getHandoffToken()));
    ThreadInfo.restoreTaskParentThreadContext();
    ThreadInfo.cancelTaskContext(newerDirectContext);

    EmittedOp exactLink =
        emitted.stream()
            .filter(operation -> operation.operation == OperationType.TASK_LINK)
            .filter(operation -> operation.token != 0L)
            .findFirst()
            .orElseThrow(AssertionError::new);
    assertEquals(900L, exactLink.value);
    assertEquals(delayed.getHandoffToken(), exactLink.token);
    assertFalse(newerDirectContext.getHandoffToken() == exactLink.token);
  }

  @Test
  void virtualThreadEventsDoNotHaveABoundedPoolDropPath() {
    List<OperationType> operations = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest((operation, value, token) -> operations.add(operation));

    for (int i = 0; i < 1_000; i++) {
      ThreadInfo.onVirtualThreadMount();
      ThreadInfo.onVirtualThreadUnmount();
    }

    assertEquals(2_000, operations.size());
    assertEquals(
        1_000,
        operations.stream().filter(operation -> operation == OperationType.VT_MOUNT).count());
    assertEquals(
        1_000,
        operations.stream().filter(operation -> operation == OperationType.VT_UNMOUNT).count());
  }

  @Test
  void directVirtualThreadScopeSurvivesParkAndTerminatesOnce() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicLong kernelTid = new AtomicLong(101L);
    setStorageThreadIdProvider(kernelTid::get);
    Thread virtualThread = Thread.currentThread();

    VirtualThreadInst.StartAdvice.enter(virtualThread);
    VirtualThreadInst.StartAdvice.exit(virtualThread, null);
    long handoffToken = SSLStorage.taskContext(virtualThread).getHandoffToken();
    kernelTid.set(900L);
    VirtualThreadInst.MountAdvice.exit(virtualThread);
    VirtualThreadInst.UnmountAdvice.exit();
    VirtualThreadInst.MountAdvice.exit(virtualThread);
    VirtualThreadInst.RunAdvice.exit(virtualThread);
    VirtualThreadInst.AfterDoneAdvice.exit(virtualThread);

    assertNull(SSLStorage.taskContext(virtualThread));
    assertFalse(ThreadInfo.hasTaskRelayState());
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
    assertEquals(2, emitted.stream().filter(op -> op.operation == OperationType.VT_MOUNT).count());
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.VT_UNMOUNT).count());
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.VT_TERMINATE).count());
    List<EmittedOp> links =
        emitted.stream()
            .filter(op -> op.operation == OperationType.TASK_LINK)
            .collect(java.util.stream.Collectors.toList());
    assertEquals(2, links.size());
    assertEquals(101L, links.get(0).value);
    assertEquals(handoffToken, links.get(0).token);
    assertEquals(900L, links.get(1).value);
    assertEquals(0L, links.get(1).token);
  }

  @Test
  void virtualThreadThatNeverMountsCancelsItsStartHandoff() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    setStorageThreadIdProvider(() -> 101L);
    Thread virtualThread = Thread.currentThread();

    VirtualThreadInst.StartAdvice.enter(virtualThread);
    VirtualThreadInst.StartAdvice.exit(virtualThread, null);
    VirtualThreadInst.AfterDoneAdvice.exit(virtualThread);

    assertNull(SSLStorage.taskContext(virtualThread));
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CANCEL).count());
  }

  @Test
  void virtualThreadCapturesTheStartContextInsteadOfTheConstructionContext() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicLong kernelTid = new AtomicLong(101L);
    setStorageThreadIdProvider(kernelTid::get);
    Thread virtualThread = Thread.currentThread();

    assertNull(SSLStorage.taskContext(virtualThread));
    kernelTid.set(202L);
    VirtualThreadInst.StartAdvice.enter(virtualThread);
    VirtualThreadInst.StartAdvice.exit(virtualThread, null);

    TaskContext startContext = SSLStorage.taskContext(virtualThread);
    assertEquals(202L, startContext.getParentThreadId());
    assertFalse(startContext.getParentThreadId() == 101L);

    kernelTid.set(900L);
    VirtualThreadInst.MountAdvice.exit(virtualThread);
    VirtualThreadInst.RunAdvice.exit(virtualThread);
    VirtualThreadInst.AfterDoneAdvice.exit(virtualThread);

    assertTrue(
        emitted.stream()
            .anyMatch(op -> op.operation == OperationType.TASK_LINK && op.value == 202L));
    assertFalse(
        emitted.stream()
            .anyMatch(op -> op.operation == OperationType.TASK_LINK && op.value == 101L));
  }

  @Test
  void failedVirtualThreadStartCancelsItsHandoff() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    setStorageThreadIdProvider(() -> 101L);
    Object virtualThread = new Object();

    VirtualThreadInst.StartAdvice.enter(virtualThread);
    VirtualThreadInst.StartAdvice.exit(virtualThread, new IllegalThreadStateException());

    assertNull(SSLStorage.taskContext(virtualThread));
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CANCEL).count());
  }

  @Test
  void clearedWeakTaskReferenceCancelsItsHandoffToken() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));

    WeakIdentityTaskMapTestAccess.clearAndObserve(new TaskContext(101L, 42L));

    assertTrue(
        emitted.stream()
            .anyMatch(
                operation ->
                    operation.operation == OperationType.TASK_CANCEL && operation.value == 42L));
  }

  @Test
  void threadPoolWorkerHooksScopeHiddenLambdaTasksOnceAcrossOverrides() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    setStorageThreadIdProvider(() -> 900L);
    Runnable task = () -> {};
    ThreadInfo.setRemoteParentSocketFileDescriptor(17);
    SSLStorage.trackTask(101L, task);
    long handoffToken = SSLStorage.taskContext(task).getHandoffToken();
    ThreadInfo.setRemoteParentSocketFileDescriptor(99);

    boolean outerBefore = JavaExecutorInst.BeforeExecuteAdvice.enter();
    boolean nestedBefore = JavaExecutorInst.BeforeExecuteAdvice.enter();
    JavaExecutorInst.BeforeExecuteAdvice.exit(task, null, nestedBefore);
    JavaExecutorInst.BeforeExecuteAdvice.exit(task, null, outerBefore);

    assertNull(SSLStorage.taskContext(task));
    assertTrue(ThreadInfo.hasTaskRelayState());
    assertEquals(17, ThreadInfo.takeRemoteParentSocketFileDescriptor());

    boolean outerAfter = JavaExecutorInst.AfterExecuteAdvice.enter();
    boolean nestedAfter = JavaExecutorInst.AfterExecuteAdvice.enter();
    JavaExecutorInst.AfterExecuteAdvice.exit(nestedAfter);
    JavaExecutorInst.AfterExecuteAdvice.exit(outerAfter);

    assertFalse(ThreadInfo.hasTaskRelayState());
    assertEquals(99, ThreadInfo.takeRemoteParentSocketFileDescriptor());
    assertEquals(3, emitted.size());
    assertEquals(OperationType.TASK_CAPTURE, emitted.get(0).operation);
    assertEquals(OperationType.TASK_LINK, emitted.get(1).operation);
    assertEquals(101L, emitted.get(1).value);
    assertEquals(handoffToken, emitted.get(1).token);
    assertEquals(OperationType.TASK_LINK, emitted.get(2).operation);
    assertEquals(900L, emitted.get(2).value);
    assertEquals(0L, emitted.get(2).token);
  }

  private static void setStorageThreadIdProvider(java.util.function.LongSupplier provider) {
    try {
      Method setter =
          SSLStorage.class.getDeclaredMethod(
              "setThreadIdProviderForTest", java.util.function.LongSupplier.class);
      setter.setAccessible(true);
      setter.invoke(null, provider);
    } catch (ReflectiveOperationException failure) {
      throw new AssertionError(failure);
    }
  }

  private static void enableRemoteParentWithNoopEmitter() {
    ThreadInfo.setTaskContextEmitterForTest((operation, value, token) -> {});
    ThreadInfo.setRemoteParentEnabled(true);
  }

  private static Thread socketClaimingTask(
      long threadId,
      long token,
      RemoteParentSocketContext socketContext,
      CountDownLatch ready,
      CountDownLatch start,
      CountDownLatch complete,
      AtomicInteger linked,
      AtomicInteger claimed,
      AtomicInteger unexpected) {
    return new Thread(
        () -> {
          boolean entered =
              ThreadInfo.enterTaskParentThreadContext(threadId, 101L, token, socketContext);
          if (entered) {
            linked.incrementAndGet();
          }
          ready.countDown();
          try {
            if (!start.await(5, TimeUnit.SECONDS)) {
              unexpected.incrementAndGet();
              return;
            }
            int descriptor = ThreadInfo.takeRemoteParentSocketFileDescriptor();
            if (descriptor == 21) {
              claimed.incrementAndGet();
            } else if (descriptor != -1) {
              unexpected.incrementAndGet();
            }
          } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            unexpected.incrementAndGet();
          } finally {
            if (entered) {
              ThreadInfo.restoreTaskParentThreadContext();
            }
            if (ThreadInfo.remoteParentSocketFileDescriptor() != -1) {
              unexpected.incrementAndGet();
            }
            complete.countDown();
          }
        });
  }

  private static final class EmittedOp {
    private final OperationType operation;
    private final long value;
    private final long token;

    private EmittedOp(OperationType operation, long value, long token) {
      this.operation = operation;
      this.value = value;
      this.token = token;
    }
  }
}
