/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.instrumentations.JavaExecutorInst;
import io.opentelemetry.obi.java.instrumentations.VirtualThreadInst;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import io.opentelemetry.obi.java.instrumentations.data.WeakIdentityTaskMapTestAccess;
import java.lang.reflect.Method;
import java.net.InetAddress;
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
    for (int i = 0; i <= ThreadInfo.MAX_TASK_RELAY_DEPTH && ThreadInfo.hasTaskRelayState(); i++) {
      ThreadInfo.restoreTaskParentThreadContext();
    }
    ThreadInfo.setRemoteParentEnabled(false);
    ThreadInfo.setTaskContextEmitterForTest(null);
    ThreadInfo.setProcessIncarnationSourceForTest(null);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    ThreadInfo.clearRemoteParentLookupSource();
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
  void remoteParentThreadContextEmissionsAreSerialized() throws Exception {
    ThreadInfo.setRemoteParentEnabled(true);
    CountDownLatch firstEntered = new CountDownLatch(1);
    CountDownLatch releaseFirst = new CountDownLatch(1);
    AtomicInteger active = new AtomicInteger();
    AtomicInteger maxActive = new AtomicInteger();
    AtomicInteger failures = new AtomicInteger();
    List<Long> emitted = Collections.synchronizedList(new ArrayList<>());
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> {
          int concurrent = active.incrementAndGet();
          maxActive.accumulateAndGet(concurrent, Math::max);
          try {
            assertEquals(OperationType.THREAD, operation);
            emitted.add(value);
            if (value == 101L) {
              firstEntered.countDown();
              if (!releaseFirst.await(5, TimeUnit.SECONDS)) {
                throw new AssertionError("timed out waiting to release first emitter");
              }
            }
          } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AssertionError(interrupted);
          } finally {
            active.decrementAndGet();
          }
        });

    Thread first =
        new Thread(
            () -> {
              try {
                ThreadInfo.sendParentThreadContext(101L);
              } catch (Throwable failure) {
                failures.incrementAndGet();
              }
            });
    Thread second =
        new Thread(
            () -> {
              try {
                ThreadInfo.sendParentThreadContext(202L);
              } catch (Throwable failure) {
                failures.incrementAndGet();
              }
            });

    try {
      first.start();
      assertTrue(firstEntered.await(5, TimeUnit.SECONDS));
      second.start();
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (second.getState() != Thread.State.BLOCKED && System.nanoTime() < deadline) {
        Thread.sleep(1L);
      }
      assertEquals(Thread.State.BLOCKED, second.getState());
      assertEquals(1, emitted.size());
      assertEquals(1, maxActive.get());
    } finally {
      releaseFirst.countDown();
      first.join(TimeUnit.SECONDS.toMillis(5));
      second.join(TimeUnit.SECONDS.toMillis(5));
    }

    assertFalse(first.isAlive());
    assertFalse(second.isAlive());
    assertEquals(0, failures.get());
    assertEquals(java.util.Arrays.asList(101L, 202L), emitted);
    assertEquals(1, maxActive.get());
  }

  @Test
  void threadContextEmissionsRemainSerializedAcrossRemoteParentActivation() throws Exception {
    ThreadInfo.setRemoteParentEnabled(false);
    CountDownLatch firstEntered = new CountDownLatch(1);
    CountDownLatch releaseFirst = new CountDownLatch(1);
    AtomicInteger active = new AtomicInteger();
    AtomicInteger maxActive = new AtomicInteger();
    AtomicInteger failures = new AtomicInteger();
    List<Long> emitted = Collections.synchronizedList(new ArrayList<>());
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> {
          int concurrent = active.incrementAndGet();
          maxActive.accumulateAndGet(concurrent, Math::max);
          try {
            assertEquals(OperationType.THREAD, operation);
            emitted.add(value);
            if (value == 303L) {
              firstEntered.countDown();
              if (!releaseFirst.await(5, TimeUnit.SECONDS)) {
                throw new AssertionError("timed out waiting to release first emitter");
              }
            }
          } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AssertionError(interrupted);
          } finally {
            active.decrementAndGet();
          }
        });

    Thread first =
        new Thread(
            () -> {
              try {
                ThreadInfo.sendParentThreadContext(303L);
              } catch (Throwable failure) {
                failures.incrementAndGet();
              }
            });
    Thread second =
        new Thread(
            () -> {
              try {
                ThreadInfo.sendParentThreadContext(404L);
              } catch (Throwable failure) {
                failures.incrementAndGet();
              }
            });

    try {
      first.start();
      assertTrue(firstEntered.await(5, TimeUnit.SECONDS));
      ThreadInfo.setRemoteParentEnabled(true);
      second.start();
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (second.getState() != Thread.State.BLOCKED && System.nanoTime() < deadline) {
        Thread.sleep(1L);
      }
      assertEquals(Thread.State.BLOCKED, second.getState());
      assertEquals(1, emitted.size());
      assertEquals(1, maxActive.get());
    } finally {
      releaseFirst.countDown();
      first.join(TimeUnit.SECONDS.toMillis(5));
      second.join(TimeUnit.SECONDS.toMillis(5));
    }

    assertFalse(first.isAlive());
    assertFalse(second.isAlive());
    assertEquals(0, failures.get());
    assertEquals(java.util.Arrays.asList(303L, 404L), emitted);
    assertEquals(1, maxActive.get());
  }

  @Test
  void processRegistrationWaitsForThreadContextPublication() throws Exception {
    ThreadInfo.setProcessIncarnation(505L);
    CountDownLatch threadEntered = new CountDownLatch(1);
    CountDownLatch releaseThread = new CountDownLatch(1);
    AtomicInteger failures = new AtomicInteger();
    List<OperationType> emitted = Collections.synchronizedList(new ArrayList<>());
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> {
          emitted.add(operation);
          if (operation == OperationType.THREAD) {
            threadEntered.countDown();
            try {
              if (!releaseThread.await(5, TimeUnit.SECONDS)) {
                throw new AssertionError("timed out waiting to release thread publication");
              }
            } catch (InterruptedException interrupted) {
              Thread.currentThread().interrupt();
              throw new AssertionError(interrupted);
            }
          }
        });

    Thread publisher =
        new Thread(
            () -> {
              try {
                ThreadInfo.sendParentThreadContext(606L);
              } catch (Throwable failure) {
                failures.incrementAndGet();
              }
            });
    Thread registrar =
        new Thread(
            () -> {
              try {
                ThreadInfo.registerProcessIncarnation();
              } catch (Throwable failure) {
                failures.incrementAndGet();
              }
            });

    try {
      publisher.start();
      assertTrue(threadEntered.await(5, TimeUnit.SECONDS));
      registrar.start();
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (registrar.getState() != Thread.State.BLOCKED && System.nanoTime() < deadline) {
        Thread.sleep(1L);
      }
      assertEquals(Thread.State.BLOCKED, registrar.getState());
      assertEquals(java.util.Arrays.asList(OperationType.THREAD), emitted);
    } finally {
      releaseThread.countDown();
      publisher.join(TimeUnit.SECONDS.toMillis(5));
      registrar.join(TimeUnit.SECONDS.toMillis(5));
    }

    assertFalse(publisher.isAlive());
    assertFalse(registrar.isAlive());
    assertEquals(0, failures.get());
    assertEquals(
        java.util.Arrays.asList(OperationType.THREAD, OperationType.PROCESS_REGISTER), emitted);
  }

  @Test
  void remoteParentThreadContextEmissionLockIsReentrantAndReleasedAfterFailure() {
    ThreadInfo.setRemoteParentEnabled(true);
    List<Long> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> {
          emitted.add(value);
          if (value == 101L) {
            ThreadInfo.sendParentThreadContext(202L);
          }
        });

    ThreadInfo.sendParentThreadContext(101L);
    assertEquals(java.util.Arrays.asList(101L, 202L), emitted);

    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> {
          throw new IllegalStateException("synthetic emission failure");
        });
    assertThrows(IllegalStateException.class, () -> ThreadInfo.sendParentThreadContext(303L));

    AtomicInteger recovered = new AtomicInteger();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> recovered.incrementAndGet());
    ThreadInfo.sendParentThreadContext(404L);
    assertEquals(1, recovered.get());
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
    ThreadInfo.markRemoteParentDirectLookup(lifecycle);
    TaskContext context = ThreadInfo.captureTaskContext(101L, lifecycle);
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
    ThreadInfo.markRemoteParentDirectLookup(live);
    TaskContext liveContext = ThreadInfo.captureTaskContext(101L, live);
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
    ThreadInfo.markRemoteParentDirectLookup(oldLifecycle);
    TaskContext oldContext = ThreadInfo.captureTaskContext(101L, oldLifecycle);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    ThreadInfo.invalidateRemoteParentSocketFileDescriptor(oldLifecycle);

    RemoteParentSocketContext.Lifecycle freshLifecycle = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(74, freshLifecycle);
    ThreadInfo.markRemoteParentDirectLookup(freshLifecycle);
    TaskContext freshContext = ThreadInfo.captureTaskContext(102L, freshLifecycle);
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
  void scopedCaptureRequiresALiveLifecycleAndRejectsMismatchedSocketOwnership() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    RemoteParentSocketContext.Lifecycle lifecycle = new RemoteParentSocketContext.Lifecycle();
    RemoteParentSocketContext.Lifecycle otherLifecycle = new RemoteParentSocketContext.Lifecycle();
    assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(77, lifecycle));

    TaskContext unproven = ThreadInfo.captureTaskContext(101L, lifecycle);
    ThreadInfo.markRemoteParentDirectLookup(lifecycle);
    TaskContext outside = ThreadInfo.captureTaskContext(101L, null);
    TaskContext mismatched = ThreadInfo.captureTaskContext(101L, otherLifecycle);
    TaskContext exact = ThreadInfo.captureTaskContext(101L, lifecycle);

    assertEquals(0L, unproven.getHandoffToken());
    assertNull(unproven.getRemoteParentSocketContext());
    assertEquals(0L, outside.getHandoffToken());
    assertNull(outside.getRemoteParentSocketContext());
    assertEquals(0L, mismatched.getHandoffToken());
    assertNull(mismatched.getRemoteParentSocketContext());
    assertTrue(exact.getHandoffToken() != 0L);
    assertEquals(77, exact.getRemoteParentSocketContext().peek());

    lifecycle.invalidate();
    TaskContext terminal = ThreadInfo.captureTaskContext(101L, lifecycle);
    assertEquals(0L, terminal.getHandoffToken());
    assertNull(terminal.getRemoteParentSocketContext());
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());

    ThreadInfo.cancelTaskContext(mismatched);
    ThreadInfo.cancelTaskContext(exact);
  }

  @Test
  void descriptorlessCaptureRequiresTheExactDirectLifecycle() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    RemoteParentSocketContext.Lifecycle directLifecycle = new RemoteParentSocketContext.Lifecycle();
    RemoteParentSocketContext.Lifecycle unrelatedLifecycle =
        new RemoteParentSocketContext.Lifecycle();

    ThreadInfo.markRemoteParentDirectLookup(directLifecycle);
    TaskContext mismatched = ThreadInfo.captureTaskContext(101L, unrelatedLifecycle);
    TaskContext exact = ThreadInfo.captureTaskContext(101L, directLifecycle);

    assertEquals(0L, mismatched.getHandoffToken());
    assertNull(mismatched.getRemoteParentSocketContext());
    assertTrue(exact.getHandoffToken() != 0L);
    assertNull(exact.getRemoteParentSocketContext());
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());

    ThreadInfo.cancelTaskContext(exact);
  }

  @Test
  void ordinaryTaskCaptureUsesThreadPropagationWithoutAStrictAlias() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    RemoteParentSocketContext.Lifecycle lifecycle = new RemoteParentSocketContext.Lifecycle();
    assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(78, lifecycle));

    TaskContext context = ThreadInfo.captureTaskContext(101L);
    assertEquals(0L, context.getHandoffToken());
    assertNull(context.getRemoteParentSocketContext());
    assertTrue(
        ThreadInfo.enterTaskParentThreadContext(
            900L,
            context.getParentThreadId(),
            context.getHandoffToken(),
            context.getRemoteParentSocketContext()));
    ThreadInfo.restoreTaskParentThreadContext();
    assertEquals(78, ThreadInfo.remoteParentSocketFileDescriptor());

    assertEquals(2, emitted.size());
    assertEquals(
        0, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
    assertEquals(OperationType.THREAD, emitted.get(0).operation);
    assertEquals(101L, emitted.get(0).value);
    assertEquals(OperationType.THREAD, emitted.get(1).operation);
    assertEquals(900L, emitted.get(1).value);
  }

  @Test
  void taskSocketDescriptorIsClaimedOnceAndNotRestored() {
    enableRemoteParentWithNoopEmitter();
    RemoteParentSocketContext.Lifecycle lifecycle = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(18, lifecycle);
    ThreadInfo.markRemoteParentDirectLookup(lifecycle);
    TaskContext context = ThreadInfo.captureTaskContext(101L, lifecycle);
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
    RemoteParentSocketContext.Lifecycle lifecycle = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(22, lifecycle);
    ThreadInfo.markRemoteParentDirectLookup(lifecycle);
    TaskContext context = ThreadInfo.captureTaskContext(101L, lifecycle);

    ThreadInfo.cancelTaskContext(context);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();

    assertEquals(22, context.getRemoteParentSocketContext().take());
  }

  @Test
  void reusedNumericDescriptorCreatesIndependentOwnership() {
    enableRemoteParentWithNoopEmitter();
    RemoteParentSocketContext.Lifecycle firstLifecycle = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(23, firstLifecycle);
    ThreadInfo.markRemoteParentDirectLookup(firstLifecycle);
    TaskContext first = ThreadInfo.captureTaskContext(101L, firstLifecycle);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    RemoteParentSocketContext.Lifecycle secondLifecycle = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(23, secondLifecycle);
    ThreadInfo.markRemoteParentDirectLookup(secondLifecycle);
    TaskContext second = ThreadInfo.captureTaskContext(101L, secondLifecycle);
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
  void javaDisabledTaskScopeStillRestoresTheWorkerParent() {
    ThreadInfo.setRemoteParentEnabled(false);
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L));
    assertTrue(ThreadInfo.hasTaskRelayState());
    ThreadInfo.restoreTaskParentThreadContext();

    assertFalse(ThreadInfo.hasTaskRelayState());
    assertEquals(2, emitted.size());
    assertEquals(OperationType.THREAD, emitted.get(0).operation);
    assertEquals(101L, emitted.get(0).value);
    assertEquals(OperationType.THREAD, emitted.get(1).operation);
    assertEquals(900L, emitted.get(1).value);
  }

  @Test
  void javaDisabledCycleRejectionUnlinksTheCurrentWorkerContext() {
    ThreadInfo.setRemoteParentEnabled(false);
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L));
    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 202L));
    assertFalse(ThreadInfo.enterTaskParentThreadContext(900L, 101L));

    assertEquals(OperationType.TASK_UNLINK, emitted.get(emitted.size() - 1).operation);
    ThreadInfo.restoreTaskParentThreadContext();
    ThreadInfo.restoreTaskParentThreadContext();
  }

  @Test
  void balancedTaskScopesReuseThePerWorkerRelayState() {
    ThreadInfo.setRemoteParentEnabled(false);
    ThreadInfo.setTaskContextEmitterForTest((operation, value, token) -> {});

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L));
    ThreadInfo.TaskRelayState state = ThreadInfo.taskRelayStateForTest();
    ThreadInfo.restoreTaskParentThreadContext();
    assertFalse(ThreadInfo.hasTaskRelayState());

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 202L));
    assertSame(state, ThreadInfo.taskRelayStateForTest());
    ThreadInfo.restoreTaskParentThreadContext();
    assertFalse(ThreadInfo.hasTaskRelayState());
  }

  @Test
  void duplicateRestoreCannotReuseCachedLookupMetadata() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.markRemoteParentDirectLookup();

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L));
    ThreadInfo.restoreTaskParentThreadContext();
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());
    assertEquals(2, emitted.size());

    ThreadInfo.blockRemoteParentLookup();
    ThreadInfo.restoreTaskParentThreadContext();

    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
    assertEquals(2, emitted.size());
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
  void lookupSourceFollowsTheMostRecentExecutionBoundary() {
    enableRemoteParentWithNoopEmitter();

    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());
    ThreadInfo.markRemoteParentDirectLookup();
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 42L));
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_TASK, ThreadInfo.remoteParentLookupSource());
    ThreadInfo.restoreTaskParentThreadContext();
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());

    ThreadInfo.beginRemoteParentReceiveScope();
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
    ThreadInfo.markRemoteParentDirectLookup();
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());
    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 43L));
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_TASK, ThreadInfo.remoteParentLookupSource());
    ThreadInfo.restoreTaskParentThreadContext();
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());
    ThreadInfo.endRemoteParentReceiveScope();
  }

  @Test
  void nestedReceivePreventsRestoringAnOlderDirectSource() {
    enableRemoteParentWithNoopEmitter();
    ThreadInfo.markRemoteParentDirectLookup();

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 42L));
    ThreadInfo.beginRemoteParentReceiveScope();
    try {
      ThreadInfo.markRemoteParentDirectLookup();
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());
    } finally {
      ThreadInfo.endRemoteParentReceiveScope();
    }
    ThreadInfo.restoreTaskParentThreadContext();

    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
  }

  @Test
  void nonExactTaskEntryBlocksAndThenRestoresAnInboundDirectSource() {
    enableRemoteParentWithNoopEmitter();
    ThreadInfo.markRemoteParentDirectLookup();

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L));
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
    ThreadInfo.restoreTaskParentThreadContext();

    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());
  }

  @Test
  void taskRestoreFailureBlocksLookupAndUnlinksBestEffort() {
    List<EmittedOp> emitted = new ArrayList<>();
    AtomicInteger failingLinks = new AtomicInteger();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> {
          emitted.add(new EmittedOp(operation, value, token));
          if (operation == OperationType.TASK_LINK && failingLinks.getAndIncrement() == 2) {
            throw new IllegalStateException("restore failed");
          }
        });
    ThreadInfo.setRemoteParentEnabled(true);

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 41L));
    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 202L, 42L));
    assertThrows(IllegalStateException.class, ThreadInfo::restoreTaskParentThreadContext);

    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(OperationType.TASK_UNLINK, emitted.get(emitted.size() - 1).operation);
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
    assertEquals(OperationType.THREAD, emitted.get(4).operation);
    assertEquals(0L, emitted.get(4).token);
  }

  @Test
  void nestedOrdinaryScopePreservesAndRestoresAnExactOuterAlias() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 11L));
    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 202L));
    ThreadInfo.restoreTaskParentThreadContext();
    ThreadInfo.restoreTaskParentThreadContext();

    assertEquals(5, emitted.size());
    assertEquals(OperationType.TASK_LINK, emitted.get(0).operation);
    assertEquals(11L, emitted.get(0).token);
    assertEquals(OperationType.TASK_RELAY_CAPTURE, emitted.get(1).operation);
    long restoreToken = emitted.get(1).value;
    assertTrue(restoreToken != 0L);
    assertEquals(OperationType.THREAD, emitted.get(2).operation);
    assertEquals(202L, emitted.get(2).value);
    assertEquals(OperationType.TASK_LINK, emitted.get(3).operation);
    assertEquals(restoreToken, emitted.get(3).token);
    assertEquals(OperationType.THREAD, emitted.get(4).operation);
    assertEquals(900L, emitted.get(4).value);
  }

  @Test
  void nestedExactScopeRestoresAnOrdinaryOuterParentWithoutCapturingARelayAlias() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);

    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L));
    assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 202L, 22L));
    ThreadInfo.restoreTaskParentThreadContext();
    ThreadInfo.restoreTaskParentThreadContext();

    assertEquals(4, emitted.size());
    assertEquals(OperationType.THREAD, emitted.get(0).operation);
    assertEquals(101L, emitted.get(0).value);
    assertEquals(OperationType.TASK_LINK, emitted.get(1).operation);
    assertEquals(22L, emitted.get(1).token);
    assertEquals(OperationType.THREAD, emitted.get(2).operation);
    assertEquals(101L, emitted.get(2).value);
    assertEquals(OperationType.THREAD, emitted.get(3).operation);
    assertEquals(900L, emitted.get(3).value);
    assertEquals(
        0, emitted.stream().filter(op -> op.operation == OperationType.TASK_RELAY_CAPTURE).count());
  }

  @Test
  void scopeEnteredBeforeDisableStillRestoresTheWorkerParent() throws Exception {
    List<Long> emitted = Collections.synchronizedList(new ArrayList<>());
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch disabled = new CountDownLatch(1);
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> {
          if (operation == OperationType.THREAD) {
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
  void genericTaskCaptureIsStrictOnlyInsideAnExactNettyHandlerConnectionScope() throws Exception {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    ExactNettyContext exact = new ExactNettyContext(31);
    ExactNettyContext unrelated = new ExactNettyContext(32);
    Object outside = new Object();
    Object connectionOnly = new Object();
    Object handlerOnly = new Object();
    Object mismatched = new Object();
    Object authorized = new Object();
    Object after = new Object();
    Object stale = new Object();

    try {
      assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(32, unrelated.lifecycle));
      SSLStorage.trackTask(101L, outside);
      TaskContext outsideContext = SSLStorage.takeTaskContext(outside);
      assertEquals(0L, outsideContext.getHandoffToken());
      assertNull(outsideContext.getRemoteParentSocketContext());
      assertTrue(
          ThreadInfo.enterTaskParentThreadContext(
              900L,
              outsideContext.getParentThreadId(),
              outsideContext.getHandoffToken(),
              outsideContext.getRemoteParentSocketContext()));
      ThreadInfo.restoreTaskParentThreadContext();
      exact.runInConnectionScopeOnly(() -> SSLStorage.trackTask(101L, connectionOnly));
      exact.runInHandlerWithoutConnection(() -> SSLStorage.trackTask(101L, handlerOnly));
      exact.runInHandlerScope(() -> SSLStorage.trackTask(101L, mismatched));
      TaskContext mismatchedContext = SSLStorage.takeTaskContext(mismatched);
      assertEquals(0L, mismatchedContext.getHandoffToken());
      assertNull(mismatchedContext.getRemoteParentSocketContext());
      assertEquals(
          0, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
      assertTrue(
          ThreadInfo.enterTaskParentThreadContext(
              900L,
              mismatchedContext.getParentThreadId(),
              mismatchedContext.getHandoffToken(),
              mismatchedContext.getRemoteParentSocketContext()));
      assertEquals(-1, ThreadInfo.takeRemoteParentSocketFileDescriptor());
      ThreadInfo.restoreTaskParentThreadContext();
      assertEquals(
          0, emitted.stream().filter(op -> op.operation == OperationType.TASK_LINK).count());

      assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(31, exact.lifecycle));
      exact.runInHandlerScope(() -> SSLStorage.trackTask(101L, authorized));
      SSLStorage.trackTask(101L, after);

      TaskContext connectionOnlyContext = SSLStorage.taskContext(connectionOnly);
      TaskContext handlerOnlyContext = SSLStorage.taskContext(handlerOnly);
      TaskContext authorizedContext = SSLStorage.taskContext(authorized);
      TaskContext afterContext = SSLStorage.taskContext(after);
      assertEquals(0L, connectionOnlyContext.getHandoffToken());
      assertNull(connectionOnlyContext.getRemoteParentSocketContext());
      assertEquals(0L, handlerOnlyContext.getHandoffToken());
      assertNull(handlerOnlyContext.getRemoteParentSocketContext());
      assertTrue(authorizedContext.getHandoffToken() != 0L);
      assertEquals(31, authorizedContext.getRemoteParentSocketContext().peek());
      assertEquals(0L, afterContext.getHandoffToken());
      assertNull(afterContext.getRemoteParentSocketContext());

      exact.runInHandlerScope(
          () -> {
            exact.invalidate();
            SSLStorage.trackTask(101L, stale);
          });
      TaskContext staleContext = SSLStorage.taskContext(stale);
      assertEquals(0L, staleContext.getHandoffToken());
      assertNull(staleContext.getRemoteParentSocketContext());
      assertEquals(
          1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
      assertEquals(
          0, emitted.stream().filter(op -> op.operation == OperationType.TASK_LINK).count());
      List<EmittedOp> ordinaryParents =
          emitted.stream()
              .filter(op -> op.operation == OperationType.THREAD)
              .collect(java.util.stream.Collectors.toList());
      assertEquals(4, ordinaryParents.size());
      assertEquals(101L, ordinaryParents.get(0).value);
      assertEquals(900L, ordinaryParents.get(1).value);
      assertEquals(101L, ordinaryParents.get(2).value);
      assertEquals(900L, ordinaryParents.get(3).value);
    } finally {
      SSLStorage.untrackTask(outside);
      SSLStorage.untrackTask(connectionOnly);
      SSLStorage.untrackTask(handlerOnly);
      SSLStorage.untrackTask(mismatched);
      SSLStorage.untrackTask(authorized);
      SSLStorage.untrackTask(after);
      SSLStorage.untrackTask(stale);
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      exact.close();
      unrelated.close();
    }
  }

  @Test
  void exactTaskRelayCanCaptureAnotherHandoffWithoutANettyHandlerScope() throws Exception {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    ExactNettyContext exact = new ExactNettyContext(38);
    Object firstTask = new Object();
    Object secondTask = new Object();
    TaskContext first = null;
    TaskContext second = null;

    try {
      assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(38, exact.lifecycle));
      exact.runInHandlerScope(() -> SSLStorage.trackTask(101L, firstTask));
      first = SSLStorage.takeTaskContext(firstTask);
      assertTrue(first.getHandoffToken() != 0L);
      assertEquals(38, first.getRemoteParentSocketContext().peek());
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.clearRemoteParentLookupSource();

      assertTrue(
          ThreadInfo.enterTaskParentThreadContext(
              201L,
              first.getParentThreadId(),
              first.getHandoffToken(),
              first.getRemoteParentSocketContext(),
              first.getRemoteParentSocketLifecycle()));
      try {
        assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_TASK, ThreadInfo.remoteParentLookupSource());
        assertSame(exact.lifecycle, ThreadInfo.remoteParentLookupLifecycle());
        SSLStorage.trackTask(201L, secondTask);
        second = SSLStorage.takeTaskContext(secondTask);
        assertTrue(second.getHandoffToken() != 0L);
        assertFalse(first.getHandoffToken() == second.getHandoffToken());
        assertSame(first.getRemoteParentSocketContext(), second.getRemoteParentSocketContext());
        assertSame(exact.lifecycle, second.getRemoteParentSocketLifecycle());
      } finally {
        ThreadInfo.restoreTaskParentThreadContext();
      }
      assertFalse(ThreadInfo.hasTaskRelayState());

      assertTrue(
          ThreadInfo.enterTaskParentThreadContext(
              301L,
              second.getParentThreadId(),
              second.getHandoffToken(),
              second.getRemoteParentSocketContext(),
              second.getRemoteParentSocketLifecycle()));
      try {
        assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_TASK, ThreadInfo.remoteParentLookupSource());
        assertSame(exact.lifecycle, ThreadInfo.remoteParentLookupLifecycle());
        assertEquals(38, ThreadInfo.takeRemoteParentSocketFileDescriptor());
      } finally {
        ThreadInfo.restoreTaskParentThreadContext();
      }
      assertFalse(ThreadInfo.hasTaskRelayState());
      assertEquals(6, emitted.size());
      assertOperation(emitted.get(0), OperationType.TASK_CAPTURE, first.getHandoffToken(), 0L);
      assertOperation(emitted.get(1), OperationType.TASK_LINK, 101L, first.getHandoffToken());
      assertOperation(
          emitted.get(2), OperationType.TASK_RELAY_CAPTURE, second.getHandoffToken(), 0L);
      assertOperation(emitted.get(3), OperationType.THREAD, 201L, 0L);
      assertOperation(emitted.get(4), OperationType.TASK_LINK, 201L, second.getHandoffToken());
      assertOperation(emitted.get(5), OperationType.THREAD, 301L, 0L);
    } finally {
      SSLStorage.untrackTask(firstTask);
      SSLStorage.untrackTask(secondTask);
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      exact.close();
    }
  }

  @Test
  void exactTaskRelayRejectsMismatchedAndInvalidatedLifecycles() throws Exception {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    ExactNettyContext exact = new ExactNettyContext(39);
    Object firstTask = new Object();
    Object rejectedTask = new Object();

    try {
      assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(39, exact.lifecycle));
      exact.runInHandlerScope(() -> SSLStorage.trackTask(101L, firstTask));
      TaskContext first = SSLStorage.takeTaskContext(firstTask);
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      ThreadInfo.clearRemoteParentLookupSource();

      assertTrue(
          ThreadInfo.enterTaskParentThreadContext(
              201L,
              first.getParentThreadId(),
              first.getHandoffToken(),
              first.getRemoteParentSocketContext(),
              first.getRemoteParentSocketLifecycle()));
      try {
        TaskContext mismatched =
            ThreadInfo.captureTaskContext(201L, new RemoteParentSocketContext.Lifecycle());
        assertEquals(0L, mismatched.getHandoffToken());
        assertNull(mismatched.getRemoteParentSocketContext());

        exact.invalidate();
        SSLStorage.trackTask(201L, rejectedTask);
        TaskContext invalidated = SSLStorage.taskContext(rejectedTask);
        assertEquals(0L, invalidated.getHandoffToken());
        assertNull(invalidated.getRemoteParentSocketContext());
      } finally {
        ThreadInfo.restoreTaskParentThreadContext();
      }
      assertEquals(
          1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
      assertEquals(
          0,
          emitted.stream().filter(op -> op.operation == OperationType.TASK_RELAY_CAPTURE).count());
      assertFalse(ThreadInfo.hasTaskRelayState());
    } finally {
      SSLStorage.untrackTask(firstTask);
      SSLStorage.untrackTask(rejectedTask);
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      exact.close();
    }
  }

  @Test
  void nonReceiveNettyHandlerScopesCannotAuthorizeStrictCapture() throws Exception {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    ExactNettyContext exact = new ExactNettyContext(35);
    Object outbound = new Object();
    Object legacy = new Object();

    try {
      assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(35, exact.lifecycle));
      exact.runInNonReceiveHandlerScope(() -> SSLStorage.trackTask(101L, outbound));
      exact.runInLegacyHandlerScope(() -> SSLStorage.trackTask(101L, legacy));

      assertEquals(0L, SSLStorage.taskContext(outbound).getHandoffToken());
      assertEquals(0L, SSLStorage.taskContext(legacy).getHandoffToken());
      assertEquals(
          0, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
    } finally {
      SSLStorage.untrackTask(outbound);
      SSLStorage.untrackTask(legacy);
      exact.close();
    }
  }

  @Test
  void inboundHandlerAlwaysCapturesDirectDespiteAnExactTaskOnTheSameLifecycle() throws Exception {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    ExactNettyContext exact = new ExactNettyContext(36);
    Object nextRequest = new Object();
    boolean entered = false;

    try {
      entered = ThreadInfo.enterTaskParentThreadContext(900L, 101L, 42L);
      assertTrue(entered);
      exact.runInHandlerScope(() -> SSLStorage.trackTask(900L, nextRequest));

      assertTrue(SSLStorage.taskContext(nextRequest).getHandoffToken() != 0L);
      assertEquals(
          1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
      assertEquals(
          0,
          emitted.stream().filter(op -> op.operation == OperationType.TASK_RELAY_CAPTURE).count());
    } finally {
      SSLStorage.untrackTask(nextRequest);
      if (entered) {
        ThreadInfo.restoreTaskParentThreadContext();
      }
      exact.close();
    }
  }

  @Test
  void newerInlineExactTaskCannotCaptureTheEnclosingReceive() throws Exception {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    ExactNettyContext exact = new ExactNettyContext(37);
    Object nested = new Object();
    Object resumed = new Object();

    try {
      exact.runInHandlerScope(
          () -> {
            assertTrue(ThreadInfo.enterTaskParentThreadContext(900L, 101L, 42L));
            try {
              SSLStorage.trackTask(101L, nested);
            } finally {
              ThreadInfo.restoreTaskParentThreadContext();
            }
            SSLStorage.trackTask(101L, resumed);
          });

      assertEquals(0L, SSLStorage.taskContext(nested).getHandoffToken());
      assertTrue(SSLStorage.taskContext(resumed).getHandoffToken() != 0L);
      assertEquals(
          1, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
    } finally {
      SSLStorage.untrackTask(nested);
      SSLStorage.untrackTask(resumed);
      exact.close();
    }
  }

  @Test
  void delayedTaskUsesItsSubmissionTokenAfterAnotherParentStages() throws Exception {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    Object taskA = new Object();
    Object taskB = new Object();
    ExactNettyContext exact = new ExactNettyContext(33);

    try {
      exact.runInHandlerScope(
          () -> {
            SSLStorage.trackTask(101L, taskA);
            SSLStorage.trackTask(101L, taskB);
          });
      TaskContext contextA = SSLStorage.taskContext(taskA);
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
    } finally {
      SSLStorage.untrackTask(taskA);
      SSLStorage.untrackTask(taskB);
      exact.close();
    }
  }

  @Test
  void sameTidDifferentSubmissionTokensBecomeAmbiguous() throws Exception {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    Object reusedTask = new Object();
    ExactNettyContext exact = new ExactNettyContext(34);

    try {
      exact.runInHandlerScope(
          () -> {
            SSLStorage.trackTask(101L, reusedTask);
            SSLStorage.trackTask(101L, reusedTask);
          });

      assertEquals(
          2, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
      assertEquals(
          2, emitted.stream().filter(op -> op.operation == OperationType.TASK_CANCEL).count());
      assertTrue(SSLStorage.taskContext(reusedTask) == null);
      assertTrue(SSLStorage.takeTaskContext(reusedTask) == null);
    } finally {
      SSLStorage.untrackTask(reusedTask);
      exact.close();
    }
  }

  @Test
  void delayedTaskOnItsSubmitterTidStillLinksTheExactToken() {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);

    RemoteParentSocketContext.Lifecycle lifecycle = new RemoteParentSocketContext.Lifecycle();
    ThreadInfo.markRemoteParentDirectLookup(lifecycle);
    TaskContext delayed = ThreadInfo.captureTaskContext(900L, lifecycle);
    TaskContext newerDirectContext = ThreadInfo.captureTaskContext(900L, lifecycle);
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
  void directVirtualThreadScopeUsesOrdinaryPropagationAndTerminatesOnce() {
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
    assertEquals(0L, handoffToken);
    kernelTid.set(900L);
    VirtualThreadInst.MountAdvice.exit(virtualThread);
    VirtualThreadInst.UnmountAdvice.exit();
    VirtualThreadInst.MountAdvice.exit(virtualThread);
    VirtualThreadInst.RunAdvice.exit(virtualThread);
    VirtualThreadInst.AfterDoneAdvice.exit(virtualThread);

    assertNull(SSLStorage.taskContext(virtualThread));
    assertFalse(ThreadInfo.hasTaskRelayState());
    assertEquals(
        0, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
    assertEquals(2, emitted.stream().filter(op -> op.operation == OperationType.VT_MOUNT).count());
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.VT_UNMOUNT).count());
    assertEquals(
        1, emitted.stream().filter(op -> op.operation == OperationType.VT_TERMINATE).count());
    List<EmittedOp> parents =
        emitted.stream()
            .filter(op -> op.operation == OperationType.THREAD)
            .collect(java.util.stream.Collectors.toList());
    assertEquals(2, parents.size());
    assertEquals(101L, parents.get(0).value);
    assertEquals(0L, parents.get(0).token);
    assertEquals(900L, parents.get(1).value);
    assertEquals(0L, parents.get(1).token);
  }

  @Test
  void virtualThreadThatNeverMountsDropsItsOrdinaryStartContext() {
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
        0, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
    assertEquals(
        0, emitted.stream().filter(op -> op.operation == OperationType.TASK_CANCEL).count());
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
    assertEquals(0L, startContext.getHandoffToken());
    assertFalse(startContext.getParentThreadId() == 101L);

    kernelTid.set(900L);
    VirtualThreadInst.MountAdvice.exit(virtualThread);
    VirtualThreadInst.RunAdvice.exit(virtualThread);
    VirtualThreadInst.AfterDoneAdvice.exit(virtualThread);

    assertTrue(
        emitted.stream().anyMatch(op -> op.operation == OperationType.THREAD && op.value == 202L));
    assertFalse(
        emitted.stream().anyMatch(op -> op.operation == OperationType.THREAD && op.value == 101L));
  }

  @Test
  void failedVirtualThreadStartDropsItsOrdinaryContext() {
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
        0, emitted.stream().filter(op -> op.operation == OperationType.TASK_CAPTURE).count());
    assertEquals(
        0, emitted.stream().filter(op -> op.operation == OperationType.TASK_CANCEL).count());
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
  void threadPoolWorkerHooksScopeHiddenLambdaTasksOnceAcrossOverrides() throws Exception {
    List<EmittedOp> emitted = new ArrayList<>();
    ThreadInfo.setTaskContextEmitterForTest(
        (operation, value, token) -> emitted.add(new EmittedOp(operation, value, token)));
    ThreadInfo.setRemoteParentEnabled(true);
    setStorageThreadIdProvider(() -> 900L);
    Runnable task = () -> {};
    ExactNettyContext exact = new ExactNettyContext(17);

    try {
      assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(17, exact.lifecycle));
      exact.runInHandlerScope(() -> SSLStorage.trackTask(101L, task));
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
      assertEquals(OperationType.THREAD, emitted.get(2).operation);
      assertEquals(900L, emitted.get(2).value);
      assertEquals(0L, emitted.get(2).token);
    } finally {
      SSLStorage.untrackTask(task);
      exact.close();
    }
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

  private static final class ExactNettyContext implements AutoCloseable {
    private final Object channel = new Object();
    private final Connection connection;
    private final RemoteParentSocketContext.Lifecycle lifecycle;
    private boolean handlerScope;

    ExactNettyContext(int socketFileDescriptor) throws Exception {
      connection =
          new Connection(
              InetAddress.getByName("127.0.0.1"),
              20_000 + socketFileDescriptor,
              InetAddress.getByName("127.0.0.2"),
              30_000 + socketFileDescriptor,
              socketFileDescriptor);
      assertTrue(SSLStorage.associateConnectionWithChannel(channel, connection) == connection);
      lifecycle =
          (RemoteParentSocketContext.Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
      assertTrue(lifecycle != null && lifecycle.active());
    }

    void runInHandlerScope(Runnable action) {
      SSLStorage.beginNettyHandlerScope(null, true);
      handlerScope = true;
      try {
        assertTrue(SSLStorage.setCurrentNettyConnection(connection));
        ThreadInfo.markRemoteParentDirectLookup(lifecycle);
        action.run();
      } finally {
        handlerScope = false;
        SSLStorage.endNettyHandlerScope();
      }
    }

    void runInConnectionScopeOnly(Runnable action) {
      SSLStorage.beginNettyConnectionScope();
      try {
        assertTrue(SSLStorage.setCurrentNettyConnection(connection));
        action.run();
      } finally {
        SSLStorage.endNettyConnectionScope();
      }
    }

    void runInNonReceiveHandlerScope(Runnable action) {
      runInHandlerScope(false, action);
    }

    void runInLegacyHandlerScope(Runnable action) {
      SSLStorage.beginNettyHandlerScope(null);
      handlerScope = true;
      try {
        assertTrue(SSLStorage.setCurrentNettyConnection(connection));
        action.run();
      } finally {
        handlerScope = false;
        SSLStorage.endNettyHandlerScope();
      }
    }

    void runInHandlerWithoutConnection(Runnable action) {
      SSLStorage.beginNettyHandlerScope(null, true);
      handlerScope = true;
      try {
        action.run();
      } finally {
        handlerScope = false;
        SSLStorage.endNettyHandlerScope();
      }
    }

    private void runInHandlerScope(boolean receiving, Runnable action) {
      SSLStorage.beginNettyHandlerScope(null, receiving);
      handlerScope = true;
      try {
        assertTrue(SSLStorage.setCurrentNettyConnection(connection));
        if (receiving) {
          ThreadInfo.markRemoteParentDirectLookup(lifecycle);
        }
        action.run();
      } finally {
        handlerScope = false;
        SSLStorage.endNettyHandlerScope();
      }
    }

    @Override
    public void close() {
      if (handlerScope) {
        handlerScope = false;
        SSLStorage.endNettyHandlerScope();
      }
      SSLStorage.cleanupConnection(channel, connection);
    }

    void invalidate() {
      SSLStorage.cleanupConnection(channel, connection);
    }
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

  private static void assertOperation(
      EmittedOp actual, OperationType operation, long value, long token) {
    assertEquals(operation, actual.operation);
    assertEquals(value, actual.value);
    assertEquals(token, actual.token);
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
