/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class ExecutorRuntimeProbe {
  private static final List<Event> EVENTS = Collections.synchronizedList(new ArrayList<Event>());

  private ExecutorRuntimeProbe() {}

  public static void main(String[] args) throws Exception {
    installEventRecorder();
    verifyDirectSameThreadOwnership();
    verifyParentChainDepthAndCycleLimits();
    verifyNestedExecutorHandoffs();
    verifyCancellationTimeoutAndRejectionCleanup();
    System.out.println("executor-agent-probe passed");
  }

  private static void verifyDirectSameThreadOwnership() {
    try {
      setSocketFileDescriptor(70);
      require(socketFileDescriptor() == 70, "same-thread socket ownership was not visible");
      require(takeSocketFileDescriptor() == 70, "same-thread socket ownership was not claimed");
      require(takeSocketFileDescriptor() == -1, "same-thread socket ownership was claimed twice");
    } finally {
      clearSocketFileDescriptor();
    }
  }

  private static void verifyParentChainDepthAndCycleLimits() throws Exception {
    int maxDepth = maxTaskRelayDepth();
    require(maxDepth == 64, "unexpected task relay depth limit: " + maxDepth);

    verifyParentChainDepthLimit(maxDepth);
    verifyParentChainCycleLimit(maxDepth);
    System.out.println("parent-chain-limit depth=64 cycle=blocked cleanup=clean");
  }

  private static void verifyParentChainDepthLimit(int maxDepth) throws Exception {
    AtomicInteger executed = new AtomicInteger();
    AtomicInteger recoveryExecuted = new AtomicInteger();
    AtomicReference<Thread> executionThread = new AtomicReference<Thread>();
    FutureTask<?>[] tasks =
        nestedTasks("depth", maxDepth + 1, maxDepth, 81, executed, executionThread);
    FutureTask<?> recovery =
        nestedTasks("depth-recovery", 1, -1, -1, recoveryExecuted, executionThread)[0];
    Runnable[] submitted = append(tasks, recovery);
    int[] submitterGroups = new int[submitted.length];
    for (int i = 0; i < submitterGroups.length; i++) {
      submitterGroups[i] = i;
    }

    CapturedTasks captured = captureTasks("depth", submitted, submitterGroups);
    try {
      int start = eventCount();
      AtomicInteger primaryEnd = new AtomicInteger(-1);
      WorkerResult worker =
          runOnDedicatedWorker(
              "depth",
              workerThreadId -> {
                tasks[0].run();
                requireCompletedAndUntracked(tasks);
                requireRelayCleanup("depth limit");
                primaryEnd.set(eventCount());
                recovery.run();
                requireCompletedAndUntracked(new FutureTask<?>[] {recovery});
                requireRelayCleanup("depth recovery");
              });
      int end = eventCount();

      require(
          executionThread.get() == worker.thread,
          "depth chain did not execute on its dedicated worker");
      captured.requireParentsDifferFrom(worker.threadId);
      List<Event> events = snapshot(start, primaryEnd.get());
      require(executed.get() == maxDepth + 1, "depth rejection suppressed application execution");
      require(
          events.size() == maxDepth * 2 + 1,
          "depth limit emitted an unexpected event sequence: " + events);
      for (int i = 0; i < maxDepth; i++) {
        requireEvent(events.get(i), "THREAD", captured.parentThreadId(i), 0L, "depth entry " + i);
      }
      requireEvent(events.get(maxDepth), "TASK_UNLINK", 0L, 0L, "depth rejection");
      for (int i = 0; i < maxDepth - 1; i++) {
        requireEvent(
            events.get(maxDepth + 1 + i),
            "THREAD",
            captured.parentThreadId(maxDepth - 2 - i),
            0L,
            "depth unwind " + i);
      }
      requireEvent(
          events.get(events.size() - 1), "THREAD", worker.threadId, 0L, "depth final unwind");
      requireNoStrictHandoffEvents(events, "depth limit");
      requireRecoveryEvents(
          snapshot(primaryEnd.get(), end),
          captured.parentThreadId(submitted.length - 1),
          worker.threadId,
          recoveryExecuted.get(),
          "depth recovery");
    } finally {
      captured.close();
    }
  }

  private static void verifyParentChainCycleLimit(int maxDepth) throws Exception {
    AtomicInteger executed = new AtomicInteger();
    AtomicInteger recoveryExecuted = new AtomicInteger();
    AtomicReference<Thread> executionThread = new AtomicReference<Thread>();
    FutureTask<?>[] tasks = nestedTasks("cycle", 3, 2, 82, executed, executionThread);
    FutureTask<?> recovery =
        nestedTasks("cycle-recovery", 1, -1, -1, recoveryExecuted, executionThread)[0];
    Runnable[] submitted = append(tasks, recovery);
    CapturedTasks captured = captureTasks("cycle", submitted, new int[] {0, 1, 0, 2});
    try {
      require(
          captured.parentThreadId(0) == captured.parentThreadId(2),
          "cycle endpoints were not captured from the same live submitter");
      require(
          captured.parentThreadId(0) != captured.parentThreadId(1),
          "cycle submitter identities were not distinct");

      int start = eventCount();
      AtomicInteger primaryEnd = new AtomicInteger(-1);
      WorkerResult worker =
          runOnDedicatedWorker(
              "cycle",
              workerThreadId -> {
                tasks[0].run();
                requireCompletedAndUntracked(tasks);
                requireRelayCleanup("cycle limit");
                primaryEnd.set(eventCount());
                recovery.run();
                requireCompletedAndUntracked(new FutureTask<?>[] {recovery});
                requireRelayCleanup("cycle recovery");
              });
      int end = eventCount();

      require(
          executionThread.get() == worker.thread,
          "cycle chain did not execute on its dedicated worker");
      captured.requireParentsDifferFrom(worker.threadId);
      List<Event> events = snapshot(start, primaryEnd.get());
      require(executed.get() == 3, "cycle rejection suppressed application execution");
      require(events.size() == 5, "cycle limit emitted an unexpected event sequence: " + events);
      requireEvent(events.get(0), "THREAD", captured.parentThreadId(0), 0L, "cycle first entry");
      requireEvent(events.get(1), "THREAD", captured.parentThreadId(1), 0L, "cycle second entry");
      requireEvent(events.get(2), "TASK_UNLINK", 0L, 0L, "cycle rejection");
      requireEvent(events.get(3), "THREAD", captured.parentThreadId(0), 0L, "cycle first unwind");
      requireEvent(events.get(4), "THREAD", worker.threadId, 0L, "cycle final unwind");
      requireNoStrictHandoffEvents(events, "cycle limit");
      requireRecoveryEvents(
          snapshot(primaryEnd.get(), end),
          captured.parentThreadId(submitted.length - 1),
          worker.threadId,
          recoveryExecuted.get(),
          "cycle recovery");
    } finally {
      captured.close();
    }
  }

  private static FutureTask<?>[] nestedTasks(
      String scenario,
      int count,
      int rejectedIndex,
      int rejectionDescriptor,
      AtomicInteger executed,
      AtomicReference<Thread> executionThread) {
    FutureTask<?>[] tasks = new FutureTask<?>[count];
    for (int i = tasks.length - 1; i >= 0; i--) {
      final int index = i;
      tasks[i] =
          new FutureTask<Void>(
              new NamedTask(
                  scenario + '-' + Integer.toString(i),
                  () -> {
                    Thread current = Thread.currentThread();
                    Thread observed = executionThread.get();
                    if (observed == null) {
                      executionThread.compareAndSet(null, current);
                      observed = executionThread.get();
                    }
                    require(
                        current == observed,
                        scenario + " chain changed execution threads at " + index);
                    if (index == rejectedIndex) {
                      require(
                          remoteParentLookupSource()
                              == threadInfoIntConstant("REMOTE_PARENT_LOOKUP_BLOCKED"),
                          scenario + " rejection did not block remote-parent lookup");
                      require(
                          socketFileDescriptor() == -1,
                          scenario + " rejection retained socket ownership");
                    }
                    executed.incrementAndGet();
                    if (index + 1 < tasks.length) {
                      if (index + 1 == rejectedIndex) {
                        setSocketFileDescriptor(rejectionDescriptor);
                        markRemoteParentDirectLookup();
                        require(
                            remoteParentLookupSource()
                                == threadInfoIntConstant("REMOTE_PARENT_LOOKUP_DIRECT"),
                            scenario + " did not stage direct lookup before rejection");
                        require(
                            socketFileDescriptor() == rejectionDescriptor,
                            scenario + " did not stage socket ownership before rejection");
                      }
                      tasks[index + 1].run();
                    }
                  }),
              null);
    }
    return tasks;
  }

  private static Runnable[] append(FutureTask<?>[] tasks, FutureTask<?> extra) {
    Runnable[] combined = new Runnable[tasks.length + 1];
    System.arraycopy(tasks, 0, combined, 0, tasks.length);
    combined[tasks.length] = extra;
    return combined;
  }

  private static void requireRecoveryEvents(
      List<Event> events, long parentThreadId, long workerThreadId, int executed, String scenario) {
    require(executed == 1, scenario + " did not execute");
    require(events.size() == 2, scenario + " emitted an unexpected event sequence: " + events);
    requireEvent(events.get(0), "THREAD", parentThreadId, 0L, scenario + " entry");
    requireEvent(events.get(1), "THREAD", workerThreadId, 0L, scenario + " unwind");
  }

  private static void requireCompletedAndUntracked(FutureTask<?>[] tasks) throws Exception {
    for (int i = 0; i < tasks.length; i++) {
      require(tasks[i].isDone(), "nested task did not complete at " + i);
      tasks[i].get(1, TimeUnit.SECONDS);
      require(taskContext(tasks[i]) == null, "nested task retained context at " + i);
    }
  }

  private static void requireRelayCleanup(String scenario) {
    require(!hasTaskRelayState(), scenario + " retained task relay state");
    require(socketFileDescriptor() == -1, scenario + " retained socket ownership");
    require(
        remoteParentLookupSource() == threadInfoIntConstant("REMOTE_PARENT_LOOKUP_DIRECT"),
        scenario + " left remote-parent lookup blocked");
  }

  private static void requireNoStrictHandoffEvents(List<Event> events, String scenario) {
    require(
        count(events, "TASK_CAPTURE") == 0
            && count(events, "TASK_RELAY_CAPTURE") == 0
            && count(events, "TASK_LINK") == 0
            && count(events, "TASK_CANCEL") == 0,
        scenario + " emitted an unexpected strict handoff operation: " + events);
  }

  private static void requireEvent(
      Event event, String operation, long value, long token, String description) {
    require(
        operation.equals(event.operation) && event.value == value && event.token == token,
        description
            + " was "
            + event
            + " instead of "
            + operation
            + '('
            + value
            + ','
            + token
            + ')');
  }

  private static CapturedTasks captureTasks(
      String scenario, Runnable[] tasks, int[] submitterGroups) throws Exception {
    require(tasks.length > 0, scenario + " did not provide tasks to capture");
    require(
        tasks.length == submitterGroups.length,
        scenario + " task and submitter-group counts differ");
    int groupCount = 0;
    for (int group : submitterGroups) {
      require(group >= 0, scenario + " used a negative submitter group");
      groupCount = Math.max(groupCount, group + 1);
    }
    boolean[] groupUsed = new boolean[groupCount];
    for (int group : submitterGroups) {
      groupUsed[group] = true;
    }
    for (int group = 0; group < groupUsed.length; group++) {
      require(groupUsed[group], scenario + " skipped submitter group " + group);
    }

    ThreadPoolExecutor executor =
        new ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<Runnable>());
    CountDownLatch workerBlocked = new CountDownLatch(1);
    CountDownLatch releaseWorker = new CountDownLatch(1);
    CountDownLatch submitted = new CountDownLatch(groupCount);
    CountDownLatch releaseSubmitters = new CountDownLatch(1);
    Thread[] submitters = new Thread[groupCount];
    long[] parentThreadIds = new long[tasks.length];
    long[] groupThreadIds = new long[groupCount];
    AtomicReference<Throwable> submitterFailure = new AtomicReference<Throwable>();
    CapturedTasks captured =
        new CapturedTasks(
            scenario,
            tasks,
            parentThreadIds,
            groupThreadIds,
            executor,
            releaseWorker,
            releaseSubmitters,
            submitters);

    try {
      executor.execute(
          new NamedTask(
              scenario + "-capture-blocker",
              () -> {
                workerBlocked.countDown();
                awaitUninterruptibly(releaseWorker);
              }));
      require(
          workerBlocked.await(5, TimeUnit.SECONDS),
          scenario + " capture executor worker did not block");

      for (int group = 0; group < groupCount; group++) {
        final int submitterGroup = group;
        Thread submitter =
            new Thread(
                () -> {
                  try {
                    long parentThreadId = currentThreadId();
                    groupThreadIds[submitterGroup] = parentThreadId;
                    for (int i = 0; i < tasks.length; i++) {
                      if (submitterGroups[i] != submitterGroup) {
                        continue;
                      }
                      executor.execute(tasks[i]);
                      Object context = taskContextUnchecked(tasks[i]);
                      require(context != null, scenario + " task was not captured at " + i);
                      long capturedParent = taskContextLong(context, "getParentThreadId");
                      require(
                          capturedParent == parentThreadId,
                          scenario + " task captured the wrong submitter at " + i);
                      require(
                          taskContextLong(context, "getHandoffToken") == 0L,
                          scenario + " unexpectedly captured a strict handoff at " + i);
                      parentThreadIds[i] = capturedParent;
                    }
                  } catch (Throwable failure) {
                    recordFailure(submitterFailure, failure);
                  } finally {
                    submitted.countDown();
                    awaitUninterruptibly(releaseSubmitters);
                  }
                },
                "executor-probe-" + scenario + "-submitter-" + Integer.toString(group));
        submitter.setDaemon(true);
        submitters[group] = submitter;
        submitter.start();
      }

      require(
          submitted.await(10, TimeUnit.SECONDS), scenario + " task submissions did not complete");
      rethrowHelperFailure(scenario + " submitter", submitterFailure.get());
      for (int group = 0; group < groupThreadIds.length; group++) {
        require(groupThreadIds[group] > 0L, scenario + " submitter had no native TID at " + group);
        require(submitters[group].isAlive(), scenario + " submitter exited before execution");
        for (int previous = 0; previous < group; previous++) {
          require(
              groupThreadIds[group] != groupThreadIds[previous],
              scenario + " live submitters shared a native TID");
        }
      }

      List<Runnable> queued = new ArrayList<Runnable>();
      executor.getQueue().drainTo(queued);
      requireQueuedExactly(scenario, queued, tasks);
      return captured;
    } catch (Exception | Error failure) {
      try {
        captured.close();
      } catch (Throwable cleanupFailure) {
        failure.addSuppressed(cleanupFailure);
      }
      throw failure;
    }
  }

  private static void requireQueuedExactly(
      String scenario, List<Runnable> queued, Runnable[] expected) {
    require(
        queued.size() == expected.length,
        scenario + " captured " + queued.size() + " queued tasks instead of " + expected.length);
    boolean[] found = new boolean[expected.length];
    for (Runnable queuedTask : queued) {
      int match = -1;
      for (int i = 0; i < expected.length; i++) {
        if (queuedTask == expected[i]) {
          match = i;
          break;
        }
      }
      require(match >= 0, scenario + " capture queue contained an unknown task");
      require(!found[match], scenario + " capture queue contained a task twice at " + match);
      found[match] = true;
    }
    for (int i = 0; i < found.length; i++) {
      require(found[i], scenario + " capture queue omitted task " + i);
    }
  }

  private static WorkerResult runOnDedicatedWorker(String scenario, WorkerAction action)
      throws Exception {
    AtomicReference<Throwable> workerFailure = new AtomicReference<Throwable>();
    long[] workerThreadId = new long[1];
    Thread worker =
        new Thread(
            () -> {
              try {
                workerThreadId[0] = currentThreadId();
                action.run(workerThreadId[0]);
              } catch (Throwable failure) {
                recordFailure(workerFailure, failure);
              }
            },
            "executor-probe-" + scenario + "-runtime-worker");
    worker.setDaemon(true);
    worker.start();
    worker.join(TimeUnit.SECONDS.toMillis(10));
    if (worker.isAlive()) {
      worker.interrupt();
      worker.join(TimeUnit.SECONDS.toMillis(2));
    }
    require(!worker.isAlive(), scenario + " runtime worker did not terminate");
    rethrowHelperFailure(scenario + " runtime worker", workerFailure.get());
    require(workerThreadId[0] > 0L, scenario + " runtime worker had no native TID");
    return new WorkerResult(worker, workerThreadId[0]);
  }

  private static void rethrowHelperFailure(String description, Throwable failure) {
    if (failure != null) {
      throw new AssertionError(description + " failed", failure);
    }
  }

  private static void recordFailure(AtomicReference<Throwable> destination, Throwable failure) {
    if (!destination.compareAndSet(null, failure)) {
      destination.get().addSuppressed(failure);
    }
  }

  private static void awaitUninterruptibly(CountDownLatch latch) {
    boolean interrupted = false;
    while (true) {
      try {
        latch.await();
        break;
      } catch (InterruptedException ignored) {
        interrupted = true;
      }
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
  }

  private static void installEventRecorder() throws Exception {
    Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
    Class<?> emitter =
        Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo$TaskContextEmitter", true, null);
    Object recorder =
        Proxy.newProxyInstance(
            null,
            new Class<?>[] {emitter},
            (proxy, method, values) -> {
              if ("emit".equals(method.getName())) {
                EVENTS.add(
                    new Event(
                        String.valueOf(values[0]),
                        ((Long) values[1]).longValue(),
                        ((Long) values[2]).longValue()));
              }
              return null;
            });
    Method setEmitter = threadInfo.getDeclaredMethod("setTaskContextEmitterForTest", emitter);
    setEmitter.setAccessible(true);
    setEmitter.invoke(null, recorder);
    threadInfo.getMethod("setRemoteParentEnabled", boolean.class).invoke(null, true);
  }

  private static void verifyNestedExecutorHandoffs() throws Exception {
    ExecutorService first = Executors.newFixedThreadPool(2);
    ExecutorService second = Executors.newFixedThreadPool(2);
    CountDownLatch complete = new CountDownLatch(1);
    AtomicInteger claimedDescriptor = new AtomicInteger(-2);
    NamedTask[] tasks = new NamedTask[3];
    tasks[2] =
        new NamedTask(
            "third",
            () -> {
              claimedDescriptor.set(takeSocketFileDescriptor());
              complete.countDown();
            });
    tasks[1] = new NamedTask("second", () -> first.execute(tasks[2]));
    tasks[0] = new NamedTask("first", () -> second.execute(tasks[1]));
    int start = eventCount();

    try {
      setSocketFileDescriptor(71);
      first.execute(tasks[0]);
      require(complete.await(5, TimeUnit.SECONDS), "nested executor chain did not complete");
      require(
          claimedDescriptor.get() == -1,
          "ordinary nested executor acquired unauthorized socket ownership");
      require(
          socketFileDescriptor() == 71,
          "ordinary nested executor consumed the submitter socket ownership");
      awaitNoContext(tasks[0]);
      awaitNoContext(tasks[1]);
      awaitNoContext(tasks[2]);
      awaitOperationCount(start, "THREAD", 6);

      List<Event> events = snapshotSince(start);
      require(
          count(events, "TASK_CAPTURE") == 0
              && count(events, "TASK_LINK") == 0
              && count(events, "TASK_CANCEL") == 0,
          "ordinary nested executor emitted a strict bridge operation: " + events);
      require(count(events, "THREAD") >= 6, "ordinary parents were not restored: " + events);

      CountDownLatch secondComplete = new CountDownLatch(1);
      AtomicInteger secondDescriptor = new AtomicInteger(-2);
      NamedTask secondHop =
          new NamedTask(
              "second-run-worker",
              () -> {
                secondDescriptor.set(takeSocketFileDescriptor());
                secondComplete.countDown();
              });
      NamedTask firstHop = new NamedTask("second-run-submitter", () -> second.execute(secondHop));
      setSocketFileDescriptor(72);
      first.execute(firstHop);
      require(secondComplete.await(5, TimeUnit.SECONDS), "second executor chain did not complete");
      require(
          secondDescriptor.get() == -1,
          "fresh ordinary executor chain acquired unauthorized socket ownership");
      require(
          socketFileDescriptor() == 72,
          "fresh ordinary executor chain consumed the submitter socket ownership");

      CountDownLatch reuseComplete = new CountDownLatch(2);
      AtomicInteger leakedDescriptors = new AtomicInteger();
      first.execute(
          new NamedTask(
              "first-reuse",
              () -> {
                if (socketFileDescriptor() != -1) {
                  leakedDescriptors.incrementAndGet();
                }
                reuseComplete.countDown();
              }));
      second.execute(
          new NamedTask(
              "second-reuse",
              () -> {
                if (socketFileDescriptor() != -1) {
                  leakedDescriptors.incrementAndGet();
                }
                reuseComplete.countDown();
              }));
      require(reuseComplete.await(5, TimeUnit.SECONDS), "worker reuse probes did not complete");
      require(leakedDescriptors.get() == 0, "executor worker reused accepted socket ownership");
      List<Event> allEvents = snapshotSince(start);
      require(
          count(allEvents, "TASK_CAPTURE") == 0
              && count(allEvents, "TASK_LINK") == 0
              && count(allEvents, "TASK_CANCEL") == 0,
          "generic executor path emitted a strict bridge operation: " + allEvents);
    } finally {
      clearSocketFileDescriptor();
      shutdown(first);
      shutdown(second);
    }
  }

  private static void verifyCancellationTimeoutAndRejectionCleanup() throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    CountDownLatch workerBlocked = new CountDownLatch(1);
    CountDownLatch releaseWorker = new CountDownLatch(1);
    executor.execute(
        new NamedTask(
            "blocker",
            () -> {
              workerBlocked.countDown();
              await(releaseWorker);
            }));
    require(workerBlocked.await(5, TimeUnit.SECONDS), "executor worker did not block");
    int start = eventCount();

    setSocketFileDescriptor(73);
    FutureTask<Void> cancelled = new FutureTask<Void>(new NamedTask("cancelled", () -> {}), null);
    executor.execute(cancelled);
    clearSocketFileDescriptor();
    require(taskContext(cancelled) != null, "queued cancellation task was not tracked");
    require(cancelled.cancel(false), "queued task was not cancelled");
    awaitNoContext(cancelled);

    FutureTask<Void> timedOut = new FutureTask<Void>(new NamedTask("timed-out", () -> {}), null);
    executor.execute(timedOut);
    require(taskContext(timedOut) != null, "queued timeout task was not tracked");
    try {
      timedOut.get(1, TimeUnit.MILLISECONDS);
      throw new AssertionError("queued task unexpectedly completed before timeout");
    } catch (TimeoutException expected) {
    }
    require(timedOut.cancel(false), "timed-out task was not cancelled");
    awaitNoContext(timedOut);

    ExecutorService rejectedExecutor = Executors.newSingleThreadExecutor();
    rejectedExecutor.shutdown();
    NamedTask rejected = new NamedTask("rejected", () -> {});
    setSocketFileDescriptor(74);
    try {
      rejectedExecutor.execute(rejected);
      throw new AssertionError("shutdown executor accepted a task");
    } catch (RejectedExecutionException expected) {
    } finally {
      clearSocketFileDescriptor();
    }
    awaitNoContext(rejected);

    releaseWorker.countDown();
    CountDownLatch reuseComplete = new CountDownLatch(1);
    AtomicInteger reusedDescriptor = new AtomicInteger(-2);
    executor.execute(
        new NamedTask(
            "post-cancellation-reuse",
            () -> {
              reusedDescriptor.set(socketFileDescriptor());
              reuseComplete.countDown();
            }));
    require(reuseComplete.await(5, TimeUnit.SECONDS), "post-cancellation probe did not complete");
    require(reusedDescriptor.get() == -1, "cancelled task leaked socket ownership to its worker");
    shutdown(executor);
    List<Event> events = snapshotSince(start);
    require(
        count(events, "TASK_CAPTURE") == 0
            && count(events, "TASK_LINK") == 0
            && count(events, "TASK_CANCEL") == 0,
        "ordinary cancel, timeout, or rejection emitted a strict bridge operation: " + events);
    require(
        count(events, "THREAD") >= 2,
        "executed ordinary task did not restore its parent: " + events);
  }

  private static void awaitNoContext(Object task) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < deadline) {
      if (taskContext(task) == null) {
        return;
      }
      Thread.sleep(10);
    }
    throw new AssertionError("task retained context: " + task);
  }

  private static void awaitOperationCount(int start, String operation, long expected)
      throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < deadline) {
      if (count(snapshotSince(start), operation) >= expected) {
        return;
      }
      Thread.sleep(10);
    }
    throw new AssertionError(
        operation + " count did not reach " + expected + ": " + snapshotSince(start));
  }

  private static Object taskContext(Object task) throws Exception {
    Class<?> storage =
        Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
    return storage.getMethod("taskContext", Object.class).invoke(null, task);
  }

  private static Object taskContextUnchecked(Object task) {
    try {
      return taskContext(task);
    } catch (Exception failure) {
      throw new AssertionError(failure);
    }
  }

  private static long taskContextLong(Object context, String method) {
    try {
      return ((Long) context.getClass().getMethod(method).invoke(context)).longValue();
    } catch (ReflectiveOperationException failure) {
      throw new AssertionError(failure);
    }
  }

  private static void untrackTask(Object task) {
    try {
      Class<?> storage =
          Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
      storage.getMethod("untrackTask", Object.class).invoke(null, task);
    } catch (ReflectiveOperationException failure) {
      throw new AssertionError(failure);
    }
  }

  private static long currentThreadId() {
    try {
      Class<?> storage =
          Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
      return ((Long) storage.getMethod("currentThreadId").invoke(null)).longValue();
    } catch (ReflectiveOperationException failure) {
      throw new AssertionError(failure);
    }
  }

  private static int maxTaskRelayDepth() {
    try {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      Field field = threadInfo.getDeclaredField("MAX_TASK_RELAY_DEPTH");
      field.setAccessible(true);
      return field.getInt(null);
    } catch (ReflectiveOperationException failure) {
      throw new AssertionError(failure);
    }
  }

  private static int threadInfoIntConstant(String name) {
    try {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      return threadInfo.getField(name).getInt(null);
    } catch (ReflectiveOperationException failure) {
      throw new AssertionError(failure);
    }
  }

  private static boolean hasTaskRelayState() {
    try {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      Method method = threadInfo.getDeclaredMethod("hasTaskRelayState");
      method.setAccessible(true);
      return ((Boolean) method.invoke(null)).booleanValue();
    } catch (ReflectiveOperationException failure) {
      throw new AssertionError(failure);
    }
  }

  private static void setSocketFileDescriptor(int socketFileDescriptor) {
    invokeThreadInfo(
        "setRemoteParentSocketFileDescriptor",
        new Class<?>[] {int.class},
        new Object[] {Integer.valueOf(socketFileDescriptor)});
  }

  private static int socketFileDescriptor() {
    return ((Integer)
            invokeThreadInfo("remoteParentSocketFileDescriptor", new Class<?>[0], new Object[0]))
        .intValue();
  }

  private static int takeSocketFileDescriptor() {
    return ((Integer)
            invokeThreadInfo(
                "takeRemoteParentSocketFileDescriptor", new Class<?>[0], new Object[0]))
        .intValue();
  }

  private static int remoteParentLookupSource() {
    return ((Integer) invokeThreadInfo("remoteParentLookupSource", new Class<?>[0], new Object[0]))
        .intValue();
  }

  private static void markRemoteParentDirectLookup() {
    invokeThreadInfo("markRemoteParentDirectLookup", new Class<?>[0], new Object[0]);
  }

  private static void clearSocketFileDescriptor() {
    invokeThreadInfo("clearRemoteParentSocketFileDescriptor", new Class<?>[0], new Object[0]);
  }

  private static Object invokeThreadInfo(String name, Class<?>[] parameterTypes, Object[] values) {
    try {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      return threadInfo.getMethod(name, parameterTypes).invoke(null, values);
    } catch (ReflectiveOperationException failure) {
      throw new AssertionError(failure);
    }
  }

  private static void await(CountDownLatch latch) {
    try {
      latch.await();
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
    }
  }

  private static void shutdown(ExecutorService executor) throws InterruptedException {
    executor.shutdownNow();
    require(executor.awaitTermination(5, TimeUnit.SECONDS), "executor did not terminate");
  }

  private static int eventCount() {
    synchronized (EVENTS) {
      return EVENTS.size();
    }
  }

  private static List<Event> snapshotSince(int start) {
    synchronized (EVENTS) {
      return new ArrayList<Event>(EVENTS.subList(start, EVENTS.size()));
    }
  }

  private static List<Event> snapshot(int start, int end) {
    synchronized (EVENTS) {
      require(start >= 0 && end >= start && end <= EVENTS.size(), "invalid event snapshot range");
      return new ArrayList<Event>(EVENTS.subList(start, end));
    }
  }

  private static long count(List<Event> events, String operation) {
    long count = 0;
    for (Event event : events) {
      if (operation.equals(event.operation)) {
        count++;
      }
    }
    return count;
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }

  private static void joinUntil(Thread thread, long deadlineNanos) throws InterruptedException {
    if (thread == null || !thread.isAlive()) {
      return;
    }
    long remaining = deadlineNanos - System.nanoTime();
    if (remaining <= 0L) {
      return;
    }
    thread.join(Math.max(1L, TimeUnit.NANOSECONDS.toMillis(remaining)));
  }

  private interface WorkerAction {
    void run(long workerThreadId) throws Exception;
  }

  private static final class WorkerResult {
    private final Thread thread;
    private final long threadId;

    private WorkerResult(Thread thread, long threadId) {
      this.thread = thread;
      this.threadId = threadId;
    }
  }

  private static final class CapturedTasks {
    private final String scenario;
    private final Runnable[] tasks;
    private final long[] parentThreadIds;
    private final long[] groupThreadIds;
    private final ThreadPoolExecutor executor;
    private final CountDownLatch releaseWorker;
    private final CountDownLatch releaseSubmitters;
    private final Thread[] submitters;
    private boolean closed;

    private CapturedTasks(
        String scenario,
        Runnable[] tasks,
        long[] parentThreadIds,
        long[] groupThreadIds,
        ThreadPoolExecutor executor,
        CountDownLatch releaseWorker,
        CountDownLatch releaseSubmitters,
        Thread[] submitters) {
      this.scenario = scenario;
      this.tasks = tasks;
      this.parentThreadIds = parentThreadIds;
      this.groupThreadIds = groupThreadIds;
      this.executor = executor;
      this.releaseWorker = releaseWorker;
      this.releaseSubmitters = releaseSubmitters;
      this.submitters = submitters;
    }

    private long parentThreadId(int index) {
      return parentThreadIds[index];
    }

    private void requireParentsDifferFrom(long workerThreadId) {
      for (int i = 0; i < parentThreadIds.length; i++) {
        require(parentThreadIds[i] > 0L, scenario + " task had no captured parent at " + i);
        require(
            parentThreadIds[i] != workerThreadId,
            scenario + " task parent reused the runtime worker TID at " + i);
      }
      for (int group = 0; group < groupThreadIds.length; group++) {
        require(
            groupThreadIds[group] != workerThreadId,
            scenario + " submitter reused the runtime worker TID at " + group);
      }
    }

    private void close() {
      if (closed) {
        return;
      }
      closed = true;
      AtomicReference<Throwable> cleanupFailure = new AtomicReference<Throwable>();
      boolean interrupted = false;

      for (Runnable task : tasks) {
        try {
          untrackTask(task);
        } catch (Throwable failure) {
          recordFailure(cleanupFailure, failure);
        }
      }
      releaseSubmitters.countDown();
      releaseWorker.countDown();
      try {
        executor.shutdownNow();
      } catch (Throwable failure) {
        recordFailure(cleanupFailure, failure);
      }
      try {
        if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
          recordFailure(
              cleanupFailure, new AssertionError(scenario + " capture executor did not terminate"));
        }
      } catch (InterruptedException failure) {
        interrupted = true;
        recordFailure(cleanupFailure, failure);
      }

      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      for (Thread submitter : submitters) {
        try {
          joinUntil(submitter, deadline);
        } catch (InterruptedException failure) {
          interrupted = true;
          recordFailure(cleanupFailure, failure);
        }
      }
      for (Thread submitter : submitters) {
        if (submitter != null && submitter.isAlive()) {
          submitter.interrupt();
        }
      }
      deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
      for (Thread submitter : submitters) {
        try {
          joinUntil(submitter, deadline);
        } catch (InterruptedException failure) {
          interrupted = true;
          recordFailure(cleanupFailure, failure);
        }
        if (submitter != null && submitter.isAlive()) {
          recordFailure(
              cleanupFailure,
              new AssertionError(scenario + " submitter did not terminate: " + submitter));
        }
      }

      if (interrupted) {
        Thread.currentThread().interrupt();
      }
      rethrowHelperFailure(scenario + " capture cleanup", cleanupFailure.get());
    }
  }

  private static final class NamedTask implements Runnable {
    private final String name;
    private final Runnable action;

    private NamedTask(String name, Runnable action) {
      this.name = name;
      this.action = action;
    }

    @Override
    public void run() {
      action.run();
    }

    @Override
    public String toString() {
      return name;
    }
  }

  private static final class Event {
    private final String operation;
    private final long value;
    private final long token;

    private Event(String operation, long value, long token) {
      this.operation = operation;
      this.value = value;
      this.token = token;
    }

    @Override
    public String toString() {
      return operation + '(' + Long.toString(value) + ',' + Long.toString(token) + ')';
    }
  }
}
