/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class ExecutorRuntimeProbe {
  private static final List<Event> EVENTS = Collections.synchronizedList(new ArrayList<Event>());

  private ExecutorRuntimeProbe() {}

  public static void main(String[] args) throws Exception {
    installEventRecorder();
    verifyNestedExecutorHandoffs();
    verifyCancellationTimeoutAndRejectionCleanup();
    System.out.println("executor-agent-probe passed");
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
    NamedTask[] tasks = new NamedTask[3];
    tasks[2] = new NamedTask("third", complete::countDown);
    tasks[1] = new NamedTask("second", () -> first.execute(tasks[2]));
    tasks[0] = new NamedTask("first", () -> second.execute(tasks[1]));
    int start = eventCount();

    try {
      first.execute(tasks[0]);
      require(complete.await(5, TimeUnit.SECONDS), "nested executor chain did not complete");
      awaitNoContext(tasks[0]);
      awaitNoContext(tasks[1]);
      awaitNoContext(tasks[2]);
      awaitOperationCount(start, "TASK_LINK", 6);

      List<Event> events = snapshotSince(start);
      require(count(events, "TASK_CAPTURE") == 3, "nested captures were not exact: " + events);
      require(count(events, "TASK_LINK") >= 6, "nested links were not restored: " + events);
      require(hasLinkedCapture(events), "nested handoff tokens were not linked: " + events);
    } finally {
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

    FutureTask<Void> cancelled = new FutureTask<Void>(new NamedTask("cancelled", () -> {}), null);
    executor.execute(cancelled);
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
    try {
      rejectedExecutor.execute(rejected);
      throw new AssertionError("shutdown executor accepted a task");
    } catch (RejectedExecutionException expected) {
    }
    awaitNoContext(rejected);

    releaseWorker.countDown();
    shutdown(executor);
    require(
        count(snapshotSince(start), "TASK_CANCEL") >= 3,
        "cancel, timeout, and rejection did not cancel every handoff: " + snapshotSince(start));
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

  private static long count(List<Event> events, String operation) {
    long count = 0;
    for (Event event : events) {
      if (operation.equals(event.operation)) {
        count++;
      }
    }
    return count;
  }

  private static boolean hasLinkedCapture(List<Event> events) {
    for (Event capture : events) {
      if (!"TASK_CAPTURE".equals(capture.operation) || capture.value == 0L) {
        continue;
      }
      for (Event link : events) {
        if ("TASK_LINK".equals(link.operation) && link.token == capture.value) {
          return true;
        }
      }
    }
    return false;
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
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
