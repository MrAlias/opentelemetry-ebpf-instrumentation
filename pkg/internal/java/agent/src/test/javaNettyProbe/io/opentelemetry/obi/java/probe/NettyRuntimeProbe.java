/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import io.netty.util.concurrent.DefaultEventExecutor;
import io.netty.util.concurrent.Future;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class NettyRuntimeProbe {
  private static final List<Event> EVENTS = Collections.synchronizedList(new ArrayList<Event>());

  private NettyRuntimeProbe() {}

  public static void main(String[] args) throws Exception {
    installEventRecorder();
    verifyEventLoopToWorkerHandoff();
    verifyScheduledTaskHandoff();
    verifyCancellationAndRejectionCleanup();
    System.out.println("netty-agent-probe passed");
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

  private static void verifyEventLoopToWorkerHandoff() throws Exception {
    DefaultEventExecutor eventLoop = new DefaultEventExecutor();
    ExecutorService worker = Executors.newSingleThreadExecutor();
    CountDownLatch complete = new CountDownLatch(1);
    AtomicInteger claimedDescriptor = new AtomicInteger(-2);
    NamedTask workerTask =
        new NamedTask(
            "worker",
            () -> {
              claimedDescriptor.set(takeSocketFileDescriptor());
              complete.countDown();
            });
    NamedTask eventLoopTask = new NamedTask("event-loop", () -> worker.execute(workerTask));
    int start = eventCount();

    try {
      setSocketFileDescriptor(81);
      eventLoop.execute(eventLoopTask);
      require(complete.await(5, TimeUnit.SECONDS), "Netty-to-worker handoff did not complete");
      require(claimedDescriptor.get() == 81, "Netty worker lost accepted socket ownership");
      awaitNoContext(eventLoopTask);
      awaitNoContext(workerTask);

      List<Event> events = snapshotSince(start);
      require(
          count(events, "TASK_CAPTURE") >= 2, "Netty-to-worker captures were missing: " + events);
      require(allCapturesLinked(events), "Netty-to-worker tokens were not linked: " + events);

      CountDownLatch reuseComplete = new CountDownLatch(2);
      AtomicInteger leakedDescriptors = new AtomicInteger();
      eventLoop.execute(
          new NamedTask(
              "event-loop-reuse",
              () -> {
                if (socketFileDescriptor() != -1) {
                  leakedDescriptors.incrementAndGet();
                }
                reuseComplete.countDown();
              }));
      worker.execute(
          new NamedTask(
              "worker-reuse",
              () -> {
                if (socketFileDescriptor() != -1) {
                  leakedDescriptors.incrementAndGet();
                }
                reuseComplete.countDown();
              }));
      require(reuseComplete.await(5, TimeUnit.SECONDS), "Netty reuse probes did not complete");
      require(leakedDescriptors.get() == 0, "Netty worker reused accepted socket ownership");
    } finally {
      clearSocketFileDescriptor();
      worker.shutdownNow();
      require(worker.awaitTermination(5, TimeUnit.SECONDS), "worker did not terminate");
      eventLoop.shutdownGracefully(0, 5, TimeUnit.SECONDS).syncUninterruptibly();
    }
  }

  private static void verifyCancellationAndRejectionCleanup() throws Exception {
    DefaultEventExecutor eventLoop = new DefaultEventExecutor();
    CountDownLatch workerBlocked = new CountDownLatch(1);
    CountDownLatch releaseWorker = new CountDownLatch(1);
    eventLoop.execute(
        new NamedTask(
            "blocker",
            () -> {
              workerBlocked.countDown();
              await(releaseWorker);
            }));
    require(workerBlocked.await(5, TimeUnit.SECONDS), "Netty event loop did not block");
    try {
      setSocketFileDescriptor(83);
      NamedTask cancelled = new NamedTask("cancelled", () -> {});
      Future<?> future = eventLoop.schedule(cancelled, 1, TimeUnit.HOURS);
      clearSocketFileDescriptor();
      require(taskContext(future) != null, "scheduled Netty wrapper was not tracked");
      require(future.cancel(false), "scheduled Netty task was not cancelled");
      awaitNoContext(future);

      releaseWorker.countDown();
      AtomicInteger reusedDescriptor = new AtomicInteger(-2);
      eventLoop.submit(() -> reusedDescriptor.set(socketFileDescriptor())).syncUninterruptibly();
      require(
          reusedDescriptor.get() == -1,
          "cancelled Netty task leaked socket ownership to its event loop");
      eventLoop.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
      NamedTask rejected = new NamedTask("rejected", () -> {});
      setSocketFileDescriptor(84);
      try {
        eventLoop.execute(rejected);
        throw new AssertionError("terminated Netty event loop accepted a task");
      } catch (RejectedExecutionException expected) {
      } finally {
        clearSocketFileDescriptor();
      }
      awaitNoContext(rejected);

      require(
          count(snapshotSince(0), "TASK_CANCEL") >= 2,
          "Netty cancel/reject paths did not cancel handoffs: " + snapshotSince(0));
    } finally {
      releaseWorker.countDown();
      eventLoop.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
    }
  }

  private static void verifyScheduledTaskHandoff() throws Exception {
    DefaultEventExecutor eventLoop = new DefaultEventExecutor();
    CountDownLatch complete = new CountDownLatch(1);
    AtomicInteger claimedDescriptor = new AtomicInteger(-2);
    NamedTask scheduled =
        new NamedTask(
            "scheduled",
            () -> {
              claimedDescriptor.set(takeSocketFileDescriptor());
              complete.countDown();
            });
    eventLoop.submit(() -> {}).syncUninterruptibly();
    int start = eventCount();

    try {
      setSocketFileDescriptor(82);
      Future<?> future = eventLoop.schedule(scheduled, 0, TimeUnit.MILLISECONDS);
      require(complete.await(5, TimeUnit.SECONDS), "scheduled Netty handoff did not complete");
      require(claimedDescriptor.get() == 82, "scheduled Netty task lost socket ownership");
      future.syncUninterruptibly();
      awaitNoContext(scheduled);
      awaitNoContext(future);

      List<Event> events = snapshotSince(start);
      require(
          count(events, "TASK_CAPTURE") == 1,
          "scheduled Netty handoff was not captured exactly once: " + events);
      require(allCapturesLinked(events), "scheduled Netty token was not linked: " + events);
    } finally {
      clearSocketFileDescriptor();
      eventLoop.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
    }
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

  private static Object taskContext(Object task) throws Exception {
    Class<?> storage =
        Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
    return storage.getMethod("taskContext", Object.class).invoke(null, task);
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

  private static boolean allCapturesLinked(List<Event> events) {
    boolean captureFound = false;
    for (Event capture : events) {
      if (!"TASK_CAPTURE".equals(capture.operation) || capture.value == 0L) {
        continue;
      }
      captureFound = true;
      boolean linked = false;
      for (Event event : events) {
        if ("TASK_LINK".equals(event.operation) && event.token == capture.value) {
          linked = true;
          break;
        }
      }
      if (!linked) {
        return false;
      }
    }
    return captureFound;
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
