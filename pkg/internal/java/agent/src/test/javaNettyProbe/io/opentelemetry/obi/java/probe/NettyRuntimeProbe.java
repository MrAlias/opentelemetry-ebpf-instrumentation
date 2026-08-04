/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import io.netty.util.concurrent.DefaultEventExecutor;
import io.netty.util.concurrent.Future;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

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
    ExactNettyConnection exact = new ExactNettyConnection(81);
    CountDownLatch complete = new CountDownLatch(1);
    AtomicInteger claimedDescriptor = new AtomicInteger(-2);
    NamedTask workerTask =
        new NamedTask(
            "worker",
            () -> {
              claimedDescriptor.set(takeSocketFileDescriptor());
              complete.countDown();
            });
    NamedTask eventLoopTask =
        new NamedTask(
            "event-loop",
            () ->
                exact.runInHandlerScope(
                    () -> {
                      setSocketFileDescriptor(81, exact.lifecycle);
                      worker.execute(workerTask);
                      clearSocketFileDescriptor();
                    }));
    int start = eventCount();

    try {
      eventLoop.execute(eventLoopTask);
      require(complete.await(5, TimeUnit.SECONDS), "Netty-to-worker handoff did not complete");
      require(claimedDescriptor.get() == 81, "Netty worker lost accepted socket ownership");
      awaitNoContext(eventLoopTask);
      awaitNoContext(workerTask);

      List<Event> events = snapshotSince(start);
      require(
          count(events, "TASK_CAPTURE") == 1,
          "only the exact Netty-to-worker submission should be captured: " + events);
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
      exact.close();
      worker.shutdownNow();
      require(worker.awaitTermination(5, TimeUnit.SECONDS), "worker did not terminate");
      eventLoop.shutdownGracefully(0, 5, TimeUnit.SECONDS).syncUninterruptibly();
    }
  }

  private static void verifyCancellationAndRejectionCleanup() throws Exception {
    DefaultEventExecutor eventLoop = new DefaultEventExecutor();
    ExactNettyConnection cancellationConnection = new ExactNettyConnection(83);
    ExactNettyConnection rejectionConnection = new ExactNettyConnection(84);
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
      int cancellationStart = eventCount();
      NamedTask cancelled = new NamedTask("cancelled", () -> {});
      AtomicReference<Future<?>> futureReference = new AtomicReference<>();
      cancellationConnection.runInHandlerScope(
          () -> {
            setSocketFileDescriptor(83, cancellationConnection.lifecycle);
            futureReference.set(eventLoop.schedule(cancelled, 1, TimeUnit.HOURS));
          });
      Future<?> future = futureReference.get();
      clearSocketFileDescriptor();
      require(taskContext(future) != null, "scheduled Netty wrapper was not tracked");
      require(future.cancel(false), "scheduled Netty task was not cancelled");
      awaitNoContext(future);
      List<Event> cancellationEvents = snapshotSince(cancellationStart);
      require(
          count(cancellationEvents, "TASK_CAPTURE") == 1
              && count(cancellationEvents, "TASK_LINK") == 0
              && count(cancellationEvents, "TASK_CANCEL") == 1,
          "scheduled Netty cancellation did not release exactly one handoff: "
              + cancellationEvents);

      releaseWorker.countDown();
      AtomicInteger reusedDescriptor = new AtomicInteger(-2);
      eventLoop.submit(() -> reusedDescriptor.set(socketFileDescriptor())).syncUninterruptibly();
      require(
          reusedDescriptor.get() == -1,
          "cancelled Netty task leaked socket ownership to its event loop");
      eventLoop.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
      NamedTask rejected = new NamedTask("rejected", () -> {});
      int rejectionStart = eventCount();
      try {
        rejectionConnection.runInHandlerScope(
            () -> {
              setSocketFileDescriptor(84, rejectionConnection.lifecycle);
              eventLoop.execute(rejected);
            });
        throw new AssertionError("terminated Netty event loop accepted a task");
      } catch (RejectedExecutionException expected) {
      } finally {
        clearSocketFileDescriptor();
      }
      awaitNoContext(rejected);
      List<Event> rejectionEvents = snapshotSince(rejectionStart);
      require(
          count(rejectionEvents, "TASK_CAPTURE") == 1
              && count(rejectionEvents, "TASK_LINK") == 0
              && count(rejectionEvents, "TASK_CANCEL") == 1,
          "rejected Netty submission did not release exactly one handoff: " + rejectionEvents);
    } finally {
      releaseWorker.countDown();
      cancellationConnection.close();
      rejectionConnection.close();
      eventLoop.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
    }
  }

  private static void verifyScheduledTaskHandoff() throws Exception {
    DefaultEventExecutor eventLoop = new DefaultEventExecutor();
    ExactNettyConnection exact = new ExactNettyConnection(82);
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
      AtomicReference<Future<?>> futureReference = new AtomicReference<>();
      exact.runInHandlerScope(
          () -> {
            setSocketFileDescriptor(82, exact.lifecycle);
            futureReference.set(eventLoop.schedule(scheduled, 0, TimeUnit.MILLISECONDS));
          });
      Future<?> future = futureReference.get();
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
      exact.close();
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

  private static void setSocketFileDescriptor(int socketFileDescriptor, Object lifecycle) {
    Class<?> lifecycleClass = socketLifecycleClass();
    Object staged =
        invokeThreadInfo(
            "setRemoteParentSocketFileDescriptor",
            new Class<?>[] {int.class, lifecycleClass},
            new Object[] {Integer.valueOf(socketFileDescriptor), lifecycle});
    require(Boolean.TRUE.equals(staged), "failed to stage exact socket ownership");
  }

  private static Class<?> socketLifecycleClass() {
    try {
      return Class.forName(
          "io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext$Lifecycle",
          true,
          null);
    } catch (ClassNotFoundException failure) {
      throw new AssertionError(failure);
    }
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

  private static final class ExactNettyConnection implements AutoCloseable {
    private final Class<?> storage;
    private final Class<?> connectionClass;
    private final Object channel = new Object();
    private final Object connection;
    private final Object lifecycle;

    private ExactNettyConnection(int socketFileDescriptor) throws Exception {
      storage =
          Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
      connectionClass =
          Class.forName("io.opentelemetry.obi.java.instrumentations.data.Connection", true, null);
      connection =
          connectionClass
              .getConstructor(InetAddress.class, int.class, InetAddress.class, int.class, int.class)
              .newInstance(
                  InetAddress.getByName("127.0.0.1"),
                  20_000 + socketFileDescriptor,
                  InetAddress.getByName("127.0.0.2"),
                  30_000 + socketFileDescriptor,
                  socketFileDescriptor);
      require(
          storage
                  .getMethod("associateConnectionWithChannel", Object.class, connectionClass)
                  .invoke(null, channel, connection)
              == connection,
          "failed to register exact Netty connection");
      lifecycle =
          storage
              .getMethod("remoteParentSocketLifecycle", connectionClass)
              .invoke(null, connection);
      require(lifecycle != null, "exact Netty lifecycle is unavailable");
    }

    private void runInHandlerScope(Runnable action) {
      try {
        storage
            .getMethod("beginNettyHandlerScope", Object.class, boolean.class)
            .invoke(null, null, Boolean.TRUE);
        try {
          require(
              Boolean.TRUE.equals(
                  storage
                      .getMethod("setCurrentNettyConnection", Object.class)
                      .invoke(null, connection)),
              "failed to install exact Netty connection scope");
          invokeThreadInfo(
              "markRemoteParentDirectLookup",
              new Class<?>[] {Object.class},
              new Object[] {lifecycle});
          action.run();
        } finally {
          storage.getMethod("endNettyHandlerScope").invoke(null);
        }
      } catch (ReflectiveOperationException failure) {
        throw new AssertionError(failure);
      }
    }

    @Override
    public void close() {
      try {
        storage
            .getMethod("cleanupConnection", Object.class, connectionClass)
            .invoke(null, channel, connection);
      } catch (ReflectiveOperationException failure) {
        throw new AssertionError(failure);
      }
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
