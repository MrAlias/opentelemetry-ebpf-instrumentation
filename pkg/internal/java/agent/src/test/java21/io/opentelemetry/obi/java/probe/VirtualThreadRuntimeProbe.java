/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

public final class VirtualThreadRuntimeProbe {
  private static final List<Event> EVENTS = Collections.synchronizedList(new ArrayList<>());

  private VirtualThreadRuntimeProbe() {}

  public static void main(String[] args) throws Exception {
    installEventRecorder();
    verifyPublicStartMigrationAndCarrierReuse();
    verifyStructuredTaskScopeDirectStart();
    verifyCancellationAndMixedPlatformHandoff();
    verifyConcurrentVirtualThreadsDoNotRetainContext();
    System.out.println("virtual-thread-agent-probe passed");
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

  private static void verifyPublicStartMigrationAndCarrierReuse() throws Exception {
    AlternatingExecutor scheduler = new AlternatingExecutor();
    try {
      int start = EVENTS.size();
      CountDownLatch parked = new CountDownLatch(1);
      AtomicReference<Thread> firstCarrier = new AtomicReference<>();
      AtomicReference<Thread> secondCarrier = new AtomicReference<>();
      AtomicReference<Thread> virtualThreadReference = new AtomicReference<>();
      Field carrierThread =
          Class.forName("java.lang.VirtualThread").getDeclaredField("carrierThread");
      carrierThread.setAccessible(true);

      Thread virtualThread =
          newVirtualThread(
              scheduler,
              "obi-migrating-probe",
              () -> {
                try {
                  Thread current = Thread.currentThread();
                  firstCarrier.set((Thread) carrierThread.get(current));
                  parked.countDown();
                  LockSupport.park();
                  secondCarrier.set((Thread) carrierThread.get(current));
                } catch (IllegalAccessException failure) {
                  throw new AssertionError(failure);
                }
              });
      virtualThreadReference.set(virtualThread);
      virtualThread.start();
      require(parked.await(5, TimeUnit.SECONDS), "virtual thread did not reach park");
      awaitOperationSince(start, "VT_UNMOUNT");
      LockSupport.unpark(virtualThreadReference.get());
      virtualThread.join(TimeUnit.SECONDS.toMillis(5));
      require(!virtualThread.isAlive(), "migrating virtual thread did not terminate");

      require(firstCarrier.get() != null, "first carrier was not recorded");
      require(secondCarrier.get() != null, "second carrier was not recorded");
      require(firstCarrier.get() != secondCarrier.get(), "virtual thread did not migrate carriers");
      require(scheduler.executionsOnFirst() > 0, "first carrier did not run a continuation");
      require(scheduler.executionsOnSecond() > 0, "second carrier did not run a continuation");

      List<Event> events = snapshotSince(start);
      require(
          count(events, "TASK_CAPTURE") == 1,
          "public start was not captured exactly once: " + events);
      require(count(events, "VT_MOUNT") >= 2, "park/remount was not observed: " + events);
      require(count(events, "VT_UNMOUNT") >= 1, "unmount was not observed: " + events);
      require(count(events, "VT_TERMINATE") == 1, "termination was not observed once: " + events);
      require(hasExactTaskLink(events), "start handoff token was not linked: " + events);
      require(taskContext(virtualThread) == null, "completed virtual thread retained task context");

      int reuseStart = EVENTS.size();
      Thread reuse = newVirtualThread(scheduler, "obi-carrier-reuse-probe", () -> {});
      reuse.start();
      reuse.join(TimeUnit.SECONDS.toMillis(5));
      require(!reuse.isAlive(), "carrier-reuse virtual thread did not terminate");
      awaitExecutionCount(scheduler, 3);
      require(
          scheduler.executionsOnFirst() + scheduler.executionsOnSecond() >= 3,
          "the existing carrier pair was not reused");
      List<Event> reuseEvents = snapshotSince(reuseStart);
      require(
          count(reuseEvents, "TASK_CAPTURE") == 1,
          "carrier reuse start was not captured once: " + reuseEvents);
      require(
          count(reuseEvents, "VT_TERMINATE") == 1,
          "carrier reuse termination missing: " + reuseEvents);
      require(
          hasExactTaskLink(reuseEvents), "carrier reuse handoff token mismatch: " + reuseEvents);
      require(taskContext(reuse) == null, "reused carrier retained task context");
    } finally {
      scheduler.close();
    }
  }

  private static void verifyStructuredTaskScopeDirectStart() throws Exception {
    int start = EVENTS.size();
    AtomicReference<Thread> child = new AtomicReference<>();
    try (StructuredTaskScope.ShutdownOnFailure scope =
        new StructuredTaskScope.ShutdownOnFailure()) {
      scope.fork(
          () -> {
            child.set(Thread.currentThread());
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(10));
            return null;
          });
      scope.join().throwIfFailed();
    }

    Thread structuredChild = child.get();
    require(
        structuredChild != null && structuredChild.isVirtual(), "structured child was not virtual");
    List<Event> events = snapshotSince(start);
    require(
        count(events, "TASK_CAPTURE") == 1,
        "StructuredTaskScope start was not captured exactly once: " + events);
    require(count(events, "VT_MOUNT") >= 2, "structured child park/remount missing: " + events);
    require(count(events, "VT_UNMOUNT") >= 1, "structured child unmount missing: " + events);
    require(count(events, "VT_TERMINATE") == 1, "structured child termination missing: " + events);
    require(
        hasExactTaskLink(events), "StructuredTaskScope direct start was not captured: " + events);
    require(taskContext(structuredChild) == null, "structured child retained task context");
  }

  private static void verifyCancellationAndMixedPlatformHandoff() throws Exception {
    AlternatingExecutor scheduler = new AlternatingExecutor();
    ExecutorService platformExecutor = Executors.newSingleThreadExecutor();
    try {
      int cancellationStart = EVENTS.size();
      CountDownLatch parked = new CountDownLatch(1);
      Thread cancelled =
          newVirtualThread(
              scheduler,
              "obi-cancelled-probe",
              () -> {
                parked.countDown();
                LockSupport.park();
              });
      cancelled.start();
      require(parked.await(5, TimeUnit.SECONDS), "cancelled virtual thread did not reach park");
      awaitOperationSince(cancellationStart, "VT_UNMOUNT");
      cancelled.interrupt();
      cancelled.join(TimeUnit.SECONDS.toMillis(5));
      require(!cancelled.isAlive(), "cancelled virtual thread did not terminate");

      List<Event> cancellationEvents = snapshotSince(cancellationStart);
      require(
          count(cancellationEvents, "TASK_CAPTURE") == 1,
          "cancelled start was not captured exactly once: " + cancellationEvents);
      require(
          count(cancellationEvents, "VT_TERMINATE") == 1,
          "cancelled termination was not observed: " + cancellationEvents);
      require(
          hasExactTaskLink(cancellationEvents),
          "cancelled virtual-thread handoff was not exact: " + cancellationEvents);
      require(taskContext(cancelled) == null, "cancelled virtual thread retained task context");

      int mixedStart = EVENTS.size();
      AtomicReference<FutureTask<Void>> platformTask = new AtomicReference<>();
      Thread mixed =
          newVirtualThread(
              scheduler,
              "obi-mixed-probe",
              () -> {
                FutureTask<Void> task = new FutureTask<>(() -> {}, null);
                platformTask.set(task);
                platformExecutor.execute(task);
                try {
                  task.get(5, TimeUnit.SECONDS);
                } catch (Exception failure) {
                  throw new AssertionError(failure);
                }
              });
      mixed.start();
      mixed.join(TimeUnit.SECONDS.toMillis(5));
      require(!mixed.isAlive(), "mixed platform/virtual handoff did not terminate");

      List<Event> mixedEvents = snapshotSince(mixedStart);
      require(
          count(mixedEvents, "TASK_CAPTURE") >= 2,
          "mixed platform/virtual captures were missing: " + mixedEvents);
      require(
          allCapturesLinked(mixedEvents), "a mixed handoff token was not linked: " + mixedEvents);
      require(taskContext(mixed) == null, "mixed virtual thread retained task context");
      require(taskContext(platformTask.get()) == null, "mixed platform task retained context");
    } finally {
      platformExecutor.shutdownNow();
      require(
          platformExecutor.awaitTermination(5, TimeUnit.SECONDS),
          "mixed platform executor did not terminate");
      scheduler.close();
    }
  }

  private static void verifyConcurrentVirtualThreadsDoNotRetainContext() throws Exception {
    final int threadCount = 32;
    AlternatingExecutor scheduler = new AlternatingExecutor();
    List<Thread> threads = new ArrayList<>();
    int start = EVENTS.size();
    try {
      for (int index = 0; index < threadCount; index++) {
        Thread thread = newVirtualThread(scheduler, "obi-concurrent-" + index, Thread::yield);
        threads.add(thread);
        thread.start();
      }
      for (Thread thread : threads) {
        thread.join(TimeUnit.SECONDS.toMillis(5));
        require(!thread.isAlive(), "concurrent virtual thread did not terminate: " + thread);
        require(taskContext(thread) == null, "concurrent virtual thread retained task context");
      }

      List<Event> events = snapshotSince(start);
      require(
          count(events, "TASK_CAPTURE") == threadCount,
          "concurrent starts were not captured exactly: " + events);
      require(
          count(events, "VT_TERMINATE") == threadCount,
          "concurrent terminations were not exact: " + events);
      require(allCapturesLinked(events), "a concurrent handoff token was not linked: " + events);
    } finally {
      scheduler.close();
    }
  }

  private static Thread newVirtualThread(Executor scheduler, String name, Runnable task)
      throws Exception {
    Class<?> virtualThread = Class.forName("java.lang.VirtualThread");
    Constructor<?> constructor =
        virtualThread.getDeclaredConstructor(
            Executor.class, String.class, int.class, Runnable.class);
    constructor.setAccessible(true);
    return (Thread) constructor.newInstance(scheduler, name, 0, task);
  }

  private static Object taskContext(Object task) throws Exception {
    Class<?> storage =
        Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
    return storage.getMethod("taskContext", Object.class).invoke(null, task);
  }

  private static void awaitOperationSince(int start, String operation) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < deadline) {
      if (count(snapshotSince(start), operation) > 0) {
        return;
      }
      Thread.sleep(10);
    }
    throw new AssertionError("timed out waiting for " + operation + ": " + snapshotSince(start));
  }

  private static void awaitExecutionCount(AlternatingExecutor scheduler, int expected)
      throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < deadline) {
      if (scheduler.executionsOnFirst() + scheduler.executionsOnSecond() >= expected) {
        return;
      }
      Thread.sleep(10);
    }
  }

  private static List<Event> snapshotSince(int start) {
    synchronized (EVENTS) {
      return new ArrayList<>(EVENTS.subList(start, EVENTS.size()));
    }
  }

  private static long count(List<Event> events, String operation) {
    return events.stream().filter(event -> operation.equals(event.operation)).count();
  }

  private static boolean hasExactTaskLink(List<Event> events) {
    List<Event> captures =
        events.stream()
            .filter(event -> "TASK_CAPTURE".equals(event.operation))
            .collect(java.util.stream.Collectors.toList());
    if (captures.size() != 1) {
      return false;
    }
    long captureToken = captures.get(0).value;
    return captureToken != 0L
        && events.stream()
            .anyMatch(event -> "TASK_LINK".equals(event.operation) && event.token == captureToken);
  }

  private static boolean allCapturesLinked(List<Event> events) {
    List<Event> captures =
        events.stream()
            .filter(event -> "TASK_CAPTURE".equals(event.operation))
            .collect(java.util.stream.Collectors.toList());
    return !captures.isEmpty()
        && captures.stream()
            .allMatch(
                capture ->
                    capture.value != 0L
                        && events.stream()
                            .anyMatch(
                                event ->
                                    "TASK_LINK".equals(event.operation)
                                        && event.token == capture.value));
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
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

  private static final class AlternatingExecutor implements Executor, AutoCloseable {
    private static final Runnable STOP = () -> {};
    private final BlockingQueue<Runnable> firstQueue = new LinkedBlockingQueue<>();
    private final BlockingQueue<Runnable> secondQueue = new LinkedBlockingQueue<>();
    private final Thread first = carrier("obi-carrier-a", firstQueue);
    private final Thread second = carrier("obi-carrier-b", secondQueue);
    private int submissions;
    private int firstExecutions;
    private int secondExecutions;

    private AlternatingExecutor() {
      first.start();
      second.start();
    }

    @Override
    public synchronized void execute(Runnable command) {
      if ((submissions++ & 1) == 0) {
        firstQueue.add(command);
      } else {
        secondQueue.add(command);
      }
    }

    private Thread carrier(String name, BlockingQueue<Runnable> queue) {
      return new Thread(
          () -> {
            try {
              for (; ; ) {
                Runnable task = queue.take();
                if (task == STOP) {
                  return;
                }
                task.run();
                synchronized (this) {
                  if (queue == firstQueue) {
                    firstExecutions++;
                  } else {
                    secondExecutions++;
                  }
                }
              }
            } catch (InterruptedException interrupted) {
              Thread.currentThread().interrupt();
            }
          },
          name);
    }

    private synchronized int executionsOnFirst() {
      return firstExecutions;
    }

    private synchronized int executionsOnSecond() {
      return secondExecutions;
    }

    @Override
    public void close() throws InterruptedException {
      firstQueue.add(STOP);
      secondQueue.add(STOP);
      first.join(TimeUnit.SECONDS.toMillis(5));
      second.join(TimeUnit.SECONDS.toMillis(5));
      require(!first.isAlive() && !second.isAlive(), "carrier executors did not terminate");
    }
  }
}
