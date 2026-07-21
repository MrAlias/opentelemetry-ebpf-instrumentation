/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.FutureInst;
import io.opentelemetry.obi.java.instrumentations.JavaExecutorInst;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import net.bytebuddy.agent.ByteBuddyAgent;
import org.junit.jupiter.api.Test;
import testutil.InstrumentableScheduledExecutor;

class ScheduledExecutorHandoffTest {
  @Test
  void scheduleTransfersContextToTheQueuedWrapper() throws Exception {
    ScheduledThreadPoolExecutor executor = new InstrumentableScheduledExecutor(false);
    CountDownLatch releaseWorker = new CountDownLatch(1);
    CountDownLatch workerBlocked = new CountDownLatch(1);
    Instrumentation instrumentation = null;
    java.lang.instrument.ClassFileTransformer transformer = null;

    try {
      executor.execute(
          () -> {
            workerBlocked.countDown();
            awaitRelease(releaseWorker);
          });
      assertTrue(workerBlocked.await(5, TimeUnit.SECONDS));

      instrumentation = ByteBuddyAgent.install();
      transformer =
          Agent.builder(Collections.emptyMap(), instrumentation)
              .type(JavaExecutorInst.type())
              .transform(JavaExecutorInst.transformer())
              .type(FutureInst.type())
              .transform(FutureInst.transformer())
              .installOn(instrumentation);
      setThreadIdProvider(() -> 101L);
      ThreadInfo.setRemoteParentEnabled(false);
      Agent.retransformLoadedClasses(instrumentation);

      CountDownLatch taskRan = new CountDownLatch(1);
      Runnable submitted = taskRan::countDown;
      Future<?> scheduled = executor.schedule(submitted, 0, TimeUnit.MILLISECONDS);

      assertNull(SSLStorage.taskContext(submitted));
      assertNotNull(SSLStorage.taskContext(scheduled));

      releaseWorker.countDown();
      assertTrue(taskRan.await(5, TimeUnit.SECONDS));
      scheduled.get(5, TimeUnit.SECONDS);
      assertNull(SSLStorage.taskContext(scheduled));
    } finally {
      releaseWorker.countDown();
      executor.shutdownNow();
      assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
      if (instrumentation != null && transformer != null) {
        instrumentation.removeTransformer(transformer);
      }
      setThreadIdProvider(null);
      ThreadInfo.setRemoteParentEnabled(false);
    }
  }

  @Test
  void subclassDecoratorTransfersAndCancelsTheReturnedWrapper() throws Exception {
    ScheduledThreadPoolExecutor executor = new InstrumentableScheduledExecutor(true);
    CountDownLatch releaseWorker = new CountDownLatch(1);
    CountDownLatch workerBlocked = new CountDownLatch(1);
    Instrumentation instrumentation = null;
    java.lang.instrument.ClassFileTransformer transformer = null;

    try {
      executor.execute(
          () -> {
            workerBlocked.countDown();
            awaitRelease(releaseWorker);
          });
      assertTrue(workerBlocked.await(5, TimeUnit.SECONDS));

      instrumentation = ByteBuddyAgent.install();
      transformer =
          Agent.builder(Collections.emptyMap(), instrumentation)
              .type(JavaExecutorInst.type())
              .transform(JavaExecutorInst.transformer())
              .type(FutureInst.type())
              .transform(FutureInst.transformer())
              .installOn(instrumentation);
      setThreadIdProvider(() -> 101L);
      ThreadInfo.setRemoteParentEnabled(false);
      Agent.retransformLoadedClasses(instrumentation);

      Runnable submitted = () -> {};
      Future<?> scheduled = executor.schedule(submitted, 1, TimeUnit.HOURS);

      assertNull(SSLStorage.taskContext(submitted));
      assertNull(SSLStorage.taskContext(InstrumentableScheduledExecutor.delegate(scheduled)));
      assertNotNull(SSLStorage.taskContext(scheduled));
      assertTrue(scheduled.cancel(false));
      assertNull(SSLStorage.taskContext(scheduled));
    } finally {
      releaseWorker.countDown();
      executor.shutdownNow();
      assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
      if (instrumentation != null && transformer != null) {
        instrumentation.removeTransformer(transformer);
      }
      setThreadIdProvider(null);
      ThreadInfo.setRemoteParentEnabled(false);
    }
  }

  private static void await(CountDownLatch latch) {
    try {
      assertTrue(latch.await(5, TimeUnit.SECONDS));
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new AssertionError(interrupted);
    }
  }

  private static void awaitRelease(CountDownLatch latch) {
    try {
      latch.await();
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
    }
  }

  private static void setThreadIdProvider(java.util.function.LongSupplier provider) {
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
}
