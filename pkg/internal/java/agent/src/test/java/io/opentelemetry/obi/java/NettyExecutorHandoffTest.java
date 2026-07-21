/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.netty.util.concurrent.DefaultEventExecutor;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.JavaExecutorInst;
import io.opentelemetry.obi.java.instrumentations.NettyExecutorInst;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import net.bytebuddy.agent.ByteBuddyAgent;
import org.junit.jupiter.api.Test;

class NettyExecutorHandoffTest {
  @Test
  void eventLoopConsumesContextForHiddenLambdaTasks() throws Exception {
    DefaultEventExecutor executor = new DefaultEventExecutor();
    Instrumentation instrumentation = ByteBuddyAgent.install();
    java.lang.instrument.ClassFileTransformer transformer =
        Agent.builder(Collections.emptyMap(), instrumentation)
            .type(JavaExecutorInst.type())
            .transform(JavaExecutorInst.transformer())
            .type(NettyExecutorInst.type())
            .transform(NettyExecutorInst.transformer())
            .installOn(instrumentation);
    CountDownLatch releaseWorker = new CountDownLatch(1);
    setThreadIdProvider(() -> 101L);
    ThreadInfo.setRemoteParentEnabled(false);

    try {
      Agent.retransformLoadedClasses(instrumentation);

      CountDownLatch workerBlocked = new CountDownLatch(1);
      executor.execute(
          () -> {
            workerBlocked.countDown();
            await(releaseWorker);
          });
      assertTrue(workerBlocked.await(5, TimeUnit.SECONDS));

      CountDownLatch taskRan = new CountDownLatch(1);
      Runnable task = taskRan::countDown;
      executor.execute(task);
      assertNotNull(SSLStorage.taskContext(task));

      releaseWorker.countDown();
      assertTrue(taskRan.await(5, TimeUnit.SECONDS));
      assertNull(SSLStorage.taskContext(task));
    } finally {
      releaseWorker.countDown();
      executor.shutdownGracefully(0, 5, TimeUnit.SECONDS).syncUninterruptibly();
      instrumentation.removeTransformer(transformer);
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
