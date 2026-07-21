/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.BlockingQueueInst;
import io.opentelemetry.obi.java.instrumentations.FutureInst;
import io.opentelemetry.obi.java.instrumentations.JavaExecutorInst;
import io.opentelemetry.obi.java.instrumentations.RunnableInst;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SSLStorageTest {

  static class DummySSLEngine extends SSLEngine {
    @Override
    public String getPeerHost() {
      return null;
    }

    @Override
    public int getPeerPort() {
      return 0;
    }

    @Override
    public void beginHandshake() {}

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
      return null;
    }

    @Override
    public void closeInbound() {}

    @Override
    public boolean isInboundDone() {
      return false;
    }

    @Override
    public void closeOutbound() {}

    @Override
    public boolean isOutboundDone() {
      return false;
    }

    @Override
    public String[] getSupportedCipherSuites() {
      return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
      return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {}

    @Override
    public String[] getSupportedProtocols() {
      return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
      return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {}

    @Override
    public Runnable getDelegatedTask() {
      return null;
    }

    @Override
    public boolean getEnableSessionCreation() {
      return false;
    }

    @Override
    public boolean getNeedClientAuth() {
      return false;
    }

    @Override
    public boolean getUseClientMode() {
      return false;
    }

    @Override
    public boolean getWantClientAuth() {
      return false;
    }

    @Override
    public void setEnableSessionCreation(boolean b) {}

    @Override
    public void setNeedClientAuth(boolean b) {}

    @Override
    public void setUseClientMode(boolean b) {}

    @Override
    public void setWantClientAuth(boolean b) {}

    @Override
    public javax.net.ssl.SSLSession getHandshakeSession() {
      return null;
    }

    @Override
    public javax.net.ssl.SSLSession getSession() {
      return null;
    }

    @Override
    public SSLEngineResult unwrap(java.nio.ByteBuffer src, java.nio.ByteBuffer dst) {
      return null;
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
        throws SSLException {
      return null;
    }

    @Override
    public SSLEngineResult wrap(java.nio.ByteBuffer src, java.nio.ByteBuffer dst) {
      return null;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
        throws SSLException {
      return null;
    }
  }

  @AfterEach
  void cleanup() {
    // Clean up thread locals
    SSLStorage.unencrypted.remove();
    SSLStorage.nettyConnection.remove();
    SSLStorage.setThreadIdProviderForTest(null);
  }

  @Test
  void testSessionConnectionMapping() throws Exception {
    SSLEngine engine = new DummySSLEngine();
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.1"), 1234, InetAddress.getByName("1.2.3.4"), 5678);

    assertNull(SSLStorage.getConnectionForSession(engine));
    SSLStorage.setConnectionForSession(engine, conn);
    assertEquals(conn, SSLStorage.getConnectionForSession(engine));
  }

  @Test
  void testBufConnectionMapping() throws Exception {
    String bufKey = "buf123";
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.2"), 4321, InetAddress.getByName("5.6.7.8"), 8765);

    assertNull(SSLStorage.getConnectionForBuf(bufKey));
    SSLStorage.setConnectionForBuf(bufKey, conn);
    assertEquals(conn, SSLStorage.getConnectionForBuf(bufKey));
    assertEquals(bufKey, conn.getBufferKey());
  }

  @Test
  void testActiveConnectionTracking() throws Exception {
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.3"), 1111, InetAddress.getByName("8.8.8.8"), 2222);

    assertTrue(SSLStorage.connectionUntracked(conn));
    SSLStorage.setConnectionForBuf("bufX", conn);
    assertFalse(SSLStorage.connectionUntracked(conn));
    assertEquals(conn, SSLStorage.getActiveConnection(conn));
  }

  @Test
  void testCleanupConnectionBufMapping() throws Exception {
    String bufKey = "bufY";
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.4"), 3333, InetAddress.getByName("9.9.9.9"), 4444);

    SSLStorage.setConnectionForBuf(bufKey, conn);
    assertEquals(conn, SSLStorage.getConnectionForBuf(bufKey));
    SSLStorage.cleanupConnectionBufMapping(conn);
    assertNull(SSLStorage.getConnectionForBuf(bufKey));
    assertNull(SSLStorage.getActiveConnection(conn));
  }

  @Test
  void testBufferMapping() {
    String encrypted = "enc";
    BytesWithLen plain = new BytesWithLen(new byte[] {1, 2, 3}, 3);

    assertNull(SSLStorage.getUnencryptedBuffer(encrypted));
    SSLStorage.setBufferMapping(encrypted, plain);
    assertEquals(plain, SSLStorage.getUnencryptedBuffer(encrypted));
    SSLStorage.removeBufferMapping(encrypted);
    assertNull(SSLStorage.getUnencryptedBuffer(encrypted));
  }

  @Test
  void taskParentIsConsumedBeforeWorkerReuse() {
    Object reusableTask = new Object();

    SSLStorage.trackTask(101L, reusableTask);
    assertEquals(101L, SSLStorage.takeTaskContext(reusableTask).getParentThreadId());
    assertNull(SSLStorage.takeTaskContext(reusableTask));

    SSLStorage.trackTask(202L, reusableTask);
    assertEquals(202L, SSLStorage.takeTaskContext(reusableTask).getParentThreadId());
    assertNull(SSLStorage.takeTaskContext(reusableTask));
  }

  @Test
  void taskIdentityHashCollisionDoesNotCrossContaminateParents() {
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(4);
    Object first = new Object();
    Object second = new Object();

    tasks.track(first, new TaskContext(101L, 0L), 7);
    tasks.track(second, new TaskContext(202L, 0L), 7);

    assertEquals(101L, tasks.get(first, 7, false).getParentThreadId());
    assertEquals(202L, tasks.get(second, 7, false).getParentThreadId());
    assertEquals(101L, tasks.get(first, 7, true).getParentThreadId());
    assertEquals(202L, tasks.get(second, 7, true).getParentThreadId());
  }

  @Test
  void taskOwnershipMapRemainsBounded() {
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(2);
    Object first = new Object();
    Object second = new Object();
    Object third = new Object();

    tasks.track(first, new TaskContext(101L, 0L), 1);
    tasks.track(second, new TaskContext(202L, 0L), 2);
    tasks.track(third, new TaskContext(303L, 0L), 3);

    assertNull(tasks.get(first, 1, false));
    assertEquals(202L, tasks.get(second, 2, false).getParentThreadId());
    assertEquals(303L, tasks.get(third, 3, false).getParentThreadId());
  }

  @Test
  void repeatedNettyReflectionFailuresLogOnlyOnceWhenDebugIsDisabled() throws Exception {
    PrintStream originalError = System.err;
    boolean originalDebug = SSLStorage.debugOn;
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    SSLStorage.debugOn = false;
    SSLStorage.resetNettyFailureLoggingForTest();
    try {
      System.setErr(new PrintStream(output, true, "UTF-8"));
      for (int i = 0; i < 10; i++) {
        SSLStorage.logNettyAdviceFailure("test operation", new ReflectiveOperationException());
      }
    } finally {
      System.setErr(originalError);
      SSLStorage.debugOn = originalDebug;
      SSLStorage.resetNettyFailureLoggingForTest();
    }

    String message = output.toString("UTF-8");
    assertEquals(1, message.split("Netty helper unavailable", -1).length - 1);
  }

  @Test
  void concurrentParentsForTheSameTaskFailOpenAsAmbiguous() throws Exception {
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(4);
    Object shared = new Object();
    CountDownLatch start = new CountDownLatch(1);
    ExecutorService executor = Executors.newFixedThreadPool(2);

    try {
      Future<?> first =
          executor.submit(
              () -> {
                start.await();
                tasks.track(shared, new TaskContext(101L, 0L), 7);
                return null;
              });
      Future<?> second =
          executor.submit(
              () -> {
                start.await();
                tasks.track(shared, new TaskContext(202L, 0L), 7);
                return null;
              });
      start.countDown();
      first.get();
      second.get();
    } finally {
      executor.shutdownNow();
    }

    assertNull(tasks.get(shared, 7, false));
    assertNull(tasks.get(shared, 7, true));
    assertNull(tasks.get(shared, 7, true));

    tasks.track(shared, new TaskContext(303L, 0L), 7);
    assertEquals(303L, tasks.get(shared, 7, true).getParentThreadId());
  }

  @Test
  void nestedSubmissionAdviceReusesTheOuterTaskCapture() {
    Runnable task = () -> {};
    SSLStorage.setThreadIdProviderForTest(() -> 101L);

    int outer = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(task, "execute");
    TaskContext captured = SSLStorage.taskContext(task);
    int nested = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(task, "addTask");

    assertEquals(SSLStorage.SUBMISSION_OWNER, outer);
    assertEquals(SSLStorage.SUBMISSION_NESTED, nested);
    assertSame(captured, SSLStorage.taskContext(task));
    JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
        Runnable::run, task, "addTask", null, nested);
    JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
        Runnable::run, task, "execute", null, outer);
    assertSame(captured, SSLStorage.takeTaskContext(task));
  }

  @Test
  void concurrentAdviceSubmissionsOfTheSameObjectFailOpenInEitherRunOrder() throws Exception {
    Runnable shared = () -> {};
    CountDownLatch entered = new CountDownLatch(2);
    CountDownLatch exit = new CountDownLatch(1);
    SSLStorage.setThreadIdProviderForTest(() -> Thread.currentThread().getId() + 100L);
    ExecutorService executor = Executors.newFixedThreadPool(2);

    try {
      Future<?> first = executor.submit(() -> submitAndWait(shared, entered, exit));
      Future<?> second = executor.submit(() -> submitAndWait(shared, entered, exit));
      assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS));
      exit.countDown();
      first.get();
      second.get();
    } finally {
      exit.countDown();
      executor.shutdownNow();
    }

    assertFalse(RunnableInst.RunnableAdvice.enter(shared));
    assertFalse(RunnableInst.RunnableAdvice.enter(shared));
    assertNull(SSLStorage.takeTaskContext(shared));
    SSLStorage.untrackTask(shared);
  }

  @Test
  void sequentialSameTidSubmissionsCarryDifferentGenerationsAndBecomeAmbiguous() {
    Runnable shared = () -> {};
    SSLStorage.setThreadIdProviderForTest(() -> 77L);

    int first = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(shared, "execute");
    JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
        Runnable::run, shared, "execute", null, first);
    int second = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(shared, "execute");
    JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
        Runnable::run, shared, "execute", null, second);

    assertNull(SSLStorage.takeTaskContext(shared));
    SSLStorage.untrackTask(shared);
  }

  @Test
  void successfulFutureCancellationCleansWrapperAndSubmittedTask() {
    Runnable submitted = () -> {};
    FutureTask<Void> future = new FutureTask<>(submitted, null);
    SSLStorage.trackTask(101L, submitted);
    SSLStorage.trackTask(101L, future);
    SSLStorage.trackTaskCancellation(future, submitted);

    FutureInst.CancelAdvice.exit(future, true, null);

    assertNull(SSLStorage.taskContext(future));
    assertNull(SSLStorage.taskContext(submitted));
  }

  @Test
  void customFutureCancellationDoesNotDropTheTaskBeforeCancellation() {
    Runnable submitted = () -> {};
    CompletableFuture<Void> future = new CompletableFuture<>();
    SSLStorage.trackTask(101L, submitted);

    SSLStorage.trackTaskCancellation(future, submitted);
    assertNotNull(SSLStorage.taskContext(submitted));
    FutureInst.CancelAdvice.exit(future, true, null);

    assertNull(SSLStorage.taskContext(submitted));
  }

  @Test
  void forkJoinCancellationCleansItsPendingContext() {
    ForkJoinTask<?> task = ForkJoinTask.adapt(() -> {});
    SSLStorage.trackTask(101L, task);

    FutureInst.CancelAdvice.exit(task, true, null);

    assertNull(SSLStorage.taskContext(task));
  }

  @Test
  void executingWrapperConsumesTheSubmittedTasksCancellationEntry() {
    Runnable submitted = () -> {};
    FutureTask<Void> future = new FutureTask<>(submitted, null);
    SSLStorage.trackTask(101L, submitted);
    SSLStorage.trackTask(101L, future);
    SSLStorage.trackTaskCancellation(future, submitted);

    assertNotNull(SSLStorage.takeTaskContext(future));

    assertNull(SSLStorage.taskContext(submitted));
  }

  @Test
  void cancellationOwnerCyclesAreRemovedOnce() {
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(4);
    Object first = new Object();
    Object second = new Object();
    tasks.track(first, new TaskContext(101L, 0L));
    tasks.track(second, new TaskContext(101L, 0L));
    tasks.trackCancellationOwner(first, second);
    tasks.trackCancellationOwner(second, first);

    tasks.untrack(first);

    assertNull(tasks.get(first));
    assertNull(tasks.get(second));
  }

  @Test
  void longCancellationOwnerChainsDoNotRecurse() {
    int chainLength = 1_024;
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(chainLength);
    Object[] chain = new Object[chainLength];
    for (int i = 0; i < chain.length; i++) {
      chain[i] = new Object();
      tasks.track(chain[i], new TaskContext(101L, 0L));
      if (i > 0) {
        tasks.trackCancellationOwner(chain[i - 1], chain[i]);
      }
    }

    tasks.untrack(chain[0]);

    for (Object task : chain) {
      assertNull(tasks.get(task));
    }
  }

  @Test
  void shutdownNowAndQueueRemovalCleanReturnedTasks() {
    FutureTask<Void> removed = new FutureTask<>(() -> {}, null);
    FutureTask<Void> shutdown = new FutureTask<>(() -> {}, null);
    SSLStorage.trackTask(101L, removed);
    SSLStorage.trackTask(101L, shutdown);

    JavaExecutorInst.RemoveTaskAdvice.exit(removed, true, null);
    JavaExecutorInst.ShutdownNowAdvice.exit(java.util.Collections.singletonList(shutdown), null);

    assertNull(SSLStorage.taskContext(removed));
    assertNull(SSLStorage.taskContext(shutdown));
  }

  @Test
  void silentDiscardPolicyCleansTheRejectedTask() {
    Runnable rejected = () -> {};
    SSLStorage.trackTask(101L, rejected);
    Object queue = new Object();

    int rejection =
        SSLStorage.beginRejectedExecution(new ThreadPoolExecutor.DiscardPolicy(), queue);
    SSLStorage.endRejectedExecution(rejection, rejected, false);

    assertNull(SSLStorage.taskContext(rejected));
  }

  @Test
  void discardOldestPolicyCleansOnlyThePolledTaskFromItsQueue() {
    Runnable oldest = () -> {};
    Runnable replacement = () -> {};
    SSLStorage.trackTask(101L, oldest);
    SSLStorage.trackTask(101L, replacement);
    Object rejectedQueue = new Object();
    Object unrelatedQueue = new Object();

    int rejection =
        SSLStorage.beginRejectedExecution(
            new ThreadPoolExecutor.DiscardOldestPolicy(), rejectedQueue);
    BlockingQueueInst.PollAdvice.exit(unrelatedQueue, replacement, null);
    BlockingQueueInst.PollAdvice.exit(rejectedQueue, oldest, null);
    SSLStorage.endRejectedExecution(rejection, replacement, false);

    assertNull(SSLStorage.taskContext(oldest));
    assertNotNull(SSLStorage.taskContext(replacement));
    SSLStorage.untrackTask(replacement);
  }

  @Test
  void discardOldestPolicyCleansTheRejectedTaskAfterShutdown() {
    Runnable rejected = () -> {};
    SSLStorage.trackTask(101L, rejected);

    int rejection =
        SSLStorage.beginRejectedExecution(
            new ThreadPoolExecutor.DiscardOldestPolicy(), new Object());
    SSLStorage.endRejectedExecution(rejection, rejected, true);

    assertNull(SSLStorage.taskContext(rejected));
  }

  @Test
  void customRejectionHandlersRetainTaskOwnership() {
    Runnable rejected = () -> {};
    RejectedExecutionHandler customHandler = (task, executor) -> {};
    SSLStorage.trackTask(101L, rejected);

    int rejection = SSLStorage.beginRejectedExecution(customHandler, new Object());
    SSLStorage.endRejectedExecution(rejection, rejected, false);

    assertNotNull(SSLStorage.taskContext(rejected));
    SSLStorage.untrackTask(rejected);
  }

  @Test
  void bulkSubmissionDoesNotReplaceANestedCallableCapture() {
    Callable<Void> task = () -> null;
    SSLStorage.setThreadIdProviderForTest(() -> 101L);

    Object[][] bulk =
        JavaExecutorInst.SetCallableStateForCallableCollectionAdvice.submitEnter(
            Arrays.asList(task));
    TaskContext captured = SSLStorage.taskContext(task);
    int nested = JavaExecutorInst.SetCallableStateAdvice.enterJobSubmit(task, "submit");

    assertEquals(SSLStorage.SUBMISSION_NESTED, nested);
    assertSame(captured, SSLStorage.taskContext(task));
    JavaExecutorInst.SetCallableStateAdvice.exitJobSubmit(task, "submit", null, null, nested);
    assertSame(captured, SSLStorage.taskContext(task));
    JavaExecutorInst.SetCallableStateForCallableCollectionAdvice.submitExit(bulk);
    assertNull(SSLStorage.taskContext(task));
  }

  @Test
  void forkJoinInternalSubmissionTransfersHiddenRunnableToItsWrapper() {
    Runnable task = () -> {};
    ForkJoinTask<?> wrapper = ForkJoinTask.adapt(task);
    SSLStorage.setThreadIdProviderForTest(() -> 101L);

    int outer = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(task, "execute");
    int wrapped =
        JavaExecutorInst.SetJavaForkJoinStateAdvice.enterJobSubmit(wrapper, "externalPush");
    JavaExecutorInst.SetJavaForkJoinStateAdvice.exitJobSubmit(wrapper, null, wrapped);
    JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
        ForkJoinPool.commonPool(), task, "execute", null, outer);

    assertNull(SSLStorage.taskContext(task));
    assertNotNull(SSLStorage.taskContext(wrapper));
    SSLStorage.untrackTask(wrapper);
  }

  @Test
  void throwingBeforeExecuteCleansTheTaskWithoutAfterExecute() {
    Runnable task = () -> {};
    SSLStorage.trackTask(101L, task);

    boolean outermost = JavaExecutorInst.BeforeExecuteAdvice.enter();
    JavaExecutorInst.BeforeExecuteAdvice.exit(
        task, new IllegalStateException("rejected"), outermost);

    assertNull(SSLStorage.taskContext(task));
  }

  private static void submitAndWait(Runnable task, CountDownLatch entered, CountDownLatch exit) {
    int submission = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(task, "execute");
    entered.countDown();
    try {
      assertTrue(exit.await(5, java.util.concurrent.TimeUnit.SECONDS));
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new AssertionError(interrupted);
    } finally {
      JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
          Runnable::run, task, "execute", null, submission);
    }
  }
}
