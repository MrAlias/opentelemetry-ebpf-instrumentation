/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.Future;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class JavaExecutorInst {
  private static final int SUBMISSION_SKIPPED = -1;

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(Executor.class);
  }

  public static boolean matches(Class<?> clazz) {
    return Executor.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(SetExecuteRunnableStateAdvice.class)
                    .on(
                        ElementMatchers.named("execute")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))))
            .visit(
                Advice.to(SetExecuteRunnableStateAdvice.class)
                    .on(
                        ElementMatchers.named("addTask")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))))
            .visit(
                Advice.to(SetJavaForkJoinStateAdvice.class)
                    .on(
                        ElementMatchers.named("execute")
                            .and(ElementMatchers.takesArgument(0, ForkJoinTask.class))))
            .visit(
                Advice.to(SetJavaForkJoinStateAdvice.class)
                    .on(
                        ElementMatchers.named("submit")
                            .and(ElementMatchers.takesArgument(0, ForkJoinTask.class))))
            .visit(
                Advice.to(SetJavaForkJoinStateAdvice.class)
                    .on(
                        ElementMatchers.named("invoke")
                            .and(ElementMatchers.takesArgument(0, ForkJoinTask.class))))
            .visit(
                Advice.to(SetJavaForkJoinStateAdvice.class)
                    .on(
                        ElementMatchers.namedOneOf("externalPush", "externalSubmit")
                            .and(ElementMatchers.takesArgument(0, ForkJoinTask.class))))
            .visit(
                Advice.to(SetJavaForkJoinPoolStateAdvice.class)
                    .on(
                        ElementMatchers.named("poolSubmit")
                            .and(ElementMatchers.takesArgument(1, ForkJoinTask.class))))
            .visit(
                Advice.to(SetSubmitRunnableStateAdvice.class)
                    .on(
                        ElementMatchers.named("submit")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))
                            .and(
                                ElementMatchers.returns(
                                    ElementMatchers.hasSuperType(
                                        ElementMatchers.is(Future.class))))))
            .visit(
                Advice.to(SetSubmitRunnableStateAdvice.class)
                    .on(
                        ElementMatchers.namedOneOf(
                                "schedule", "scheduleAtFixedRate", "scheduleWithFixedDelay")
                            .and(ElementMatchers.isPublic())
                            .and(ElementMatchers.not(ElementMatchers.isBridge()))
                            .and(ElementMatchers.takesArgument(0, Runnable.class))
                            .and(
                                ElementMatchers.returns(
                                    ElementMatchers.hasSuperType(
                                        ElementMatchers.is(Future.class))))))
            .visit(
                Advice.to(SetCallableStateAdvice.class)
                    .on(
                        ElementMatchers.named("submit")
                            .and(ElementMatchers.takesArgument(0, Callable.class))
                            .and(
                                ElementMatchers.returns(
                                    ElementMatchers.hasSuperType(
                                        ElementMatchers.is(Future.class))))))
            .visit(
                Advice.to(DecorateScheduledTaskAdvice.class)
                    .on(
                        ElementMatchers.named("decorateTask")
                            .and(
                                ElementMatchers.takesArgument(
                                    0,
                                    ElementMatchers.is(Runnable.class)
                                        .or(ElementMatchers.is(Callable.class))))
                            .and(ElementMatchers.takesArguments(2))))
            .visit(
                Advice.to(SetCallableStateAdvice.class)
                    .on(
                        ElementMatchers.named("schedule")
                            .and(ElementMatchers.isPublic())
                            .and(ElementMatchers.not(ElementMatchers.isBridge()))
                            .and(ElementMatchers.takesArgument(0, Callable.class))
                            .and(
                                ElementMatchers.returns(
                                    ElementMatchers.hasSuperType(
                                        ElementMatchers.is(Future.class))))))
            .visit(
                Advice.to(SetCallableStateForCallableCollectionAdvice.class)
                    .on(
                        ElementMatchers.namedOneOf("invokeAny", "invokeAll")
                            .and(ElementMatchers.takesArgument(0, Collection.class))))
            .visit(
                Advice.to(RemoveTaskAdvice.class)
                    .on(
                        ElementMatchers.named("remove")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))
                            .and(ElementMatchers.returns(boolean.class))))
            .visit(
                Advice.to(ShutdownNowAdvice.class)
                    .on(
                        ElementMatchers.named("shutdownNow")
                            .and(ElementMatchers.takesArguments(0))
                            .and(ElementMatchers.returns(List.class))))
            .visit(
                Advice.to(BeforeExecuteAdvice.class)
                    .on(
                        ElementMatchers.named("beforeExecute")
                            .and(ElementMatchers.takesArgument(0, Thread.class))
                            .and(ElementMatchers.takesArgument(1, Runnable.class))))
            .visit(
                Advice.to(AfterExecuteAdvice.class)
                    .on(
                        ElementMatchers.named("afterExecute")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))
                            .and(ElementMatchers.takesArgument(1, Throwable.class))));
  }

  @SuppressWarnings("unused")
  public static final class SetExecuteRunnableStateAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int enterJobSubmit(
        @Advice.Argument(value = 0, readOnly = false) Runnable task, @Advice.Origin String method) {
      // Loom re-submits the SAME per-VT runContinuation lambda on every
      // unpark, from platform threads; tracking it turns the relay emit
      // below into a java_tasks poisoner for carrier tids. Skip Loom
      // internals. User tasks submitted from virtual threads still need an
      // exact handoff when they later execute on a platform thread. Netty's
      // scheduled-task constructor transfers the public submission directly
      // to its internal wrapper before that wrapper is enqueued.
      if (task == null
          || ThreadInfo.loomTask(task)
          || "io.netty.util.concurrent.ScheduledFutureTask".equals(task.getClass().getName())) {
        return SUBMISSION_SKIPPED;
      }
      long threadId = SSLStorage.currentThreadId();
      int submission = SSLStorage.beginTaskSubmission(threadId, task);
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetExecuteRunnableStateAdvice] "
                + "("
                + method
                + ")"
                + +threadId
                + " enter jobSubmit task = "
                + task.hashCode());
      }
      return submission;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.This Executor executor,
        @Advice.Argument(0) Runnable task,
        @Advice.Origin("#m") String method,
        @Advice.Thrown Throwable throwable,
        @Advice.Enter int submission) {
      if (submission == SSLStorage.SUBMISSION_OWNER
          && (throwable != null
              || ("execute".equals(method)
                  && executor instanceof ForkJoinPool
                  && !(task instanceof ForkJoinTask)))) {
        SSLStorage.untrackTask(task);
      }
      if (submission != SUBMISSION_SKIPPED) {
        SSLStorage.endTaskSubmission(task);
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class SetJavaForkJoinPoolStateAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int enterJobSubmit(@Advice.Argument(1) ForkJoinTask<?> task) {
      if (ThreadInfo.loomTask(task)) {
        return SUBMISSION_SKIPPED;
      }
      return SSLStorage.beginTaskSubmission(SSLStorage.currentThreadId(), task);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.Argument(1) ForkJoinTask<?> task,
        @Advice.Thrown Throwable throwable,
        @Advice.Enter int submission) {
      if (throwable != null && submission == SSLStorage.SUBMISSION_OWNER) {
        SSLStorage.untrackTask(task);
      }
      if (submission != SUBMISSION_SKIPPED) {
        SSLStorage.endTaskSubmission(task);
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class SetJavaForkJoinStateAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int enterJobSubmit(
        @Advice.Argument(0) ForkJoinTask<?> task, @Advice.Origin String method) {
      // see SetExecuteRunnableStateAdvice, same reasoning
      if (ThreadInfo.loomTask(task)) {
        return SUBMISSION_SKIPPED;
      }
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetJavaForkJoinStateAdvice] ("
                + method
                + ") enter jobSubmit task = "
                + task.hashCode());
      }
      long threadId = SSLStorage.currentThreadId();
      return SSLStorage.beginTaskSubmission(threadId, task);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.Argument(0) ForkJoinTask<?> task,
        @Advice.Thrown Throwable throwable,
        @Advice.Enter int submission) {
      if (throwable != null && submission == SSLStorage.SUBMISSION_OWNER) {
        SSLStorage.untrackTask(task);
      }
      if (submission != SUBMISSION_SKIPPED) {
        SSLStorage.endTaskSubmission(task);
      }
    }
  }

  @SuppressWarnings("unused")
  public static class SetSubmitRunnableStateAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int enterJobSubmit(@Advice.Argument(value = 0, readOnly = false) Runnable task) {
      // see SetExecuteRunnableStateAdvice, same reasoning
      if (ThreadInfo.loomTask(task)) {
        return SUBMISSION_SKIPPED;
      }
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetSubmitRunnableStateAdvice] enter jobSubmit task = " + task.hashCode());
      }
      long threadId = SSLStorage.currentThreadId();
      return SSLStorage.beginTaskSubmission(threadId, task);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.Argument(0) Runnable task,
        @Advice.Origin("#m") String method,
        @Advice.Thrown Throwable throwable,
        @Advice.Return Future<?> future,
        @Advice.Enter int submission) {
      if (throwable != null && submission == SSLStorage.SUBMISSION_OWNER) {
        SSLStorage.untrackTask(task);
      } else if (submission == SSLStorage.SUBMISSION_OWNER && future != null) {
        if (method.startsWith("schedule")) {
          SSLStorage.transferTaskContext(task, future);
        } else {
          SSLStorage.trackTaskCancellation(future, task);
        }
      }
      if (submission != SUBMISSION_SKIPPED) {
        SSLStorage.endTaskSubmission(task);
      }
    }
  }

  @SuppressWarnings("unused")
  public static class SetCallableStateAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int enterJobSubmit(
        @Advice.Argument(0) Callable<?> task, @Advice.Origin String method) {
      // see SetExecuteRunnableStateAdvice, same reasoning
      if (ThreadInfo.loomTask(task)) {
        return SUBMISSION_SKIPPED;
      }
      long threadId = SSLStorage.currentThreadId();
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetCallableStateAdvice] task = " + task.hashCode() + ", thread = " + threadId);
      }
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetCallableStateAdvice] (" + method + ") enter jobSubmit task = " + task.hashCode());
      }
      return SSLStorage.beginTaskSubmission(threadId, task);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.Argument(0) Callable<?> task,
        @Advice.Origin("#m") String method,
        @Advice.Thrown Throwable throwable,
        @Advice.Return Future<?> future,
        @Advice.Enter int submission) {
      if (throwable != null && submission == SSLStorage.SUBMISSION_OWNER) {
        SSLStorage.untrackTask(task);
      } else if (submission == SSLStorage.SUBMISSION_OWNER && future != null) {
        if (method.startsWith("schedule")) {
          SSLStorage.transferTaskContext(task, future);
        } else {
          SSLStorage.trackTaskCancellation(future, task);
        }
      }
      if (submission != SUBMISSION_SKIPPED) {
        SSLStorage.endTaskSubmission(task);
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class DecorateScheduledTaskAdvice {
    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Argument(0) Object submitted,
        @Advice.Argument(1) Object original,
        @Advice.Return Object scheduled,
        @Advice.Thrown Throwable throwable) {
      if (throwable == null
          && scheduled != null
          && !SSLStorage.transferTaskContext(submitted, scheduled)) {
        SSLStorage.transferTaskContext(original, scheduled);
      }
    }
  }

  @SuppressWarnings("unused")
  public static class SetCallableStateForCallableCollectionAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object[][] submitEnter(
        @Advice.Argument(0) Collection<? extends Callable<?>> tasks) {
      if (tasks == null) {
        return null;
      }

      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[SetCallableStateForCallableCollectionAdvice] enter jobSubmit tasks = "
                + tasks.hashCode());
      }

      long threadId = SSLStorage.currentThreadId();
      Object[] submitted = tasks.toArray();
      Object[] begun = new Object[submitted.length];
      Object[] owned = new Object[submitted.length];
      for (int i = 0; i < submitted.length; i++) {
        Object task = submitted[i];
        if (!ThreadInfo.loomTask(task)) {
          begun[i] = task;
          if (SSLStorage.beginTaskSubmission(threadId, task) == SSLStorage.SUBMISSION_OWNER) {
            owned[i] = task;
          }
        }
      }

      return new Object[][] {begun, owned};
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void submitExit(@Advice.Enter Object[][] submissions) {
      if (submissions == null) {
        return;
      }
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println("[SetCallableStateForCallableCollectionAdvice] exit jobSubmit");
      }
      Object[] begun = submissions[0];
      Object[] owned = submissions[1];
      for (int i = 0; i < begun.length; i++) {
        Object task = begun[i];
        if (task != null) {
          if (owned[i] != null) {
            SSLStorage.untrackTask(task);
          }
          SSLStorage.endTaskSubmission(task);
        }
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class BeforeExecuteAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static boolean enter() {
      return SSLStorage.beginExecutorHook();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Argument(1) Runnable task,
        @Advice.Thrown Throwable throwable,
        @Advice.Enter boolean outermost) {
      SSLStorage.endExecutorBeforeHook(outermost, task, throwable == null);
    }
  }

  @SuppressWarnings("unused")
  public static final class AfterExecuteAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static boolean enter() {
      return SSLStorage.beginExecutorHook();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter boolean outermost) {
      SSLStorage.endExecutorAfterHook(outermost);
    }
  }

  @SuppressWarnings("unused")
  public static final class RemoveTaskAdvice {
    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Argument(0) Runnable task,
        @Advice.Return boolean removed,
        @Advice.Thrown Throwable throwable) {
      if (throwable == null && removed) {
        SSLStorage.untrackTask(task);
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class ShutdownNowAdvice {
    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Return List<? extends Runnable> tasks, @Advice.Thrown Throwable throwable) {
      if (throwable == null && tasks != null) {
        for (Runnable task : tasks) {
          SSLStorage.untrackTask(task);
        }
      }
    }
  }
}
