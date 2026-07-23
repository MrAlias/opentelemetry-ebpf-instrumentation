/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import java.util.concurrent.ForkJoinTask;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class JavaForkJoinTaskInst {
  private static final int SUBMISSION_SKIPPED = -1;

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(ForkJoinTask.class);
  }

  public static boolean matches(Class<?> clazz) {
    return ForkJoinTask.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(ForkJoinTaskAdvice.class)
                    .on(
                        ElementMatchers.named("exec")
                            .and(
                                ElementMatchers.takesArguments(0)
                                    .and(ElementMatchers.not(ElementMatchers.isAbstract())))))
            .visit(
                Advice.to(ForkJoinTaskAdvice.class)
                    .on(
                        ElementMatchers.named("doExec")
                            .and(
                                ElementMatchers.takesArguments(0)
                                    .and(ElementMatchers.not(ElementMatchers.isAbstract())))))
            .visit(
                Advice.to(ForkAdvice.class)
                    .on(ElementMatchers.named("fork").and(ElementMatchers.takesArguments(0))));
  }

  @SuppressWarnings("unused")
  public static final class ForkAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int enterJobSubmit(@Advice.This ForkJoinTask<?> task) {
      // see RunnableInst, same reasoning
      if (ThreadInfo.loomTask(task)) {
        return SUBMISSION_SKIPPED;
      }
      long threadId = SSLStorage.currentThreadId();
      int submission = SSLStorage.beginTaskSubmission(threadId, task);
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println("[ForkAdvice] " + threadId + "fork task = " + task.hashCode());
      }
      return submission;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(
        @Advice.This ForkJoinTask<?> task,
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
  public static final class ForkJoinTaskAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static boolean enterJobSubmit(
        @Advice.This ForkJoinTask<?> task, @Advice.Origin String method) {
      // see RunnableInst, same reasoning
      if (ThreadInfo.loomTask(task)) {
        return false;
      }
      TaskContext taskContext = SSLStorage.takeTaskContext(task);
      Long parentId = taskContext == null ? null : taskContext.getParentThreadId();
      long threadId = SSLStorage.currentThreadId();
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[ForkJoinTaskAdvice] ("
                + method
                + ") exec task = "
                + task.hashCode()
                + ", parent = "
                + parentId
                + ", thread = "
                + threadId);
      }
      if (parentId != null && (parentId != threadId || taskContext.getHandoffToken() != 0L)) {
        return ThreadInfo.enterTaskParentThreadContext(
            threadId,
            parentId,
            taskContext.getHandoffToken(),
            taskContext.getRemoteParentSocketContext());
      }
      if (taskContext != null) {
        ThreadInfo.cancelTaskContext(taskContext);
      }
      return false;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exitJobSubmit(@Advice.Enter boolean linked) {
      if (linked) {
        ThreadInfo.restoreTaskParentThreadContext();
      }
    }
  }
}
