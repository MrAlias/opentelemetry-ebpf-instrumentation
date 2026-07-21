/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.util.concurrent.Callable;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public final class NettyExecutorInst {
  private static final String ABSTRACT_EVENT_EXECUTOR =
      "io.netty.util.concurrent.AbstractEventExecutor";
  private static final String SCHEDULED_FUTURE_TASK =
      "io.netty.util.concurrent.ScheduledFutureTask";

  private NettyExecutorInst() {}

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.named(ABSTRACT_EVENT_EXECUTOR)
        .or(ElementMatchers.named(SCHEDULED_FUTURE_TASK));
  }

  public static boolean matches(Class<?> clazz) {
    String name = clazz.getName();
    return ABSTRACT_EVENT_EXECUTOR.equals(name) || SCHEDULED_FUTURE_TASK.equals(name);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(TaskAdvice.class)
                    .on(
                        ElementMatchers.namedOneOf("runTask", "safeExecute")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))))
            .visit(
                Advice.to(ScheduledTaskConstructorAdvice.class)
                    .on(
                        ElementMatchers.isConstructor()
                            .and(
                                ElementMatchers.takesArgument(1, Runnable.class)
                                    .or(ElementMatchers.takesArgument(1, Callable.class)))));
  }

  @SuppressWarnings("unused")
  public static final class TaskAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static boolean enter(@Advice.Argument(0) Runnable task) {
      if (ThreadInfo.loomTask(task)) {
        return false;
      }
      return SSLStorage.enterTaskScope(task);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter boolean linked) {
      if (linked) {
        ThreadInfo.restoreTaskParentThreadContext();
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class ScheduledTaskConstructorAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(
        @Advice.This Object scheduledTask, @Advice.Argument(1) Object submittedTask) {
      SSLStorage.transferTaskContext(submittedTask, scheduledTask);
    }
  }
}
