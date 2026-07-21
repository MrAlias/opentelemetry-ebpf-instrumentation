/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.util.concurrent.ThreadPoolExecutor;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public final class RejectedExecutionHandlerInst {
  private RejectedExecutionHandlerInst() {}

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.namedOneOf(
        "java.util.concurrent.ThreadPoolExecutor$AbortPolicy",
        "java.util.concurrent.ThreadPoolExecutor$CallerRunsPolicy",
        "java.util.concurrent.ThreadPoolExecutor$DiscardOldestPolicy",
        "java.util.concurrent.ThreadPoolExecutor$DiscardPolicy");
  }

  public static boolean matches(Class<?> clazz) {
    String name = clazz.getName();
    return "java.util.concurrent.ThreadPoolExecutor$AbortPolicy".equals(name)
        || "java.util.concurrent.ThreadPoolExecutor$CallerRunsPolicy".equals(name)
        || "java.util.concurrent.ThreadPoolExecutor$DiscardOldestPolicy".equals(name)
        || "java.util.concurrent.ThreadPoolExecutor$DiscardPolicy".equals(name);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder.visit(
            Advice.to(RejectedExecutionAdvice.class)
                .on(
                    ElementMatchers.named("rejectedExecution")
                        .and(ElementMatchers.takesArgument(0, Runnable.class))
                        .and(ElementMatchers.takesArgument(1, ThreadPoolExecutor.class))));
  }

  @SuppressWarnings("unused")
  public static final class RejectedExecutionAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int enter(
        @Advice.This Object handler, @Advice.Argument(1) ThreadPoolExecutor executor) {
      return SSLStorage.beginRejectedExecution(handler, executor.getQueue());
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Argument(0) Runnable task,
        @Advice.Argument(1) ThreadPoolExecutor executor,
        @Advice.Enter int rejection) {
      SSLStorage.endRejectedExecution(rejection, task, executor.isShutdown());
    }
  }
}
