/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.util.concurrent.BlockingQueue;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public final class BlockingQueueInst {
  private BlockingQueueInst() {}

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(BlockingQueue.class);
  }

  public static boolean matches(Class<?> clazz) {
    return BlockingQueue.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder.visit(
            Advice.to(PollAdvice.class)
                .on(
                    ElementMatchers.named("poll")
                        .and(ElementMatchers.takesArguments(0))
                        .and(ElementMatchers.returns(Object.class))));
  }

  @SuppressWarnings("unused")
  public static final class PollAdvice {
    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.This Object queue, @Advice.Return Object task, @Advice.Thrown Throwable throwable) {
      if (throwable == null) {
        SSLStorage.onRejectedQueuePoll(queue, task);
      }
    }
  }
}
