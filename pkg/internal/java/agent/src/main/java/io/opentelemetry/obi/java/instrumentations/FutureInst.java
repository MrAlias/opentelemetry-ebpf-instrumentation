/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.util.concurrent.Future;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public final class FutureInst {
  private FutureInst() {}

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(Future.class);
  }

  public static boolean matches(Class<?> clazz) {
    return Future.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder.visit(
            Advice.to(CancelAdvice.class)
                .on(
                    ElementMatchers.named("cancel")
                        .and(ElementMatchers.takesArguments(boolean.class))
                        .and(ElementMatchers.returns(boolean.class))));
  }

  @SuppressWarnings("unused")
  public static final class CancelAdvice {
    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.This Future<?> task,
        @Advice.Return boolean cancelled,
        @Advice.Thrown Throwable throwable) {
      if (throwable == null && cancelled) {
        SSLStorage.untrackTask(task);
      }
    }
  }
}
