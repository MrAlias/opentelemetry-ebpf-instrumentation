/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.OkHttpContext;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class OkHttpInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.namedOneOf(
        "okhttp3.RealCall",
        "okhttp3.internal.connection.RealCall",
        "okhttp3.internal.http1.Http1ExchangeCodec");
  }

  public static boolean matches(Class<?> clazz) {
    String name = clazz.getName();
    return name.equals("okhttp3.RealCall")
        || name.equals("okhttp3.internal.connection.RealCall")
        || name.equals("okhttp3.internal.http1.Http1ExchangeCodec");
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(ExecuteAdvice.class)
                    .on(ElementMatchers.named("execute").and(ElementMatchers.takesArguments(0))))
            .visit(
                Advice.to(HeadersAdvice.class)
                    .on(
                        ElementMatchers.named("writeRequestHeaders")
                            .and(ElementMatchers.takesArguments(1))
                            .and(
                                ElementMatchers.takesArgument(
                                    0, ElementMatchers.named("okhttp3.Request")))));
  }

  public static final class ExecuteAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static boolean enter() {
      return OkHttpContext.enter();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter boolean previous) {
      OkHttpContext.restore(previous);
    }
  }

  public static final class HeadersAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(
        @Advice.This Object codec,
        @Advice.Argument(value = 0, readOnly = false, typing = Assigner.Typing.DYNAMIC)
            Object request)
        throws Exception {
      request = OkHttpContext.inject(codec, request);
    }
  }
}
