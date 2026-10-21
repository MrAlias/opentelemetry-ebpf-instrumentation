/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.ApacheHttpClient5Context;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class ApacheHttpClient5Inst {
  private static final String EXECUTOR = "org.apache.hc.core5.http.impl.io.HttpRequestExecutor";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.named(EXECUTOR);
  }

  public static boolean matches(Class<?> clazz) {
    return EXECUTOR.equals(clazz.getName());
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, loader, module, domain) ->
        builder.visit(
            Advice.to(ExecuteAdvice.class)
                .on(
                    ElementMatchers.named("execute")
                        .and(
                            ElementMatchers.takesArgument(
                                0,
                                ElementMatchers.named(
                                    "org.apache.hc.core5.http.ClassicHttpRequest")))
                        .and(
                            ElementMatchers.takesArgument(
                                1,
                                ElementMatchers.named(
                                    "org.apache.hc.core5.http.io.HttpClientConnection")))));
  }

  public static class ExecuteAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static ApacheHttpClient5Context.Injection enter(
        @Advice.Argument(0) Object request, @Advice.Argument(1) Object connection)
        throws Exception {
      return ApacheHttpClient5Context.inject(request, connection);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(
        @Advice.Argument(0) Object request,
        @Advice.Enter ApacheHttpClient5Context.Injection injection)
        throws Exception {
      ApacheHttpClient5Context.finish(request, injection);
    }
  }
}
