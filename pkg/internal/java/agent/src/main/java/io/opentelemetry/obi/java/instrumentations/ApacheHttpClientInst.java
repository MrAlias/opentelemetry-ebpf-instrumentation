/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.ApacheHttpClientPropagation;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class ApacheHttpClientInst {
  private static final String CLIENT = "org.apache.http.impl.client.CloseableHttpClient";
  private static final String EXECUTOR = "org.apache.http.protocol.HttpRequestExecutor";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.named(CLIENT).or(ElementMatchers.named(EXECUTOR));
  }

  public static boolean matches(Class<?> clazz) {
    return CLIENT.equals(clazz.getName()) || EXECUTOR.equals(clazz.getName());
  }

  public static AgentBuilder.Transformer transformer(boolean propagation) {
    return (builder, type, classLoader, module, protectionDomain) -> {
      if (!propagation) {
        return builder;
      }
      return builder
          .visit(
              Advice.to(ExecuteAdvice.class)
                  .on(
                      ElementMatchers.named("execute")
                          .and(ElementMatchers.isDeclaredBy(ElementMatchers.named(CLIENT)))
                          .and(ElementMatchers.not(ElementMatchers.isBridge()))))
          .visit(
              Advice.to(SendAdvice.class)
                  .on(
                      ElementMatchers.named("doSendRequest")
                          .and(ElementMatchers.isDeclaredBy(ElementMatchers.named(EXECUTOR)))
                          .and(ElementMatchers.takesArguments(3))));
    };
  }

  public static final class ExecuteAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static ApacheHttpClientPropagation enter() {
      ApacheHttpClientPropagation scope = ApacheHttpClientPropagation.enter();
      ApacheHttpClientPropagation.captureParent(scope);
      return scope;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter ApacheHttpClientPropagation scope) {
      ApacheHttpClientPropagation.exit(scope);
    }
  }

  public static final class SendAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static ApacheHttpClientPropagation enter(@Advice.Argument(1) Object connection)
        throws Exception {
      return ApacheHttpClientPropagation.beginAttempt(connection);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter ApacheHttpClientPropagation scope) {
      ApacheHttpClientPropagation.endAttempt(scope);
    }
  }
}
