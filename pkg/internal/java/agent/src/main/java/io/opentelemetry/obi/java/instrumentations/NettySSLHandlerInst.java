/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class NettySSLHandlerInst {
  private static final String instClassName = "io.netty.handler.ssl.SslHandler";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.named(instClassName);
  }

  public static boolean matches(Class<?> clazz) {
    return clazz.getName().equals(instClassName);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(UnwrapAdvice.class)
                    .on(ElementMatchers.named("unwrap").and(ElementMatchers.takesArguments(3))))
            .visit(
                Advice.to(WrapAdvice.class)
                    .on(ElementMatchers.named("wrap").and(ElementMatchers.takesArguments(2))));
  }

  public static final class UnwrapAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void unwrap(@Advice.Argument(0) final Object ctx) {
      SSLStorage.beginNettyConnectionScope();
      try {
        if (SSLStorage.getBootDebugOn().get(null).equals(true)) {
          System.err.println("[NettySSLHandlerInst] Netty SSL handler unwrap");
        }
        if (ctx == null) {
          return;
        }

        Object c =
            SSLStorage.getBootExtractMethod()
                .invoke(null, ctx); // static method, so null as instance

        @SuppressWarnings("unchecked")
        ThreadLocal<Object> threadLocal =
            (ThreadLocal<Object>)
                SSLStorage.getBootNettyConnectionField()
                    .get(null); // static field, so null as instance
        threadLocal.set(c);
      } catch (Throwable failure) {
        SSLStorage.logNettyAdviceFailure("enter Netty unwrap", failure);
      }
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void unwrap(@Advice.Thrown Throwable throwable) {
      try {
        SSLStorage.endNettyConnectionScope();
      } catch (Throwable failure) {
        SSLStorage.logNettyAdviceFailure("exit Netty unwrap", failure);
      }
    }
  }

  public static final class WrapAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void wrap(@Advice.Argument(0) final Object ctx) {
      SSLStorage.beginNettyConnectionScope();
      try {
        if (SSLStorage.getBootDebugOn().get(null).equals(true)) {
          System.err.println("[NettySSLHandlerInst] Netty SSL handler wrap");
        }

        if (ctx == null) {
          return;
        }

        Object c =
            SSLStorage.getBootExtractMethod()
                .invoke(null, ctx); // static method, so null as instance

        @SuppressWarnings("unchecked")
        ThreadLocal<Object> threadLocal =
            (ThreadLocal<Object>)
                SSLStorage.getBootNettyConnectionField()
                    .get(null); // static field, so null as instance
        threadLocal.set(c);
      } catch (Throwable failure) {
        SSLStorage.logNettyAdviceFailure("enter Netty wrap", failure);
      }
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void wrap(@Advice.Thrown Throwable throwable) {
      try {
        SSLStorage.endNettyConnectionScope();
      } catch (Throwable failure) {
        SSLStorage.logNettyAdviceFailure("exit Netty wrap", failure);
      }
    }
  }
}
