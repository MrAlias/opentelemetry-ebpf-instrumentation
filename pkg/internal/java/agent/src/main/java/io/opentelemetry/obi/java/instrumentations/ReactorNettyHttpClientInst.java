/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.ReactorNettyContext;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class ReactorNettyHttpClientInst {
  private static final String OPERATIONS = "reactor.netty.http.client.HttpClientOperations";
  private static final String MONO = "reactor.core.publisher.Mono";
  private static final String FLUX = "reactor.core.publisher.Flux";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.namedOneOf(MONO, FLUX, OPERATIONS);
  }

  public static boolean matches(Class<?> clazz) {
    return MONO.equals(clazz.getName())
        || FLUX.equals(clazz.getName())
        || OPERATIONS.equals(clazz.getName());
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) -> {
      if (!OPERATIONS.equals(type.getName())) {
        if (classLoader == null
            || classLoader.getResource("reactor/netty/http/client/HttpClient.class") == null) {
          return builder;
        }
        return builder.visit(
            Advice.to(SubscribeAdvice.class)
                .on(
                    ElementMatchers.named("subscribe")
                        .and(ElementMatchers.takesArguments(1))
                        .and(
                            ElementMatchers.takesArgument(
                                0, ElementMatchers.named("org.reactivestreams.Subscriber")))));
      }
      return builder.visit(
          Advice.to(HeadersAdvice.class)
              .on(
                  ElementMatchers.named("beforeMarkSentHeaders")
                      .and(ElementMatchers.takesArguments(0))));
    };
  }

  public static class SubscribeAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(
        @Advice.This Object publisher,
        @Advice.Argument(value = 0, readOnly = false, typing = Assigner.Typing.DYNAMIC)
            Object subscriber)
        throws Exception {
      subscriber = ReactorNettyContext.wrap(publisher, subscriber);
    }
  }

  public static class HeadersAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(
        @Advice.This Object request, @Advice.FieldValue("isSecure") boolean secure)
        throws Exception {
      ReactorNettyContext.prepare(request, secure);
    }
  }
}
