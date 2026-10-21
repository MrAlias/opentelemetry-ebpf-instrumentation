/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.instrumentations.data.JdkHttpClientPropagation;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.channels.SocketChannel;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BiPredicate;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class JdkHttpClientInst {
  private static final String HTTP_CLIENT_CLASS = "java.net.http.HttpClient";
  private static final String SELECTOR_MANAGER_CLASS =
      "jdk.internal.net.http.HttpClientImpl$SelectorManager";
  private static final String ASYNC_EVENT_CLASS = "jdk.internal.net.http.AsyncEvent";
  private static final String HTTP_CLIENT_IMPL = "jdk.internal.net.http.HttpClientImpl";
  private static final String HTTP_REQUEST_IMPL = "jdk.internal.net.http.HttpRequestImpl";
  private static final String HTTP2_CONNECTION = "jdk.internal.net.http.Http2Connection";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.hasSuperType(ElementMatchers.named(HTTP_CLIENT_CLASS))
        .or(ElementMatchers.named(SELECTOR_MANAGER_CLASS))
        .or(ElementMatchers.named(HTTP_REQUEST_IMPL))
        .or(ElementMatchers.named(HTTP2_CONNECTION))
        .or(ElementMatchers.hasSuperType(ElementMatchers.named(ASYNC_EVENT_CLASS)));
  }

  public static boolean matches(Class<?> clazz) {
    if (SELECTOR_MANAGER_CLASS.equals(clazz.getName())
        || HTTP_REQUEST_IMPL.equals(clazz.getName())
        || HTTP2_CONNECTION.equals(clazz.getName())) {
      return true;
    }
    for (Class<?> current = clazz; current != null; current = current.getSuperclass()) {
      if (HTTP_CLIENT_CLASS.equals(current.getName())
          || ASYNC_EVENT_CLASS.equals(current.getName())) {
        return true;
      }
    }
    return false;
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(SynchronousSendAdvice.class)
                    .on(
                        ElementMatchers.named("send")
                            .and(
                                ElementMatchers.isDeclaredBy(
                                    ElementMatchers.named(HTTP_CLIENT_IMPL)))))
            .visit(
                Advice.to(RequestAdvice.class)
                    .on(
                        ElementMatchers.isConstructor()
                            .and(
                                ElementMatchers.isDeclaredBy(
                                    ElementMatchers.named(HTTP_REQUEST_IMPL)))
                            .and(ElementMatchers.takesArguments(2))
                            .and(
                                ElementMatchers.takesArgument(
                                    0, ElementMatchers.named("java.net.http.HttpRequest")))))
            .visit(
                Advice.to(HeadersAdvice.class)
                    .on(
                        ElementMatchers.named("encodeHeaders")
                            .and(
                                ElementMatchers.isDeclaredBy(
                                    ElementMatchers.named(HTTP2_CONNECTION)))
                            .and(ElementMatchers.takesArguments(1))))
            .visit(
                Advice.to(SendAdvice.class)
                    .on(
                        ElementMatchers.namedOneOf("send", "sendAsync")
                            .and(ElementMatchers.isPublic())))
            .visit(
                Advice.to(RegisterEventAdvice.class)
                    .on(
                        ElementMatchers.namedOneOf("register", "eventUpdated")
                            .and(ElementMatchers.takesArguments(1))))
            .visit(
                Advice.to(HandleEventAdvice.class)
                    .on(
                        ElementMatchers.named("handleEvent")
                            .and(ElementMatchers.takesArguments(2))))
            .visit(
                Advice.to(HandleAsyncEventAdvice.class)
                    .on(
                        ElementMatchers.named("handle")
                            .and(ElementMatchers.takesArguments(0))
                            .and(ElementMatchers.not(ElementMatchers.isAbstract()))));
  }

  @SuppressWarnings("unused")
  public static final class SynchronousSendAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static JdkHttpClientPropagation.Scope enter() {
      return JdkHttpClientPropagation.enter();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter JdkHttpClientPropagation.Scope scope) {
      JdkHttpClientPropagation.exit(scope);
    }
  }

  @SuppressWarnings("unused")
  public static final class RequestAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(
        @Advice.This Object request, @Advice.FieldValue("secure") boolean secure) {
      if (secure) {
        JdkHttpClientPropagation.remember(request);
      }
    }
  }

  @SuppressWarnings({"unused", "unchecked"})
  public static final class HeadersAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(
        @Advice.Argument(0) Object frame, @Advice.FieldValue("connection") Object connection)
        throws Exception {
      // Reflection stays in the inlined advice, inside java.net.http's module.
      Class<?> frameClass = frame.getClass();
      Object stream = frameClass.getMethod("getAttachment").invoke(frame);
      Class<?> streamClass = Class.forName("jdk.internal.net.http.Stream");
      Field requestField = streamClass.getDeclaredField("request");
      requestField.setAccessible(true);
      Object request = requestField.get(stream);
      if (!JdkHttpClientPropagation.tracked(request)) {
        return;
      }
      Class<?> connectionClass = Class.forName("jdk.internal.net.http.HttpConnection");
      Method secure = connectionClass.getDeclaredMethod("isSecure");
      secure.setAccessible(true);
      if (!Boolean.TRUE.equals(secure.invoke(connection))) {
        return;
      }
      Class<?> headersClass = Class.forName("java.net.http.HttpHeaders");
      Object user = frameClass.getMethod("getUserHeaders").invoke(frame);
      Object system = frameClass.getMethod("getSystemHeaders").invoke(frame);
      Map<String, List<String>> userMap =
          (Map<String, List<String>>) headersClass.getMethod("map").invoke(user);
      Map<String, List<String>> systemMap =
          (Map<String, List<String>>) headersClass.getMethod("map").invoke(system);
      if (userMap.containsKey("traceparent") || systemMap.containsKey("traceparent")) {
        return;
      }
      Method channelMethod = connectionClass.getDeclaredMethod("channel");
      channelMethod.setAccessible(true);
      SocketChannel channel = (SocketChannel) channelMethod.invoke(connection);
      int streamId = (Integer) frameClass.getMethod("streamid").invoke(frame);
      Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
      headers.putAll(systemMap);
      String value = JdkHttpClientPropagation.value(request);
      if (value == null) {
        return;
      }
      headers.put("traceparent", Collections.singletonList(value));
      Object replacement =
          headersClass
              .getMethod("of", Map.class, BiPredicate.class)
              .invoke(null, headers, JdkHttpClientPropagation.ALL_HEADERS);
      Field systemField = frameClass.getDeclaredField("system");
      systemField.setAccessible(true);
      if (JdkHttpClientPropagation.bind(request, channel, streamId)) {
        systemField.set(frame, replacement);
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class SendAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static long enter() {
      long threadId = Agent.NativeLib.gettid();
      return SSLStorage.enterJdkHttpClientContext(threadId);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter long previousContext) {
      SSLStorage.restoreJdkHttpClientContext(previousContext);
    }
  }

  @SuppressWarnings("unused")
  public static final class RegisterEventAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Argument(0) Object event) {
      SSLStorage.trackJdkHttpClientEvent(event);
    }
  }

  @SuppressWarnings("unused")
  public static final class HandleEventAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static long enter(@Advice.Argument(0) Object event) {
      return SSLStorage.enterJdkHttpClientEvent(event);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter long previousContext) {
      SSLStorage.restoreJdkHttpClientContext(previousContext);
    }
  }

  @SuppressWarnings("unused")
  public static final class HandleAsyncEventAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static long enter(@Advice.This Object event) {
      return SSLStorage.enterJdkHttpClientEvent(event);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter long previousContext) {
      SSLStorage.restoreJdkHttpClientContext(previousContext);
    }
  }
}
