/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.ConnectionInfo;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.util.NettyChannelExtractor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;

public final class ReactorNettyContext {
  private static final Object CONTEXT_KEY = new Object();
  // tp_info_t and connection_info_t in the Java ioctl protocol.
  private static final int CONTEXT_SIZE = 48;
  private static final int CONNECTION_SIZE = 36;
  private static final int HEADER_SIZE = 55;

  public static Object wrap(Object publisher, Object subscriber) throws Exception {
    ClassLoader loader = publisher.getClass().getClassLoader();
    Class<?> coreSubscriber = Class.forName("reactor.core.CoreSubscriber", false, loader);
    Object context =
        coreSubscriber.isInstance(subscriber)
            ? coreSubscriber.getMethod("currentContext").invoke(subscriber)
            : Class.forName("reactor.util.context.Context", false, loader)
                .getMethod("empty")
                .invoke(null);
    if (context(context) != null) {
      return subscriber;
    }
    NativeMemory parent = new NativeMemory(1 + CONTEXT_SIZE);
    parent.setByte(0, OperationType.CAPTURE_CONTEXT.code);
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, parent.getAddress());
    return subscriber(subscriber, context, parent, coreSubscriber);
  }

  static Object subscriber(
      Object delegate, Object context, NativeMemory parent, Class<?> coreSubscriber)
      throws Exception {
    Method put = context.getClass().getMethod("put", Object.class, Object.class);
    put.setAccessible(true);
    final Object requestContext = put.invoke(context, CONTEXT_KEY, parent);
    java.util.List<Class<?>> interfaces = new java.util.ArrayList<>();
    interfaces.add(coreSubscriber);
    for (String marker :
        new String[] {
          "reactor.core.Fuseable$ConditionalSubscriber",
          "reactor.core.Fuseable$QueueSubscription",
          "reactor.core.Fuseable$SynchronousSubscription"
        }) {
      Class<?> type = Class.forName(marker, false, coreSubscriber.getClassLoader());
      if (type.isInstance(delegate)) {
        interfaces.add(type);
      }
    }
    return Proxy.newProxyInstance(
        coreSubscriber.getClassLoader(),
        interfaces.toArray(new Class<?>[0]),
        (proxy, method, arguments) -> {
          if (method.getDeclaringClass() == Object.class) {
            if (method.getName().equals("equals")) {
              return proxy == arguments[0];
            }
            if (method.getName().equals("hashCode")) {
              return System.identityHashCode(proxy);
            }
          }
          if (method.getName().equals("currentContext") && method.getParameterTypes().length == 0) {
            return requestContext;
          }
          try {
            return method.invoke(delegate, arguments);
          } catch (InvocationTargetException error) {
            throw error.getCause();
          }
        });
  }

  static NativeMemory context(Object context) throws Exception {
    Method get = context.getClass().getMethod("getOrDefault", Object.class, Object.class);
    get.setAccessible(true);
    Object parent = get.invoke(context, CONTEXT_KEY, null);
    return parent instanceof NativeMemory ? (NativeMemory) parent : null;
  }

  public static void prepare(Object request, boolean secure) throws Exception {
    if (!secure
        || !"HTTP/1.1".equals(invoke(request, "version").toString())
        || Boolean.TRUE.equals(invoke(request, "isWebsocket"))) {
      return;
    }
    NativeMemory context = context(invoke(request, "currentContextView"));
    if (context == null) {
      return;
    }
    Connection connection =
        NettyChannelExtractor.extractConnectionFromChannelHandlerContext(request);
    if (connection == null) {
      return;
    }
    int contextOffset = 1 + CONNECTION_SIZE;
    int headerOffset = contextOffset + CONTEXT_SIZE;
    NativeMemory packet = new NativeMemory(headerOffset + HEADER_SIZE);
    packet.setByte(0, OperationType.PREPARE_HTTP.code);
    ConnectionInfo.writeSendConnectionInfo(packet, 1, connection);
    for (int offset = 0; offset < CONTEXT_SIZE; offset += Long.BYTES) {
      packet.setLong(contextOffset + offset, context.getLong(1 + offset));
    }
    Agent.NativeLib.ioctl(0, Agent.IOCTL_CMD, packet.getAddress());
    byte[] value = packet.read(headerOffset, HEADER_SIZE);
    if (value[0] != '0') {
      return;
    }
    injectHeader(invoke(request, "requestHeaders"), new String(value, StandardCharsets.US_ASCII));
  }

  static void injectHeader(Object headers, String value) throws Exception {
    Method contains = headers.getClass().getMethod("contains", CharSequence.class);
    contains.setAccessible(true);
    if (Boolean.TRUE.equals(contains.invoke(headers, "traceparent"))) {
      return;
    }
    Method set = headers.getClass().getMethod("set", CharSequence.class, Object.class);
    set.setAccessible(true);
    set.invoke(headers, "traceparent", value);
  }

  private static Object invoke(Object target, String name) throws Exception {
    Method method = target.getClass().getMethod(name);
    method.setAccessible(true);
    return method.invoke(target);
  }
}
