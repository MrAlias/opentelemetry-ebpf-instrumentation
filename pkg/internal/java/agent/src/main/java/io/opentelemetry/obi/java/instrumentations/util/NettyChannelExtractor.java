/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;

public class NettyChannelExtractor {

  // Called always by reflection, that's why unused
  @SuppressWarnings("unused")
  public static Connection extractConnectionFromChannelHandlerContext(Object ctx) {
    Connection c = null;
    try {
      Method channelMethod = ctx.getClass().getMethod("channel");
      channelMethod.setAccessible(true);
      Object channel = channelMethod.invoke(ctx);

      Method localAddressMethod = channel.getClass().getMethod("localAddress");
      localAddressMethod.setAccessible(true);
      InetSocketAddress localAddress = (InetSocketAddress) localAddressMethod.invoke(channel);

      Method remoteAddressMethod = channel.getClass().getMethod("remoteAddress");
      remoteAddressMethod.setAccessible(true);
      InetSocketAddress remoteAddress = (InetSocketAddress) remoteAddressMethod.invoke(channel);

      if (SSLStorage.debugOn) {
        System.err.println("[NettyChannelExtractor] Netty channel localAddress: " + localAddress);
        System.err.println("[NettyChannelExtractor] Netty channel remoteAddress: " + remoteAddress);
      }
      Object lifecycleKey = channelLifecycleKey(channel);
      if (lifecycleKey == channel && !SSLStorage.isNettyCloseHookAvailable(channel)) {
        return null;
      }
      Connection cached = SSLStorage.getConnectionForChannel(lifecycleKey);
      if (cached != null) {
        return cached;
      }
      c =
          new Connection(
              localAddress.getAddress(),
              localAddress.getPort(),
              remoteAddress.getAddress(),
              remoteAddress.getPort(),
              socketFileDescriptor(channel));
      c = SSLStorage.associateConnectionWithChannel(lifecycleKey, c);
    } catch (Throwable failure) {
      SSLStorage.logNettyAdviceFailure("extract Netty channel data", failure);
    }

    return c;
  }

  public static Object channelLifecycleKey(Object channel) {
    if (channel == null) {
      return null;
    }
    try {
      Object javaChannel = invokeNoArg(channel, "javaChannel");
      return javaChannel instanceof SocketChannel ? javaChannel : channel;
    } catch (Throwable ignored) {
      return channel;
    }
  }

  private static int socketFileDescriptor(Object channel) {
    try {
      Object descriptor = invokeNoArg(channel, "fd");
      if (descriptor == null) {
        descriptor = invokeNoArg(channel, "socket");
      }
      if (descriptor != null) {
        Object value = invokeNoArg(descriptor, "intValue");
        if (value instanceof Number) {
          return ((Number) value).intValue();
        }
      }

    } catch (Throwable ignored) {
    }

    try {
      Object javaChannel = invokeNoArg(channel, "javaChannel");
      if (javaChannel instanceof SocketChannel) {
        return BootstrapNative.socketFileDescriptor(((SocketChannel) javaChannel).socket());
      }
    } catch (Throwable ignored) {
    }
    return -1;
  }

  private static Object invokeNoArg(Object target, String methodName) throws Exception {
    Class<?> type = target.getClass();
    while (type != null) {
      try {
        Method method = type.getDeclaredMethod(methodName);
        method.setAccessible(true);
        return method.invoke(target);
      } catch (NoSuchMethodException ignored) {
        type = type.getSuperclass();
      }
    }
    return null;
  }
}
