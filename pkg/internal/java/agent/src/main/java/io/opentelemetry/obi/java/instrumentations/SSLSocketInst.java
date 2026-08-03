/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.ebpf.ProxyInputStream;
import io.opentelemetry.obi.java.ebpf.ProxyOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class SSLSocketInst {
  private static final String DEFAULT_SSL_SOCKET_IMPL = "sun.security.ssl.SSLSocketImpl";

  public static ElementMatcher<? super TypeDescription> type() {
    // sun.security.ssl.SSLSocketImpl streams are handled by SSLSocketStreamInst so that we can
    // get the streams with dynamic attach after they are established. Its terminal close is
    // matched separately by defaultSocketCloseType().
    return ElementMatchers.isSubTypeOf(SSLSocket.class)
        .and(ElementMatchers.not(ElementMatchers.named(DEFAULT_SSL_SOCKET_IMPL)))
        .and(ElementMatchers.not(ElementMatchers.isAbstract()))
        .and(ElementMatchers.not(ElementMatchers.isInterface()));
  }

  /** Matches the JDK implementation separately so only its terminal close path is advised. */
  public static ElementMatcher<? super TypeDescription> defaultSocketCloseType() {
    return ElementMatchers.named(DEFAULT_SSL_SOCKET_IMPL);
  }

  public static boolean matches(Class<?> clazz) {
    return SSLSocket.class.isAssignableFrom(clazz);
  }

  /** Matches the inherited base close method for custom SSL sockets that do not override it. */
  public static ElementMatcher<? super TypeDescription> inheritedSocketCloseType() {
    return ElementMatchers.named("java.net.Socket");
  }

  public static boolean matchesInheritedSocketClose(Class<?> clazz) {
    return Socket.class == clazz;
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(GetOutputStreamAdvice.class).on(ElementMatchers.named("getOutputStream")))
            .visit(
                Advice.to(GetInputStreamAdvice.class).on(ElementMatchers.named("getInputStream")))
            .visit(
                Advice.to(CloseAdvice.class)
                    .on(
                        ElementMatchers.named("close")
                            .and(ElementMatchers.takesArguments(0))
                            .and(ElementMatchers.returns(void.class))));
  }

  public static AgentBuilder.Transformer defaultSocketCloseTransformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder.visit(
            Advice.to(CloseAdvice.class)
                .on(
                    ElementMatchers.named("close")
                        .and(ElementMatchers.takesArguments(0))
                        .and(ElementMatchers.returns(void.class))));
  }

  /** Instruments only {@link Socket#close()} and gates work to SSL sockets at runtime. */
  public static AgentBuilder.Transformer inheritedSocketCloseTransformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder.visit(
            Advice.to(InheritedSocketCloseAdvice.class)
                .on(
                    ElementMatchers.named("close")
                        .and(ElementMatchers.takesArguments(0))
                        .and(ElementMatchers.returns(void.class))));
  }

  public static final class GetOutputStreamAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void getOutputStream(
        @Advice.This final SSLSocket socket,
        @Advice.Return(readOnly = false) OutputStream returnValue) {
      returnValue = new ProxyOutputStream(returnValue, socket);
    }
  }

  public static final class GetInputStreamAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void getInputStream(
        @Advice.This final SSLSocket socket,
        @Advice.Return(readOnly = false) InputStream returnValue) {
      returnValue = new ProxyInputStream(returnValue, socket);
    }
  }

  // This advice is inlined into SSL socket implementations and can therefore only reference
  // bootstrap-injected helpers.
  public static final class CloseAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object close(@Advice.This SSLSocket socket) {
      return BootstrapNative.beginRemoteParentSocketClose(socket);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void close(@Advice.This SSLSocket socket, @Advice.Enter Object lifecycle) {
      BootstrapNative.finishRemoteParentSocketClose(socket, lifecycle);
    }
  }

  // This advice is inlined into java.net.Socket. It must therefore stay bootstrap-safe and only
  // create a lifecycle for an SSLSocket that inherits Socket.close() unchanged.
  public static final class InheritedSocketCloseAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object close(@Advice.This Socket socket) {
      return socket instanceof SSLSocket
          ? BootstrapNative.beginRemoteParentSocketClose(socket)
          : null;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void close(@Advice.This Socket socket, @Advice.Enter Object lifecycle) {
      if (socket instanceof SSLSocket) {
        BootstrapNative.finishRemoteParentSocketClose(socket, lifecycle);
      }
    }
  }
}
