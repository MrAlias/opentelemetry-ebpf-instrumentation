/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import net.bytebuddy.asm.Advice;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class NettySSLHandlerInstTest {
  private Field previousNettyConnectionField;
  private Field previousDebugField;
  private Method previousExtractMethod;

  @BeforeEach
  void rememberBootstrapAccessors() {
    previousNettyConnectionField = SSLStorage.bootNettyConnectionField;
    previousDebugField = SSLStorage.bootDebugOn;
    previousExtractMethod = SSLStorage.bootExtractMethod;
  }

  @AfterEach
  void cleanup() {
    SSLStorage.nettyConnection.remove();
    SSLStorage.bootNettyConnectionField = previousNettyConnectionField;
    SSLStorage.bootDebugOn = previousDebugField;
    SSLStorage.bootExtractMethod = previousExtractMethod;
  }

  @Test
  void throwableWrapAndUnwrapClearStateBeforeEventLoopReuse() throws Exception {
    SSLStorage.bootNettyConnectionField = SSLStorage.class.getField("nettyConnection");

    assertThrowableCleanup(NettySSLHandlerInst.WrapAdvice.class, "wrap");
    assertThrowableCleanup(NettySSLHandlerInst.UnwrapAdvice.class, "unwrap");
  }

  private static void assertThrowableCleanup(Class<?> adviceClass, String methodName)
      throws Exception {
    Method exit = adviceClass.getDeclaredMethod(methodName, Throwable.class);
    assertEquals(Throwable.class, exit.getAnnotation(Advice.OnMethodExit.class).onThrowable());

    Object staleChannel = new Object();
    SSLStorage.nettyConnection.set(staleChannel);
    SSLStorage.beginNettyConnectionScope();
    assertNull(SSLStorage.nettyConnection.get());
    exit.invoke(null, new IllegalStateException("TLS operation failed"));
    assertNull(SSLStorage.nettyConnection.get());

    Object nextChannel = new Object();
    SSLStorage.beginNettyConnectionScope();
    SSLStorage.nettyConnection.set(nextChannel);
    assertSame(nextChannel, SSLStorage.nettyConnection.get());
    exit.invoke(null, (Object) null);
    assertNull(SSLStorage.nettyConnection.get());
  }

  @Test
  void nestedExtractionFailureCannotObserveOrRemoveTheOuterConnection() {
    try {
      SSLStorage.bootNettyConnectionField = SSLStorage.class.getField("nettyConnection");
      SSLStorage.bootDebugOn = SSLStorage.class.getField("debugOn");
      SSLStorage.bootExtractMethod =
          NettySSLHandlerInstTest.class.getDeclaredMethod("failExtraction", Object.class);
    } catch (ReflectiveOperationException failure) {
      throw new AssertionError(failure);
    }

    Object outer = new Object();
    SSLStorage.beginNettyConnectionScope();
    SSLStorage.nettyConnection.set(outer);

    NettySSLHandlerInst.WrapAdvice.wrap(new Object());
    assertNull(SSLStorage.nettyConnection.get());
    NettySSLHandlerInst.WrapAdvice.wrap((Throwable) null);

    assertSame(outer, SSLStorage.nettyConnection.get());
    SSLStorage.endNettyConnectionScope();
    assertNull(SSLStorage.nettyConnection.get());
  }

  public static Object failExtraction(Object ignored) {
    throw new IllegalStateException("no channel context");
  }
}
