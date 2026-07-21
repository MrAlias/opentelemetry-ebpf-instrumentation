/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import io.opentelemetry.obi.java.instrumentations.data.BytesWithLen;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import net.bytebuddy.asm.Advice;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SSLEngineWrapCleanupTest {
  @AfterEach
  void cleanup() {
    SSLStorage.unencrypted.remove();
  }

  @Test
  void thrownSingleAndArrayWrapsClearPlaintextBeforeWorkerReuse() throws Exception {
    assertThrowableCleanup(
        SSLEngineInst.WrapAdvice.class,
        SSLEngine.class,
        ByteBuffer.class,
        ByteBuffer.class,
        SSLEngineResult.class,
        Throwable.class);
    assertThrowableCleanup(
        SSLEngineInst.WrapAdviceArray.class,
        SSLEngine.class,
        ByteBuffer[].class,
        ByteBuffer.class,
        SSLEngineResult.class,
        Throwable.class);
  }

  private static void assertThrowableCleanup(Class<?> adviceClass, Class<?>... parameterTypes)
      throws Exception {
    Method exit = adviceClass.getDeclaredMethod("wrap", parameterTypes);
    assertEquals(Throwable.class, exit.getAnnotation(Advice.OnMethodExit.class).onThrowable());

    BytesWithLen stale = new BytesWithLen(new byte[] {1, 2, 3}, 3);
    SSLStorage.unencrypted.set(stale);
    exit.invoke(null, null, null, null, null, new IllegalStateException("wrap failed"));
    assertNull(SSLStorage.unencrypted.get());

    BytesWithLen next = new BytesWithLen(new byte[] {4}, 1);
    SSLStorage.unencrypted.set(next);
    assertSame(next, SSLStorage.unencrypted.get());
    SSLStorage.unencrypted.remove();
  }
}
