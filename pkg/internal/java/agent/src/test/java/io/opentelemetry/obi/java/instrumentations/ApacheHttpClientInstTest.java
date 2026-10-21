/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.*;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import org.junit.jupiter.api.Test;

class ApacheHttpClientInstTest {
  @Test
  void matchesOnlyTheApacheFourSynchronousClassesAndGeneratesValidAdvice() {
    for (String name :
        new String[] {
          "org.apache.http.impl.client.CloseableHttpClient",
          "org.apache.http.protocol.HttpRequestExecutor"
        }) {
      DynamicType.Builder<?> builder = new ByteBuddy().subclass(Object.class).name(name);
      if (name.endsWith("CloseableHttpClient")) {
        builder =
            builder
                .defineMethod("execute", Object.class, Visibility.PUBLIC)
                .intercept(FixedValue.nullValue());
      } else {
        builder =
            builder
                .defineMethod("doSendRequest", Object.class, Visibility.PROTECTED)
                .withParameters(Object.class, Object.class, Object.class)
                .intercept(FixedValue.nullValue());
      }
      assertTrue(ApacheHttpClientInst.type().matches(builder.toTypeDescription()));
      assertSame(
          builder,
          ApacheHttpClientInst.transformer(false)
              .transform(builder, builder.toTypeDescription(), null, null, null));
      assertTrue(
          ApacheHttpClientInst.transformer(true)
                  .transform(builder, builder.toTypeDescription(), null, null, null)
                  .make()
                  .getBytes()
                  .length
              > 0);
    }
    for (String name :
        new String[] {
          "org.apache.hc.client5.http.impl.classic.CloseableHttpClient",
          "org.apache.http.impl.nio.client.CloseableHttpAsyncClient",
          "java.net.http.HttpClient"
        }) {
      assertFalse(
          ApacheHttpClientInst.type()
              .matches(new ByteBuddy().subclass(Object.class).name(name).toTypeDescription()));
    }
    assertFalse(ApacheHttpClientInst.matches(Object.class));
  }
}
