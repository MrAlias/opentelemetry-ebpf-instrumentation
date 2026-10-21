/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class JdkHttpClientPropagationTest {
  @Test
  void retainsEqualRequestsByIdentityAndCleansUpNestedScopes() {
    Object first = new String("same request");
    Object second = new String("same request");
    JdkHttpClientPropagation.Scope outer = JdkHttpClientPropagation.enter();
    try {
      JdkHttpClientPropagation.remember(first, new byte[JdkHttpClientPropagation.CONTEXT_SIZE]);
      assertTrue(JdkHttpClientPropagation.tracked(first));
      assertFalse(JdkHttpClientPropagation.tracked(second));
      JdkHttpClientPropagation.Scope inner = JdkHttpClientPropagation.enter();
      try {
        JdkHttpClientPropagation.remember(second, new byte[JdkHttpClientPropagation.CONTEXT_SIZE]);
        assertTrue(JdkHttpClientPropagation.tracked(first));
        assertTrue(JdkHttpClientPropagation.tracked(second));
      } finally {
        JdkHttpClientPropagation.exit(inner);
      }
      assertTrue(JdkHttpClientPropagation.tracked(first));
      assertFalse(JdkHttpClientPropagation.tracked(second));
    } finally {
      JdkHttpClientPropagation.exit(outer);
    }
    assertFalse(JdkHttpClientPropagation.tracked(first));
  }

  @Test
  void ignoresRequestsOutsideSynchronousScope() {
    Object request = new Object();
    JdkHttpClientPropagation.remember(request, new byte[JdkHttpClientPropagation.CONTEXT_SIZE]);
    assertFalse(JdkHttpClientPropagation.tracked(request));
  }

  @Test
  void formatsTheNativeContextWithW3CFlags() {
    byte[] context = new byte[JdkHttpClientPropagation.CONTEXT_SIZE];
    Arrays.fill(context, 0, 16, (byte) 0xab);
    Arrays.fill(context, 16, 24, (byte) 0xcd);
    context[40] = 1;
    assertEquals(
        "00-abababababababababababababababab-cdcdcdcdcdcdcdcd-01",
        JdkHttpClientPropagation.traceparent(context));
    context[40] = 0;
    assertEquals(
        "00-abababababababababababababababab-cdcdcdcdcdcdcdcd-00",
        JdkHttpClientPropagation.traceparent(context));
  }
}
