/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.data.OkHttpContext;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.junit.jupiter.api.Test;

class OkHttpInstTest {
  private static final String TRACEPARENT =
      "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

  @Test
  void derivesRequestWithoutChangingBodyHeadersOrTag() throws Exception {
    Object tag = new Object();
    RequestBody body = RequestBody.create(MediaType.get("text/plain"), "payload");
    Request original =
        new Request.Builder()
            .url("https://localhost/path?q=value")
            .post(body)
            .tag(tag)
            .addHeader("X-Test", "one")
            .addHeader("X-Test", "two")
            .build();

    Request derived = (Request) OkHttpContext.withTraceparent(original, TRACEPARENT);

    assertNotSame(original, derived);
    assertNull(original.header("traceparent"));
    assertEquals(Collections.singletonList(TRACEPARENT), derived.headers("traceparent"));
    assertEquals(original.headers("X-Test"), derived.headers("X-Test"));
    assertSame(body, derived.body());
    assertSame(tag, derived.tag());
    assertEquals(original.url(), derived.url());
    assertEquals(original.method(), derived.method());
  }

  @Test
  void leavesRequestsOutsideExecuteAlone() throws Exception {
    Request request = new Request.Builder().url("https://localhost/").build();
    assertSame(request, OkHttpContext.inject(new Object(), request));
    boolean previous = OkHttpContext.enter();
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      assertSame(request, executor.submit(() -> OkHttpContext.inject(new Object(), request)).get());
    } finally {
      executor.shutdownNow();
      OkHttpContext.restore(previous);
    }
    assertSame(request, OkHttpContext.inject(new Object(), request));
  }

  @Test
  void targetsRealCallAndHttp1Codec() throws Exception {
    Request request = new Request.Builder().url("https://localhost/").build();
    assertTrue(OkHttpInst.matches(new OkHttpClient().newCall(request).getClass()));
    assertTrue(OkHttpInst.matches(Class.forName("okhttp3.internal.http1.Http1ExchangeCodec")));
    assertFalse(OkHttpInst.matches(Class.forName("okhttp3.internal.http2.Http2ExchangeCodec")));
    assertFalse(
        OkHttpInst.matches(Class.forName("okhttp3.internal.connection.RealCall$AsyncCall")));
  }
}
