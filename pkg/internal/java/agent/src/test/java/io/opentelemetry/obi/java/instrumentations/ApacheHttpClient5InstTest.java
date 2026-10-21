/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.data.ApacheHttpClient5Context;
import java.lang.reflect.Proxy;
import java.net.Socket;
import javax.net.ssl.SSLSocketFactory;
import org.apache.hc.client5.http.io.ManagedHttpClientConnection;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.impl.io.HttpRequestExecutor;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.jupiter.api.Test;

class ApacheHttpClient5InstTest {
  private ManagedHttpClientConnection connection(Socket socket) {
    return (ManagedHttpClientConnection)
        Proxy.newProxyInstance(
            getClass().getClassLoader(),
            new Class<?>[] {ManagedHttpClientConnection.class},
            (proxy, method, args) -> {
              if (method.getName().equals("getSocket")) return socket;
              throw new AssertionError(method);
            });
  }

  @Test
  void limitsMatcherToClassicExecutor() throws Exception {
    assertTrue(ApacheHttpClient5Inst.matches(HttpRequestExecutor.class));
    assertFalse(
        ApacheHttpClient5Inst.matches(
            Class.forName("org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient")));
  }

  @Test
  void preservesApplicationHeaderWithoutCallingNativeCode() throws Exception {
    BasicClassicHttpRequest request = new BasicClassicHttpRequest("POST", "/");
    BasicHeader supplied =
        new BasicHeader("TraceParent", "00-11111111111111111111111111111111-2222222222222222-01");
    request.addHeader(supplied);
    try (Socket socket = SSLSocketFactory.getDefault().createSocket()) {
      assertNull(ApacheHttpClient5Context.inject(request, connection(socket)));
    }
    assertSame(supplied, request.getFirstHeader("traceparent"));
    assertEquals(1, request.getHeaders("traceparent").length);
  }

  @Test
  void skipsPlaintextAndOtherProtocolVersions() throws Exception {
    BasicClassicHttpRequest request = new BasicClassicHttpRequest("POST", "/");
    try (Socket socket = new Socket()) {
      assertNull(ApacheHttpClient5Context.inject(request, connection(socket)));
    }
    request.setVersion(HttpVersion.HTTP_2);
    try (Socket socket = SSLSocketFactory.getDefault().createSocket()) {
      assertNull(ApacheHttpClient5Context.inject(request, connection(socket)));
    }
    assertEquals(0, request.getHeaders().length);
  }

  @Test
  void removesOnlyTheInjectedHeader() throws Exception {
    BasicClassicHttpRequest request = new BasicClassicHttpRequest("POST", "/");
    BasicHeader injected = new BasicHeader("traceparent", "injected");
    BasicHeader application = new BasicHeader("TraceParent", "application");
    request.addHeader(injected);
    request.addHeader(application);
    ApacheHttpClient5Context.remove(request, injected);
    assertArrayEquals(new Object[] {application}, request.getHeaders());
    ApacheHttpClient5Context.remove(request, null);
    assertSame(application, request.getFirstHeader("traceparent"));
  }
}
