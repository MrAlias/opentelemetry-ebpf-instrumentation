/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.Executors;
import javax.net.ssl.*;
import okhttp3.*;

public class Source {
  public static void main(String[] args) throws Exception {
    X509TrustManager trust =
        new X509TrustManager() {
          public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
          }

          public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}

          public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
        };
    SSLContext tls = SSLContext.getInstance("TLS");
    tls.init(null, new TrustManager[] {trust}, null);
    OkHttpClient client =
        new OkHttpClient.Builder()
            .protocols(Collections.singletonList(Protocol.HTTP_1_1))
            .sslSocketFactory(tls.getSocketFactory(), trust)
            .hostnameVerifier((h, s) -> true)
            .build();
    HttpServer server = HttpServer.create(new InetSocketAddress(18080), 0);
    server.setExecutor(Executors.newFixedThreadPool(16));
    server.createContext(
        "/health",
        x -> {
          x.sendResponseHeaders(200, 0);
          x.close();
        });
    server.createContext(
        "/call",
        x -> {
          try {
            String id = x.getRequestHeaders().getFirst("X-Id");
            Request.Builder b =
                new Request.Builder()
                    .url("https://localhost:18443/echo?id=" + id)
                    .header("X-Unrelated", "keep-me")
                    .post(RequestBody.create(MediaType.get("text/plain"), "body-" + id));
            String supplied = x.getRequestHeaders().getFirst("X-Supplied-Traceparent");
            if (supplied != null) b.header("TraceParent", supplied);
            Object tag = new Object();
            Request request = b.tag(tag).build();
            RequestBody originalBody = request.body();
            try (Response response = client.newCall(request).execute()) {
              if (!request
                  .headers("traceparent")
                  .equals(
                      supplied == null
                          ? Collections.emptyList()
                          : Collections.singletonList(supplied)))
                throw new AssertionError("request mutated");
              if (request.body() != originalBody
                  || request.tag() != tag
                  || !"POST".equals(request.method())) throw new AssertionError("request changed");
              if (!"keep-me".equals(request.header("X-Unrelated")))
                throw new AssertionError("header mutated");
              byte[] bytes = response.body().bytes();
              x.sendResponseHeaders(response.code(), bytes.length);
              x.getResponseBody().write(bytes);
            }
          } catch (Throwable t) {
            t.printStackTrace();
            byte[] bytes = t.toString().getBytes(StandardCharsets.UTF_8);
            x.sendResponseHeaders(500, bytes.length);
            x.getResponseBody().write(bytes);
          } finally {
            x.close();
          }
        });
    server.start();
  }
}
