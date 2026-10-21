/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class Source {
  public static void main(String[] args) throws Exception {
    SSLContext tls = SSLContext.getInstance("TLS");
    tls.init(
        null,
        new TrustManager[] {
          new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
              return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
          }
        },
        null);
    HttpClient client =
        HttpClient.newBuilder()
            .sslContext(tls)
            .version(HttpClient.Version.HTTP_2)
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    HttpServer server = HttpServer.create(new InetSocketAddress(28180), 0);
    server.setExecutor(Executors.newFixedThreadPool(16));
    server.createContext(
        "/health",
        exchange -> {
          boolean loaded = System.getProperty("otel.obi.java.agent.version") != null;
          boolean ready = !"false".equals(System.getProperty("otel.obi.java.agent.ready"));
          exchange.sendResponseHeaders(loaded && ready ? 200 : 503, 0);
          exchange.close();
        });
    server.createContext(
        "/call/",
        exchange -> {
          try {
            HttpRequest.Builder request =
                HttpRequest.newBuilder(
                        URI.create(
                            System.getProperty("proxy.url", "https://proxy:8443")
                                + exchange.getRequestURI().getPath()))
                    .timeout(Duration.ofSeconds(30));
            String owned = exchange.getRequestHeaders().getFirst("X-Application-Traceparent");
            if (owned != null) {
              request.header("TraceParent", owned);
            }
            HttpResponse<byte[]> response =
                client.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            exchange
                .getResponseHeaders()
                .set("X-Source-HTTP-Version", response.version().toString());
            exchange
                .getResponseHeaders()
                .set("X-Java-Version", System.getProperty("java.runtime.version"));
            exchange.sendResponseHeaders(response.statusCode(), response.body().length);
            exchange.getResponseBody().write(response.body());
          } catch (Exception error) {
            error.printStackTrace();
            exchange.sendResponseHeaders(502, 0);
          } finally {
            exchange.close();
          }
        });
    server.start();
  }
}
