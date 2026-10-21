/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

public class Main {
  private static final CyclicBarrier concurrentCalls = new CyclicBarrier(4);
  private static final CloseableHttpClient client =
      HttpClients.custom()
          .setMaxConnTotal(8)
          .setMaxConnPerRoute(4)
          .setDefaultRequestConfig(
              RequestConfig.custom()
                  .setConnectTimeout(10000)
                  .setSocketTimeout(10000)
                  .setConnectionRequestTimeout(10000)
                  .build())
          .build();

  public static void main(String[] args) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress(24180), 0);
    server.setExecutor(Executors.newFixedThreadPool(8));
    server.createContext(
        "/health",
        exchange -> reply(exchange, 200, System.getProperty("otel.obi.java.agent.version", "")));
    server.createContext("/call/", Main::call);
    server.start();
  }

  private static void call(HttpExchange exchange) {
    try {
      String path = exchange.getRequestURI().getPath().substring("/call".length());
      HttpPost request = new HttpPost("https://proxy:8443" + path);
      request.setEntity(new ByteArrayEntity(readAll(exchange.getRequestBody())));
      request.setHeader("X-Unrelated", "preserved");
      request.setHeader("tracestate", "vendor=value");
      String owned = exchange.getRequestHeaders().getFirst("X-Application-Traceparent");
      if (owned != null) {
        request.setHeader("TrAcEpArEnT", owned);
      }
      if (path.contains("-concurrent-")) {
        concurrentCalls.await(10, TimeUnit.SECONDS);
      }
      try (CloseableHttpResponse response = client.execute(request)) {
        reply(exchange, response.getStatusLine().getStatusCode(), EntityUtils.toString(response.getEntity()));
      }
    } catch (Exception error) {
      try {
        reply(exchange, 500, error.toString());
      } catch (Exception ignored) {
        exchange.close();
      }
    }
  }

  private static byte[] readAll(InputStream input) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[4096];
    int length;
    while ((length = input.read(buffer)) != -1) {
      output.write(buffer, 0, length);
    }
    return output.toByteArray();
  }

  private static void reply(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length);
    exchange.getResponseBody().write(bytes);
    exchange.close();
  }
}
