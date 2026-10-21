/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;
import reactor.netty.resources.LoopResources;

public class ReactorClient {
  public static void main(String[] args) throws Exception {
    AtomicInteger active = new AtomicInteger();
    SslContext sslContext =
        SslContextBuilder.forClient()
            .sslProvider(SslProvider.JDK)
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build();
    HttpClient client =
        HttpClient.create(ConnectionProvider.builder("requests").maxConnections(2).build())
            .runOn(LoopResources.create("reactor-test", 1, true))
            .protocol(HttpProtocol.HTTP11)
            .secure(reactor.netty.tcp.SslProvider.builder().sslContext(sslContext).build());
    int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
    String url = System.getenv().getOrDefault("PROXY_URL", "https://proxy:8443") + "/outbound";
    Mono<String> shared = request(client, url, active);
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.setExecutor(Executors.newFixedThreadPool(8));
    server.createContext("/health", exchange -> respond(exchange, 200, "ready"));
    server.createContext(
        "/call/",
        exchange -> {
          String supplied = exchange.getRequestHeaders().getFirst("X-Supplied-Traceparent");
          Mono<String> response =
              supplied == null
                  ? shared
                  : request(client.headers(h -> h.set("TraceParent", supplied)), url, active);
          if (exchange.getRequestHeaders().containsKey("X-Handoff")) {
            response = response.subscribeOn(Schedulers.boundedElastic());
          }
          try {
            respond(exchange, 200, response.block());
          } catch (RuntimeException error) {
            respond(exchange, 500, error.toString());
          }
        });
    server.start();
  }

  private static Mono<String> request(HttpClient client, String url, AtomicInteger active) {
    return client
        .doOnRequest(
            (req, connection) -> req.requestHeaders().set("X-Active-Subscriptions", active.get()))
        .get()
        .uri(url)
        .responseSingle((res, body) -> body.asString())
        .timeout(Duration.ofSeconds(15))
        .doOnSubscribe(subscription -> active.incrementAndGet())
        .doFinally(signal -> active.decrementAndGet());
  }

  private static void respond(HttpExchange exchange, int status, String body) {
    try {
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(status, bytes.length);
      exchange.getResponseBody().write(bytes);
      exchange.close();
    } catch (IOException error) {
      throw new IllegalStateException(error);
    }
  }
}
