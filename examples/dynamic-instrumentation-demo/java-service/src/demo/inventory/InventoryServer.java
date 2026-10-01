/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package demo.inventory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

public final class InventoryServer {
  private static final CatalogService CATALOG = new CatalogService();

  private InventoryServer() {}

  public static void main(String[] args) throws IOException {
    int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "18082"));
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/healthz", InventoryServer::health);
    server.createContext("/availability", InventoryServer::availability);
    server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    server.start();
    System.out.printf("Java inventory fixture listening on %d%n", port);
  }

  static void health(HttpExchange exchange) throws IOException {
    respond(exchange, 204, "");
  }

  static void availability(HttpExchange exchange) throws IOException {
    String sku = queryValue(exchange.getRequestURI().getRawQuery(), "sku", "frog-plush");
    Product product;
    try {
      product = CATALOG.findProduct(sku);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      respond(exchange, 503, "{\"error\":\"catalog request interrupted\"}");
      return;
    } catch (IOException e) {
      respond(exchange, 502, "{\"error\":\"catalog unavailable\"}");
      return;
    }
    String body = String.format(
        "{\"sku\":\"%s\",\"available\":%d,\"price_cents\":%d}",
        product.sku(), product.available(), product.priceCents());
    respond(exchange, 200, body);
  }

  static String queryValue(String query, String name, String fallback) {
    if (query == null) {
      return fallback;
    }
    for (String part : query.split("&")) {
      String[] pair = part.split("=", 2);
      if (pair.length == 2 && pair[0].equals(name) && !pair[1].isBlank()) {
        return pair[1];
      }
    }
    return fallback;
  }

  static void respond(HttpExchange exchange, int status, String body) throws IOException {
    byte[] payload = body.getBytes(StandardCharsets.UTF_8);
    if (!body.isEmpty()) {
      exchange.getResponseHeaders().set("Content-Type", "application/json");
    }
    exchange.sendResponseHeaders(status, body.isEmpty() ? -1 : payload.length);
    if (!body.isEmpty()) {
      exchange.getResponseBody().write(payload);
    }
    exchange.close();
  }
}
