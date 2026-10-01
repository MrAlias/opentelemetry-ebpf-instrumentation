/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package demo.inventory;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class NodeCatalogClient {
  private static final Pattern AVAILABLE = Pattern.compile("\\\"available\\\"\\s*:\\s*(\\d+)");
  private static final Pattern PRICE = Pattern.compile("\\\"price_cents\\\"\\s*:\\s*(\\d+)");

  private final HttpClient client =
      HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
  private final String endpoint =
      System.getenv().getOrDefault(
          "NODE_CATALOG_URL", "http://inventory-node:18083/availability");

  CatalogProduct findProduct(String sku) throws IOException, InterruptedException {
    String encoded = URLEncoder.encode(sku, StandardCharsets.UTF_8);
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(endpoint + "?sku=" + encoded))
            .timeout(Duration.ofSeconds(2))
            .GET()
            .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != 200) {
      throw new IOException("catalog returned HTTP " + response.statusCode());
    }
    return new CatalogProduct(sku, integer(response.body(), AVAILABLE), integer(response.body(), PRICE));
  }

  private static int integer(String body, Pattern pattern) throws IOException {
    Matcher matcher = pattern.matcher(body);
    if (!matcher.find()) {
      throw new IOException("catalog response is missing a required field");
    }
    return Integer.parseInt(matcher.group(1));
  }
}

record CatalogProduct(String sku, int available, int priceCents) {}
