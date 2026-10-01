/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package demo.inventory;

final class CatalogService {
  private final StockRepository stock = new StockRepository();
  private final PricingService pricing = new PricingService();
  private final NodeCatalogClient catalog = new NodeCatalogClient();

  Product findProduct(String sku) throws java.io.IOException, InterruptedException {
    CatalogProduct product = catalog.findProduct(sku);
    return new Product(
        sku,
        stock.availableUnits(sku, product.available()),
        pricing.priceCents(sku, product.priceCents()));
  }
}

record Product(String sku, int available, int priceCents) {}
