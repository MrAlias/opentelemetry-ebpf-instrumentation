/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package demo.inventory;

final class PricingService {
  int priceCents(String sku, int catalogPriceCents) {
    return catalogPriceCents + sku.length() * 5;
  }
}
