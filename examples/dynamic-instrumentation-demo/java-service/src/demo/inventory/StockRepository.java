/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package demo.inventory;

final class StockRepository {
  int availableUnits(String sku, int catalogAvailable) {
    return Math.min(catalogAvailable, Math.max(1, 24 - sku.length()));
  }
}
