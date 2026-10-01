// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

'use strict';

exports.validateSku = function validateSku(sku) {
  return typeof sku === 'string' && sku.length > 0;
};

exports.lookupStock = function lookupStock(sku) {
  return Math.max(1, 18 - sku.length);
};

exports.calculatePrice = function calculatePrice(sku) {
  return 1800 + sku.length * 20;
};
