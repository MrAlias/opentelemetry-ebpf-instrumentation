// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

'use strict';

const http = require('http');
const catalog = require('./catalog.cjs');

exports.health = function health(_request, response) {
  response.writeHead(204).end();
};

exports.availability = function availability(request, response) {
  const url = new URL(request.url, 'http://inventory-node');
  const sku = url.searchParams.get('sku') || 'frog-mug';
  if (!catalog.validateSku(sku)) {
    response.writeHead(400).end('invalid sku');
    return;
  }
  const body = JSON.stringify({
    sku,
    available: catalog.lookupStock(sku),
    price_cents: catalog.calculatePrice(sku),
  });
  response.writeHead(200, { 'content-type': 'application/json' }).end(body);
};

exports.route = function route(request, response) {
  if (request.url === '/healthz') {
    exports.health(request, response);
    return;
  }
  if (request.url.startsWith('/availability')) {
    exports.availability(request, response);
    return;
  }
  response.writeHead(404).end('not found');
};

const port = Number.parseInt(process.env.PORT || '18083', 10);
http.createServer(exports.route).listen(port, () => {
  console.log(`Node inventory fixture listening on ${port}`);
});
