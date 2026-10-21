// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

test('grpc-js unary metadata, stream ownership and callbacks remain request scoped', () => {
  const output = execFileSync(process.execPath, [path.join(__dirname, 'scenario_grpc.js')],
    { encoding: 'utf8', timeout: 30000 });
  assert.deepEqual(JSON.parse(output), { begins: 20, commits: 20 });
});

for (const loader of ['commonjs', 'esm']) {
  test(`grpc-js loaded through ${loader} after injection propagates unary metadata`, () => {
    execFileSync(process.execPath, [path.join(__dirname, 'scenario_grpc_load.js'), loader],
      { encoding: 'utf8', timeout: 30000 });
  });
}
