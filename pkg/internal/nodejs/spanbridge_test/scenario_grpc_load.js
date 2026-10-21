// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const traceparent = `00-${'a'.repeat(32)}-${'b'.repeat(16)}-01`;
let begins = 0;
let commits = 0;
const write = fs.writeSync;
fs.writeSync = function (fd, record, ...args) {
  if (!Buffer.isBuffer(record) || record.toString('ascii', 0, 14) !== 'obi-grpc-unary') {
    return write.call(this, fd, record, ...args);
  }
  if (record.readUInt32LE(16) === 1) {
    ++begins;
    record.write(traceparent, 40);
    record[95] = 1;
  } else {
    ++commits;
    assert.ok(record.readUInt32LE(28) & 1);
  }
  return record.length;
};
global[Symbol.for('otel-ebpf-instrumentation.fdextractor')] = {
  requestFd: () => -1,
  bindRequest: callback => callback,
};
eval(fs.readFileSync(path.join(__dirname, '..', 'grpcinjector.js'), 'utf8')
  .replace('= false; /*OBI_GRPC_ENABLED*/', '= true; /*OBI_GRPC_ENABLED*/'));

async function main() {
  const grpc = process.argv[2] === 'esm' ? await import('@grpc/grpc-js') : require('@grpc/grpc-js');
  const definition = { unary: {
    path: '/test.Echo/Unary', requestStream: false, responseStream: false,
    requestSerialize: () => Buffer.alloc(0), requestDeserialize: () => ({}),
    responseSerialize: value => Buffer.from(JSON.stringify(value)),
    responseDeserialize: value => JSON.parse(value.toString()),
  } };
  const server = new grpc.Server();
  server.addService(definition, { unary(call, callback) {
    callback(null, { traceparents: call.metadata.get('traceparent') });
  } });
  const port = await new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0',
    grpc.ServerCredentials.createInsecure(), (error, port) => error ? reject(error) : resolve(port)));
  const Client = grpc.makeGenericClientConstructor(definition, 'Echo');
  const client = new Client(`127.0.0.1:${port}`, grpc.credentials.createInsecure());
  const metadata = new grpc.Metadata();
  try {
    const response = await new Promise((resolve, reject) => client.unary({}, metadata,
      (error, result) => error ? reject(error) : resolve(result)));
    assert.deepEqual(response.traceparents, [traceparent]);
    assert.deepEqual(metadata.get('traceparent'), []);
    assert.equal(begins, 1);
    assert.equal(commits, 1);
  } finally {
    client.close();
    await new Promise(resolve => server.tryShutdown(resolve));
  }
}

main().catch(error => { console.error(error); process.exit(1); });
