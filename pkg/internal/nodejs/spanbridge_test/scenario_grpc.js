// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

'use strict';

const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const grpc = require('@grpc/grpc-js');

const encode = value => Buffer.from(JSON.stringify(value));
const decode = value => JSON.parse(value.toString());
const definition = { unary: {
  path: '/test.Echo/Unary', requestStream: false, responseStream: false,
  requestSerialize: encode, requestDeserialize: decode,
  responseSerialize: encode, responseDeserialize: decode,
} };
definition.stream = { ...definition.unary, path: '/test.Echo/Stream', responseStream: true };
const contexts = new Map();
const commits = [];
let begins = 0;
const write = fs.writeSync;
fs.writeSync = function (fd, record, ...args) {
  if (!Buffer.isBuffer(record) || record.toString('ascii', 0, 14) !== 'obi-grpc-unary') {
    return write.call(this, fd, record, ...args);
  }
  assert.equal(record.length, 96);
  if (record.readUInt32LE(16) === 1) {
    const incoming = record.readUInt32LE(20);
    const traceID = incoming === 0xffffffff ? crypto.randomBytes(16).toString('hex') : contexts.get(incoming);
    assert.ok(traceID, `request fd ${incoming} was not captured at call time`);
    const span = crypto.randomBytes(8);
    span.copy(record, 32);
    record.write(`00-${traceID}-${span.toString('hex')}-01`, 40);
    record[95] = 1;
    ++begins;
  } else {
    assert.equal(record.readUInt32LE(16), 2);
    assert.ok(record.readUInt16LE(24));
    assert.ok(record.readUInt16LE(26));
    assert.ok(record.readUInt32LE(28) & 1);
    commits.push(record.readUInt32LE(28));
  }
  return record.length;
};

const extractor = fs.readFileSync(path.join(__dirname, '..', 'fdextractor.js'), 'utf8')
  .replace('= false; /*OBI_TRACES_ENABLED*/', '= true; /*OBI_TRACES_ENABLED*/');
const injector = fs.readFileSync(path.join(__dirname, '..', 'grpcinjector.js'), 'utf8');
const inject = enabled => eval(injector.replace('= false; /*OBI_GRPC_ENABLED*/',
  `= ${enabled}; /*OBI_GRPC_ENABLED*/`));
const requestFd = () => global[Symbol.for('otel-ebpf-instrumentation.fdextractor')].requestFd();

async function main() {
  const server = new grpc.Server();
  server.addService(definition, { unary(call, callback) {
    setTimeout(() => callback(null, { traceparents: call.metadata.get('traceparent'),
      application: call.metadata.get('application-key') }), call.request.delay || 1);
  }, stream(call) {
    call.write({ traceparents: call.metadata.get('traceparent') });
    call.end();
  } });
  const port = await new Promise((resolve, reject) => {
    server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(),
      (error, port) => error ? reject(error) : resolve(port));
  });
  const Client = grpc.makeGenericClientConstructor(definition, 'Echo');
  const client = new Client(`127.0.0.1:${port}`, grpc.credentials.createInsecure());
  const metadata = new grpc.Metadata();
  metadata.set('application-key', 'preserved');
  const invoke = (data, meta = metadata) => new Promise((resolve, reject) => {
    client.unary(data, meta, {}, (error, value) => error ? reject(error) : resolve(value));
  });
  // Establish the session before injection, as a runtime inspector attach does.
  assert.deepEqual((await invoke({})).traceparents, []);
  eval(extractor);
  inject(true);
  inject(true);

  const source = http.createServer(async (req, res) => {
    const fd = req.socket._handle.fd;
    const traceID = req.headers['x-trace-id'];
    contexts.set(fd, traceID);
    assert.equal(requestFd(), fd);
    if (req.url === '/stream') {
      const results = [];
      const stream = client.stream({});
      stream.on('data', result => results.push(result));
      stream.on('end', () => res.end(JSON.stringify(results)));
      return;
    }
    const owned = metadata.clone();
    owned.set('traceparent', 'application-owned-invalid-value');
    const first = await invoke({ delay: 30 }, req.url === '/owned' ? owned : metadata);
    assert.equal(requestFd(), fd, 'unary callback restored another incoming request');
    const second = await invoke({});
    assert.equal(requestFd(), fd);
    res.end(JSON.stringify([first, second]));
  });
  await new Promise(resolve => source.listen(0, '127.0.0.1', resolve));
  const call = (traceID, url = '/') => new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port: source.address().port, agent: false,
      path: url, headers: { 'x-trace-id': traceID } }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve(JSON.parse(body)));
    }).on('error', reject);
  });
  for (let round = 0; round < 3; round++) {
    await Promise.all(['a', 'b', 'c'].map(async digit => {
      const traceID = digit.repeat(32);
      for (const result of await call(traceID)) {
        assert.equal(result.traceparents.length, 1);
        assert.equal(result.traceparents[0].split('-')[1], traceID);
        assert.deepEqual(result.application, ['preserved']);
      }
    }));
  }
  assert.equal(begins, 18);
  assert.equal(commits.length, 18, 're-injection must not stack hooks');
  assert.equal(new Set(commits).size, 18);
  assert.deepEqual(metadata.get('traceparent'), []);
  assert.equal(requestFd(), -1);
  const background = await invoke({});
  assert.equal(background.traceparents.length, 1);
  assert.ok(!['a', 'b', 'c'].map(digit => digit.repeat(32)).includes(background.traceparents[0].split('-')[1]), 'background inherited a request');
  const owned = metadata.clone();
  owned.set('traceparent', 'application-owned-invalid-value');
  assert.deepEqual((await invoke({}, owned)).traceparents, ['application-owned-invalid-value']);
  const [ownedResult, followup] = await call('e'.repeat(32), '/owned');
  assert.deepEqual(ownedResult.traceparents, ['application-owned-invalid-value']);
  assert.equal(followup.traceparents[0].split('-')[1], 'e'.repeat(32));
  const streamed = await call('f'.repeat(32), '/stream');
  assert.deepEqual(streamed, [{ traceparents: [] }], 'streaming RPC was instrumented');
  inject(false);
  const disabled = await call('d'.repeat(32));
  assert.deepEqual(disabled.map(result => result.traceparents), [[], []]);
  assert.equal(begins, 20, 'disabled instrumentation exchanged context');
  source.close();
  client.close();
  await new Promise(resolve => server.tryShutdown(resolve));
  console.log(JSON.stringify({ begins, commits: commits.length }));
}

main().catch(error => { console.error(error); process.exit(1); });
