// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

'use strict';

const assert = require('assert/strict');
const { fork, spawn, execFileSync } = require('child_process');
const { once } = require('events');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'obi-nodegrpc-'));
console.log(`Evidence directory: ${directory}`);
const children = [];
const observations = [];
const mode = process.env.PROPAGATION || 'headers';
const baseline = process.env.BASELINE === '1';
const binary = path.resolve(process.env.OBI_BINARY || 'bin/obi');
const native = process.env.OBI_NATIVE === '1';
const tls = { TLS_KEY: path.join(directory, 'key.pem'), TLS_CERT: path.join(directory, 'cert.pem') };
const container = `obi-nodegrpc-${process.pid}`;
let obi;
let logs = '';

async function start(role, env = {}) {
  const child = fork(path.join(__dirname, 'service.js'), [role], {
    env: { ...process.env, ...tls, ...env }, silent: true,
  });
  children.push(child);
  child.stderr.pipe(process.stderr);
  const [ready] = await once(child, 'message');
  return { child, port: ready.port };
}

function request(port, id, traceID, query = '') {
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port, path: `/${id}${query}`,
      headers: { traceparent: `00-${traceID}-eeeeeeeeeeeeeeee-01` }, agent: false,
    }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try { assert.equal(res.statusCode, 200, body); resolve(JSON.parse(body)); }
        catch (error) { reject(error); }
      });
    });
    req.on('error', reject);
  });
}

async function main() {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', tls.TLS_KEY, '-out', tls.TLS_CERT], { stdio: 'ignore' });
  const downstream = await start('downstream');
  const proxy = await start('proxy', { DOWNSTREAM_PORT: String(downstream.port) });
  const connections = [];
  proxy.child.on('message', event => { if (event.connections) connections.push(event); });
  const source = await start('source', { PROXY_PORT: String(proxy.port) });
  const environment = [
    `OTEL_EBPF_OPEN_PORT=${source.port}`, 'OTEL_EBPF_TRACE_PRINTER=json',
    `OTEL_EBPF_BPF_CONTEXT_PROPAGATION=${mode}`, 'OTEL_EBPF_NODEJS_MANUAL_SPANS=false',
    'OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS=true', 'OTEL_EBPF_LOG_LEVEL=DEBUG',
    'OTEL_EBPF_BPF_BATCH_TIMEOUT=10ms', 'OTEL_EBPF_DISCOVERY_POLL_INTERVAL=100ms',
  ];
  if (process.env.BPF_DEBUG === '1') environment.push('OTEL_EBPF_BPF_DEBUG=true');
  const command = native ? ['sudo', ['-n', 'env', ...environment, binary]] : ['docker', [
    'run', '--rm', '--name', container, '--privileged', '--pid=host',
    '--network=host', '-v', `${binary}:/obi:ro`, '-v', '/sys:/sys',
    ...environment.flatMap(value => ['-e', value]), 'alpine:3.23', '/obi']];
  obi = spawn(...command, { stdio: ['ignore', 'pipe', 'pipe'], detached: native });
  for (const stream of [obi.stdout, obi.stderr]) stream.on('data', data => {
    logs += data;
    fs.appendFileSync(path.join(directory, 'obi.log'), data);
  });
  const deadline = Date.now() + 300000;
  let ready = false;
  while (!ready) {
    if (obi.exitCode !== null) throw new Error(`OBI exited: ${logs}`);
    if (Date.now() > deadline) throw new Error('OBI attachment timed out: ' + logs);
    await new Promise(resolve => setTimeout(resolve, 250));
    // Discovery is port driven and needs traffic before the first attach.
    const health = await request(source.port, 'health', '1'.repeat(32));
    ready = health.injected && logs.includes('"kind":"SPAN_KIND_SERVER"');
  }
  await new Promise(resolve => setTimeout(resolve, 5000));
  for (let round = 0; round < 3; round++) {
    const results = await Promise.all([0, 1, 2].map(index => {
      const traceID = (round * 3 + index + 16).toString(16).padStart(32, '0');
      return request(source.port, `rpc-${round}-${index}`, traceID,
        `?delay=${80 - index * 20}&followup=1`).then(result => ({ traceID, result }));
    }));
    observations.push(...results);
  }
  observations.push({ traceID: 'a'.repeat(32), result: await request(source.port, 'owned', 'a'.repeat(32), '?owned=1&followup=1') });
  const pending = once(source.child, 'message');
  source.child.send('background');
  const [background] = await pending;
  const readSpans = () => logs.split('\n').flatMap(line => {
    try { const value = JSON.parse(line); return Array.isArray(value) ? value : []; }
    catch (_) { return []; }
  });
  const expectedClients = baseline || mode === 'disabled' ? [] : [
    ...observations.flatMap(({ result }) => result.id === 'owned'
      ? [result.followup] : [result, result.followup]), background,
  ].flatMap(rpc => rpc.traceparents.map(value => value.split('-')[2]));
  const spanDeadline = Date.now() + 30000;
  let spans;
  do {
    spans = readSpans();
    const serversReady = observations.every(({ traceID }) => spans.some(span =>
      span.traceID === traceID && span.kind === 'SPAN_KIND_SERVER' && span.type === 'HTTP'));
    const clientsReady = expectedClients.every(spanID => spans.some(span =>
      span.spanID === spanID && span.kind === 'SPAN_KIND_CLIENT'));
    if (serversReady && clientsReady) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  } while (Date.now() < spanDeadline);
  assert.ok(spans.length > 0, 'OBI must produce source spans');
  const evidence = { mode, baseline, versions: {
    node: process.version, openssl: process.versions.openssl, uv: process.versions.uv,
    grpc: require('@grpc/grpc-js/package.json').version,
    otel: require('@opentelemetry/sdk-trace-node/package.json').version,
    grpcInstrumentation: require('@opentelemetry/instrumentation-grpc/package.json').version,
  }, connections, observations, background, spans };
  fs.writeFileSync(path.join(directory, 'evidence.json'), JSON.stringify(evidence, null, 2));
  console.log(`Evidence: ${directory}`);
  assert.equal(Math.max(...connections.map(event => event.connections)), 1, 'one TLS session');
  for (const { traceID, result } of observations) {
    const sourceServers = spans.filter(span => span.traceID === traceID &&
      span.kind === 'SPAN_KIND_SERVER' && span.type === 'HTTP');
    assert.equal(sourceServers.length, 1, `source server span missing for ${result.id}`);
    assert.equal(sourceServers[0].parentSpanID, 'eeeeeeeeeeeeeeee');
    assert.deepEqual(result.original, [], 'shared application metadata was mutated');
    assert.equal(result.ownedOriginal.length, 1);
    assert.deepEqual(result.metadata, ['preserved']);
    if (result.id === 'owned') {
      assert.deepEqual(result.traceparents, result.ownedOriginal);
      const [, ownedTraceID, ownedParentID] = result.ownedOriginal[0].split('-');
      assert.equal(result.span.traceId, ownedTraceID);
      assert.equal(result.parent.spanId, ownedParentID);
    }
    const generated = result.id === 'owned' ? [result.followup] : [result, result.followup];
    for (const rpc of generated) {
      if (baseline || mode === 'disabled') {
        assert.deepEqual(rpc.traceparents, []);
        assert.equal(rpc.parent, undefined);
        assert.notEqual(rpc.span.traceId, traceID);
        continue;
      }
      assert.equal(rpc.traceparents.length, 1, rpc.id);
      const [, receivedTraceID, clientID] = rpc.traceparents[0].split('-');
      assert.equal(receivedTraceID, traceID, rpc.id);
      assert.equal(rpc.span.traceId, traceID);
      assert.equal(rpc.parent.spanId, clientID);
      const clients = spans.filter(span => span.traceID === traceID && span.spanID === clientID);
      assert.equal(clients.length, 1, `missing or duplicated OBI client span ${clientID}`);
      const client = clients[0];
      assert.equal(client.kind, 'SPAN_KIND_CLIENT');
      const server = spans.find(span => span.traceID === traceID && span.spanID === client.parentSpanID);
      assert.ok(server, `missing source server parent for ${rpc.id}`);
      assert.equal(server.parentSpanID, 'eeeeeeeeeeeeeeee');
    }
  }
  assert.ok(observations.some(({ result }) => result.maxActive >= 3), 'overlapping RPCs');
  if (baseline || mode === 'disabled') {
    assert.deepEqual(background.traceparents, []);
    assert.equal(background.parent, undefined);
  } else {
    assert.equal(background.traceparents.length, 1);
    const [, traceID, spanID] = background.traceparents[0].split('-');
    assert.ok(observations.every(observation => observation.traceID !== traceID), 'background inherited a request');
    const client = spans.find(span => span.traceID === traceID && span.spanID === spanID);
    assert.ok(client, 'background client span missing');
    assert.equal(client.parentSpanID, '0000000000000000');
    assert.equal(background.parent.spanId, spanID);
  }
  console.log(JSON.stringify({ passed: true, mode, baseline, versions: evidence.versions,
    rpcs: connections.length, spans: spans.length }));
}

main().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => {
  fs.writeFileSync(path.join(directory, 'obi.log'), logs);
  for (const child of children) child.kill();
  if (obi) {
    if (native) spawn('sudo', ['-n', 'kill', '-TERM', '--', String(-obi.pid)], { stdio: 'ignore' });
    else spawn('docker', ['stop', '-t', '2', container], { stdio: 'ignore' }).on('close', () => obi.kill());
  }
});
