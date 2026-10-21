'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { fork } = require('node:child_process');
const path = require('node:path');
const http = require('node:http');

async function start(t, file, env = {}) {
  const child = fork(path.join(__dirname, file), [], {
    cwd: __dirname,
    env: { ...process.env, PORT: '0', ...env },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  let errors = '';
  child.stderr.on('data', (data) => { errors += data; });
  t.after(() => child.kill());
  return new Promise((resolve, reject) => {
    child.once('message', ({ port }) => resolve(port));
    child.once('error', reject);
    child.once('exit', (code) => reject(new Error(`${file} exited ${code}: ${errors}`)));
  });
}

function call(port, id, mode, existing = '') {
  const body = Buffer.from(`body-\u0000-π-${id}`);
  return new Promise((resolve, reject) => {
    const query = new URLSearchParams({ id: String(id), headers: mode, existing, stream: '1' });
    const req = http.request(`http://127.0.0.1:${port}/request?${query}`, {
      method: 'POST', headers: { traceparent: `00-${String(id).padStart(32, '0')}-0123456789abcdef-01` },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        try {
          const data = Buffer.concat(chunks).toString();
          assert.equal(res.statusCode, 200, data);
          const result = JSON.parse(data);
          assert.equal(result.body, body.toString('base64'));
          assert.equal(result.id, String(id));
          assert.equal(result.protocol, '1.1');
          assert.equal(result.preserved, 'yes');
          assert.equal(result.dispatcherUnchanged, true);
          resolve(result);
        } catch (err) { reject(err); }
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

test('fixture preserves pooled HTTPS requests and raw application traceparents without OBI', { timeout: 60000 }, async (t) => {
  const downstream = await start(t, 'downstream.js');
  const proxy = await start(t, 'proxy.js', {
    DOWNSTREAM_URL: `http://127.0.0.1:${downstream}/echo`,
    TLS_KEY: path.join(__dirname, '../nodejsserver/key.pem'),
    TLS_CERT: path.join(__dirname, '../nodejsserver/cert.pem'),
  });
  const source = await start(t, 'source.js', {
    PROXY_URL: `https://127.0.0.1:${proxy}`,
    NODE_TLS_REJECT_UNAUTHORIZED: '0',
  });
  const connections = new Set();
  let id = 0;
  for (let wave = 0; wave < 3; wave++) {
    const results = await Promise.all(['object', 'flat', 'iterable', 'headers'].map((mode) => call(source, ++id, mode)));
    for (const result of results) {
      assert.deepEqual(result.traceparents, []);
      connections.add(result.connection);
    }
  }
  assert.ok(connections.size < id, 'normal Agent reused a TLS connection');
  const existing = '00-abcdefabcdefabcdefabcdefabcdefab-1234567890abcdef-01';
  for (const mode of ['object', 'flat', 'iterable', 'headers']) {
    const result = await call(source, ++id, mode, existing);
    assert.deepEqual(result.traceparents, [existing]);
    assert.equal(result.downstreamTraceID, existing.split('-')[1]);
    assert.equal(result.downstreamParentSpanID, existing.split('-')[2]);
  }
});

for (const scenario of ['enabled', 'reinjected', 'disabled', 'missing', 'throw']) {
  test(`OBI Undici carrier: ${scenario}`, { timeout: 60000 }, async (t) => {
    const downstream = await start(t, 'downstream.js');
    const proxy = await start(t, 'proxy.js', {
      DOWNSTREAM_URL: `http://127.0.0.1:${downstream}/echo`,
      TLS_KEY: path.join(__dirname, '../nodejsserver/key.pem'),
      TLS_CERT: path.join(__dirname, '../nodejsserver/cert.pem'),
    });
    const source = await start(t, 'source.js', {
      PROXY_URL: `https://127.0.0.1:${proxy}`,
      NODE_TLS_REJECT_UNAUTHORIZED: '0',
      NODE_OPTIONS: `--require=${path.join(__dirname, 'agent-preload.js')}`,
      OBI_TEST_REINJECT: scenario === 'reinjected' ? '1' : '',
      OBI_TEST_DISABLE: scenario === 'disabled' ? '1' : '',
      OBI_TEST_REPLY: scenario,
    });
    const enabled = scenario === 'enabled' || scenario === 'reinjected';
    const connections = new Set();
    let id = 0;
    for (let wave = 0; wave < 3; wave++) {
      const results = await Promise.all(['object', 'flat', 'iterable', 'headers'].map((mode) => call(source, ++id, mode)));
      for (const result of results) {
        connections.add(result.connection);
        if (enabled) {
          assert.equal(result.traceparents.length, 1);
          assert.match(result.traceparents[0], /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
          assert.equal(result.traceparents[0].split('-')[1], result.id.padStart(32, '0'));
          assert.equal(result.downstreamTraceID, result.id.padStart(32, '0'));
          assert.equal(result.downstreamParentSpanID, result.traceparents[0].split('-')[2]);
        } else {
          assert.deepEqual(result.traceparents, []);
        }
      }
    }
    assert.ok(connections.size < id, 'normal pooled dispatcher reused connections');
    const existing = '00-abcdefabcdefabcdefabcdefabcdefab-1234567890abcdef-01';
    for (const mode of ['object', 'flat', 'iterable', 'headers']) {
      assert.deepEqual((await call(source, ++id, mode, existing)).traceparents, [existing]);
    }
  });
}
