'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const { once } = require('events');

const contexts = new Map();
const ROOT_TRACE_ID = 'cccccccccccccccccccccccccccccccc';
let nextSpan = 1;
const originalRead = fs.readSync;
// Model only the BPF side channel. Assertions inspect real TLS wire headers;
// the integration suite separately verifies the kernel and exported span ids.
fs.readSync = (fd, buffer, ...rest) => {
  const prefix = '/dev/null/obi-https/';
  if (buffer.toString().startsWith(prefix)) {
    if (process.env.PROPAGATION !== 'unsupported') {
      const requestFd = buffer.toString('ascii', prefix.length, prefix.length + 4);
      const traceID = requestFd === 'none' ? ROOT_TRACE_ID : contexts.get(Number(requestFd));
      if (traceID) buffer.write(`00-${traceID}-${String(nextSpan++).padStart(16, '0')}-01`, prefix.length + 5);
    }
    return 0;
  }
  return originalRead(fd, buffer, ...rest);
};

function inject(enabled) {
  const src = fs.readFileSync(process.env.AGENT_SOURCE || path.join(__dirname, '..', 'fdextractor.js'), 'utf8')
    .replace('= false; /*OBI_TRACES_ENABLED*/', '= true; /*OBI_TRACES_ENABLED*/')
    .replace('= false; /*OBI_HEADERS_ENABLED*/', `= ${enabled}; /*OBI_HEADERS_ENABLED*/`);
  eval(src);
}

if (process.env.PROPAGATION === 'upgrade') {
  const net = require('net');
  // Previous agents saved only the net methods in this persistent store.
  globalThis[Symbol.for('otel-ebpf-instrumentation.fdextractor')] = {
    serverEmit: net.Server.prototype.emit,
    socketConnect: net.Socket.prototype.connect,
    socketWrite: net.Socket.prototype.write,
  };
}
inject(true);
if (process.env.PROPAGATION === 'reinjected') inject(true);
if (process.env.PROPAGATION === '0') inject(false);

const serverEmit = http.Server.prototype.emit;
http.Server.prototype.emit = function (event, ...args) {
  if (event === 'request' && args[0].headers.traceparent) {
    contexts.set(args[0].socket._handle.fd, args[0].headers.traceparent.split('-')[1]);
  }
  return serverEmit.call(this, event, ...args);
};

(async () => {
  const downstream = http.createServer((req, res) => { req.resume(); req.on('end', () => res.end('ok')); });
  downstream.listen(0, '127.0.0.1');
  await once(downstream, 'listening');
  process.env.DOWNSTREAM_HOST = '127.0.0.1';
  process.env.DOWNSTREAM_PORT = String(downstream.address().port);
  process.env.PROXY_PORT = '0';
  const components = path.resolve(__dirname, '../../../../internal/test/integration/components/nodejsserver');
  const proxy = require(path.join(components, 'https_proxy.js'));
  await once(proxy, 'listening');
  process.env.PROXY_PORT = String(proxy.address().port);
  process.env.PROXY_HOST = '127.0.0.1';
  process.env.SOURCE_PORT = '0';
  const source = require(path.join(components, 'https_source.js'));
  await once(source, 'listening');

  async function request(mode, index) {
    const traceID = String(index + 1).padStart(32, '0');
    const observation = await new Promise((resolve, reject) => {
      http.get({
        host: '127.0.0.1', port: source.address().port,
        path: `/call/${mode}?mode=${mode}`, agent: false,
        headers: { traceparent: `00-${traceID}-1234567890abcdef-01` },
      }, res => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(body)); } catch (err) { reject(new Error(body, { cause: err })); }
        });
      }).on('error', reject);
    });
    return { mode, traceID, observation };
  }

  const results = [];
  for (const mode of ['options', 'string', 'url', 'url-only', 'raw', 'array-value', 'expect', 'owned', 'late-owned', 'raw-owned', 'invalid-owned']) {
    results.push(await request(mode, results.length));
  }
  results.push(...await Promise.all([request('overlap', 20), request('overlap', 21)]));
  const queued = await Promise.all([request('queued', 30), request('queued', 31)]);
  if (queued[0].observation.connection !== queued[1].observation.connection) throw new Error('queued calls did not share a TLS socket');
  results.push(...queued);
  const background = await new Promise((resolve, reject) => {
    const out = require('https').request({
      host: '127.0.0.1', port: proxy.address().port, method: 'POST', path: '/rolldice',
      rejectUnauthorized: false, agent: false, headers: { 'x-unrelated': 'preserved' },
    }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve(JSON.parse(body)));
    });
    out.on('error', reject);
    out.end('stream-background');
  });
  results.push({ mode: 'background', traceID: ROOT_TRACE_ID, observation: background });
  process.stdout.write(JSON.stringify(results));
  process.exit(0);
})().catch(err => { console.error(err); process.exit(1); });
