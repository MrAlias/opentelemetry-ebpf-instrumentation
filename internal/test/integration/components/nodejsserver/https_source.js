// OBI is the only instrumentation in this service.
'use strict';

const http = require('node:http');
const https = require('node:https');
const { AsyncResource } = require('node:async_hooks');

const agent = new https.Agent({ keepAlive: true, maxSockets: 1, rejectUnauthorized: false });
https.globalAgent = agent;
const overlapAgent = new https.Agent({ keepAlive: true, maxSockets: 2 });
const supplied = '00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01';
const background = new AsyncResource('https-test-background');
const queued = [];

module.exports = http.createServer(async (req, res) => {
  if (req.url === '/smoke') return res.end(process.version);
  const url = new URL(req.url, 'http://source');
  const mode = url.searchParams.get('mode') || 'options';
  const id = url.pathname.slice('/call/'.length);
  // Both incoming requests remain live across timers and promise continuations.
  await new Promise(resolve => setTimeout(resolve, 30));
  await Promise.resolve();
  if (mode === 'queued') {
    // Both handlers stay live before sharing a single outgoing TLS socket.
    await new Promise(resume => {
      queued.push(resume);
      if (queued.length === 2) queued.splice(0).forEach(resume => resume());
    });
  }
  const options = {
    hostname: process.env.PROXY_HOST || 'proxy',
    port: Number(process.env.PROXY_PORT || 8443),
    path: '/rolldice?id=' + id,
    method: 'POST',
    agent: mode === 'overlap' ? overlapAgent : agent,
    rejectUnauthorized: false,
    headers: { 'x-request-id': id, 'x-unrelated': 'preserved', 'content-type': 'text/plain' },
  };
  if (mode === 'owned') options.headers.TrAcEpArEnT = supplied;
  if (mode === 'expect') options.headers.Expect = '100-continue';
  if (mode === 'invalid-owned') options.headers.TRACEPARENT = 'application-owned-invalid-value';
  if (mode === 'raw') options.headers = ['Host', 'proxy', 'X-Unrelated', 'preserved', 'X-Request-ID', id];
  if (mode === 'raw-owned') options.headers = ['Host', 'proxy', 'X-Unrelated', 'preserved', 'X-Request-ID', id, 'TrAcEpArEnT', supplied];
  if (mode === 'array-value') options.headers = ['Host', 'proxy', 'X-Unrelated', 'preserved', 'X-Request-ID', id, 'X-Values', ['traceparent', 'untouched']];
  const target = new URL(`https://${options.hostname}:${options.port}${options.path}`);
  const onResponse = upstream => {
    res.writeHead(upstream.statusCode, { 'content-type': 'application/json' });
    upstream.pipe(res);
  };
  const send = () => {
    let out;
    if (mode === 'string') out = https.request(target.href, options, onResponse);
    else if (mode === 'url') out = https.request(target, options, onResponse);
    else if (mode === 'url-only') {
      // The URL-only overload uses a response event instead of a callback.
      target.searchParams.set('get', '1');
      out = https.request(target);
      out.on('response', onResponse);
    } else out = https.request(options, onResponse);
    if (mode === 'late-owned') out.setHeader('TRACEPARENT', supplied);
    out.on('error', err => { res.statusCode = 502; res.end(String(err)); });
    if (mode === 'url-only') return out.end();
    out.write('stream-');
    setImmediate(() => out.end(id));
  };
  if (mode === 'background') background.runInAsyncScope(send);
  else send();
}).listen(Number(process.env.SOURCE_PORT || 3030), '0.0.0.0');
