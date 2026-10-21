'use strict';

const http = require('http');
const { request, getGlobalDispatcher } = require('undici');
const { Readable } = require('stream');
const dispatcher = getGlobalDispatcher();

const server = http.createServer(async (req, res) => {
  if (req.url === '/smoke') {
    res.end('ready');
    return;
  }
  try {
    const url = new URL(req.url, 'http://source');
    const mode = url.searchParams.get('headers') || 'object';
    const entries = [['x-test-id', url.searchParams.get('id')], ['x-preserved', 'yes']];
    const existing = url.searchParams.get('existing');
    if (existing) entries.push(['TrAcEpArEnT', existing]);
    let headers;
    switch (mode) {
      case 'object': headers = Object.fromEntries(entries); break;
      case 'flat': headers = entries.flat(); break;
      case 'iterable': headers = new Map(entries); break;
      case 'headers': headers = new Headers(entries); break;
      default: throw new Error(`unknown header mode ${mode}`);
    }
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    const outgoing = await request(`${process.env.PROXY_URL || 'https://proxy:8443'}/echo`, {
      method: 'POST',
      headers,
      body: url.searchParams.has('stream') ? Readable.from([body.subarray(0, 3), body.subarray(3)]) : body,
    });
    const result = await outgoing.body.json();
    result.dispatcherUnchanged = dispatcher === getGlobalDispatcher();
    result.versions = { node: process.version, undici: require('undici/package.json').version };
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(result));
  } catch (err) {
    res.statusCode = 500;
    res.end(err.stack);
  }
});
server.listen(Number(process.env.PORT || 8080), '0.0.0.0');

server.on('listening', () => {
  if (process.send) process.send({ port: server.address().port });
});
