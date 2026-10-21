'use strict';

const https = require('https');
const http = require('http');
const fs = require('fs');
const sockets = new WeakMap();
let nextSocket = 0;

const server = https.createServer({ key: fs.readFileSync(process.env.TLS_KEY || 'key.pem'), cert: fs.readFileSync(process.env.TLS_CERT || 'cert.pem') }, (req, res) => {
  if (!sockets.has(req.socket)) sockets.set(req.socket, ++nextSocket);
  const traceparents = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === 'traceparent') traceparents.push(req.rawHeaders[i + 1]);
  }
  const observation = {
    id: req.headers['x-test-id'], traceparents,
    connection: sockets.get(req.socket), protocol: req.httpVersion,
    preserved: req.headers['x-preserved'],
  };
  const headers = { ...req.headers };
  delete headers.host;
  const downstream = http.request(process.env.DOWNSTREAM_URL || 'http://downstream:8081/echo', {
    method: req.method, headers,
  }, (response) => {
    const chunks = [];
    response.on('data', (chunk) => chunks.push(chunk));
    response.on('end', () => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ...observation, ...JSON.parse(Buffer.concat(chunks)) }));
    });
  });
  downstream.on('error', (err) => { res.statusCode = 502; res.end(err.message); });
  req.pipe(downstream);
}).listen(Number(process.env.PORT || 8443), '0.0.0.0');

server.on('listening', () => {
  if (process.send) process.send({ port: server.address().port });
});
