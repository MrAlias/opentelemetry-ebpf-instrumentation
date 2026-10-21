'use strict';

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');

let connection = 0;
let active = 0;
let maxActive = 0;
const connections = new WeakMap();
const server = https.createServer({
  key: fs.readFileSync(__dirname + '/key.pem'),
  cert: fs.readFileSync(__dirname + '/cert.pem'),
}, (req, res) => {
  active++;
  maxActive = Math.max(maxActive, active);
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString();
    const forward = () => {
      const forwarded = http.request({
        hostname: process.env.DOWNSTREAM_HOST || 'downstream',
        port: Number(process.env.DOWNSTREAM_PORT || 8080),
        path: req.url,
        method: req.method,
        // This proxy has no OTel SDK and forwards headers exactly as received.
        headers: req.rawHeaders,
      }, downstream => {
        downstream.resume();
        downstream.on('end', () => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({
            rawHeaders: req.rawHeaders,
            body,
            connection: connections.get(req.socket),
            downstreamStatus: downstream.statusCode,
            maxActive,
          }));
          active--;
        });
      });
      forwarded.on('error', err => { res.statusCode = 502; res.end(String(err)); });
      forwarded.end(body);
    };
    if (req.url.includes('overlap-')) setTimeout(forward, 150);
    else forward();
  });
});
server.keepAliveTimeout = 60_000;
server.on('secureConnection', socket => connections.set(socket, ++connection));
server.listen(Number(process.env.PROXY_PORT || 8443), '0.0.0.0');
module.exports = server;
