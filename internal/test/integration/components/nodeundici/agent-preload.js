'use strict';

// Behavioral tests emulate the BPF reply; the Go integration test uses real BPF.
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const contexts = new Map();
const readSync = fs.readSync;
fs.readSync = function (fd, buffer, ...args) {
  const prefix = '/dev/null/obi-undici/';
  if (Buffer.isBuffer(buffer) && buffer.subarray(0, prefix.length).toString() === prefix) {
    if (process.env.OBI_TEST_REPLY === 'throw') throw new Error('query failed');
    if (process.env.OBI_TEST_REPLY === 'missing') return 0;
    const incomingFd = Number(buffer.subarray(prefix.length, prefix.length + 4).toString());
    const context = contexts.get(incomingFd);
    if (context) {
      buffer.write(`00-${context.split('-')[1]}-${randomBytes(8).toString('hex')}-01`, buffer.length - 55);
    }
    return 0;
  }
  return readSync.call(this, fd, buffer, ...args);
};
const src = fs.readFileSync(path.resolve(__dirname, '../../../../../pkg/internal/nodejs/fdextractor.js'), 'utf8')
  .replace('= false; /*OBI_TRACES_ENABLED*/', '= true; /*OBI_TRACES_ENABLED*/')
  .replace('= false; /*OBI_HEADER_PROPAGATION_ENABLED*/', '= true; /*OBI_HEADER_PROPAGATION_ENABLED*/');
const inject = (code) => {
  const previous = Object.getOwnPropertyDescriptor(global, 'require');
  Object.defineProperty(global, 'require', { configurable: true, value: (name) => require(name) });
  try { require('vm').runInThisContext(code); }
  finally {
    if (previous) Object.defineProperty(global, 'require', previous);
    else delete global.require;
  }
};
inject(src);
if (process.env.OBI_TEST_REINJECT) inject(src);
if (process.env.OBI_TEST_DISABLE) {
  inject(src.replace('= true; /*OBI_HEADER_PROPAGATION_ENABLED*/', '= false; /*OBI_HEADER_PROPAGATION_ENABLED*/'));
}
const emit = http.Server.prototype.emit;
http.Server.prototype.emit = function (event, ...args) {
  if (event === 'request') {
    contexts.set(args[0].socket._handle.fd, args[0].headers.traceparent);
  }
  return emit.call(this, event, ...args);
};
