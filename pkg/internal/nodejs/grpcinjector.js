// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

(() => {
  const KEY = Symbol.for('otel-ebpf-instrumentation.grpc-unary');
  const ENABLED = false; /*OBI_GRPC_ENABLED*/
  if (global[KEY]) {
    global[KEY].enabled = ENABLED;
    return;
  }
  if (!ENABLED) return;

  const fs = require('fs');
  const http2 = require('http2');
  const Module = require('module');
  const state = global[KEY] = { enabled: ENABLED };
  const pending = new Map();
  const patched = new WeakSet();
  const interceptorsPath = /[\\/]@grpc[\\/]grpc-js[\\/]build[\\/]src[\\/]client-interceptors\.js$/;
  const extractor = () => global[Symbol.for('otel-ebpf-instrumentation.fdextractor')];
  const RECORD_SIZE = 96;
  const OP_OFFSET = 16;
  const FD_OFFSET = 20;
  const SOURCE_PORT_OFFSET = 24;
  const DESTINATION_PORT_OFFSET = 26;
  const STREAM_OFFSET = 28;
  const TP_OFFSET = 40;
  const TP_LENGTH = 55;
  const STATUS_OFFSET = 95;
  let nullFd;

  function exchange(record) {
    if (nullFd === undefined) nullFd = fs.openSync('/dev/null', 'w');
    fs.writeSync(nullFd, record);
  }

  function begin() {
    const agent = extractor();
    const fd = agent && agent.requestFd && agent.requestFd();
    if (!Number.isInteger(fd) || fd < -1) return;
    const record = Buffer.alloc(RECORD_SIZE);
    record.write('obi-grpc-unary');
    record.writeUInt32LE(1, OP_OFFSET);
    record.writeUInt32LE(fd >>> 0, FD_OFFSET);
    exchange(record);
    if (record[STATUS_OFFSET] !== 1) return;
    const traceparent = record.toString('ascii', TP_OFFSET, TP_OFFSET + TP_LENGTH);
    if (!/^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/.test(traceparent)) return;
    return { traceparent, record };
  }

  // Generated clients capture makeUnaryRequest before inspector attachment;
  // the interceptor factory is still resolved for every invocation.
  function wire(module) {
    if (!module || typeof module.getInterceptingCall !== 'function' || patched.has(module)) return;
    patched.add(module);
    const getCall = module.getInterceptingCall;
    module.getInterceptingCall = function (interceptors, method, options, channel) {
      const call = getCall.apply(this, arguments);
      if (method.requestStream || method.responseStream) return call;
      const start = call.start;
      call.start = function (metadata, listener) {
        if (!state.enabled) return start.apply(this, arguments);
        let invocation;
        if (metadata.get('traceparent').length === 0) {
          try { invocation = begin(); } catch (_) {}
        }
        const outgoing = invocation ? metadata.clone() : metadata;
        if (invocation) {
          outgoing.set('traceparent', invocation.traceparent);
          pending.set(invocation.traceparent, invocation.record);
        }
        const agent = extractor();
        const bound = { ...listener };
        for (const event of ['onReceiveMetadata', 'onReceiveMessage', 'onReceiveStatus']) {
          if (typeof listener[event] !== 'function') continue;
          const callback = function (...args) {
            if (invocation && event === 'onReceiveStatus') pending.delete(invocation.traceparent);
            return listener[event].apply(this, args);
          };
          bound[event] = agent.bindRequest ? agent.bindRequest(callback) : callback;
        }
        try {
          return start.call(this, outgoing, bound);
        } catch (error) {
          if (invocation) pending.delete(invocation.traceparent);
          throw error;
        }
      };
      return call;
    };
  }

  function wireLoaded() {
    for (const filename of Object.keys(require.cache || {})) {
      if (interceptorsPath.test(filename)) {
        wire(require.cache[filename].exports);
      }
    }
  }

  // Obtain the shared request prototype without opening a connection, including
  // sessions established before the inspector attached.
  const probe = http2.connect('http://localhost', { createConnection: () => new (require('net').Socket)() });
  probe.on('error', () => {});
  const sessionPrototype = Object.getPrototypeOf(probe);
  probe.destroy();
  const request = sessionPrototype.request;
  sessionPrototype.request = function (headers, ...rest) {
    const session = this;
    const record = headers && pending.get(headers.traceparent);
    const stream = request.call(this, headers, ...rest);
    if (!state.enabled || !record) return stream;
    const commit = () => {
      try {
        const socket = session.socket;
        if (!stream.id || !socket.localPort || !socket.remotePort) return;
        const message = Buffer.from(record);
        message.writeUInt32LE(2, OP_OFFSET);
        message.writeUInt16LE(socket.localPort, SOURCE_PORT_OFFSET);
        message.writeUInt16LE(socket.remotePort, DESTINATION_PORT_OFFSET);
        message.writeUInt32LE(stream.id, STREAM_OFFSET);
        exchange(message);
      } catch (_) {}
    };
    if (stream.id) commit();
    else stream.once('ready', commit);
    return stream;
  };

  wireLoaded();
  const load = Module._load;
  Module._load = function (name) {
    const exported = load.apply(this, arguments);
    try {
      if (name === '@grpc/grpc-js') {
        wireLoaded();
      } else if (/(?:^|[\\/])client-interceptors(?:\.js)?$/.test(name)) {
        const filename = Module._resolveFilename(name, arguments[1], arguments[2]);
        if (interceptorsPath.test(filename)) {
          wire(exported);
        }
      }
    } catch (_) {}
    return exported;
  };
})();
