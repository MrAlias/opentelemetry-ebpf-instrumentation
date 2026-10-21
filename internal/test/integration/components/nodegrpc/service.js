// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

'use strict';

const http = require('http');
const http2 = require('http2');
const fs = require('fs');
const role = process.argv[2];

if (role === 'downstream') {
  const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
  const { registerInstrumentations } = require('@opentelemetry/instrumentation');
  const { GrpcInstrumentation } = require('@opentelemetry/instrumentation-grpc');
  new NodeTracerProvider().register();
  registerInstrumentations({ instrumentations: [new GrpcInstrumentation()] });
}

const grpc = require('@grpc/grpc-js');
const encode = value => Buffer.from(JSON.stringify(value));
const decode = value => JSON.parse(value.toString());
const service = {
  unary: {
    path: '/test.Echo/Unary', requestStream: false, responseStream: false,
    requestSerialize: encode, requestDeserialize: decode,
    responseSerialize: encode, responseDeserialize: decode,
  },
};

if (role === 'downstream') {
  const { context, trace } = require('@opentelemetry/api');
  let active = 0;
  let maxActive = 0;
  const server = new grpc.Server();
  server.addService(service, {
    unary(call, callback) {
      maxActive = Math.max(maxActive, ++active);
      const current = trace.getSpan(context.active());
      const span = current.spanContext();
      const result = {
        id: call.request.id, traceparents: call.metadata.get('traceparent'),
        metadata: call.metadata.get('application-key'), span, parent: current.parentSpanContext,
        peer: call.getPeer(), maxActive,
      };
      setTimeout(() => { --active; callback(null, result); }, call.request.delay || 10);
    },
  });
  server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (err, port) => {
    if (err) throw err;
    process.send({ port });
  });
} else if (role === 'proxy') {
  const upstream = http2.connect(`http://127.0.0.1:${process.env.DOWNSTREAM_PORT}`);
  const server = http2.createSecureServer({
    key: fs.readFileSync(process.env.TLS_KEY), cert: fs.readFileSync(process.env.TLS_CERT),
  });
  let connections = 0;
  server.on('session', () => ++connections);
  server.on('stream', (stream, headers) => {
    const request = upstream.request(headers);
    request.on('response', response => stream.respond(response, { waitForTrailers: true }));
    let trailers = {};
    request.on('trailers', values => { trailers = values; });
    stream.on('wantTrailers', () => stream.sendTrailers(trailers));
    stream.pipe(request).pipe(stream);
    request.on('error', () => stream.close());
    process.send({ connections, traceparent: headers.traceparent });
  });
  server.listen(0, '127.0.0.1', () => process.send({ port: server.address().port }));
} else if (role === 'source') {
  // The source deliberately loads no OpenTelemetry API, SDK or instrumentation.
  const Client = grpc.makeGenericClientConstructor(service, 'Echo');
  const client = new Client(`${process.env.GRPC_TARGET_HOST || 'localhost'}:${process.env.PROXY_PORT}`,
    grpc.credentials.createSsl(fs.readFileSync(process.env.TLS_CERT)), {
      'grpc.ssl_target_name_override': 'localhost',
      'grpc.default_authority': 'localhost',
    });
  const shared = new grpc.Metadata();
  shared.set('application-key', 'preserved');
  const owned = new grpc.Metadata();
  owned.set('application-key', 'preserved');
  owned.set('traceparent', '00-33333333333333333333333333333333-4444444444444444-01');
  const invoke = (id, metadata, delay) => new Promise((resolve, reject) => {
    client.unary({ id, delay }, metadata, (error, result) => error ? reject(error) : resolve(result));
  });
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/health') {
        res.end(JSON.stringify({ injected: !!global[Symbol.for('otel-ebpf-instrumentation.fdextractor')] }));
        return;
      }
      const id = url.pathname.slice(1);
      const result = await invoke(id, url.searchParams.has('owned') ? owned : shared,
        Number(url.searchParams.get('delay')));
      if (url.searchParams.has('followup')) {
        result.followup = await invoke(id + '-callback', shared, 5);
      }
      result.original = shared.get('traceparent');
      result.ownedOriginal = owned.get('traceparent');
      res.end(JSON.stringify(result));
    } catch (error) {
      res.statusCode = 500;
      res.end(String(error));
    }
  });
  server.listen(0, '127.0.0.1', () => process.send({ port: server.address().port }));
  process.on('message', async message => {
    if (message === 'background') process.send(await invoke('background', shared, 5));
  });
}
