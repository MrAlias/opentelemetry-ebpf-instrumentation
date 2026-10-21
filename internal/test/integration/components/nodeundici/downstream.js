'use strict';

const { NodeTracerProvider, SimpleSpanProcessor } = require('@opentelemetry/sdk-trace-node');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');
const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
const { trace, context } = require('@opentelemetry/api');
const { resourceFromAttributes } = require('@opentelemetry/resources');

const provider = new NodeTracerProvider({
  resource: resourceFromAttributes({ 'service.name': process.env.OTEL_SERVICE_NAME || 'undici-downstream' }),
  spanProcessors: [new SimpleSpanProcessor(new OTLPTraceExporter())],
});
provider.register();
new HttpInstrumentation().enable();
const http = require('http');
const server = http.createServer(async (req, res) => {
  const span = trace.getSpan(context.active());
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({
    body: Buffer.concat(chunks).toString('base64'),
    downstreamTraceID: span.spanContext().traceId,
    downstreamSpanID: span.spanContext().spanId,
    downstreamParentSpanID: span.parentSpanContext?.spanId,
  }));
}).listen(Number(process.env.PORT || 8081), '0.0.0.0');

server.on('listening', () => {
  if (process.send) process.send({ port: server.address().port });
});
