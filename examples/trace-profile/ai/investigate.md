# Investigation prompt

Investigate elevated latency for `GET /work` in service `obi-ai-demo` during the supplied incident interval.

Use only MCP telemetry and diagnostic tools. Do not inspect application source, fixture configuration, or expected answers. First inspect agent state and available evidence. Request diagnostic attachment if collection is missing; stop for operator authorization when required.

After attachment, allow discovery and export time, bounded to two minutes of collection retries. Query only the new incident interval, with start at or after the returned collection_start. Use recorded span exemplars to connect profiles to traces, and inspect exact span profiles before attributing CPU consumption to `/work`. Other concurrent requests may exist.

Separate observed facts, supported hypotheses, uncertainty, and next evidence needed. Include clickable profile and trace evidence using returned URLs. For Tempo Explore link generation, use queryType=traceql and the recorded trace ID as query. CPU execution is not wall-clock latency; absent samples do not establish a cause. Application modification and mitigation are outside this experiment.
