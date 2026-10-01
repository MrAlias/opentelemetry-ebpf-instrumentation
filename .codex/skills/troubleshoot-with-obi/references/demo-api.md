# Demo API reference

Base URLs:

- OBI: `http://127.0.0.1:8090/obi`
- Tempo: `http://127.0.0.1:8090/tempo`
- Checkout: `http://127.0.0.1:18081`

The service selector is `[{"open_ports":"18080"}]`.

## OBI requests

Health:

```sh
curl --fail --silent --show-error http://127.0.0.1:8090/obi/healthz
```

Discover symbols:

```sh
curl --fail --silent --show-error --get \
  http://127.0.0.1:8090/obi/v1/dynamic-instrumentation/symbols \
  --data-urlencode 'service=[{"open_ports":"18080"}]'
```

List active dynamic probes:

```sh
curl --fail --silent --show-error --get \
  http://127.0.0.1:8090/obi/v1/dynamic-instrumentation/probes \
  --data-urlencode 'service=[{"open_ports":"18080"}]'
```

Create or replace a rule after substituting the rule ID, span name, and exact
symbol. Multiple entries may be placed in `spans`. Keep the port selector so the
rule follows a rebuilt process:

```sh
curl --fail --silent --show-error --request PUT \
  http://127.0.0.1:8090/obi/v1/dynamic-instrumentation/rules/RULE_ID \
  --header 'Content-Type: application/json' \
  --data '{"service":[{"open_ports":"18080"}],"spans":[{"name":"diagnostic.candidate","on":{"function_span":"EXACT_SYMBOL"}}]}'
```

Delete the investigation rule:

```sh
curl --fail --silent --show-error --request DELETE \
  http://127.0.0.1:8090/obi/v1/dynamic-instrumentation/rules/RULE_ID
```

## Traffic and Tempo

Generate a uniquely identifiable coupon request. Create a fresh 32-hex-character
trace ID, substitute it below, and retain it as direct evidence:

```sh
curl --fail --silent --show-error \
  --header 'Content-Type: application/json' \
  --header 'traceparent: 00-TRACE_ID_32_HEX-0123456789abcdef-01' \
  --data '{"cart_id":"codex-UNIQUE","coupon":"FROG20"}' \
  http://127.0.0.1:18081/checkout
```

Search recent service traces with TraceQL:

```sh
curl --fail --silent --show-error --get \
  http://127.0.0.1:8090/tempo/api/search \
  --data-urlencode 'q={ resource.service.name = "coupon-checkout" }' \
  --data-urlencode 'limit=50'
```

Retrieve one complete trace after substituting its ID:

```sh
curl --fail --silent --show-error \
  http://127.0.0.1:8090/tempo/api/v2/traces/TRACE_ID
```

Tempo search is eventually consistent. Retry briefly after generating traffic;
use trace start times or unique captured argument values to separate fresh traces
from baseline traces.

## Focused verification

```sh
(cd examples/dynamic-instrumentation-demo/app && go test ./...)
docker compose --env-file examples/dynamic-instrumentation-demo/.env \
  --file examples/dynamic-instrumentation-demo/compose.yaml build checkout
docker compose --env-file examples/dynamic-instrumentation-demo/.env \
  --file examples/dynamic-instrumentation-demo/compose.yaml up --detach --no-deps checkout
```
