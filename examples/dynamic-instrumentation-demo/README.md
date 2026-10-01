# OBI dynamic instrumentation demo

This demo builds on the dynamic instrumentation API present at commit
`3475b65f8943926dc07c14909e139c8dfd3ddc10`. It adds one read-only rule catalog
endpoint so clients can retrieve the ownership and complete definitions OBI
already retains in memory. Nginx serves static files and proxies same-origin
requests directly to OBI and read-only requests to Tempo.

The primary scenario is intentionally deterministic. Most Go checkouts finish
quickly, but requests using `FROG20` take about 900 ms longer. Every checkout is
a distributed request: the Go service calls Java inventory, which calls the
Node.js catalog. OBI exports the connected HTTP spans and any function spans to
both Splunk Observability Cloud and a local Tempo evidence mirror.

```text
loadgen -> coupon-checkout (Go) -> inventory-java -> inventory-node
```

The Java fixture uses the OpenTelemetry Java agent for its HTTP server/client
spans. OBI's Java agent coexists with it and parents dynamically selected
function spans to the active Java context. This keeps the hierarchy connected
on development hosts where OBI disables kernel context injection after its
runtime compatibility check.

The load generator sends only checkout requests. It does not call the inventory
services independently, so one trace represents the complete causal request.

## Requirements

- Linux with BTF and the privileges needed to run OBI
- Docker with Compose
- A Splunk Observability Cloud realm and access token that can ingest traces and
  metrics
- This repository checked out at the pinned commit above (or the demo branch
  containing these files)

## Start the demo

```sh
cd examples/dynamic-instrumentation-demo
cp .env.example .env
# Edit .env with a real SPLUNK_REALM and SPLUNK_ACCESS_TOKEN.
docker compose up --build -d
```

Building OBI from the repository root is deliberate: the image therefore uses
the pinned implementation rather than a mutable published tag. The first build
generates the eBPF artifacts and can take several minutes.

Open <http://127.0.0.1:8090>. OBI and Tempo do not publish host ports. The demo
services expose these loopback-only endpoints for manual traffic:

| Service | Language | URL | Purpose |
| --- | --- | --- | --- |
| `coupon-checkout` | Go | <http://127.0.0.1:18081> | Primary latency investigation |
| `inventory-java` | Java | <http://127.0.0.1:18084> | Inventory lookup and Node catalog client |
| `inventory-node` | Node.js | <http://127.0.0.1:18085> | Product availability and pricing catalog |

The containers listen on `18080`, `18082`, and `18083`, while their host
mappings use `18081`, `18084`, and `18085`. Keeping those ranges separate
prevents Docker's port proxies from matching OBI's service selector.

The UI is an instrumentation control plane over the existing OBI API. Its
service inventory groups every process matching the configured selector, shows
its detected language and all discovered functions, distinguishes available
functions from active probes, and links every instrumented function to its
actual owning rules. Selecting functions opens a contextual composer that can
create a rule or safely add the selection to an existing API rule.

The function picker defaults to application scope so Go runtime and dependency
symbols do not overwhelm the primary workflow. One integrated toolbar switches
between application, dependency, runtime/internal, and complete catalogs, then
refines that scope by instrumentation status or search. OBI currently returns
flat symbol names, so this demo infers scope from language naming conventions;
it does not remove or change the underlying symbol catalog.

The Rules workspace lists definitions directly from OBI. API rules can be
edited, duplicated, and deleted. Rules loaded from OBI configuration are visible
with their ownership and attachment state but remain read-only. Trace
investigation remains in Splunk APM or another telemetry backend rather than
being duplicated in this control plane.

## Prove the existing API before using the UI

List symbols for all three services:

```sh
curl --fail --silent --show-error --get \
  http://127.0.0.1:8090/obi/v1/dynamic-instrumentation/symbols \
  --data-urlencode 'service=[{"open_ports":"18080,18082-18083"}]'
```

Each process includes a `language` field. Go symbols resemble
`main.applyCoupon`, Java symbols resemble
`demo.inventory.CatalogService.findProduct`, and Node.js symbols include their
source file and export path.

Choose an exact symbol from that response, then attach it to the known service.
Using a service selector, rather than a one-time PID, lets the rule attach again
when the checkout container is rebuilt:

```sh
curl --fail --silent --show-error --request PUT \
  http://127.0.0.1:8090/obi/v1/dynamic-instrumentation/rules/manual-demo \
  --header 'Content-Type: application/json' \
  --data '{
    "service":[{"open_ports":"18080"}],
    "spans":[{"name":"diagnostic.selected_function","on":{"function_span":"EXACT_SYMBOL"}}]
  }'
```

An `attached` result means the uprobe is live. Generate a coupon request and then
search the mirrored traces:

```sh
curl --fail --silent --show-error \
  --header 'Content-Type: application/json' \
  --data '{"cart_id":"manual-1","coupon":"FROG20","sku":"frog-plush"}' \
  http://127.0.0.1:18081/checkout

curl --fail --silent --show-error --get \
  http://127.0.0.1:8090/tempo/api/search \
  --data-urlencode 'q={ resource.service.name = "coupon-checkout" } && { resource.service.name = "inventory-java" } && { resource.service.name = "inventory-node" }' \
  --data-urlencode 'limit=20'
```

Remove the rule when finished:

```sh
curl --fail --silent --show-error --request DELETE \
  http://127.0.0.1:8090/obi/v1/dynamic-instrumentation/rules/manual-demo
```

The rule catalog endpoint returns API and configuration rules with their service
selectors, span definitions, and current attachment results:

```sh
curl --fail --silent --show-error \
  http://127.0.0.1:8090/obi/v1/dynamic-instrumentation/rules
```

The browser does not persist a shadow copy of rule state. Reloading the page
always reconstructs the inventory and ownership model from OBI.

## Validate the complete trace hierarchy

Run the smoke target after starting the stack:

```sh
make demo-smoke
```

In addition to checking service and API health, this attaches only the missing
Java probes, emits three requests with unique trace IDs, and verifies every
direct parent edge from the Go checkout span through the Java dynamic spans to
the Node server span. The temporary rule is removed on success or failure;
existing user probes are reused and left unchanged.

## AI troubleshooting demo

The repository includes the `troubleshoot-with-obi` Codex skill. Start the stack,
then ask Codex:

> My users report that checkout gets slow whenever they use a coupon. Use the
> OBI demo to identify the issue, fix it, and prove the result with trace evidence.

The skill requires telemetry evidence before source inspection, uses a uniquely
named temporary rule, patches only the implicated function, rebuilds only the
checkout container, verifies the replacement process, and removes its rule.

## Splunk presentation

In Splunk APM, filter for `coupon-checkout` in namespace `obi-dynamic-demo` and
open a checkout trace. Its service chain includes `inventory-java` and
`inventory-node`. The instrumentation UI manages what OBI attaches; use Splunk
APM to inspect the resulting traces and diagnose application behavior.

## Stop and reset

```sh
docker compose down --volumes
git -C ../.. restore examples/dynamic-instrumentation-demo/app/main.go
```

The second command restores the deliberate fault after the AI has patched it.
It only targets the demo service file; review its diff first if it contains work
you intend to keep.

This is a local demonstration, not a production deployment. The OBI API has no
authentication, dynamic spans may capture argument values, and the containers
run with privileges that should not be exposed beyond the demo host.
