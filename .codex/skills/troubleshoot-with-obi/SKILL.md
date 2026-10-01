---
name: troubleshoot-with-obi
description: Diagnose and fix the repository's local OBI dynamic-instrumentation checkout demo using evidence from OBI and Tempo. Use when a user asks to investigate the coupon-checkout demo, dynamically probe the running Go service, root-cause its latency, patch it, and prove the improvement.
---

# Troubleshoot with OBI

Use the existing OBI API through `http://127.0.0.1:8090/obi/` and the read-only
Tempo proxy through `http://127.0.0.1:8090/tempo/`. Do not add an API, controller,
database, MCP server, or executable helper.

Read [references/demo-api.md](references/demo-api.md) before beginning. Work from
the repository root. Treat `examples/dynamic-instrumentation-demo/compose.yaml`
as the Compose project definition.

## Guardrails

- Do not inspect checkout source until trace evidence implicates one function.
- Use only exact function names returned by the symbols endpoint.
- Limit an investigation to four candidate functions at a time.
- Name the rule `codex-investigation-<unix-seconds>` and retain its ID.
- Require at least three fresh slow traces. A candidate is causal only when its
  dynamic span accounts for at least 70% of the parent request duration in each.
- Never print or read the Splunk access token. Use Tempo for automated evidence.
- Restrict code changes and rebuilds to `examples/dynamic-instrumentation-demo/app/`.
- Delete the named API rule before finishing, including after failures. If normal
  deletion fails, report it and restart only the OBI Compose service.

## Workflow

1. Confirm the stack and OBI health. Query recent checkout traces and establish
   separate baseline durations for coupon and non-coupon traffic. Do not read
   application source.
2. Call symbol discovery with the known port selector. Identify a small set of
   checkout-domain functions from the returned names; do not probe runtime or
   framework internals.
3. Create one uniquely named rule containing exact `function_span` entries for
   the candidate functions and the known port selector. Record the discovered
   host PID and require `attached` results before continuing. Do not target the
   PID in the rule: the selector must allow reattachment after a rebuild.
4. Generate at least three new `FROG20` checkouts. Wait for completed traces to
   become searchable, retrieve their trace details, and compare child dynamic
   span durations with their parent request spans. Record trace IDs.
5. If no candidate meets the repeated-evidence threshold, remove the rule and
   repeat once with a different small candidate set. Do not widen to a blanket
   glob.
6. Only after one function meets the threshold, inspect that function and its
   focused tests. Explain the concrete blocking work visible in both code and
   traces. Patch only that function and add or adjust a focused test if needed.
7. Run `go test ./...` inside the app directory. Rebuild and replace only the
   checkout service with Compose. Confirm symbol discovery returns a replacement
   host PID and confirm the still-active rule attaches to that process.
8. Generate fresh coupon and non-coupon traffic. Use at least three new traces to
   calculate before/after coupon duration and ensure normal checkout behavior did
   not regress. Require a material improvement of at least 50%.
9. Delete the named rule. Verify it no longer appears in the active probes list.
10. Report baseline and fixed durations, dynamic-span contribution, captured
    synthetic arguments when present, evidence trace IDs, root cause, exact patch,
    test result, replacement PID, and cleanup result. Distinguish measurement
    from inference.
