# Workload Rules

This design introduces a unified workload rule engine. Global OBI behavior lives under `defaults`, and `workloads.rules[]` combines matching, admission, and workload-scoped refinement.

Benefits:

- Strongest local coherence: workload-specific config lives where workload matching is defined.
- Keeps a clean global baseline under `defaults`.
- Avoids external policy indirection while still using shared config shapes.

Drawbacks:

- Re-couples matching and refinement.
- A new `defaults` wrapper moves current top-level OBI sections, increasing migration churn.
- Needs careful semantics for how multiple matching include rules merge refinements.
