# Policies

This design keeps top-level OBI baseline sections and adds reusable named `policies` that selection rules reference through `apply`.

Benefits:

- Strong separation between workload admission and workload refinement.
- Reusable scoped configuration bundles avoid duplication.
- Deterministic composition through ordered policy application.

Drawbacks:

- Adds indirection between matching and refinement.
- `selection` is not itself a reusable object shape, which creates some asymmetry in the model.
- Named policy fragments are less obviously first-class than Collector components.
