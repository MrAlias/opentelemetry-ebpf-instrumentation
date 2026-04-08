# Inline Refinement

This design keeps the current top-level OBI baseline sections and lets `selection.rules[]` inline workload-scoped refinements directly beside `match` and `action`.

Benefits:

- Workload-specific configuration stays next to workload matching logic.
- No external indirection through named policy references.
- Reuses the same config shapes directly under rules.

Drawbacks:

- Matching and refinement are coupled in the same object.
- Reuse of the same override block across multiple rules requires duplication.
- Merge semantics for overlapping include rules must be tightly specified.
