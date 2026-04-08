# Config v2 Alternatives

This directory builds out three holistic redesign directions for OBI configuration:

- `inline-refinement`: selection rules admit workloads and may inline scoped config overrides.
- `policies`: selection rules admit workloads and reference named reusable policy bundles.
- `workload-rules`: a unified workload rule engine with a `defaults` baseline and workload-scoped overrides.

Each alternative includes:

- `default-configuration.yaml`: a concrete default configuration in that design.
- `obi-extension.schema.json`: a local JSON Schema for the `extensions.obi` subtree.
- `design.md`: a concise description of the design, benefits, and drawbacks.

Validation commands:

```sh
go run ./devdocs/config/version-2.0/alternatives/verify_alternative.go --mode inline-refinement --config ./devdocs/config/version-2.0/alternatives/inline-refinement/default-configuration.yaml
go run ./devdocs/config/version-2.0/alternatives/verify_alternative.go --mode policies --config ./devdocs/config/version-2.0/alternatives/policies/default-configuration.yaml
go run ./devdocs/config/version-2.0/alternatives/verify_alternative.go --mode workload-rules --config ./devdocs/config/version-2.0/alternatives/workload-rules/default-configuration.yaml

python3 devdocs/config/version-2.0/validate_example.py --schema ./devdocs/config/version-2.0/alternatives/inline-refinement/obi-extension.schema.json --config ./devdocs/config/version-2.0/alternatives/inline-refinement/default-configuration.yaml
python3 devdocs/config/version-2.0/validate_example.py --schema ./devdocs/config/version-2.0/alternatives/policies/obi-extension.schema.json --config ./devdocs/config/version-2.0/alternatives/policies/default-configuration.yaml
python3 devdocs/config/version-2.0/validate_example.py --schema ./devdocs/config/version-2.0/alternatives/workload-rules/obi-extension.schema.json --config ./devdocs/config/version-2.0/alternatives/workload-rules/default-configuration.yaml
```
