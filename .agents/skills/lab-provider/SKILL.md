---
name: lab-provider
description: Add or maintain libcrafter lab provider adapters, capability contracts, provider matrix tests, and documentation for substrate-independent oracle and probe execution.
---

# Lab Provider

Use this skill when adding, changing, or reviewing a provider adapter under
`tools/lab/engine/providers/`. A lab provider owns substrate mechanics only:
planning roles, exposing capabilities, creating endpoints, normalizing endpoint
manifests, validating sessions, collecting artifacts, and cleanup.

Oracle and probe workload semantics must stay outside lab. The provider should
not know oracle packet cases or probe service behavior.

## Provider Contract

Every lab provider must implement the adapter protocol in
`tools/lab/engine/providers/base.py` and be registered through the lab provider
registry. Keep these contracts provider-neutral:

- provider name, endpoint provider, and exposure
- credential or prerequisite availability
- default and normalized provider capabilities
- role planning and deterministic address defaults
- dry-run infrastructure metadata
- provider workflow command records
- endpoint planning/creation
- endpoint normalization
- request/session validation
- appliance runtime metadata for endpoint-backed execution

Capability names should describe substrate behavior, such as IPv4 unicast,
controlled services, provider MAC knowledge, broadcast support, and controlled
router support. Workload-specific capability derivation belongs in oracle or
probe boundary modules.

Provider adapters should report coarse appliance runtime profiles rather than
protocol-specific execution promises. Use `wan-raw`, `lan-raw`, `whad-serial`,
or `dot11-monitor` when the provider can place that role, and keep host or VM
preparation details such as Docker readiness, USB passthrough, serial access,
monitor-mode interfaces, and artifact roots in provider or endpoint metadata.
Prepared dongle VMs should be exposed through persistent asset leases so
multiple agent sessions do not use the same hardware concurrently.

## Validation

For provider changes, run focused tests first, then the matrix:

- `python3 -m unittest tools.lab.tests.test_provider_registry`
- `python3 -m unittest tools.lab.tests.test_provider_matrix`
- provider-specific tests under `tools/lab/tests/`
- oracle/probe dry-run matrix tests when the provider contract changes

Dry-run behavior must be deterministic and must not create infrastructure.
Live behavior must use explicit confirmation and best-effort cleanup on every
failure path.

## Documentation

Update provider docs when the provider contract, prerequisites, credentials,
capabilities, or artifact shape changes. Keep agent operating guidance in
`.agents/docs/` or repo-local skills, and user-facing tool documentation in
`docs/` or the relevant tool README.
