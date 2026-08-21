---
name: packet-validation
description: Add or run deterministic libcrafter packet behavior validation through oracle specs, reference backends, offline checks, pcap checks, probe plans, and artifacts.
---

# Packet validation

Use this skill whenever packet construction, decode, checksums, framing,
options, malformed behavior, or response matching changes.

## Required workflow

1. Update the relevant `tools/oracle/specs/` contract first.
2. Keep independent implementation logic inside
   `tools/oracle/engine/backends/`.
3. Update backend materialization and normalization for the new case.
4. Run strict spec validation and focused offline validation.
5. Run pcap validation when framing, link types, capture files, or persisted
   bytes are affected.
6. Generate the relevant deterministic probe plan when peer behavior matters.
7. Run Rust unit and adapter tests for any bounded executor changes.
8. Record intentional mismatches and unsupported behavior in tracked specs or
   nearby documentation.

Typical commands:

```sh
tools/oracle/run specs validate --strict
tools/oracle/run offline --profile PROFILE --seed SEED --count COUNT
tools/oracle/run pcap --profile PROFILE --seed SEED --count COUNT
tools/probe/run --profile PROFILE --seed SEED --count COUNT --out target/probe/plan
cargo test -p probe-adapters
```

This repository does not own machine selection, credentials, remote access,
machine lifecycle, peer preparation, hardware leases, or execution topology.
When hardware-backed qualification is necessary, use only operator-supplied
untracked tooling, after the deterministic gate passes, and preserve evidence
for the exact candidate revision.
