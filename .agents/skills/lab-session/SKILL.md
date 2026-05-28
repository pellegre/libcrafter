---
name: lab-session
description: Provision, use, collect, and tear down multi-endpoint libcrafter lab sessions across Hetzner, QEMU, VirtualBox, and future lab providers. Use when oracle, probe, or generated tools need provider-backed packet work that must be independent of the developer machine.
---

# Lab Session

Use this skill when a task needs a disposable provider-backed session with two
or more coordinated endpoints. A lab session owns substrate setup, repository
push/bootstrap, endpoint metadata, artifact collection, and teardown; oracle,
probe, or generated tools own the workload they run inside that substrate.

For one-off manual work on a single endpoint, use `wire-endpoint`. For adding
or changing provider adapters, use `lab-provider`.

## Required Order

1. Start with dry-run planning:
   - `tools/lab/run plan --provider <provider> --dry-run --profile smoke --seed 1 --role stimulus --role target`
   - `tools/oracle/run live --provider <provider> --dry-run --profile smoke --seed 1 --count 10`
   - `tools/probe/run --provider <provider> --dry-run --profile smoke --seed 1 --count 10`
2. Inspect the lab session metadata before any live work:
   - provider, wire provider, and exposure
   - endpoint roles and planned addresses
   - provider capabilities
   - provider workflow and command records
   - remote artifact root and cleanup state
3. Run live only after an explicit protected confirmation such as
   `--confirm-live-run`.
4. Push/bootstrap repository state through lab helpers or the lab-backed
   oracle/probe runners, not by relying on tools installed on the developer
   machine.
5. Collect artifacts from every endpoint before teardown whenever possible.
6. Tear down the lab session after every run, including failed runs.

## Provider Rules

Supported lab providers are registered in `tools/lab/engine/providers/`.
Use provider names from the lab registry instead of hard-coded provider lists.
Provider-backed oracle and probe runs should go through lab sessions so packet
exchange behavior is independent of the substrate where the agent is running.

Do not store credentials, provider account identifiers, public IPs, live host
IDs, or packet captures from sensitive networks in tracked files. If credentials
or local virtualization prerequisites are missing, keep dry-run artifacts and
report the skipped live work clearly.

## Artifacts

Keep the artifacts needed to debug a failed run offline:

- lab session manifest
- provider workflow and command records
- endpoint manifests
- repository archive/bootstrap logs
- workload request/response JSON
- pcaps, decoded summaries, stdout/stderr logs, and cleanup state

Tracked documentation may describe artifact shapes, but live artifacts belong
under ignored output directories such as `target/` or lab state/artifact roots.
