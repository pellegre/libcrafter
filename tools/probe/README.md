# Probe plans and bounded executors

Probe describes peer-behavior workloads built with libcrafter.

The Python runner is deterministic and plan-only:

```sh
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/smoke
tools/probe/run --profile behavior --seed 1052 --count 40 --out target/probe/behavior
```

Each module under `tools/probe/engine/protocols/` registers protocol cases and
packet-plan builders. Plans contain packet intent, expected response contracts,
capture filters, and runtime requirements. They do not contain machine
selection, credentials, lifecycle commands, topology, or peer-preparation
scripts.

The Rust crate under `tools/probe/adapters/` materializes supported plans as
typed libcrafter packets. Dry-run is the default. Its explicit live mode is a
bounded execution primitive that accepts concrete interfaces and addresses; it
does not decide where or how the process runs.

Build and test the executor with:

```sh
cargo test -p probe-adapters
cargo build -p probe-adapters --bin stimulus_endpoint
```

See `docs/adding-a-protocol.md` for the extension contract.
