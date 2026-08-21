# Validation tools

`libcrafter` keeps packet semantics and deterministic validation in this
repository. It does not manage execution infrastructure.

The tracked tools have three jobs:

- `tools/oracle/run` generates source-backed corpora and compares bytes,
  decoded models, and pcap behavior with independent implementations.
- `tools/probe/run` emits deterministic peer-behavior plans. It never selects a
  machine or sends packets.
- `crafter-smoke` builds and runs a small bounded workload against the selected
  `crafter` source tree.

```sh
tools/oracle/run specs validate --strict
tools/oracle/run corpus --profile ci --seed 12345 --count 100 --out target/oracle/corpus
tools/oracle/run offline --corpus target/oracle/corpus/plans.json --out target/oracle/offline
tools/oracle/run pcap --corpus target/oracle/corpus/plans.json --out target/oracle/pcap
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
cargo run -p crafter-smoke
```

The Rust executors under `tools/oracle/adapters` and `tools/probe/adapters`
accept concrete request data and perform bounded packet work. They do not
choose hosts, obtain credentials, create machines, prepare peers, lease
hardware, or tear resources down.

An operator-supplied external runner may check out an exact candidate revision,
satisfy the plan's runtime requirements, invoke a bounded executor, and collect
its artifacts. That runner and its topology are intentionally untracked.
