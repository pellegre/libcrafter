# Documentation

This directory documents the public `crafter` packet library and the
repository's deterministic validation workloads.

- [`guide/`](guide/) describes protocol construction, decode, and wire
  coverage.
- [`reference/`](reference/) documents the Rust API, packet I/O, and examples.
- [`operations/`](operations/) documents the tracked oracle, probe-plan, and
  bounded smoke workloads.

## Validation boundary

The repository owns protocol-correct packet primitives, deterministic oracle
specs, pcap validation, substrate-neutral probe plans, and bounded executors.
It does not select machines, manage credentials, connect over SSH, provision
VMs or containers, configure radio appliances, create peer services, or collect
artifacts from remote systems.

An external operator may check out an exact libcrafter revision, supply concrete
interfaces and peers, invoke a bounded workload, and collect its artifacts.
That orchestration is intentionally not part of this repository.

Start with:

```sh
tools/oracle/run specs validate --strict
tools/oracle/run offline --profile smoke --seed 1 --count 10
tools/oracle/run pcap --profile smoke --seed 1 --count 10
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
cargo run -p crafter-smoke
```

See [operations/tools.md](operations/tools.md) for the complete tracked tool
boundary. Agent operating guidance belongs in
[`.agents/docs/cookbook.md`](../.agents/docs/cookbook.md).
