# Probe Tool

`tools/probe/` owns behavioral probe validation. Probe sends libcrafter packets
into disposable lab targets and verifies kernel or controlled service replies.

The Python runner under `tools/probe/engine/` generates deterministic probe
plans, writes request artifacts, orchestrates provider execution, and builds
reports. The Rust endpoint binary lives in `tools/probe/adapters/`; it is tool
infrastructure, not a public `crafter` example.

Common dry-run command:

```sh
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
```

Build the Rust adapter directly:

```sh
cargo build -p probe-adapters --bin stimulus_endpoint
```
