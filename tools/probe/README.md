# Probe Tool

`tools/probe/` owns behavioral probe validation. Probe sends libcrafter packets
through disposable lab sessions and verifies kernel or controlled service
replies.

The Python runner under `tools/probe/engine/` generates deterministic probe
plans, writes request artifacts, orchestrates provider execution, and builds
reports. The Rust endpoint binary lives in `tools/probe/adapters/`; it is tool
infrastructure, not a public `crafter` example.

Common dry-run commands:

```sh
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10
```

Provider-backed probe dry-runs use `tools/lab` to plan `stimulus` and `target`
roles, derive endpoint addresses and interfaces, and include lab session
metadata in the report. Probe still owns target service setup, TCP RST guards,
stimulus execution, response parsing, and result assembly.

Build the Rust adapter directly:

```sh
cargo build -p probe-adapters --bin stimulus_endpoint
```
