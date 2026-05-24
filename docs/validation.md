# Oracle Validation

The oracle validates packet behavior against reference backends. Scapy is the
default read/write backend and is selected explicitly with `--backend scapy`.
Keep Scapy logic inside `tools/oracle/`; do not add ad hoc Scapy imports to
tests or scripts when an oracle mode covers the same behavior.

## Offline Validation

Offline validation compares generated raw packet vectors and normalized decode
models without root privileges or live traffic:

```sh
tools/oracle/run offline --backend scapy --profile smoke --seed 1 --count 10
```

Use `--profile`, `--seed`, and `--count` to make failures reproducible. When a
report identifies a packet index, rerun with the same inputs and `--index`.

## Pcap Validation

Pcap validation exercises packet materialization, pcap write/read behavior, and
roundtrip decoding:

```sh
tools/oracle/run pcap --backend scapy --profile smoke --seed 1 --count 10
```

Use pcap mode when changes affect link types, timestamps, pcap framing, or
decode behavior that should survive file serialization.

## Live Validation

Live validation routes packet exchange through a provider. Use local dry-runs
for planning and CI-safe checks:

```sh
tools/oracle/run live --backend scapy --provider local-dry-run --profile smoke --seed 1 --count 10
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
```

Real provider-backed validation is reserved for explicit live-lab workflows on
disposable infrastructure:

```sh
tools/live-lab/libcrafter-live-lab run --provider hetzner --suite oracle-live
```

See [live-lab.md](live-lab.md) for provider credentials, artifacts, and cleanup.

## CI Expectations

Pull request CI should run deterministic offline validation and pcap smoke
validation. Hetzner dry-runs are safe for planning. Real live packet exchange
must stay behind explicit protected workflow confirmation and cleanup logic.

Recommended local preflight:

```sh
cargo test --workspace
tools/oracle/run offline --backend scapy --profile ci --seed 12345 --count 2000
tools/oracle/run pcap --backend scapy --profile smoke --seed 12345 --count 250
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
```

Oracle artifacts default below `target/oracle/`, with mode-specific reports
under `target/oracle/offline`, `target/oracle/pcap`, and `target/oracle/live`.
