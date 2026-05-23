# Oracle Validation

`tools/oracle/run` is the packet behavior validation entrypoint. It owns the
sampling plan, report format, artifact layout, and reproduction coordinates.
Scapy is selected as a reference backend with `--backend scapy`; backend code
lives under `tools/oracle/engine/backends/scapy/` and should not leak into tests
as direct imports.

## Common Commands

Offline validation compares raw packet vectors and normalized decoded models:

```sh
tools/oracle/run offline --backend scapy --profile smoke --seed 1 --count 10
```

Pcap validation compares pcap writer, reader, and roundtrip behavior:

```sh
tools/oracle/run pcap --backend scapy --profile smoke --seed 1 --count 10
```

Live validation goes through a provider. The local provider is a dry run that
does not send packets or create infrastructure:

```sh
tools/oracle/run live --backend scapy --provider local-dry-run --profile smoke --seed 1 --count 10
```

Provider-backed live planning must stay dry-run unless a protected live-lab
workflow is intentionally creating disposable resources:

```sh
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
```

## Artifacts And Reproduction

Oracle artifacts default below `target/oracle/`:

```text
target/oracle/offline/
target/oracle/pcap/
target/oracle/live/
target/oracle/fixtures/
```

Reports include the mode, backend, profile, seed, count, direction, and packet
index. Reproduce a failing generated packet with the same command coordinates
and add `--index <n>` when the report identifies a single packet.

## CI Policy

Pull request CI runs deterministic offline and pcap oracle validation with the
Scapy backend. Live provider workflows must not create infrastructure on normal
pull request runs; they should use dry-run checks or require explicit protected
workflow confirmation.
