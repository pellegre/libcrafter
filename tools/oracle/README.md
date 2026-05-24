# Oracle Validation

`tools/oracle/run` is the supported packet behavior validation entrypoint. It
owns spec loading, generated stacks, profile sampling, case selection, backend
capability checks, report format, artifact layout, and reproduction
coordinates.

Packet behavior coverage is data-driven. Add or adjust coverage through
`tools/oracle/specs/` and backend adapters under `tools/oracle/engine/backends/`;
do not add ad hoc Scapy snippets to tests, scripts, or examples. Scapy is the
full read/write/live reference backend selected with `--backend scapy`, and its
code belongs under `tools/oracle/engine/backends/scapy/`.

Wireshark/tshark is registered as a parser-only backend. It can decode packets
and read pcaps for comparison paths, but it does not encode packet bytes, write
pcaps, or act as a live endpoint.

## Common Commands

Offline validation compares raw packet vectors and normalized decoded models:

```sh
tools/oracle/run offline --backend scapy --profile smoke --seed 1 --count 10
```

Pcap validation compares pcap writer, reader, and roundtrip behavior:

```sh
tools/oracle/run pcap --backend scapy --profile smoke --seed 1 --count 10
```

Parser-only decode and pcap-read checks can use Wireshark/tshark when `tshark`
is available on `PATH`:

```sh
tools/oracle/run offline --backend wireshark --profile smoke --seed 1 --count 10
tools/oracle/run pcap --backend wireshark --direction libcrafter_to_reference --profile smoke --seed 1 --count 10
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
```

Reports include the mode, backend, profile, seed, count, direction, and packet
index. Reproduce a failing generated packet with the same command coordinates
and add `--index <n>` when the report identifies a single packet.

## Specs And Backends

Executable specs define packet families, stack roots, features, pcap contracts,
profiles, case IDs, and backend support metadata. The generator samples from
those specs and rejects invalid stack/feature combinations before a backend is
invoked.

Backend adapters materialize packets, normalize decoded observations, read or
write pcaps, and provide live endpoint command plans according to their
registered backend capability set. Unsupported mode/backend combinations return
oracle reports that identify the missing capability instead of silently taking a
different path.

## CI Policy

Pull request CI runs deterministic offline and pcap oracle validation with the
Scapy backend. The live-lab workflow runs provider dry-run planning on normal
pull request and push events. Real Hetzner live exchanges run only from a
protected manual workflow dispatch with explicit confirmation and configured
credentials.
