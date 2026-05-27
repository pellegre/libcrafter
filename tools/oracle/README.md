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

Generate a reusable packet corpus before running a validation mode:

```sh
tools/oracle/run corpus --backend scapy --profile smoke --seed 1 --count 10
```

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

Live validation uses the oracle live provider boundary. `local-dry-run` is the
non-provider-backed planning path; it does not send packets or create
infrastructure:

```sh
tools/oracle/run live --backend scapy --provider local-dry-run --profile smoke --seed 1 --count 10
```

Provider-backed live planning is selected by a registered oracle live provider
adapter. Hetzner, QEMU, and VirtualBox share the same oracle live runner and
must stay dry-run unless a protected workflow is intentionally creating
disposable wire endpoints:

```sh
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --backend scapy --provider qemu --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --backend scapy --provider virtualbox --dry-run --profile smoke --seed 12345 --count 10
```

The provider matrix runner generates one corpus, runs offline and pcap
baselines, then reuses the corpus through the same live dry-run command shape
for every selected provider:

```sh
python3 tools/oracle/tests/live_provider_matrix.py --providers hetzner,qemu,virtualbox --backend scapy --profile smoke --seed 12345 --count 5 --dry-run --out target/oracle/provider-matrix-dry-run
```

Expanded wire protocol smoke checks force corpus selection for DNS, TCP, ICMP,
and IPv6 packets while keeping provider execution in dry-run mode:

```sh
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 11 --count 40 --case dns-query --out target/oracle/step-11-dns
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 11 --count 40 --case ipv4-tcp-syn --out target/oracle/step-11-tcp
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 11 --count 40 --case ipv4-icmp --out target/oracle/step-11-icmp
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 11 --count 40 --family ipv6 --out target/oracle/step-11-ipv6
```

## Artifacts And Reproduction

Oracle artifacts default below `target/oracle/`:

```text
target/oracle/corpus/
target/oracle/offline/
target/oracle/pcap/
target/oracle/live/
```

The corpus report includes the mode, corpus id, backend, profile, seed, count,
selected specs, requested filters, and ordered packet indexes. Validation reports
include the mode, backend, profile, seed, count, direction, and packet index.
Reproduce a failing generated packet with the same command coordinates and add
`--index <n>` when the report identifies a single packet.

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

Provider-backed live adapters live under `tools/oracle/engine/providers/`. They
own provider-specific endpoint plans, lifecycle command plans, bootstrap,
remote endpoint commands, capabilities, and wire comparison policy. The generic
live runner still owns packet generation, endpoint protocol comparison, report
assembly, and provider execution flow. `tools/wire` remains responsible for
creating endpoints and collecting artifacts.

The Rust-side libcrafter adapters live in `tools/oracle/adapters/` as an
internal workspace package. They depend on the public `crafter` crate API and
must not add oracle-only code to `crafter`.

## CI Policy

Pull request CI runs deterministic offline and pcap oracle validation with the
Scapy backend. The live workflow runs provider dry-run planning on normal pull
request and push events through the selected oracle live provider adapter. Real
provider-backed live exchanges run only from a protected manual workflow
dispatch with explicit confirmation and configured provider prerequisites.
