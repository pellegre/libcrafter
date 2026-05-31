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
adapter and backed by `tools/lab` sessions. Hetzner, QEMU, and VirtualBox share
the same oracle live runner and must stay dry-run unless a protected workflow
is intentionally creating disposable lab endpoints:

```sh
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 12345 --role libcrafter --role reference_backend --json
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --backend scapy --provider qemu --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --backend scapy --provider virtualbox --dry-run --profile smoke --seed 12345 --count 10
```

The provider matrix runner generates one corpus, runs offline and pcap
baselines, then reuses the corpus through the same live dry-run command shape
for every selected provider:

```sh
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox --backend scapy --profile smoke --seed 12345 --count 5 --dry-run --out target/oracle/provider-matrix-dry-run
```

Guarded real VM smoke uses the same provider-backed live runner for QEMU and
VirtualBox. It runs wire doctor checks first and skips unavailable VM providers
by default while preserving the doctor output in `matrix-summary.json`:

```sh
python3 tools/oracle/engine/live_provider_matrix.py --providers qemu,virtualbox --backend scapy --profile smoke --seed 12345 --count 2 --real --skip-unavailable --out target/oracle/provider-matrix-vm-real
```

It also skips actual VM creation unless `--allow-vm-create` or
`LIBCRAFTER_ORACLE_VM_SMOKE_ALLOW_CREATE=1` is set. Set
`LIBCRAFTER_ORACLE_VM_SMOKE_STRICT=1` or pass `--strict-vm-smoke` when a lab
qualification run should fail instead of skip if QEMU or VirtualBox
prerequisites are missing or VM creation is disabled.

## DHCP Coverage

DHCP is validated as a normal `Packet` stack carried by UDP and IPv4, not as a
DHCP client, server, lease negotiation, or reply workflow. Two stacks split the
coverage:

- `ipv4 / udp / dhcp` (root `l3:ipv4`) is the live DHCP packet under test. Live
  validation is a one-way packet-equivalence exchange run in both directions
  (`libcrafter_to_reference` and `reference_to_libcrafter`); each direction
  sends one DHCP packet and checks the receiver's decoded observation, and no
  DHCP reply is expected. Rooted at IPv4 unicast, it is wire-eligible without
  Ethernet framing, link-layer broadcast, or provider MAC discovery.
- `ethernet / ipv4 / udp / dhcp` (root `link:ethernet`) stays for offline byte
  equivalence, pcap, link-type, and decode-root coverage where Ethernet framing
  is the behavior under test. It remains link-layer-gated for live runs
  (`requires_l2`, `requires_provider_mac`, `requires_broadcast`).

Scapy is the live reference backend for DHCP exchanges. Wireshark/tshark is
parser-only: it decodes DHCP packets and pcaps for comparison but never sends,
encodes, or acts as a live endpoint. Plan the focused DHCP live path in dry-run
mode with `--case dhcp-discover`:

```sh
tools/oracle/run live --backend scapy --provider local-dry-run --dry-run --profile smoke --seed 134 --count 2 --case dhcp-discover --out target/oracle/dhcp-dry-run
```

See `tools/oracle/LIVE.md` for the guarded real DHCP live paths (QEMU,
VirtualBox, Hetzner).

Expanded wire protocol smoke checks force corpus selection for DNS, TCP, ICMP,
and IPv6 packets while keeping provider execution in dry-run mode:

```sh
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 11 --count 40 --case dns-query --out target/oracle/step-11-dns
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 11 --count 40 --case ipv4-tcp-syn --out target/oracle/step-11-tcp
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 11 --count 40 --case ipv4-icmp --out target/oracle/step-11-icmp
tools/oracle/run live --backend scapy --provider hetzner --dry-run --profile smoke --seed 11 --count 40 --family ipv6 --out target/oracle/step-11-ipv6
```

## DNS Scapy Coverage

The DNS family has an extensive Scapy-backed suite. It validates packet
construction, decode, and capture behavior, **not** DNS client, resolver, or
server semantics. The case contract and per-feature byte policy live in
`tools/oracle/specs/fixtures/dns-scapy-coverage.md`; the cases are wired through
`tools/oracle/specs/features/dns-behavior.yaml`, `layers/dns.yaml`,
`stacks.yaml`, and `fixtures/scapy-cases.json`.

The suite covers every implemented DNS group: header (id, QR, AA/TC/RD/RA/AD/CD
flags, opcodes, rcodes, raw flags, auto-filled and empty section counts), names
and compression, questions and the QTYPE/QCLASS axes, A/AAAA, NS/CNAME/PTR,
MX/TXT, SOA/SRV, raw-unknown and deferred record types, EDNS OPT basic fields
and the option TLV matrix, DNSSEC DS/DNSKEY/RRSIG/NSEC/NSEC3, SVCB/HTTPS, section
placement, and malformed names and RDATA.

Most cases compare strict reference bytes. A few features cannot, and the case
row documents the reason:

- Compressed names use `normalized` comparison: libcrafter re-encodes names
  uncompressed, so the decoded model agrees while the wire bytes differ from the
  compressed Scapy input (`dns-name-compressed`, `dns-compressed-names`,
  `dns-name-records-compressed`).
- SVCB/HTTPS RDATA is built as Scapy-owned raw RDATA bytes through a generic
  `DNSRR`, because Scapy's high-level `SvcParam` field re-interprets known keys
  and rejects raw `port`/`ipvNhint` bytes; SvcParamValues stay opaque
  (`dns-svcb-https`).
- `\DDD` name escapes are flattened to literal text by the Scapy high-level
  encode, so byte-faithful agreement for special labels is carried by the
  `libcrafter_to_reference` direction and the `crafter` byte-preserving name
  tests, with the oracle comparing header and section counts
  (`dns-name-root-escaped`).
- Malformed names and RDATA are covered by the deterministic `crafter` decode
  corpus and `crafter/tests/resilience.rs` structured-error assertions, not by
  an offline oracle comparison (the oracle has no offline malformed pathway).

## Offline Protocol Suites

Offline validation is the default safety boundary, so it should prove
Scapy/libcrafter agreement before any pcap or live planning. Family selection is
data-driven: the generator honors each case's declared `directions` and
`byte_policy` from the feature spec's `supported_cases`, so a
`reference_to_libcrafter`-only or `normalized` case is never forced through an
unsupported `libcrafter_to_reference` strict comparison, and `structured_error`
cases (which have no offline malformed pathway) are excluded.

Run the deterministic DNS offline coverage with the `ci` profile in both
directions:

```sh
tools/oracle/run corpus --backend scapy --family dns --profile ci --seed 2701 --count 50 --out target/oracle/dns-offline-corpus
tools/oracle/run offline --backend scapy --family dns --profile ci --seed 2701 --count 50 --direction reference_to_libcrafter --out target/oracle/dns-offline-rtl
tools/oracle/run offline --backend scapy --family dns --profile ci --seed 2702 --count 50 --direction libcrafter_to_reference --out target/oracle/dns-offline-ltr
```

To force *every* offline-eligible DNS case in each direction it supports rather
than a weighted sample, emit the reproducible suite from the specs. The emitter
prints the case name, direction, derived seed, and artifact path for each
command; `--run` executes them and reports the aggregate result:

```sh
tools/oracle/run specs suite --family dns
tools/oracle/run specs suite --family dns --json
tools/oracle/run specs suite --family dns --run
```

## DNS Pcap Suite

Pcap validation round trips every representable DNS case through deterministic
pcap write/read. Pcap eligibility is data-driven from each case's `byte_policy`:
`normalized` cases (compressed names) are skipped `pcap_normalized_only` and
`structured_error` (malformed) cases are skipped `pcap_structured_error`, since
neither has a strict-byte wire form to round trip:

```sh
tools/oracle/run pcap --backend scapy --family dns --profile ci --seed 2802 --count 50 --out target/oracle/dns-pcap
```

## DNS Live Dry-Run Suite

Live validation is the two-machine packet writer/capture comparison: one
endpoint writes a DNS packet with libcrafter, the other captures and decodes it
with Scapy. It is *not* DNS client/server behavior. Live selection is
data-driven from each case's `byte_policy` in `supported_cases`, mirroring the
pcap gate:

- `strict_bytes` DNS cases are live-eligible in both
  `libcrafter_to_reference` and `reference_to_libcrafter` directions (the
  endpoint adapters send and decode the deterministic uncompressed encode);
- `normalized` cases (compressed names, sorted SvcParams, minimal bitmaps) are
  live-ineligible and skipped with `wire_normalized_only` -- libcrafter
  re-encodes the bytes, so only the decoded model agrees, which a live byte
  comparison cannot assert;
- `structured_error` (malformed) cases are kept out of live exchange and
  skipped with `wire_structured_error`.

Real packet exchange stays opt-in behind `--confirm-live-run` and the protected
provider workflow. Ordinary acceptance is dry-run only. Plan and inspect the
DNS live coverage without sending real traffic:

```sh
tools/oracle/run live --backend scapy --provider local-dry-run --family dns --profile ci --seed 2901 --count 50 --direction live_exchange --out target/oracle/dns-live-local-dry
tools/oracle/run live --backend scapy --provider hetzner --dry-run --family dns --profile ci --seed 2902 --count 50 --direction live_exchange --out target/oracle/dns-live-hetzner-dry
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox --backend scapy --profile ci --seed 2903 --count 50 --dry-run --out target/oracle/dns-live-provider-matrix
```

The `local-dry-run` provider needs no credentials. The `hetzner` `--dry-run`
plan and the provider matrix `--dry-run` never contact a real provider, never
read `HETZNER_API_TOKEN`/`HCLOUD_TOKEN`, and report
`creates_infrastructure=false` / `bootstrap=planned`. Each run prints
`wire_eligible`, `wire_skipped`, and `wire_skip_reasons` so the byte-policy
gating is inspectable.

## ICMPv4 Live Matrix

The ICMPv4 live matrix targets the `l2:ipv4` root with the `icmpv4_live`
feature. It validates packet write/parse parity between libcrafter and Scapy
over a real Hetzner private network, not kernel ICMP behavior; the root is
IPv4-rooted, so comparison canonicalizes to the IPv4 header and Ethernet fields
do not affect ICMP pass/fail. Use the offline and dry-run paths for planning;
they need no credential:

```sh
tools/oracle/run offline --backend scapy --root l2:ipv4 --feature icmpv4_live --profile smoke --seed 22 --count 20 --out target/oracle/icmp-live/offline
tools/oracle/run live --backend scapy --provider hetzner --dry-run --root l2:ipv4 --feature icmpv4_live --profile smoke --seed 70 --count 40 --out target/oracle/icmp-live/dry
```

Real Hetzner exchange requires `--confirm-live-run` and a credential in the
environment (`HETZNER_API_TOKEN`, or `HCLOUD_TOKEN`); never store the value in a
tracked file:

```sh
tools/oracle/run live --backend scapy --provider hetzner --confirm-live-run --root l2:ipv4 --feature icmpv4_live --profile smoke --seed 71 --count 60 --out target/oracle/icmp-live/full-matrix
```

Artifacts land under the requested `--out` directory (for example
`target/oracle/icmp-live/<step>/live/report.json`). Each `run live` invocation
mints a unique per-run private group, so concurrent runs never share a Hetzner
network; set `ORACLE_LIVE_PRIVATE_GROUP` only to coordinate or reproduce a
specific run.

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
own oracle-specific capabilities and wire comparison policy while delegating
provider substrate to `tools/lab`. The generic live runner still owns packet
generation, endpoint protocol comparison, report assembly, and provider
execution flow. `tools/lab` owns multi-endpoint session creation, repository
push/bootstrap, artifact collection, and cleanup; `tools/wire` owns one
endpoint and transport operations.

The Rust-side libcrafter adapters live in `tools/oracle/adapters/` as an
internal workspace package. They depend on the public `crafter` crate API and
must not add oracle-only code to `crafter`.

## CI Policy

Pull request CI runs deterministic offline and pcap oracle validation with the
Scapy backend. The live workflow runs provider dry-run planning on normal pull
request and push events through the selected oracle live provider adapter. Real
provider-backed live exchanges run only from a protected manual workflow
dispatch with explicit confirmation and configured provider prerequisites.
