# Oracle Validation

The oracle validates packet behavior against reference backends owned by
`tools/oracle/`. Keep backend-specific logic and backend names inside that tool
tree; crate tests, public docs, and fixture docs should describe only the
oracle boundary.

Oracle answers this question: given one packet plan, do libcrafter and a
reference backend agree on the emitted bytes and parsed model? Kernel and
service behavior checks belong to [probe validation](probe.md).

## Corpus Generation

Corpus generation writes the ordered packet plans shared by validation modes:

```sh
tools/oracle/run corpus --profile smoke --seed 1 --count 10
```

The artifact is written to `target/oracle/corpus/plans.json` by default. It
records the corpus id, selected specs, requested filters, backend metadata,
libcrafter metadata, ordered packet plans, and per-packet eligibility for
offline, pcap, and wire modes. Reuse `--corpus <path>` to run the exact same
packet set through multiple validation levels:

```sh
tools/oracle/run offline --corpus target/oracle/corpus/plans.json
tools/oracle/run pcap --corpus target/oracle/corpus/plans.json
tools/oracle/run live --provider hetzner --dry-run --corpus target/oracle/corpus/plans.json
```

## Offline Validation

Offline validation compares generated raw packet vectors and normalized decode
models without root privileges, pcap files, or live traffic:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
```

Use `--profile`, `--seed`, and `--count` to make failures reproducible. When a
report identifies a packet index, rerun with the same inputs and `--index`.
When a corpus exists, prefer `--corpus` so the same packet appears in the same
position across offline, pcap, and live dry-runs.

The checked-in fixture suite complements oracle validation. Fixture tests decode
committed bytes and pcaps, assert typed layers and stable fields, compare selected
summaries, verify byte-preserving roundtrips where promised, and exercise named
malformed inputs with structured error assertions. These tests run without
reference backend imports or `target/oracle/` artifacts.

Useful focused fixture checks:

```sh
cargo test -p crafter --test fixture_suite
cargo test -p crafter --test resilience malformed_corpus_reports_structured_errors
```

### DNS Coverage

The DNS family has an extensive Scapy-backed suite that validates packet
construction, decode, and capture behavior, not DNS client, resolver, or server
semantics. It covers every implemented DNS group: header (id, QR, AA/TC/RD/RA/
AD/CD flags, opcodes, rcodes, raw flags, section counts), names and compression,
questions and QTYPE/QCLASS axes, A/AAAA, NS/CNAME/PTR, MX/TXT, SOA/SRV,
raw-unknown records, EDNS OPT and options, DNSSEC DS/DNSKEY/RRSIG/NSEC/NSEC3,
SVCB/HTTPS, section placement, and malformed names and RDATA.

Reproduce the DNS coverage offline, in pcap, and as a live dry-run; offline is
the default and the others reuse the same case contract:

```sh
tools/oracle/run offline --backend scapy --family dns --profile ci --seed 3001 --count 50
tools/oracle/run pcap --backend scapy --family dns --profile ci --seed 3002 --count 50
tools/oracle/run live --backend scapy --provider hetzner --dry-run --family dns --profile ci --seed 3003 --count 50 --direction live_exchange
tools/oracle/run specs suite --family dns --run
```

Real packet exchange is opt-in and gated behind the protected provider workflow:

```sh
tools/oracle/run live --backend scapy --provider hetzner --confirm-live-run --family dns --profile ci --count 50 --direction live_exchange
```

A few DNS features are not strict-byte comparable and use raw bytes or a
normalized decoded-model comparison: compressed names compare as the normalized
model (libcrafter re-encodes uncompressed); SVCB/HTTPS RDATA is supplied as
Scapy-owned raw bytes because the high-level SvcParam encoder re-interprets known
keys; `\DDD` name escapes are flattened by the high-level encode; and malformed
inputs are covered by the crate corpus and `resilience.rs`, not an offline oracle
comparison. See [DNS wire coverage](dns.md) for the per-record contract.

## Pcap Validation

Pcap validation exercises packet materialization, classic pcap write/read
behavior, link type selection, and roundtrip decoding:

```sh
tools/oracle/run pcap --profile smoke --seed 1 --count 10
```

Use pcap mode when changes affect link types, timestamps, pcap framing, or
decode behavior that should survive file serialization.
Packets that cannot be represented in the requested pcap mode are reported as
skipped with a stable reason.

## UDP Options Validation

UDP options validation exercises the RFC 9868 surplus area after UDP Length,
normal UDP checksum handling, OCS/APC handling, option status reporting, and
unknown SAFE/UNSAFE preservation. Use a UDP-filtered corpus when changing
`Udp`, `UdpOptions`, `UdpOption`, or oracle UDP option normalization:

```sh
tools/oracle/run offline --backend scapy --profile smoke --seed 9868 --count 100 --family udp --out target/oracle/udp-options-offline
tools/oracle/run offline --backend scapy --direction reference_to_libcrafter --profile smoke --seed 9868 --count 100 --family udp --out target/oracle/udp-options-reference-to-libcrafter
tools/oracle/run offline --backend scapy --direction libcrafter_to_reference --profile smoke --seed 9868 --count 100 --family udp --out target/oracle/udp-options-libcrafter-to-reference
```

Pcap mode checks that the same UDP surplus bytes survive classic pcap
write/read and raw-link normalization:

```sh
tools/oracle/run pcap --backend scapy --profile smoke --seed 9868 --count 100 --family udp --out target/oracle/udp-options-pcap
cargo test -p crafter --test fixture_suite udp_options
```

Provider-backed live planning stays dry-run by default. The local dry-run path
filters the bounded UDP option live case set without sending packets, and the
provider matrix records provider-specific skips for cases such as IPv6
zero-checksum status or DHCP-style L2 broadcast requirements:

```sh
tools/oracle/run live --backend scapy --provider local-dry-run --profile smoke --seed 9868 --count 20 --family udp --out target/oracle/udp-options-live-local-dry-run
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox --backend scapy --profile smoke --seed 9868 --count 20 --dry-run --out target/oracle/udp-options-live-dry-run-matrix
```

## Live Validation

Live validation routes provider-backed packet exchange through lab-backed
oracle provider adapters. It uses the same corpus contract as offline and pcap
modes, then filters each packet by provider capabilities and explicit mutation
policy. Reports keep generated, eligible, skipped, sent, captured, parsed, byte
comparison, decode comparison, passed, and failed counts.

Provider-backed adapters are selected by `--provider` and registered under
`tools/oracle/engine/providers/`. They bind oracle policy to a lab provider,
but the lab provider adapters own substrate lifecycle only. Providers create,
connect, describe, and tear down disposable endpoints; they do not install
oracle packages or define workload bootstrap commands.

`tools/lab` owns repository archive transfer, remote unpack, bootstrap context,
artifacts, and cleanup records. Oracle owns the `libcrafter` and
`reference_backend` workload setup that runs after lab has unpacked the
repository. Packet generation, endpoint protocol comparison, report assembly,
and the generic provider execution flow remain in the oracle runner.
`tools/wire` owns one endpoint and artifact transport.

This refactor does not introduce Docker. A future Docker path would be a
workload runner behind oracle bootstrap for the `libcrafter` or
`reference_backend` role, not a provider abstraction.

Use the non-provider-backed local dry-run or provider-backed dry-runs for
planning and CI-safe checks:

```sh
tools/oracle/run live --provider local-dry-run --profile smoke --seed 1 --count 10
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role libcrafter --role reference_backend --json
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider qemu --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider virtualbox --dry-run --profile smoke --seed 12345 --count 10
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox --profile smoke --seed 12345 --count 5 --dry-run --out target/oracle/provider-matrix-dry-run
```

Real provider-backed validation is reserved for explicit protected workflows on
disposable wire endpoints and requires `--confirm-live-run`. Provider selection
still uses the same live oracle command and adapter registry:

```sh
tools/oracle/run live --provider hetzner --confirm-live-run --profile smoke --seed 12345 --count 10
```

For local VM providers, use the guarded matrix smoke path. It runs QEMU and
VirtualBox wire doctor checks first, uses a small corpus, and records
structured skips by default when VM creation is not explicitly enabled:

```sh
python3 tools/oracle/engine/live_provider_matrix.py --providers qemu,virtualbox --profile smoke --seed 12345 --count 2 --real --skip-unavailable --out target/oracle/provider-matrix-vm-real
```

Use `--allow-vm-create` or `LIBCRAFTER_ORACLE_VM_SMOKE_ALLOW_CREATE=1` in a lab
run when the matrix should pass `--confirm-live-run` to the same oracle live
command and create disposable local VMs. Use `--strict-vm-smoke` or
`LIBCRAFTER_ORACLE_VM_SMOKE_STRICT=1` when missing VM prerequisites or disabled
VM creation should fail the qualification run. QEMU uses `qemu/private` with
private group `oracle-live-private`; VirtualBox uses `virtualbox/lan` with the
bridged interface discovered by `VBoxManage` or requested through
`LIBCRAFTER_VBOX_BRIDGE_IFACE`.

See [lab.md](lab.md) for lab session metadata and [wire.md](wire.md) for
single-endpoint provider credentials, artifacts, and cleanup.

## CI Expectations

Pull request CI should run deterministic corpus, offline, pcap, provider-backed
wire dry-run, and probe dry-run checks. Oracle provider checks are selected
through the live provider adapter registry. Real live packet exchange must stay
behind explicit protected workflow confirmation and cleanup logic. Dry-runs are
the default validation path for provider-backed lab, oracle, and probe checks.

Recommended local preflight:

```sh
cargo test --workspace
tools/oracle/run corpus --profile ci --seed 12345 --count 100 --out target/oracle/final-corpus
tools/oracle/run offline --corpus target/oracle/final-corpus/plans.json --out target/oracle/final-offline
tools/oracle/run pcap --corpus target/oracle/final-corpus/plans.json --out target/oracle/final-pcap
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox --profile ci --seed 12345 --count 100 --dry-run --out target/oracle/final-live-matrix
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10 --out target/probe/final-dry-run
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10 --out target/probe/final-dry-run-qemu
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10 --out target/probe/final-dry-run-virtualbox
```

Oracle artifacts default below `target/oracle/`, with mode-specific reports
under `target/oracle/corpus`, `target/oracle/offline`, `target/oracle/pcap`,
and `target/oracle/live`.
Keep promoted fixture bytes under `crafter/tests/fixtures/` and reference
backend ownership under `tools/oracle/`.
