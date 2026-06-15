# Oracle Validation

The oracle validates packet behavior against reference backends owned by
`tools/oracle/`. Keep backend-specific logic and backend names inside that tool
tree; crate tests, public docs, and fixture docs should describe only the
oracle boundary.

Oracle answers this question: given one packet plan, do libcrafter and a
reference backend agree on the emitted bytes and parsed model? Kernel and
service behavior checks belong to [probe validation](probe.md).

Probe answers a different question: given a packet built by libcrafter and sent
inside a disposable lab session, does the peer kernel or controlled service
respond as expected, and can libcrafter decode and validate that response? Keep
those behavioral checks in `tools/probe/`; they are not oracle packet
equivalence cases.

The probe `behavior` profile is the full DNS/DHCP/ARP/UDP peer-response suite:
forty deterministic cases, ten per protocol, with dry-run plans that expose the
stimulus, expected response, provider requirements, target setup, and validation
contract. DNS and UDP use controlled target services plus decoded UDP/DNS or
UDP/ICMP validation. DHCP uses a controlled DHCP/BOOTP responder on a private
link-layer segment. ARP uses target kernel behavior on a link-layer-capable
segment with setup for aliases, cache flushes, padding, provider MAC checks,
and filtered captures.

Run probe behavior validation through the dry-run path first:

```sh
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --count 40 --out target/probe/behavior-dry-run
python3 tools/probe/engine/provider_matrix.py --providers hetzner,qemu,virtualbox,docker --dry-run --profile behavior --seed 1052 --count 40 --out target/probe/provider-matrix
```

Live probe behavior runs stay behind explicit confirmation and disposable lab
sessions. The guarded workflow keeps dry-run as the default when no live
provider is selected:

```sh
if [ -n "${LIBCRAFTER_PROBE_LIVE_PROVIDER:-}" ]; then
  tools/probe/run --provider "$LIBCRAFTER_PROBE_LIVE_PROVIDER" --confirm-live-run --profile behavior --seed 1051 --count 40 --out target/probe/acceptance/51-live-behavior-suite
else
  tools/probe/run --provider qemu --dry-run --profile behavior --seed 1051 --count 40 --out target/probe/acceptance/51-live-behavior-suite-dry-run
fi
```

Provider capability skips are part of the probe contract. Hetzner can plan
IPv4 unicast DNS and UDP service cases but skips DHCP and ARP link-layer cases.
QEMU, VirtualBox, and Docker private sessions can plan the full private-lab
behavior suite when local prerequisites are available. A provider skip must
come from a missing declared capability; a supported case that fails to build,
send, capture, decode, or validate is a failure to fix in libcrafter or probe
infrastructure.

## Oracle CLI modes

`tools/oracle/run` is the single entrypoint for every oracle mode. Each mode is
a subcommand; the generation/validation modes share `--backend {scapy,wireshark}`
(default `scapy`), `--profile` (default `smoke`), `--seed`, `--count`,
`--family`, `--root`, `--case`, `--feature`, `--index`, and `--out`. The modes
are:

- `corpus` — generate a reusable packet corpus artifact (`plans.json`) that the
  other modes can replay with `--corpus`. Flags: generation options + `--out`,
  `--direction`.
- `offline` — compare libcrafter raw vectors and normalized decode models
  against the reference backend without root, pcap files, or live traffic.
  Flags: generation options + `--direction`, `--corpus`, `--dry-plan`,
  `--emit-vectors`, `--emit-decoded`, `--keep-artifacts`.
- `pcap` — exercise classic pcap write/read, link-type selection, and roundtrip
  decoding. Flags: generation options + `--direction`, `--corpus`, `--dry-plan`
  (alias `--dry-run`), `--keep-artifacts`.
- `live` — route provider-backed packet exchange through lab-backed oracle
  provider adapters; the default is a planned run and real traffic is gated.
  Flags: generation options + `--provider` (required; `local-dry-run` or a
  registered provider), `--direction`, `--corpus`, `--dry-run`,
  `--confirm-live-run`, `--keep-wire-endpoints`.
- `generate` — emit deterministic packet plans as metadata only, no backend.
  Flags: common + generation options + `--direction`.
- `report` — run final oracle validation and write a summary. Flags: `--out`.
- `specs` — inspect executable oracle specs: `specs validate` loads and
  validates all specs (`--json`, `--strict`), `specs suite` emits the
  reproducible offline case suite for a `--family` (`--backend`, `--profile`,
  `--seed`, `--out`, `--json`, `--run`).
- `backend-info` — print backend dependency and version metadata. Flags:
  `--backend`.
- `self-check` — run lightweight oracle engine self checks. No flags.

Safe offline and provider dry-run examples (no root, no credentials, no live
traffic):

```sh
tools/oracle/run offline --backend scapy --profile smoke --seed 1 --count 10
tools/oracle/run pcap --backend scapy --profile smoke --seed 1 --count 10
tools/oracle/run live --backend scapy --provider local-dry-run --profile smoke --seed 1 --count 10
```

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

### IPv4 Coverage

The IPv4 behavioral suite stays offline and uses documentation address space.
Use these focused checks when touching IPv4 builders, decode behavior, summaries,
fixtures, malformed coverage, pcap RawIp coverage, or oracle specs:

```sh
cargo test -p crafter --test ipv4_public_api
cargo test -p crafter --test fixture_suite ipv4
cargo test -p crafter --test resilience ipv4
cargo test -p crafter --test fixture_suite pcap_fixture_roundtrips
tools/oracle/run offline --profile ipv4-enrichment --seed 1 --count 12 --root l3:ipv4
.agents/scripts/check-crafter-release --static
```

The fixture-suite IPv4 filter covers named IPv4 fixture assertions. The pcap
roundtrip check is the focused RawIp IPv4 DSCP/ECN pcap fixture assertion.
Keep live IPv4 packet exchange out of this suite unless a separate protected
provider workflow explicitly asks for it.

### DNS Coverage

The DNS family has an extensive reference-backed oracle suite that validates packet
construction, decode, and capture behavior, not DNS client, resolver, or server
semantics. It covers every implemented DNS group: header (id, QR, AA/TC/RD/RA/
AD/CD flags, opcodes, rcodes, raw flags, section counts), names and compression,
questions and QTYPE/QCLASS axes, A/AAAA, NS/CNAME/PTR, MX/TXT, SOA/SRV,
raw-unknown records, EDNS OPT and options, DNSSEC DS/DNSKEY/RRSIG/NSEC/NSEC3,
SVCB/HTTPS, section placement, and malformed names and RDATA.

Reproduce the DNS coverage offline, in pcap, and as a live dry-run; offline is
the default and the others reuse the same case contract:

```sh
tools/oracle/run offline --family dns --profile ci --seed 3001 --count 50
tools/oracle/run pcap --family dns --profile ci --seed 3002 --count 50
tools/oracle/run live --provider hetzner --dry-run --family dns --profile ci --seed 3003 --count 50 --direction live_exchange
tools/oracle/run specs suite --family dns --run
```

Real packet exchange is opt-in and gated behind the protected provider workflow:

```sh
tools/oracle/run live --provider hetzner --confirm-live-run --family dns --profile ci --count 50 --direction live_exchange
```

A few DNS features are not strict-byte comparable and use raw bytes or a
normalized decoded-model comparison: compressed names compare as the normalized
model (libcrafter re-encodes uncompressed); SVCB/HTTPS RDATA is supplied as
backend-owned raw bytes because the high-level SvcParam encoder re-interprets
known keys; `\DDD` name escapes are flattened by the high-level encode; and malformed
inputs are covered by the crate corpus and `resilience.rs`, not an offline oracle
comparison. See [DNS wire coverage](../guide/dns.md) for the per-record contract.

### IPv6 Enrichment Offline Profile

The `ipv6-enrichment` oracle profile is the focused offline reproducibility
suite for the enriched IPv6 base and extension-header packet surface. It covers
base field boundaries, unknown next-header raw preservation, Hop-by-Hop and
Destination Options, Fragment Header, generic Routing, Mobile Routing Type 2,
Segment Routing, routed TCP/ICMPv6 chains, and the checksum context carried
through supported extension chains. It runs without live traffic or provider
infrastructure and should keep its artifacts under `target/oracle/`.

Run the focused crate checks first. They consume checked-in documentation-space
fixtures and malformed corpus rows, and they do not need reference backend
imports or `target/oracle/` artifacts:

```sh
cargo test -p crafter --test ipv6_public_api
cargo test -p crafter --test fixture_suite ipv6
cargo test -p crafter --test fixture_suite pcap_ipv6_roundtrip
cargo test -p crafter --test resilience ipv6
```

The fixture filters cover byte-preserving IPv6 base, UDP/TCP/ICMPv6, options,
routing, fragment, and summary/show checks. The `pcap_ipv6_roundtrip` filter
pins the RawIP IPv6 pcap fixture path, link type, timestamp, captured bytes,
decode surface, and compile/decode/compile roundtrip. The resilience filter
covers curated IPv6 decode surfaces, structured errors for malformed IPv6 base
and extension buffers, random decode panic guards, unknown-next-header raw
roundtrips, and extension-chain roundtrips.

Then run the oracle profile with fixed seeds and explicit output directories:

```sh
tools/oracle/run offline --profile ipv6-enrichment --seed 2 --count 20 --root l3:ipv6 --out target/oracle/ipv6-enrichment-offline
tools/oracle/run offline --direction reference_to_libcrafter --profile ipv6-enrichment --seed 3 --count 12 --root l3:ipv6 --out target/oracle/ipv6-enrichment-reference-to-libcrafter
tools/oracle/run offline --direction libcrafter_to_reference --profile ipv6-enrichment --seed 4 --count 12 --root l3:ipv6 --out target/oracle/ipv6-enrichment-libcrafter-to-reference
```

Use the default offline run for the profile-selected comparison set, then use a
directed run such as `reference_to_libcrafter` or
`libcrafter_to_reference` when isolating one side's encode/decode behavior. Use
`--seed`, `--count`, and `--index` to make any failure rerunnable. Malformed
IPv6 extension cases are declared as structured-error coverage, but they are
not offline byte-compared because malformed extension buffers do not have a
comparable strict-byte oracle path; keep those checks in `resilience.rs` and
the malformed fixture corpus.

Provider-backed live exchange is not part of the IPv6 enrichment qualification.
If live-mode planning needs to be inspected without creating infrastructure,
start with the local dry-run path and keep the result under `target/oracle/`;
real provider traffic remains an explicit protected workflow with
`--confirm-live-run`:

```sh
tools/oracle/run live --provider local-dry-run --profile ipv6-enrichment --seed 5 --count 10 --root l3:ipv6 --out target/oracle/ipv6-enrichment-live-local-dry-run
```

For the broader crate and workspace pass around the focused IPv6 suite, run the
normal crate tests and the workspace preflight before the release gate:

```sh
cargo test -p crafter
cargo test --workspace
.agents/scripts/check-crafter-release --static
```

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

## IP Fragment Transform Validation

`IpDefrag` and `IpFragment` validation follows the same safe ladder as the rest
of the packet stack: transform unit tests, offline oracle checks, pcap
roundtrips, provider dry-runs, and only then explicitly confirmed lab-backed
live behavior. Fragment examples and generated tools should use documentation
addresses and dry-run or pcap writers unless a protected provider workflow has
been selected.

Run the offline transform and fixture checks first. They do not create
infrastructure and keep artifacts under `target/oracle/` or `target/examples/`.
`ORACLE_BACKEND` should name the oracle backend being validated:

```sh
cargo test -p crafter wire::ip
cargo test -p crafter --test fixture_suite ip_fragment
tools/oracle/run offline --backend "$ORACLE_BACKEND" --family ip --profile fragmentation-smoke --seed 1201 --count 50 --out target/oracle/ip-fragment-offline
tools/oracle/run pcap --backend "$ORACLE_BACKEND" --family ip --profile fragmentation-smoke --seed 1203 --count 50 --out target/oracle/ip-fragment-pcap
cargo run -p crafter --example ip_defrag_pcap_summary -- --out target/examples/ip-defrag-pcap-summary.json
```

The pcap summary example is the inspectable bridge between oracle fixtures and
lab artifacts: it reads fragment pcaps through public `crafter` APIs, runs
`IpDefrag`, and writes packet hashes, payload hashes, metadata, and transform
traces as JSON.

Live IP fragmentation validation must not originate as raw traffic from the
developer machine. Use lab-backed providers only, with disposable `stimulus`
and `target` roles, constrained MTUs, offloads disabled where the provider
supports it, and oracle-owned artifacts rooted at
`target/oracle/ip-fragment-*`. The
`ip-fragment-smoke` provider dry-run profile writes an oracle workload plan for
small MTU setup, offload handling, oversized/crafted fragment traffic, pcap
capture, and payload hash comparison. Artifact audits live in
`tools/oracle/engine/ip_fragment_artifacts.py`. Start with provider dry-runs:

```sh
tools/oracle/run live --backend "$ORACLE_BACKEND" --provider qemu --dry-run --family ip --profile ip-fragment-smoke --seed 1204 --count 20 --out target/oracle/ip-fragment-qemu-dry-run
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox,docker --backend "$ORACLE_BACKEND" --profile ip-fragment-smoke --seed 1204 --count 20 --dry-run --out target/oracle/ip-fragment-provider-matrix-dry-run
```

Real provider-backed fragment behavior is a protected workflow. It must use
`--confirm-live-run`, write pcaps, decoded summaries, transform JSON, provider
manifests, command logs, and `report.json` under a fresh
`target/oracle/ip-fragment-*` directory, and finish with teardown records. When a
provider lacks the needed capability or prerequisite, the run should write a
structured skip artifact under the same directory instead of silently passing:

```sh
tools/oracle/run live --backend "$ORACLE_BACKEND" --provider qemu --confirm-live-run --family ip --profile ip-fragment-smoke --seed 1205 --count 20 --out target/oracle/ip-fragment-qemu-live
python3 tools/oracle/engine/live_provider_matrix.py --providers qemu,virtualbox --backend "$ORACLE_BACKEND" --profile ip-fragment-smoke --seed 1205 --count 5 --real --confirm-live-run --skip-unavailable --out target/oracle/ip-fragment-vm-live
```

Do not keep live endpoints after fragment validation except for an explicit
debugging session approved by the operator. A completed run needs either
teardown evidence for every disposable session or a skip artifact explaining why
no live session was created.

## UDP Options Validation

UDP options validation exercises the RFC 9868 surplus area after UDP Length,
normal UDP checksum handling, OCS/APC handling, option status reporting, and
unknown SAFE/UNSAFE preservation. Use a UDP-filtered corpus when changing
`Udp`, `UdpOptions`, `UdpOption`, or oracle UDP option normalization:

```sh
tools/oracle/run offline --profile smoke --seed 9868 --count 100 --family udp --out target/oracle/udp-options-offline
tools/oracle/run offline --direction reference_to_libcrafter --profile smoke --seed 9868 --count 100 --family udp --out target/oracle/udp-options-reference-to-libcrafter
tools/oracle/run offline --direction libcrafter_to_reference --profile smoke --seed 9868 --count 100 --family udp --out target/oracle/udp-options-libcrafter-to-reference
```

Pcap mode checks that the same UDP surplus bytes survive classic pcap
write/read and raw-link normalization:

```sh
tools/oracle/run pcap --profile smoke --seed 9868 --count 100 --family udp --out target/oracle/udp-options-pcap
cargo test -p crafter --test fixture_suite udp_options
```

Provider-backed live planning stays dry-run by default. The local dry-run path
filters the bounded UDP option live case set without sending packets, and the
provider matrix records provider-specific skips for cases such as IPv6
zero-checksum status or DHCP-style L2 broadcast requirements:

```sh
tools/oracle/run live --provider local-dry-run --profile smoke --seed 9868 --count 20 --family udp --out target/oracle/udp-options-live-local-dry-run
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox,docker --profile smoke --seed 9868 --count 20 --dry-run --out target/oracle/udp-options-live-dry-run-matrix
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
`tools/endpoint` owns one endpoint and artifact transport; see
[docs/operations/endpoint.md](endpoint.md) for endpoint provider credentials, lifecycle
commands, artifacts, and cleanup.

Docker is available as a lab-backed oracle provider through the constrained
`docker/private` lab adapter. The Docker adapter owns only the private
multi-endpoint substrate; oracle still owns the `libcrafter` and
`reference_backend` workload setup. The Docker private capability model
advertises IPv4 unicast, link-layer send and capture, broadcast, provider MAC
knowledge, and controlled services, but not IPv6 or a controlled router.

Docker `lan` and `wan` are direct endpoint smokes for NAT-backed L3 reachability
from one container. They are not oracle lab-backed multi-endpoint modes and do
not claim LAN L2, WAN L2, or public inbound behavior:

```sh
tools/endpoint/run doctor --provider docker --exposure lan --dry-run
tools/endpoint/smoke/live_docker_lan_icmp.py --plan-only
tools/endpoint/smoke/live_docker_wan_dns.py --plan-only
```

Use the non-provider-backed local dry-run or provider-backed dry-runs for
planning and CI-safe checks:

```sh
tools/oracle/run live --provider local-dry-run --profile smoke --seed 1 --count 10
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role libcrafter --role reference_backend --json
tools/lab/run plan --provider docker --dry-run --profile smoke --seed 1 --role libcrafter --role reference_backend --json
tools/oracle/run live --provider hetzner --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider qemu --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider virtualbox --dry-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider docker --dry-run --profile smoke --seed 12345 --count 10
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox,docker --profile smoke --seed 12345 --count 5 --dry-run --out target/oracle/provider-matrix-dry-run
```

Real provider-backed validation is reserved for explicit protected workflows on
disposable endpoints and requires `--confirm-live-run`. Provider selection
still uses the same live oracle command and adapter registry:

```sh
tools/oracle/run live --provider hetzner --confirm-live-run --profile smoke --seed 12345 --count 10
tools/oracle/run live --provider docker --confirm-live-run --profile smoke --seed 12345 --count 10
```

For local VM providers, use the guarded matrix smoke path. It runs QEMU and
VirtualBox endpoint doctor checks first, uses a small corpus, and records
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

See [lab.md](lab.md) for lab session metadata and [docs/operations/endpoint.md](endpoint.md)
for single-endpoint provider credentials, artifacts, and cleanup.

## ICMPv4 Live Matrix

The ICMPv4 live matrix runs the oracle live path against the `l2:ipv4` root
with the `icmpv4_live` feature. It validates packet write/parse parity: that
libcrafter and the selected reference backend agree on the bytes placed on the
wire and on the decoded model after a real round trip over a Hetzner private
network. It does not validate kernel ICMP behavior, ping semantics, or
router-generated errors. The root is IPv4-rooted; comparison canonicalizes to
the IPv4 header, so Ethernet fields are not part of ICMP pass/fail.

Use the offline and dry-run paths for planning and CI-safe checks. Neither
sends packets or creates infrastructure, and neither needs a credential:

```sh
tools/oracle/run offline --root l2:ipv4 --feature icmpv4_live --profile smoke --seed 22 --count 20 --out target/oracle/icmp-live/offline
tools/oracle/run live --provider hetzner --dry-run --root l2:ipv4 --feature icmpv4_live --profile smoke --seed 70 --count 40 --out target/oracle/icmp-live/dry
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner --profile smoke --seed 70 --count 20 --dry-run --out target/oracle/icmp-live/matrix-dry
```

Real Hetzner exchange is explicit and protected. It requires `--confirm-live-run`
and a Hetzner credential in the environment (`HETZNER_API_TOKEN`, or
`HCLOUD_TOKEN`); never store the token value in a tracked file:

```sh
tools/oracle/run live --provider hetzner --confirm-live-run --root l2:ipv4 --feature icmpv4_live --profile smoke --seed 71 --count 60 --out target/oracle/icmp-live/full-matrix
```

Artifacts land under the requested `--out` directory, e.g.
`target/oracle/icmp-live/<step>/`, with the live report at
`<out>/live/report.json`. Each `run live` invocation mints a unique per-run
private group so concurrent live runs (for example an ICMP run and a DNS run,
possibly in different worktrees) never share a Hetzner network or collide on
private IP allocation. Override the group with `ORACLE_LIVE_PRIVATE_GROUP` only
to coordinate or reproduce a specific run; do not commit live IPs or captures.

## CI Expectations

Pull request CI should run deterministic corpus, offline, pcap, provider-backed
dry-run, and probe dry-run checks. Oracle provider checks are selected
through the live provider adapter registry. Real live packet exchange must stay
behind explicit protected workflow confirmation and cleanup logic. Dry-runs are
the default validation path for provider-backed lab, oracle, and probe checks.

Recommended local preflight:

```sh
cargo test --workspace
tools/oracle/run corpus --profile ci --seed 12345 --count 100 --out target/oracle/final-corpus
tools/oracle/run offline --corpus target/oracle/final-corpus/plans.json --out target/oracle/final-offline
tools/oracle/run pcap --corpus target/oracle/final-corpus/plans.json --out target/oracle/final-pcap
python3 tools/oracle/engine/live_provider_matrix.py --providers hetzner,qemu,virtualbox,docker --profile ci --seed 12345 --count 100 --dry-run --out target/oracle/final-live-matrix
tools/probe/run --provider hetzner --dry-run --profile smoke --seed 1 --count 10 --out target/probe/final-dry-run
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10 --out target/probe/final-dry-run-qemu
tools/probe/run --provider virtualbox --dry-run --profile smoke --seed 1 --count 10 --out target/probe/final-dry-run-virtualbox
tools/probe/run --provider docker --dry-run --profile smoke --seed 1 --count 10 --out target/probe/final-dry-run-docker
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --count 40 --out target/probe/final-behavior-dry-run
python3 tools/probe/engine/provider_matrix.py --providers hetzner,qemu,virtualbox,docker --dry-run --profile behavior --seed 1052 --count 40 --out target/probe/final-provider-matrix
.agents/scripts/check-crafter-release --static
```

Oracle artifacts default below `target/oracle/`, with mode-specific reports
under `target/oracle/corpus`, `target/oracle/offline`, `target/oracle/pcap`,
and `target/oracle/live`.
Keep promoted fixture bytes under `crafter/tests/fixtures/` and reference
backend ownership under `tools/oracle/`.
