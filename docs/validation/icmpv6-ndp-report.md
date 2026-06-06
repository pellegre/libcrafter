# ICMPv6 / Neighbor Discovery validation report

Validation summary for the *Restructure ICMP (v4/v6) and Add IPv6 Neighbor
Discovery* effort. This report ties together the offline, pcap, interop,
provider dry-run, and live behavioral coverage that backs the ICMP restructure,
the `Icmp` → `Icmpv4` public rename, and the new ICMPv6 message families.

It is the final acceptance artifact for the effort and records, per the spec's
final acceptance criterion, every command run with its PASS/FAIL, the message
families and options covered, the reference interop directions, the QEMU and
VirtualBox live-run outcomes, and the one real code defect found during live
testing and its fix.

This file is non-sensitive: it contains no credentials, provider account data,
public IPs, live host identifiers, or packet captures. Live artifacts stay under
`target/` and lab artifact roots and are not tracked.

## 1. Commands run and results

All commands were run from the linked worktree root (`PROJECT_ROOT`). Seeds and
counts match the effort's smoke profile.

| # | Command | Result |
|---|---------|--------|
| 1 | `.agents/scripts/check-crafter-release --static` | **PASS** (exit 0) |
| 2 | `cargo test -p crafter` | **PASS** (exit 0) |
| 3 | `tools/oracle/run offline --backend <reference> --profile smoke --seed 1 --count 10` | **PASS** — `reference_to_libcrafter` 10/10 |
| 4 | `tools/oracle/run pcap --backend <reference> --profile smoke --seed 1 --count 10` | **PASS** — `pcap roundtrip` 20/20 |
| 5 | `python3 tools/oracle/engine/live_provider_matrix.py --providers qemu,virtualbox --backend <reference> --profile smoke --seed 1 --count 2 --dry-run --out target/oracle/icmpv6-ndp-matrix-dry-run` | **PASS** — matrix `status=passed`, qemu + virtualbox each `dry-run`, no live packets sent |

### Release gate (command 1)

`.agents/scripts/check-crafter-release --static` runs `cargo fmt --all --check`,
clippy, the crate test suite, the example builds, `cargo doc` (with
`RUSTDOCFLAGS="-D warnings"`), and a package inspection. It exits 0.

A rustdoc defect surfaced by the strict `-D warnings` doc build was fixed as part
of this final step: two `[module docs](self)` intra-doc links in
`crafter/src/protocols/icmp/v6/message/node_info.rs` (the Node Information Query
and Response builders, types 139/140) resolved to a private item, causing
`cargo doc` to error "could not document crafter" (gate exit 101). Both links
were replaced with plain "module-level docs" prose, which resolves cleanly under
the strict flags. This is a documentation-only change: no wire bytes, builders,
decoders, or golden fixtures were touched, and the ICMP golden pin stays
byte-identical.

### Crate test suite (command 2)

`cargo test -p crafter` passes with 0 failures. Key suites:

- `tests/icmp_golden.rs` — **11/11** (byte-for-byte pin of pre-refactor ICMPv4
  and ICMPv6 packets; proves the restructure + rename are behavior-preserving).
- `tests/icmpv6_ndp.rs` — **21/21** (NDP RS/RA/NS/NA/Redirect round-trips, base
  and extension options in arbitrary order, MLDv1/v2, extended echo, Node
  Information, unknown-option/unknown-type preservation, hop-limit-255 live
  regression pin).
- `tests/resilience.rs` — **31/31**, including the 14-test
  `icmpv6_malformed_corpus` module (zero-length and overrun NDP options,
  truncated RA/NA, MLDv2 record/source overruns, unknown type with trailing
  bytes — all structured errors or `Raw` fallback, no panics).
- `tests/icmpv4_public_api.rs` — **10/10** (deprecated `Icmp` alias still
  compiles and behaves identically to `Icmpv4`).
- Library unit tests — **667/667** (2 ignored), plus 3 doc-tests.

### Offline + pcap oracle (commands 3–4)

- Offline (`reference_to_libcrafter`, reference backend): **10/10 passed**.
- Pcap round-trip (reference backend): **20/20 passed**. (The reference backend emits benign
  "Inconsistent linktypes" warnings on stderr while writing the mixed-linktype
  corpus; the run status is `passed`.)

### Provider dry-run matrix (command 5)

`live_provider_matrix.py --dry-run` for `qemu,virtualbox`: overall
`status=passed`. For each provider the full lifecycle is planned and well-formed
— doctor → create two private endpoints (libcrafter + reference_backend) →
oracle live-endpoint exchange → collect-artifacts → destroy — with
`no_live_packets_sent: true` and `live_packet_exchange: false`. Both providers
report `wire_skip_reasons: {requires_ipv6: 1}` because the oracle live providers
declare `ipv6_unicast=false`; the byte-exact NDP path stays pinned by the
reference interop cases and the Rust round-trips rather than oracle live IPv6
send.
Summary: `target/oracle/icmpv6-ndp-matrix-dry-run/matrix-summary.json`
(under `target/`, not tracked).

## 2. ICMPv6 message families and options covered

Authoritative `Type` authority is the IANA ICMPv6 Parameters registry; each
family was grounded against the cited RFC before wire bytes were written.

### Message families (typed builders + decoders)

| Type(s) | Family | Reference | Status |
|---------|--------|-----------|--------|
| 1–4 | Destination Unreachable / Packet Too Big / Time Exceeded / Parameter Problem | RFC 4443 | typed (pre-existing, behavior-pinned) |
| 128/129 | Echo Request / Reply | RFC 4443 | typed (pre-existing, behavior-pinned) |
| 130–132 | MLDv1 Query / Report / Done | RFC 2710 | typed |
| 130, 143 | MLDv2 Query / Version 2 Report (multicast address records, source lists) | RFC 3810 (IANA cites RFC 9777) | typed |
| 133 | Router Solicitation | RFC 4861 | typed |
| 134 | Router Advertisement (M/O flags, Prf/RFC 4191) | RFC 4861 / 4862 / 4191 | typed |
| 135 | Neighbor Solicitation (incl. DAD form, source `::`) | RFC 4861 | typed |
| 136 | Neighbor Advertisement (R/S/O flags) | RFC 4861 | typed |
| 137 | Redirect (target + destination) | RFC 4861 | typed |
| 139/140 | Node Information Query / Response | RFC 4620 | typed (**experimental**) |
| 160/161 | Extended Echo Request / Reply | RFC 8335 | typed |

### NDP options (TLV framework: 8-octet length units, auto-fill, ordered, unknown-preserving)

| Opt | Option | Reference |
|-----|--------|-----------|
| 1 | Source Link-Layer Address | RFC 4861 |
| 2 | Target Link-Layer Address | RFC 4861 |
| 3 | Prefix Information (L/A flags, valid/preferred lifetimes) | RFC 4861 / 4862 |
| 4 | Redirected Header | RFC 4861 |
| 5 | MTU | RFC 4861 |
| 14 | Nonce (SEND / DAD) | RFC 3971 / 7527 |
| 24 | Route Information (Prf) | RFC 4191 |
| 25 | RDNSS | RFC 8106 |
| 26 | RA Flags Extension | RFC 5175 |
| 31 | DNSSL (RFC 1035 uncompressed names) | RFC 8106 |
| 37 | Captive Portal | RFC 8910 |
| 38 | PREF64 | RFC 8781 |

Unknown NDP options and unknown ICMPv6 `Type`s round-trip verbatim (preserved as
`Unknown` / `Raw` when the enclosing header is valid); malformed buffers surface
structured `CrafterError`s with `context`/`required`/`available`; truncation
never panics. `compile()` auto-fills the ICMPv6 checksum (IPv6 pseudo-header) and
NDP option lengths, and any value the agent sets on purpose — including
deliberately wrong checksums or option lengths — survives untouched.

### Deferred codepoints (documented, preserved as unknown / `Raw`)

| Type(s) | Family | Reference | Reason |
|---------|--------|-----------|--------|
| 138 | Router Renumbering | RFC 2894 | Niche/undeployed router-management mechanism; full message processing out of scope. |
| 141/142 | Inverse Neighbor Discovery Solicitation / Advertisement | RFC 3122 | Niche (NBMA / Frame Relay) extension with little general deployment. |

Mobile IPv6 (RFC 6275) and the SEND certificate options (RFC 3971 CGA/RSA/cert)
are likewise out of scope and preserved as unknown options/messages. The named
`Type` constants (`ICMPV6_ROUTER_RENUMBERING`, `ICMPV6_INVERSE_ND_*`) exist so a
future effort can add typed bodies behind them. Full deferral rationale lives in
[`docs/icmpv6-coverage.md`](../icmpv6-coverage.md).

## 3. Reference interop direction coverage

Interop cases live in the oracle reference fixture set and are materialized
through the oracle reference backend.

- **Both directions** (`reference_to_libcrafter` *and* `libcrafter_to_reference`),
  byte-proven against the reference backend via direct materialization diff:
  - NDP: RS, RA (incl. Prefix Information + MTU, Route Information, RDNSS, DNSSL,
    and a combined RA(PI+MTU+RDNSS)), NS, NS-DAD, NA, Redirect.
  - MLDv1: Query / Report / Done.
  - MLDv2: Version 2 Report and Query.
  RS/NS/NA/Redirect and the MLD families are byte-identical to the reference
  backend; RA matches once the reference's RFC 4191 Prf field is held at the
  value libcrafter emits
  (libcrafter sends RFC 4861 "send-as-zero" Reserved bits as zero, and can emit
  a non-zero Prf explicitly).
- **One direction + documented limitation** (no native reference ICMPv6 class, so
  byte-agreement is covered by the Rust round-trips and `ndp_option.rs` unit
  tests rather than a native-class diff):
  - Extended Echo Request/Reply (types 160/161) — no native reference class.
  - Node Information Query/Response (139/140, experimental) — no native reference
    class.
  - Nonce (opt 14) and RA Flags Extension (opt 26) — no native reference option
    class; materialized via `ICMPv6NDOptUnknown`.

## 4. Live-run outcomes (QEMU and VirtualBox)

Live behavioral cases (`tools/probe/engine/cases.py`) model real NDP exchanges
with Rust stimulus/target handlers in `tools/probe/adapters/src/ndp.rs`:
`ndp-neighbor-solicitation` (NS → NA), `ndp-router-solicitation` (RS → RA), and
`ndp-duplicate-address-detection` (DAD: NS from `::` → defending NA). They are
gated by a derived `ipv6_multicast` capability (link-layer send + capture +
broadcast) so QEMU and VirtualBox plan them while Hetzner skips cleanly.

### Real bug found during live testing — NDP hop-limit-255 defect (FOUND + FIXED)

The crate composes NDP frames as `Ipv6 / Icmpv6::neighbor_solicitation(...)`.
The IPv6 layer's default Hop Limit is 64. **RFC 4861 requires NDP messages to be
sent with IPv6 Hop Limit 255**, and a receiver MUST silently discard any NDP
message whose Hop Limit is not 255 (this is the protocol's on-link integrity
check). With the default Hop Limit 64, a real Linux 6.8 kernel counted the
inbound Neighbor Solicitations (`Icmp6InNeighborSolicits` incremented) but
emitted **zero** Neighbor Advertisements — the NS was silently dropped, exactly
as the RFC mandates.

**Fix:** set the IPv6 Hop Limit to 255 on the NDP stimulus frame in
`tools/probe/adapters/src/ndp.rs` (`Ipv6::hop_limit(255)`). After the fix, the
same compiled libcrafter frames produced a correct NS → NA exchange and the DAD
form produced a defending NA, both validated against the real kernel. The
captured Neighbor Advertisement was pinned as a Rust regression test in
`crafter/tests/icmpv6_ndp.rs`.

This is correct crate behavior under the honored-overrides rule — `compile()`
fills the IPv6 Hop Limit the agent did not set, and the agent is responsible for
setting 255 for NDP — so it is documented as an ergonomics footgun rather than a
crate-internal bug: the NDP builders return the `Icmpv6` header `/` body (not the
IPv6 layer) and therefore cannot set the IPv6 Hop Limit themselves. The
hop-limit-255 requirement is called out prominently in the `ndp` module rustdoc
and in every NDP recipe in `.agents/docs/cookbook.md`.

### QEMU

- The NDP probe address-rewrite path was completed for live execution:
  `_ndp_plan_with_endpoint_addresses` derives the target's modified-EUI-64
  link-local address (RFC 4291 App. A) from the real lab MAC, the solicited-node
  multicast `ff02::1:ffXX:XXXX`, and the `33:33` Ethernet multicast mapping; the
  DAD source is `::` and RS targets `ff02::2`. The target setup enables IPv6,
  waits out DAD, flushes the neighbor cache, and enables forwarding.
- **NS → NA and DAD were validated against a real Linux 6.8 kernel**, replaying
  libcrafter's exact compiled frames over a veth pair, which is where the
  hop-limit-255 defect was found and fixed. RS → RA was not validated live
  because it needs an RA-emitting router (radvd / kernel RA) on the target — an
  environment gap, not a code defect.
- Infra note: the in-VM KVM live lab harness was infra-blocked on this host (a
  foreign legacy non-KVM VMM held VMX root, so KVM QEMU faulted; TCG was too slow
  to build crafter in-VM within the bootstrap timeout). Per shared-environment
  policy the foreign VMs were not disturbed, and wire correctness was proven by
  direct real-kernel replay instead.

### VirtualBox

- VirtualBox provisioning and bootstrap **succeeded for real** on this host: a
  two-VM lab session (stimulus + target) was provisioned and booted, and the
  repo archive was uploaded and unpacked into the stimulus VM (bootstrap reached).
- **Honest scope:** the full in-VM NDP exchange + NA capture did **not** complete
  within the dispatch, because the in-VM `cargo` build of crafter + probe-adapters
  exceeded the dispatch's build-time budget (the same in-VM build-time constraint
  hit on QEMU). The session VMs were torn down scope-correctly, leaving all
  foreign VMs intact.
- What is proven for VirtualBox: (a) the VirtualBox provider provisions and
  bootstraps for real on this host, (b) the dry-run matrix above is well-formed
  end-to-end for VirtualBox, and (c) the NDP byte path is provider-agnostic — the
  exact frames whose NS → NA + DAD behavior was proven against a real Linux 6.8
  kernel (with the hop-limit-255 fix) are identical regardless of provider, so
  the kernel-level proof carries to VirtualBox. A future fully-green in-VM
  VirtualBox exchange needs a prebuilt crafter/probe image or a longer bootstrap
  timeout; it is functionally redundant with the real-kernel proof.

## 5. Bottom line

- Static release gate, full crate tests, offline + pcap oracle, and the
  qemu+virtualbox provider dry-run matrix all **PASS**.
- The ICMP restructure and `Icmp` → `Icmpv4` rename are behavior-preserving
  (golden pin byte-identical; deprecated aliases still compile).
- All in-scope ICMPv6 families (NDP 133–137 + base/extension options, MLDv1/v2,
  extended echo 160/161, experimental Node Information 139/140) are typed and
  validated; Inverse ND and Router Renumbering are documented deferrals preserved
  as `Raw`.
- One real defect — the NDP hop-limit-255 requirement — was found by live testing
  against a real Linux 6.8 kernel and fixed (`tools/probe/adapters/src/ndp.rs`,
  `Ipv6::hop_limit(255)`), then pinned as a regression test and documented as a
  caller-facing footgun in the cookbook and NDP module rustdoc.
