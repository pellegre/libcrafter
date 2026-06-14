# TCP Wire Coverage

This page describes the TCP packet-layer support in the `crafter` crate: what
the `Tcp` layer builds and decodes today, how it fills dependent header fields
on `compile()`, how it preserves deliberate overrides, how TCP options are typed
and classified, and what is intentionally out of scope.

`crafter` treats TCP as one packet layer. It builds, compiles, decodes,
summarizes, and shows like every other layer, slotting into `/` composition,
`compile()`, the `decode_from_l3` entrypoints, `summary()`, and `show()`. It is
**not** a TCP/IP stack, a connection state machine, a reassembler, a congestion
controller, a scanner, or a fuzzer. See
[Explicit exclusions](#explicit-exclusions).

All protocol facts on this page trace to reviewed RFC text and IANA registries,
not model memory. The authoritative, citation-by-citation source record is
[`docs/tcp-rfc-manifest.md`](../internal/manifests/tcp-rfc-manifest.md); this guide summarizes the
user-facing API built on top of it. See [Evidence](#evidence) for the source
set.

## Coverage at a glance

| Area | State | Notes |
| --- | --- | --- |
| Header (ports, seq, ack, window, urgent pointer) | Supported | Builder setters; explicit values honored. |
| Data Offset / header length | Auto-filled | Filled from padded option bytes on `compile()`; explicit value preserved, even when intentionally malformed. |
| Control bits (flags) | Supported | Raw `flags()` word, per-bit `flag()`, and named helpers. AE/CWR/ECE ECN helpers included. |
| Reserved bits | Supported | Set explicitly; preserved within the validation model. |
| Checksum (IPv4 / IPv6 pseudo-header) | Auto-filled | Filled from network checksum context; explicit value preserved; left zero with no context. |
| Options (typed) | Supported | MSS, Window Scale, SACK-Permitted, SACK/D-SACK, Timestamps, User Timeout, Fast Open, MPTCP, TCP-AO, TCP-ENO, AccECN, experimental ExID. |
| Options (unknown / obsolete) | Supported (preserved) | Round-trip verbatim as `Generic`, classified against the IANA registry. |
| Option classification | Supported | `TcpOptionKindClass`: `Assigned`, `Experimental`, `Unassigned`. |
| Decode (structured errors) | Supported | Malformed headers and options return typed errors with context; never a panic. |
| Inspection (`summary` / `show`) | Supported | One-line summary plus a full field tree with classified option summary. |
| Sizing helpers | Supported | `effective_mss`, `max_tcp_payload`, `option_budget`, `sequence_space_len`, and friends. |
| Application dispatch by port | Supported | Only post-header TCP payload bytes reach application decoders. |
| TCP-AO / TCP-ENO crypto | Out of scope | Bytes preserved for inspection; no MAC, key, or negotiation logic. |
| MPTCP connection logic | Out of scope | Subtype parsed, bytes preserved; no multipath state. |
| Stream reassembly, state machine, congestion control | Out of scope | See [Explicit exclusions](#explicit-exclusions). |
| IP fragmentation / reassembly | Supported outside TCP | `IpFragment` / `IpDefrag` packet-stream transforms handle IP datagrams; TCP segmentation and TCP reassembly remain future work. |

## TCP construction

The `Tcp` layer is exported through `crafter::prelude::*` (also
`crafter::Tcp` and `crafter::protocols::transport::Tcp`). Build it with the
`Tcp::new()` builder, set fields with chained setters, and compose it onto an IP
layer with `/`:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let tcp = Tcp::new()
    .sport(41000)
    .dport(443)
    .seq(1)
    .flags(TCP_FLAG_SYN);

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(Ipv4Addr::new(198, 51, 100, 20))
    / tcp;

let compiled = packet.compile()?;
println!("{}", packet.summary());
```

`Tcp::new()` gives deterministic builder defaults (source port 20, destination
port 80, sequence 0, window 8192, SYN set) so a bare segment is always
constructible. Every field has a setter: `source_port`/`sport`,
`destination_port`/`dport`, `sequence_number`/`seq`,
`acknowledgment_number`/`ack`, `window`, `urgent_pointer`/`urgptr`,
`reserved`, `data_offset`/`dataofs`, and `checksum`/`chksum`. The short aliases
exist for ergonomic short-form construction; the long names read clearly in
generated tool code.

Control bits can be set three ways:

- The raw word: `flags(TCP_FLAG_SYN | TCP_FLAG_ACK)` replaces the whole flag
  field.
- A single bit: `flag(TCP_FLAG_RST, true)` sets or clears one bit, preserving the
  rest.
- Named convenience setters: `syn()`, `fin()`, `rst()`, `psh()`, `ack_flag()`,
  `urg()`, `ece()`, `cwr()`, `ns()`, `ae()`. Note `ack_flag()` sets the ACK
  *control bit* while `ack()` sets the acknowledgment *number* field.

Common segment shapes are available as self-consuming builders that stamp
exactly the expected control-bit set (replacing the default, not accumulating):
`syn_segment()`, `syn_ack_segment()`, `ack_segment()`, `rst_ack_segment()`, and
`fin_ack_segment()`. They only set predictable flag bits; ports, sequence
numbers, window, and options stay configurable and they never infer addresses,
send traffic, or model connection state.

`compile()` fills anything left unset and preserves everything set. For TCP it
fills Data Offset from the padded option bytes, pads the option area to a 32-bit
boundary, fills the checksum from the enclosing IPv4/IPv6 pseudo-header, and lets
the enclosing IP layer fill the protocol number / next-header (TCP is IP protocol
6) and lengths. See [Protocol-correct defaults](#protocol-correct-defaults).

## Protocol-correct defaults

`compile()` honors the crate-wide rule: it fills what the builder did not set and
leaves what the builder did set untouched, including values that are wrong on
purpose so generated tools can exercise a remote stack with malformed segments.

Filled when unset:

- **Data Offset / header length** from the padded option bytes (20 octets with no
  options, up to the 60-octet maximum).
- **Option padding** to the next 32-bit boundary with zero bytes (the zero pad
  byte equals the EOL kind 0).
- **Checksum** from the IPv4 or IPv6 pseudo-header when the network layer supplies
  checksum context; left zero when there is no context.
- **IP protocol number / IPv6 next-header** and **enclosing lengths** through the
  normal IP-layer composition.

Preserved when set, within the existing validation model:

- Ports, sequence number, acknowledgment number, window, urgent pointer.
- Raw flags and reserved bits, including reserved bits set on purpose.
- An explicit Data Offset, even one below the option bytes or below the 20-octet
  minimum (subject to validation; see [Decode](#decode-and-structured-errors)).
- An explicit checksum, including a deliberately invalid value (`checksum(0xbeef)`
  survives `compile()`).
- Raw option bytes, preserved verbatim.

## Options

TCP options are exposed as a typed `TcpOption` enum (also `TcpOptionIter`,
`TcpSackBlock`, and `TcpExtendedDataOffset`), all exported through the prelude.
Attach options to a segment in two ways:

```rust
use crafter::prelude::*;

// Typed options, validated and encoded for you (returns Result):
let tcp = Tcp::new()
    .sport(41000)
    .dport(443)
    .flags(TCP_FLAG_SYN)
    .tcp_option(TcpOption::mss(1460))?
    .tcp_option(TcpOption::window_scale(7))?
    .tcp_option(TcpOption::sack_permitted())?
    .tcp_option(TcpOption::timestamp(0x1020_3040, 0))?;

// Raw option bytes, preserved verbatim (no validation rewrite):
let raw = Tcp::new().option([0x02, 0x04, 0x05, 0xb4]);
```

`option(bytes)` appends raw bytes, `options(bytes)` replaces them, and
`clear_options()` removes them. `tcp_option(TcpOption)` encodes one typed option
and returns `Result` because encoding can reject a malformed value.

### Typed option constructors

Source-backed constructors cover the currently relevant standardized and deployed
options first:

- `TcpOption::end_of_list()`, `no_operation()` — RFC 9293 EOL (0) and NOP (1).
- `maximum_segment_size(u16)` / `mss(u16)` — MSS (2), RFC 9293.
- `window_scale(u8)` — Window Scale (3), RFC 7323; `valid_window_scale(shift)`
  reports the RFC 7323 shift cap of 14.
- `sack_permitted()` — SACK-Permitted (4), RFC 2018.
- `sack(blocks)` — SACK (5), RFC 2018, carrying 32-bit `TcpSackBlock`
  left/right edges. D-SACK (RFC 2883) reuses the same option kind and is
  represented at the SACK-block level, with `is_potential_dsack_first_block`
  applying the RFC 2883 first-block rules over a caller-supplied cumulative ACK.
- `timestamp(value, echo_reply)` — Timestamps (8), RFC 7323.
- `user_timeout(granularity, value)` — User Timeout (28), RFC 5482.
- `tcp_authentication(key_id, rnext_key_id, mac)` — TCP-AO (29), RFC 5925. MAC
  bytes are preserved verbatim; `crafter` never computes or verifies the MAC.
- `multipath_tcp(subtype, data)` — MPTCP (30), RFC 8684. The subtype nibble is
  parsed and subtype-specific bytes preserved; the `MPTCP_SUBTYPE_*` and
  `MPTCP_TCPRST_REASON_*` constants name the wire values.
- `fast_open(cookie)` and `fast_open_cookie_request()` — TCP Fast Open (34),
  RFC 7413.
- `tcp_eno(suboptions)` — TCP-ENO (69), RFC 8547. Suboption bytes are preserved;
  no negotiation or tcpcrypt session behavior (RFC 8548) is implemented.
- `accurate_ecn(kind, data)`, `accurate_ecn_order_0(data)`,
  `accurate_ecn_order_1(data)` — AccECN options (172 / 174), RFC 9768. The kind
  encodes counter order; counter bytes are preserved verbatim.
- `experimental(kind, experiment_id, data)`, `experimental_1(...)`,
  `experimental_2(...)` — RFC 6994 experimental options (253 / 254) with a 16-bit
  ExID. The ExID is parsed and is not confused with generic experiment payload.
- `extended_data_offset_request()`, `extended_data_offset(header_length)`,
  `extended_data_offset_ext(...)` — the existing `TcpExtendedDataOffset` API. EDO
  (draft-ietf-tcpm-tcp-edo, kind 237) is **not** an RFC-published assigned kind;
  the API is preserved for compatibility and its draft status is documented in
  the [manifest](../internal/manifests/tcp-rfc-manifest.md).
- `generic(kind, data)` — any other kind, preserved as raw bytes.

### Reading options back

`Tcp::parsed_options()` returns `Vec<TcpOption>`, `Tcp::option_iter()` yields a
`TcpOptionIter`, and `Tcp::option_bytes()` returns the exact raw bytes including
decode-time padding. Per-option accessors return the typed value when the option
matches and `None` otherwise, for example `maximum_segment_size_value()`,
`window_scale_shift()`, `is_sack_permitted()`, `sack_blocks()`,
`timestamp_values()` / `timestamp_value()` / `timestamp_echo_reply()`,
`user_timeout_value()`, `fast_open_cookie()`, `mptcp_subtype()` /
`mptcp_subtype_data()` / `mptcp_tcprst_reason()`, `tcp_authentication_value()`,
`tcp_eno_suboptions()`, `accurate_ecn_value()`, and
`experiment_id()` / `experiment_data()`.

### Classification and raw preservation

Every option kind classifies against the IANA TCP Option Kind Numbers registry,
so obsolete, reserved, and unassigned kinds stay inspectable instead of being
silently discarded. `TcpOptionKindClass` has three variants:

- `Assigned` — the kind has a current IANA name (modeled or not, including legacy
  options such as MD5 Signature, kind 19).
- `Experimental` — an RFC 6994 / RFC 3692-style experimental kind (253 or 254).
- `Unassigned` — the kind is unassigned in the current registry.

Use `tcp_option_kind_class(kind)`, `tcp_option_kind_is_assigned(kind)`,
`tcp_option_kind_is_experimental(kind)`, and `tcp_option_kind_name(kind)` for the
free-function form, or the matching `TcpOption::kind_class()`, `kind_name()`,
`kind_is_assigned()`, and `kind_is_experimental()` methods on a parsed option.

Unknown options with a structurally valid length round-trip verbatim: an
`Unassigned` kind decodes to `TcpOption::Generic { kind, data }`, recompiles to
the same bytes, and remains inspectable through `show()`. NOP padding and EOL
trailing padding are preserved in `option_bytes()` without losing the original
bytes.

## Checksums

RFC 9293 §3.1 defines the TCP checksum as the 16-bit one's-complement sum over a
pseudo-header, the TCP header, the options, any header padding, and the TCP data,
with a zero pad octet for an odd data length. `crafter` fills it from the
enclosing network layer:

- **IPv4** pseudo-header: source and destination addresses, a zero byte,
  protocol number 6, and the 16-bit TCP length.
- **IPv6** pseudo-header: source and destination addresses, the 32-bit
  upper-layer length, and next-header 6 (RFC 8200 §8.1). Unlike IPv4 UDP, TCP has
  no zero-checksum exemption.

The checksum is filled only when the network layer supplies checksum context; a
bare `Tcp` compiled without an IP layer leaves the checksum zero. An explicit
`checksum(value)` is preserved exactly, including a deliberately invalid value,
so a generated tool can emit a bad checksum on purpose. On decode an invalid
checksum is represented in the decoded segment rather than silently dropping it.
The full byte-level behavior — options, padding, and odd-length payload included
in the sum, IPv4 and IPv6 distinguished by the pseudo-header — is pinned by the
crate's checksum tests.

## Decode and structured errors

Decode through the network-layer entrypoint and reach into the typed layer:

```rust
use crafter::prelude::*;

let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
let tcp = decoded.layer::<Tcp>().expect("expected a Tcp layer");
println!("data offset: {} words", tcp.data_offset_value());
for option in tcp.parsed_options()? {
    println!("{option:?}");
}
```

`Packet::decode_from_l3` (and `decode_from_l3_with_registry`,
`decode_from_link`, and `decode_raw`) drive the registry: a structurally valid
TCP header pushes a `Tcp` layer, and only the post-header payload bytes are
handed to the application decoder reached by port, never the options area.

Decode parses only structurally valid TCP headers and returns a structured
`CrafterError` — never a panic — for malformed input. The error carries
identifying context so a tool can act on it:

- A buffer shorter than the 20-octet fixed header is a buffer-too-short error
  (`tcp header`).
- Data Offset below 5 words is `tcp.data_offset`.
- Data Offset that points past the available bytes is a buffer-too-short error.
- An option length below 2 (for non-EOL/NOP kinds), a fixed-length mismatch, or a
  length that overruns the options area is a structured option error (for
  example `tcp.option.length`, `tcp.option.mss`, `tcp.option.timestamp`).

A user-set Data Offset that is intentionally malformed but still accepted by the
validation model is not silently rewritten. The malformed-input behavior is
backed by the crate's `resilience` suite and the malformed decode corpus.

## Inspection

Every `Tcp` segment is inspectable without log-fishing:

- `Packet::summary()` joins each layer's one-line summary; the TCP line is
  `Tcp(sport=…, dport=…, flags=…)`, where the flag list uses current IANA names
  (the `0x100` bit prints as `AE`).
- `Packet::show()` prints the full field tree. The TCP fields include `sport`,
  `dport`, `seq`, `ack`, `data_offset`, `header_len`, `reserved`, `flags`,
  `window`, `checksum` (or `auto` when unset), `urgent_pointer`, `option_len`, a
  classified `option_summary` (for example `MSS(2),WScale(3),SAckOK(4)`), and the
  raw `options` hex.
- `Packet::hexdump()` (and `CompiledPacket::hexdump()`) produce a canonical
  offset/hex/ASCII dump of the compiled bytes.

Per-field getters back every inspection field: `source_port_value()`,
`destination_port_value()`, `sequence_number_value()`,
`acknowledgment_number_value()`, `data_offset_value()`, `header_len()`,
`reserved_value()`, `flags_value()`, `has_flag(flag)`, `window_value()`,
`checksum_value()`, `urgent_pointer_value()`, and `option_bytes()`.

## Sizing helpers

`crafter` ships pure, inspectable sizing helpers so a builder can size a correct
segment. They are fragmentation-adjacent documentation only: none of them
fragments, reassembles, or probes a path MTU. The caller always supplies the path
MTU.

- `tcp_header_len(option_bytes)` — TCP header length in octets for a raw
  option-byte count (20 with no options, up to 60).
- `option_budget()` — the 40-octet maximum option budget (the Data Offset bound,
  RFC 9293 §3.1); `remaining_option_budget(used)` saturates at zero.
- `max_tcp_payload(path_mtu, ip_header_len, tcp_header_len)` — the largest TCP
  payload for a caller-provided path MTU, saturating to avoid underflow.
- `effective_mss_ipv4(path_mtu)`, `effective_mss_ipv6(path_mtu)`, and the
  version-dispatching `effective_mss(is_ipv6, path_mtu)` — source-backed MSS
  guidance. IPv4 falls back to and floors at the RFC 9293 / RFC 1122 / RFC 879
  default of 536 octets; IPv6 uses the RFC 8200 / RFC 8201 minimum link MTU of
  1280 octets (an effective MSS of 1220).
- `has_syn(flags)`, `has_fin(flags)`, and `sequence_space_len(flags, payload_len)`
  — the free-function form of TCP sequence-space accounting (RFC 9293 §3.4):
  `payload_len + (SYN ? 1 : 0) + (FIN ? 1 : 0)`. The `Tcp::has_syn()`,
  `Tcp::has_fin()`, and `Tcp::sequence_space_len(payload_len)` methods read the
  segment's own flags. These let a builder compute the acknowledgment number for
  a crafted reply without a TCP state machine.

The free functions are exported through `crafter::protocols::transport`.

### PMTUD / PLPMTUD and fragmentation (guidance only)

Path MTU Discovery (PMTUD) and Packetization Layer PMTUD (PLPMTUD) drive how a
real sender chooses an MSS for a path. `crafter` documents these interactions
and exposes the packet primitives a generated PMTUD/PLPMTUD tool would build,
but **`crafter` does not fragment or reassemble TCP segments, and fragmentation
implementation is out of scope** for the crate. None of the sizing helpers
fragment, reassemble, or probe a path MTU; the caller always supplies the path
MTU.

- **MSS.** The MSS option (`TcpOption::mss` / `maximum_segment_size`, kind 2,
  RFC 9293) advertises the largest segment a peer should send. RFC 9293 §3.7.1
  ties the *effective* send MSS to the path MTU and PMTUD. Derive a path-bounded
  effective MSS with `effective_mss(is_ipv6, path_mtu)` (or the
  `effective_mss_ipv4` / `effective_mss_ipv6` variants); `crafter` never
  negotiates or enforces it.
- **IPv4 Don't Fragment (DF).** IPv4 PMTUD (RFC 1191) sets the DF bit so a sender
  learns the path MTU instead of relying on in-path fragmentation. The `Ipv4`
  layer exposes it directly: `Ipv4::new().dont_fragment(true)` (constant
  `IPV4_FLAG_DONT_FRAGMENT`), read back with `Ipv4::is_dont_fragment()`. A
  generated tool can build DF-set probes; `crafter` performs no fragmentation
  or probing itself.
- **ICMP fragmentation-needed.** A router that cannot forward a DF-set IPv4
  packet returns ICMP Destination Unreachable, code "fragmentation needed and DF
  set" (RFC 1191, type 3, code 4), carrying the next-hop MTU. Build and decode it
  with the `Icmp` layer:
  `Icmp::destination_unreachable().code(ICMP_CODE_DU_FRAGMENTATION_NEEDED)`, with
  the next-hop MTU on the quoted-IPv4 body (`mtu_next_hop` / `mtu`, read with
  `mtu_next_hop_value()`).
- **IPv6 Packet Too Big.** IPv6 has no in-path fragmentation; routers signal an
  oversize packet with the ICMPv6 Packet Too Big message (RFC 8201, ICMPv6
  type 2) carrying the reduced MTU. Build and decode it with the `Icmpv6` layer:
  `Icmpv6::packet_too_big().mtu(1280)` (constant `ICMPV6_PACKET_TOO_BIG`).
- **IPv6 minimum MTU.** The IPv6 minimum link MTU is 1280 octets
  (RFC 8200 §5 / RFC 8201). `effective_mss_ipv6` floors at this minimum (an
  effective MSS of 1220 octets after the IPv6 and TCP fixed headers); the
  `IPV6_MINIMUM_MTU` constant names it.
- **PLPMTUD (RFC 8899).** Packetization Layer PMTUD probes with progressively
  larger packets and confirms delivery at the transport layer instead of relying
  on ICMP Packet Too Big / fragmentation-needed replies. `crafter` provides the
  building blocks a PLPMTUD probe tool needs (sized TCP segments, the DF bit,
  ICMP/ICMPv6 decode) but implements no probe state machine, search, or MTU
  cache.

These are all illustrative guidance. The interaction is documented, but
the TCP layer neither performs TCP segmentation, TCP reassembly, nor path MTU
probing; a generated tool composes these primitives to do PMTUD/PLPMTUD work.
IP fragmentation and IP datagram reassembly are available separately through the
packet-stream `IpFragment` and `IpDefrag` transforms.

## Explicit exclusions

`crafter` stays a packet primitive. It builds and decodes individual TCP
segments and does **not** implement, and this guide does not authorize:

- A TCP connection state machine, retransmission engine, or congestion control.
- TCP segmentation, TCP reassembly, or application payload reconstruction.
- TCP-owned IP fragmentation, IP reassembly, or a fragment cache. Non-initial
  IPv6 fragments carrying TCP next-header are preserved as `Raw` by base decode;
  receive-side IP datagram reassembly belongs to `IpDefrag`, and transmit-side
  IP fragmentation belongs to `IpFragment`.
- TCP-AO or TCP-ENO cryptography: option bytes are preserved for inspection and
  round-trip only. No MAC is computed or verified, no key is derived or rolled,
  and no encryption is negotiated (TCP-ENO / tcpcrypt, RFC 8548).
- MPTCP connection logic: subtype bytes and the `MP_TCPRST` reason are exposed as
  inspectable data, but subflow management, path management, fallback, and
  reset reaction are the responsibility of a generated tool, not the crate.
- A scanner, fuzzer, or packet-analyzer workflow.

PMTUD/PLPMTUD (RFC 1191, RFC 8201, RFC 8899), the IPv4 Don't Fragment bit, ICMP
fragmentation-needed, IPv6 Packet Too Big, and the IPv6 minimum-MTU facts are
modeled as sizing guidance only; `crafter` never probes a path MTU, and
TCP segmentation and TCP reassembly remain future work. IP fragmentation and IP
datagram reassembly are implemented only by the packet-stream transforms. See
[PMTUD / PLPMTUD and fragmentation (guidance only)](#pmtud--plpmtud-and-fragmentation-guidance-only).
These boundaries mirror the spec's "what not to do" and the manifest's
[Explicit Exclusions](../internal/manifests/tcp-rfc-manifest.md#explicit-exclusions).

## Validation coverage

The TCP layer is validated through deterministic crate fixtures, the public-API
path tests, the malformed decode corpus, and the `resilience` structured-error
suite. All cases use documentation address space (`192.0.2.0/24`,
`198.51.100.0/24`, `2001:db8::/32`) and offline or dry-run workflows by default;
live provider runs are opt-in and start with `--dry-run`. See
[Oracle validation](../operations/validation.md) for the boundary and command shapes.

## Evidence

Protocol facts above come from the sources recorded, citation by citation, in
[`docs/tcp-rfc-manifest.md`](../internal/manifests/tcp-rfc-manifest.md). The source set, in brief:

- **RFC 9293** — base TCP (header layout, Data Offset, control bits, checksum,
  EOL/NOP/MSS options). Obsoletes RFC 793 and others.
- **IANA TCP Parameters** — current TCP Option Kind Numbers and TCP Header Flags
  registries.
- **RFC 2018 / RFC 2883** — SACK and D-SACK.
- **RFC 3168 / RFC 8311** — classic ECN bits (CWR, ECE) and ECN-nonce
  deprecation (the bit historically named `NS`).
- **RFC 7323** — Window Scale and Timestamps.
- **RFC 5482** — User Timeout.
- **RFC 5925 / RFC 5926** — TCP-AO wire format and algorithms (bytes preserved
  only).
- **RFC 6994** — experimental option ExIDs (kinds 253 / 254).
- **RFC 7413** — TCP Fast Open.
- **RFC 8547 / RFC 8548** — TCP-ENO and tcpcrypt (bytes preserved only).
- **RFC 8684** — MPTCP v1 option and subtype registries.
- **RFC 9768** — Accurate ECN feedback, the AE flag, and AccECN options
  (kinds 172 / 174).
- **RFC 1191 / RFC 8201 / RFC 8899** — PMTUD / PLPMTUD sizing guidance only.
