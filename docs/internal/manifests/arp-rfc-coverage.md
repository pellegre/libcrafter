# ARP RFC Coverage Checklist

This checklist records what `crafter`'s ARP support covers against the
source-backed ARP specification and registry set, and what it deliberately
leaves out. It is a durable companion to the generated manifest and inventory
that drive the work; those generated artifacts live under `target/arp-rfc/`
(gitignored) and are regenerated on demand, while this page stays in the tree
as the concise reviewer-facing summary.

Operational guidance for agents building ARP tools on top of the crate belongs
in [`.agents/docs/cookbook.md`](../../../.agents/docs/cookbook.md), not here. This
page describes the crate's coverage boundary; it is not a how-to.

## Source authority

Every protocol fact below is tied to a manifest-backed source: an RFC number or
an IANA `arp-parameters` registry record. Facts not traceable to that authority
are flagged as conservative assumptions for maintainer review.

- Base specification: **RFC 826**, "An Ethernet Address Resolution Protocol"
  (INTERNET STANDARD). Defines the generic, address-family-neutral ARP header
  and its variable-length address fields.
- Allocation guidance and reserved/experimental codepoints: **RFC 5494**,
  "IANA Allocation Guidelines for the Address Resolution Protocol (ARP)"
  (updates RFC 826).
- Codepoint authority: IANA `arp-parameters` registries —
  `arp-parameters-1` (Operation Codes), `arp-parameters-2` (Hardware Types),
  `arp-parameters-3` (Protocol Type; shares the Ethertype space per RFC 5342).
- ARP-family operations included as codepoints only: RARP (**RFC 903**),
  DRARP (**RFC 1931**), InARP (**RFC 2390**), ARP-NAK (**RFC 1577**), and
  MAPOS UNARP (**RFC 2176**).
- Conventions over base ARP, no new opcode: **RFC 5227** (IPv4 Address Conflict
  Detection — gratuitous/probe/announcement packets).

## Base ARP requirements (RFC 826)

| Requirement | Source | Coverage |
| --- | --- | --- |
| Eight-octet fixed header: HRD, PRO, HLN, PLN, OP | RFC 826 | Covered. `Arp` carries each field; `compile()` emits big-endian, `encoded_len = 8 + 2*HLN + 2*PLN`. |
| Variable-length sender/target hardware and protocol address fields | RFC 826 generic format | Covered. Four address fields are `Vec<u8>`; lengths are governed by HLN/PLN, not fixed to 6/4. |
| Ethernet/IPv4 request defaults (HRD=1, PRO=IPv4, HLN=6, PLN=4, OP=Request) | RFC 826 + arp-parameters-2 value-1, arp-parameters-3 Ethertype space | Covered. `Arp::new()` / `who_has` / `is_at` keep protocol-correct defaults and emit the existing golden bytes. |
| Honored overrides: explicitly set fields survive compile untouched | RFC 826 (wire format) | Covered. `compile()` fills only unset fields; deliberately wrong values are preserved. |
| Decode of any structurally valid header, including unknown HRD/PRO/OP and unknown address families | RFC 826 generic format | Covered. Decode splits address fields by HLN/PLN and stores every field verbatim, so unknown codepoints round-trip. |
| Trailing bytes after a complete ARP body remain observable | RFC 826 (fixed body length) | Covered. Decode appends remaining bytes as `Raw`. |
| Structured errors for truncated header or address fields, no silent panic | RFC 826 (header/address layout) | Covered. `buffer_too_short("arp header", 8, len)` and `buffer_too_short("arp addresses", total_len, len)`; HLN/PLN are widened to `usize` before doubling so there is no arithmetic overflow. |
| Explicit address bytes conflicting with explicit HLN/PLN fail at compile time | RFC 826 (HLN/PLN govern address length) | Covered. `validate_lengths()` returns `CrafterError::BufferTooShort { context: "arp.<field>", required, available }` for any user-set address whose byte length disagrees with the length field; `required`/`available` are bounded `u8` widths, so the check cannot overflow even at `u8::MAX`. |
| Summary, inspection, and show expose ARP detail | crate inspectable-surface requirement | Covered. `summary()` shows op + psrc/pdst; `inspection_fields()` shows HRD, PRO, HLN, PLN, OP, and all four addresses (MAC/IPv4 formatted when applicable, hex otherwise). |
| Reply matching and reply filters are correct and degrade conservatively | RFC 826 request/reply semantics | Covered. `arp_reply_matches` matches by address bytes; `arp_filter` adds host terms only for 4-byte IPv4 addresses and otherwise degrades to bare `arp`. |

## Operation codepoints (arp-parameters-1)

Known operation codepoints are exposed as named values for ergonomics and
inspection, while the raw `opcode(u16)` escape hatch keeps unknown numeric
values round-trippable. Only REQUEST and REPLY drive behavior (default request
construction and reply matching); all other codepoints are named for visibility
with no special runtime behavior.

| Operation | Code | Source | Decision |
| --- | --- | --- | --- |
| Reserved | 0 | RFC 5494 | Named constant, no behavior. |
| REQUEST | 1 | RFC 826, RFC 5227 | Named; drives default request and reply-match logic. |
| REPLY | 2 | RFC 826, RFC 5227 | Named; drives reply matching. |
| request Reverse | 3 | RFC 903 (RARP) | Codepoint only, round-trippable. |
| reply Reverse | 4 | RFC 903 (RARP) | Codepoint only, round-trippable. |
| DRARP-Request / DRARP-Reply / DRARP-Error | 5 / 6 / 7 | RFC 1931 | Codepoint only, round-trippable. |
| InARP-Request / InARP-Reply | 8 / 9 | RFC 2390 | Codepoint only, round-trippable. |
| ARP-NAK | 10 | RFC 1577 | Codepoint only, round-trippable. |
| MAPOS UNARP | 23 | RFC 2176 | Codepoint only, round-trippable. |
| OP_EXP1 / OP_EXP2 | 24 / 25 | RFC 5494 | Experimental, named constant, no behavior. |
| Reserved | 65535 | RFC 5494 | Named constant, no behavior. |
| MARS operations | 11–22 | arp-parameters-1 (person xref, no RFC) | Deferred: data-only recognition, no named ergonomics. |
| Unassigned / Reserved | 26–65534 | arp-parameters-1 | Deferred: raw numeric round-trip only. |

## Hardware / protocol type codepoints

Hardware types (arp-parameters-2) and protocol types (arp-parameters-3) stay
raw `u16` with known-value helpers; unknown numeric values are never rejected.
The Ethernet/IPv4 defaults remain protocol-correct.

| Item | Source | Decision |
| --- | --- | --- |
| Hardware type 1 "Ethernet (10Mb)" | arp-parameters-2 value-1 | Default HRD; exposed as a known value. |
| Protocol type = IPv4 Ethertype | arp-parameters-3 (Ethertype space, RFC 5342) | Default PRO; exposed as a known value. |
| Other hardware types (6 IEEE 802, 18 Fibre Channel, 19 ATM, 25 MAPOS, 32 InfiniBand, 0/65535 reserved, experimental) | arp-parameters-2 | Surfaced as data for inspection/oracle codepoints; not behavior. |
| Unknown HRD/PRO values | RFC 826 generic format | Always accepted and preserved; never rejected. |

## Extension decisions

| Extension | Source | Decision |
| --- | --- | --- |
| RARP (request/reply Reverse) | RFC 903 | Included as codepoints 3/4 only; reuses the base RFC 826 wire format, no message bodies. |
| DRARP | RFC 1931 | Included as codepoints 5/6/7 only; no DRARP host workflow. |
| InARP | RFC 2390 | Included as codepoints 8/9 only. |
| ARP-NAK | RFC 1577 | Included as codepoint 10 only; surrounding ATM/ARP machinery is out of scope. |
| MAPOS UNARP | RFC 2176 | Included as codepoint 23 only. |
| Gratuitous / probe / conflict-detection ARP | RFC 5227 | Expressed through the base builder by setting explicit sender/target fields; no dedicated constructor and no new opcode (RFC 5227 reuses REQUEST/REPLY). |
| MARS operations | arp-parameters-1 (no RFC) | Deferred; not named because no RFC document backs them in the manifest. |

## Examples

ARP composes through the same `Packet` surface as every other layer. The
typed helpers cover the common Ethernet/IPv4 case; raw byte setters and length
overrides cover everything else.

Standard Ethernet/IPv4 request and reply:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let me = MacAddr::from([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);

// who-has: broadcast request for the gateway's MAC.
let request = Ethernet::new()
    .src(me)
    .dst(MacAddr::BROADCAST)
    .ethertype(ETHERTYPE_ARP)
    / Arp::who_has(
        Ipv4Addr::new(192, 0, 2, 10),  // sender protocol address
        Ipv4Addr::new(192, 0, 2, 1),   // target protocol address
        me,                            // sender hardware address
    );

// is-at: the matching reply.
let reply = Arp::is_at(
    Ipv4Addr::new(192, 0, 2, 1),
    MacAddr::from([0x02, 0x00, 0x5e, 0x00, 0x53, 0xff]),
    Ipv4Addr::new(192, 0, 2, 10),
    me,
);

let bytes = request.compile()?;
println!("{}", request.summary());
println!("{}", reply.summary());
```

Named operation codepoints and the raw `opcode(u16)` escape hatch coexist;
unknown numeric values are never rejected and round-trip byte-for-byte:

```rust
use crafter::prelude::*;

// Named ARP-family codepoint (data only, no extension behavior).
let inverse = Arp::new().operation(ArpOperation::InArpRequest);

// Arbitrary numeric opcode stays usable and visible.
let exotic = Arp::new().opcode(0x0fa0);
assert_eq!(exotic.opcode_value(), 0x0fa0);
```

Nonstandard hardware/protocol families use the generic raw setters; the matching
length field auto-fills from the byte count unless set explicitly, and any
deliberate length mismatch is honored until compile-time validation:

```rust
use crafter::prelude::*;

let nonstandard = Arp::new()
    .hardware_type(ARP_HRD_INFINIBAND)
    .protocol_type(ETHERTYPE_IPV6)
    .opcode(1)
    .sender_hardware([0u8; 8])   // HLN auto-fills to 8
    .sender_protocol([0u8; 16])  // PLN auto-fills to 16
    .target_hardware([0xffu8; 8])
    .target_protocol([0u8; 16]);

// Typed accessors decline on mismatched widths; raw views stay visible.
assert!(nonstandard.sender_mac().is_none());
assert_eq!(nonstandard.sender_hardware_bytes_value().len(), 8);
```

Decode any structurally valid ARP frame; unknown codepoints and address
families are preserved, trailing bytes surface as `Raw`, and truncation returns
a structured `BufferTooShort`:

```rust
use crafter::prelude::*;

match Packet::decode_from_link(LinkType::Ethernet, frame) {
    Ok(packet) => println!("{}", packet.show()),
    Err(CrafterError::BufferTooShort { context, required, available }) => {
        eprintln!("decode_error context={context} required={required} available={available}");
    }
    Err(error) => eprintln!("decode_error {error}"),
}
```

See `crafter/examples/arp_who_has.rs` for a runnable dry-run example that builds
a who-has frame, inspects the operation/type/length fields, derives the reply
filter, and prints a link-layer dry-run send plan without transmitting.

## Limitations

`crafter`'s ARP support is a wire-level primitive, not an ARP engine. In
addition to the intentional gaps below:

- ARP-family operations (RARP/DRARP/InARP/ARP-NAK/MAPOS) are named codepoints
  only. There are no extension-specific message bodies, state machines, or host
  workflows; they ride the unmodified RFC 826 header.
- Hardware and protocol types are exposed as raw `u16` with known-value labels.
  There is no curated, exhaustive Ethertype or hardware-type enumeration.
- RFC 5227 gratuitous/probe/announcement packets are expressed by setting
  explicit sender/target fields on the base builder; there is no dedicated
  constructor and no new opcode.
- Live ARP is L2-only and runs exclusively through provider-backed QEMU or
  VirtualBox lab sessions, never through privileged raw sends from the developer
  host.

## Offline coverage

Offline (no privileges, no live traffic) is the default validation path.

| Area | Coverage |
| --- | --- |
| Golden-byte round trip for Ethernet/IPv4 request and reply | Covered by `crafter` unit tests and the fixture suite. |
| Decode round trip exposing IPv4 and MAC fields | Covered. |
| Compile-time rejection of inconsistent address lengths | Covered. Both typed setters and raw `*_bytes`-vs-length conflicts fail with the structured `BufferTooShort` error above, including the zero-vs-nonempty and `u8::MAX` boundary cases. |
| Nonstandard structurally valid ARP (unknown HRD/PRO/OP, variable/zero-length addresses) decode and summary | Covered. Unit tests and bounded property tests assert byte/value preservation; typed accessors decline (`None`) on mismatched widths while raw `*_bytes` views stay visible, and `summary()`/`inspection_fields()` render unknown codepoints numerically. |
| Malformed input structured errors (short header, truncated addresses) | Covered by the decode corpus (`short-arp-header`, `truncated-arp-addresses`, and the four `truncated-arp-*-address` rows), each asserting `BufferTooShort` with `context`, `required`, and `available`. |
| Oracle layer spec / stacks / fixtures modeling codepoints, variable address lengths, malformed cases, and live eligibility from data | Covered. `tools/oracle/specs/layers/arp.yaml`, `stacks.yaml`, and the fixture catalog model the full header, codepoint domains, variable/zero-length address byte vectors, and L2 live eligibility; ARP rides the generic `_requires_l2` gate so link-rooted plans stay wire-ineligible. |

## Pcap coverage

| Area | Coverage |
| --- | --- |
| Ethernet ARP request/reply pcap round trip | Covered (`pcaps/ethernet-arp-request-reply.pcap`). |
| Linux cooked capture (SLL) ARP pcap round trip | Covered (`pcaps/linux-sll-arp-who-has.pcap`). |
| BPF filter selecting ARP (e.g. `icmp or arp`) | Covered by pcap tests using `PacketWire::pcap_file(...).filter("arp")` on a mixed capture. |
| Nonstandard / variable-length ARP pcap fixtures | Covered (`pcaps/ethernet-arp-nonstandard.pcap`: InfiniBand HRD, IPv6 Ethertype, HLN=8/PLN=16 raw addresses, unknown opcode), write→read→write byte-stable. |

## Live QEMU coverage

ARP is L2 traffic and is validated live only through provider-backed lab
sessions, never through privileged raw sends from the developer host. Live runs
are opt-in.

| Area | Coverage |
| --- | --- |
| L2 capability gating (`link_layer_send` + `link_layer_capture`) | Covered. ARP rides the generic `_requires_l2` gate; QEMU provider exposes both capabilities. |
| Dry-run plan and skip artifact when authorization or VM prerequisites are absent | Required path: plan first, record a skip artifact after dry-run planning. |
| Protected confirmation, artifact collection, teardown when authorized | Required path: confirm, collect artifacts from every endpoint, then tear down. |

## Live VirtualBox coverage

| Area | Coverage |
| --- | --- |
| L2 capability gating (`link_layer_send` + `link_layer_capture`) | Covered. VirtualBox provider exposes both capabilities; ARP uses the same generic L2 gate. |
| Dry-run plan and skip artifact when authorization or VM prerequisites are absent | Required path: plan first, record a skip artifact after dry-run planning. |
| Protected confirmation, artifact collection, teardown when authorized | Required path: confirm, collect artifacts from every endpoint, then tear down. |

## Intentional gaps

These are deliberately excluded so the crate stays a wire-level primitive, not
an ARP analyzer, scanner, or stack.

- Scanner, fuzzer, ARP-cache management, and host ARP-table workflows. These are
  generated tools, not crate features.
- Per-medium IP-over-X encapsulation documents (RFC 948/1042/1044/1051/1103/
  1188/1201/1209/1329/1374/1390/2067/2625/2834/2835/3831/4338/4391/4947, etc.).
  The crate stays media-generic via HRD/PRO/HLN/PLN.
- ATM/MARS, ATM MIB, and NHRP transition machinery beyond ARP-NAK opcode 10.
- Data-center / VPN / TRILL / EVPN ARP optimization and mediation control-plane
  specs (RFC 6575/6747/6820/7067/7342/7432/7586/7961/8171/8302/9047/9161).
- Host-side ARP cache, gateway, conflict-resolution, and address-acquisition
  workflows (RFC 1027/1029/1433/1620/1868/2469/4436/4562); only their opcodes
  are recognized where listed above.
- BOOTP/DHCP material reached through cross-references; not an ARP wire format.
- IPv6 Neighbor Discovery; a separate protocol, not ARP.
- True message-structure support for RARP/DRARP/InARP/ARP-NAK/MAPOS — only
  codepoints are exposed (manifest extracted no RFC prose for these bodies).

## Assumptions needing maintainer review

Conservative positions taken where the manifest is silent or ambiguous, recorded
here rather than encoded silently:

1. RARP/DRARP/InARP/ARP-NAK/MAPOS opcodes are codepoint-only; the manifest's
   `extracted_facts` are all IANA registry records, with no RFC prose for these
   message bodies. Revisit if true message-structure support is wanted.
2. RFC 5227 probe/announcement ARP is expressed via base-builder fields rather
   than a dedicated variant. Revisit if dedicated probe/gratuitous constructors
   are wanted.
3. Hardware/protocol types are exposed as data, not exhaustive enums;
   arp-parameters-3 returned no records in this manifest build (it defers to the
   Ethertype space). Revisit if a curated Ethertype list should be embedded.
4. Zero-length and nonstandard address lengths are accepted structurally and
   never overflow; this is asserted from RFC 826's generic format rather than a
   quoted section.
