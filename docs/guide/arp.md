# ARP Wire Coverage

This page describes the ARP packet-layer support in the `crafter` crate: what
the `Arp` layer builds and decodes, how the Ethernet/IPv4 defaults and address
lengths are filled on `compile()`, how deliberate overrides are preserved, and
what is intentionally out of scope. `crafter` treats ARP as a wire-level
primitive, not an ARP engine: it builds and decodes the generic RFC 826 header
but implements no ARP cache, gateway resolution, or host ARP-table workflow. For
the full API surface see [the API reference](../reference/api.md).

All wire facts on this page trace to reviewed RFC text and the IANA
`arp-parameters` registries. The RFCs and registries the ARP layer implements are
listed in [Standards and RFCs implemented](#standards-and-rfcs-implemented) at
the end of this guide.

## Coverage at a glance

| Area | State | Notes |
| --- | --- | --- |
| Fixed eight-octet header (HRD, PRO, HLN, PLN, OP) | Supported | Big-endian on `compile()`; `encoded_len = 8 + 2*HLN + 2*PLN`. |
| Variable-length address fields | Supported | The four address fields are raw byte vectors governed by HLN/PLN, not fixed to 6/4. |
| Ethernet/IPv4 request and reply defaults | Auto-filled | `Arp::who_has(...)` / `Arp::is_at(...)` keep HRD=1, PRO=IPv4, HLN=6, PLN=4 and protocol-correct opcodes. |
| Address length fields (HLN/PLN) | Auto-filled | Filled from the byte counts unless set explicitly; deliberate mismatches are honored until compile-time validation. |
| Honored overrides | Supported | `compile()` fills only unset fields; deliberately wrong values are preserved. |
| Named operation codepoints | Supported | Request/Reply drive behavior; ARP-family codepoints (RARP, DRARP, InARP, ARP-NAK, MAPOS) are named for visibility, no extension behavior. Raw `opcode(u16)` round-trips unknown values. |
| Decode (unknown HRD/PRO/OP, variable/zero-length addresses) | Supported | Address fields split by HLN/PLN; every field preserved verbatim; trailing bytes surface as `Raw`. |
| Decode (structured errors) | Supported | Short header or truncated addresses return `BufferTooShort` with `context`, `required`, `available`; never a panic. |
| Reply matching and filters | Supported | `arp_reply_matches` matches by address bytes; `arp_filter` adds host terms only for 4-byte IPv4 addresses and otherwise degrades to bare `arp`. |
| Inspection (`summary` / `show`) | Supported | One-line op + psrc/pdst summary plus a full field tree. |

## ARP construction

The `Arp` layer is exported through `crafter::prelude::*`. The typed helpers
cover the common Ethernet/IPv4 case; raw byte setters and length overrides cover
everything else. A standard who-has request and the matching is-at reply:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let me = MacAddr::from([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);

let request = Ethernet::new()
    .src(me)
    .dst(MacAddr::BROADCAST)
    .ethertype(ETHERTYPE_ARP)
    / Arp::who_has(
        Ipv4Addr::new(192, 0, 2, 10), // sender protocol address
        Ipv4Addr::new(192, 0, 2, 1),  // target protocol address
        me,                           // sender hardware address
    );

let reply = Arp::is_at(
    Ipv4Addr::new(192, 0, 2, 1),
    MacAddr::from([0x02, 0x00, 0x5e, 0x00, 0x53, 0xff]),
    Ipv4Addr::new(192, 0, 2, 10),
    me,
);

let bytes = request.compile()?;
println!("{}", request.summary());
```

Named operation codepoints and the raw `opcode(u16)` escape hatch coexist;
unknown numeric values are never rejected and round-trip byte-for-byte. Only
REQUEST and REPLY drive behavior; the ARP-family codepoints are named for
inspection only and ride the unmodified RFC 826 header. RFC 5227 gratuitous,
probe, and announcement ARP is expressed by setting explicit sender/target
fields on the base builder — there is no dedicated constructor and no new opcode,
because RFC 5227 reuses REQUEST/REPLY.

Nonstandard hardware/protocol families use the generic raw setters. The matching
length field auto-fills from the byte count unless set explicitly, and any
deliberate length mismatch is honored until compile-time validation, which
returns a structured `BufferTooShort` for any user-set address whose byte length
disagrees with its length field:

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

assert!(nonstandard.sender_mac().is_none());
assert_eq!(nonstandard.sender_hardware_bytes_value().len(), 8);
```

See `crafter/examples/arp_who_has.rs` for a runnable dry-run example that builds
a who-has frame, inspects the operation/type/length fields, derives the reply
filter, and prints a link-layer dry-run send plan without transmitting. The
[API reference](../reference/api.md) lists the complete `Arp` constructor and
accessor surface.

## Live ARP

ARP is L2 traffic. It rides the generic `_requires_l2` capability gate and is
validated live only through provider-backed QEMU or VirtualBox lab sessions,
never through privileged raw sends from the developer host. Live runs are
opt-in: plan first, record a skip artifact when authorization or VM
prerequisites are absent, and only after explicit confirmation collect artifacts
and tear the session down.

## Standards and RFCs implemented

Every wire fact below traces to an RFC number or an IANA `arp-parameters`
registry record. The library implements the following for ARP (intentional gaps
are marked):

- **RFC 826 — An Ethernet Address Resolution Protocol** — the generic,
  address-family-neutral eight-octet header and its variable-length address
  fields. Decode accepts any structurally valid header, including unknown
  HRD/PRO/OP and unknown address families, and preserves every field verbatim.
- **RFC 5494 — IANA Allocation Guidelines for ARP** (updates RFC 826) — allocation
  guidance and the reserved/experimental opcodes (0, 65535, OP_EXP1 24,
  OP_EXP2 25).
- **RFC 5227 — IPv4 Address Conflict Detection** — gratuitous/probe/announcement
  ARP, expressed through the base builder by setting explicit sender/target
  fields; no new opcode (RFC 5227 reuses REQUEST/REPLY).
- **IANA `arp-parameters` registries** — codepoint authority:
  `arp-parameters-1` (Operation Codes), `arp-parameters-2` (Hardware Types,
  default HRD=1 Ethernet), and `arp-parameters-3` (Protocol Type, which shares
  the Ethertype space per RFC 5342; default PRO=IPv4). Known values are named for
  ergonomics; unknown HRD/PRO/OP values are always accepted and preserved.
- **ARP-family operations (codepoints only)** — RARP (**RFC 903**, opcodes 3/4),
  DRARP (**RFC 1931**, opcodes 5/6/7), InARP (**RFC 2390**, opcodes 8/9),
  ARP-NAK (**RFC 1577**, opcode 10), and MAPOS UNARP (**RFC 2176**, opcode 23).
  These are named codepoints only: they reuse the unmodified RFC 826 wire format
  with no extension-specific message bodies, state machines, or host workflows.

Intentional gaps — deliberately excluded so the crate stays a wire-level
primitive, not an ARP analyzer, scanner, or stack:

- ARP scanner, fuzzer, ARP-cache management, and host ARP-table workflows; these
  are generated tools, not crate features.
- True message-structure support for RARP/DRARP/InARP/ARP-NAK/MAPOS — only the
  opcodes are recognized.
- Per-medium IP-over-X encapsulation documents and an exhaustive curated
  Ethertype/hardware-type enumeration; the crate stays media-generic via
  HRD/PRO/HLN/PLN with raw `u16` types and known-value labels.
- ATM/MARS, NHRP transition machinery beyond ARP-NAK opcode 10, and data-center /
  VPN / TRILL / EVPN ARP optimization control-plane specs.
- IPv6 Neighbor Discovery, which is a separate protocol — see the
  [ICMPv6 guide](icmpv6.md).
