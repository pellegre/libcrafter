# OSPF Wire Coverage

This page describes the Open Shortest Path First support in the `crafter` crate:
what the OSPF layers build and decode, how OSPF rides directly over IP protocol
89 in the default registry, and how to keep OSPF workflows offline by default.

`crafter` treats OSPF as a wire-level primitive. It builds and decodes OSPFv2
per [RFC 2328](https://www.rfc-editor.org/rfc/rfc2328) and a base of OSPFv3 per
[RFC 5340](https://www.rfc-editor.org/rfc/rfc5340): the common header, the five
packet types, the link-state advertisement (LSA) bodies, and the OSPFv2
authentication trailer. Each OSPF message is a packet layer that builds,
compiles, decodes, summarizes, and shows like the other protocol layers.

It is **not** an OSPF router. There is no OSPF finite state machine, no neighbor
or adjacency formation, no Shortest Path First (SPF) computation, no link-state
database (LSDB), and no flooding or aging engine. Adjacency sequencing and route
computation belong in a generated tool built on top of these packets; the crate
surface is the wire primitive.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| Common header | Supported | 24-octet OSPFv2 header (Version, Type, Length, Router ID, Area ID, Checksum, AuType, Authentication); Length, Checksum, and the IPv4 protocol number auto-fill unless explicitly set. |
| Packet types | Supported | Hello (1), Database Description (2), Link State Request (3), Link State Update (4), and Link State Acknowledgment (5). |
| LSA types | Supported | Router (1), Network (2), Summary-IP (3), Summary-ASBR (4), AS-External (5), NSSA (7), and Opaque (9/10/11) including TE and Router-Information bodies. |
| LSA header | Supported | 20-octet header (LS age, Options, LS type, Link State ID, Advertising Router, sequence number, LS checksum, length); LS checksum (Fletcher-16) and length auto-fill unless set. |
| Authentication | Supported | Null (AuType 0), Simple Password (AuType 1), Cryptographic keyed-MD5 (AuType 2), and HMAC-SHA cryptographic authentication; the digest trailer is computed on `compile()` unless overridden. |
| Honored overrides | Supported | `compile()` fills only unset fields; deliberately wrong lengths, checksums, and auth fields are preserved for malformed-on-purpose packets. |
| Registry dispatch | Supported | IPv4 protocol 89 decodes as OSPFv2; IPv6 next-header 89 decodes as OSPFv3. |
| Decode (structured errors) | Supported | Short or truncated headers, bodies, and LSAs return `BufferTooShort` with `context`, `required`, and `available`; unknown LSA bodies are preserved as `Raw`; never a panic. |
| Inspection (`summary` / `show`) | Supported | One-line type/router/area summary plus a full field tree; `ospf_type_name`, `ospf_autype_name`, and `ospf_options_summary` label codepoints. |
| OSPFv3 base | Supported | `Ospfv3` builds the 16-octet IPv6 common header and base bodies (Hello, Database Description, Link State Request, Link State Update with Router/Network LSAs, Link State Acknowledgment) per RFC 5340. |

## Public API

The core OSPF types are exported through `crafter::prelude::*`:

- `Ospfv2` builds the OSPFv2 message layer, including the typed packet-type
  constructors (`hello`, `database_description`, `link_state_request`,
  `link_state_update`, `link_state_ack`) and the authentication helpers
  (`null_auth`, `simple_password`, `crypto_md5_auth`, `crypto_auth`).
- `Ospfv3` and the `Ospfv3*` body structs build the OSPFv3 base layer.
- `OspfBody` and the `OSPF_TYPE_*`, `OSPF_AUTYPE_*`, `OSPF_OPTIONS_*`, and
  `OSPF_VERSION_*` constants, plus `ospf_type_name`, `ospf_autype_name`, and
  `ospf_options_summary`, support inspection and documentation.

The LSA body and Hello construction types live under `crafter::protocols::ospf`
and are imported by their module path:

- `crafter::protocols::ospf::packet::{OspfHello, OspfLinkStateUpdate}` and the
  other packet bodies.
- `crafter::protocols::ospf::lsa::{OspfLsa, OspfLsaHeader, OspfLsaBody,
  OspfRouterLsa, OspfRouterLink, OspfNetworkLsa, OspfSummaryLsa,
  OspfAsExternalLsa, OspfNssaLsa, OspfOpaqueLsa}` and the `OSPF_LSA_*` and
  `OSPF_ROUTER_LINK_*` codepoints.

Use the same packet shape as the rest of the crate: build a layer, wrap it in an
IPv4 (or IPv6) layer, call `compile()`, and inspect `summary()` or `show()`. All
examples use documentation address space and the `AllSPFRouters` multicast
destination `224.0.0.5`. Use real routers only in an explicitly authorized lab
session.

## Hello Construction

`Ospfv2::hello()` creates a Hello packet (Type 1). Configure the Hello body with
an `OspfHello`, then wrap the OSPF layer in IPv4. `compile()` fills the OSPF
Length and Checksum and the IPv4 protocol number (89):

```rust
use crafter::prelude::*;
use crafter::protocols::ospf::packet::OspfHello;
use std::net::Ipv4Addr;

fn hello() -> crafter::Result<Packet> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 1))
        .dst(Ipv4Addr::new(224, 0, 0, 5)) // AllSPFRouters
        / Ospfv2::hello()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .hello_body(
                OspfHello::new()
                    .network_mask(Ipv4Addr::new(255, 255, 255, 0))
                    .hello_interval(10)
                    .router_dead_interval(40)
                    .router_priority(1)
                    .designated_router(Ipv4Addr::new(192, 0, 2, 1))
                    .neighbors([Ipv4Addr::new(192, 0, 2, 2)]),
            );

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", bytes.hexdump());
    Ok(packet)
}
```

## Link State Update With A Router-LSA

`Ospfv2::link_state_update()` creates a Link State Update packet (Type 4) that
carries one or more LSAs. Build each LSA from an `OspfLsaHeader` and a typed
`OspfLsaBody`; here a Router-LSA (`OspfLsaBody::Router`) describing two links.
`compile()` fills the LSA `length` and `ls_checksum` (Fletcher-16) and the OSPF
Length and Checksum unless they are set explicitly:

```rust
use crafter::prelude::*;
use crafter::protocols::ospf::lsa::{
    OspfLsa, OspfLsaBody, OspfLsaHeader, OspfRouterLink, OspfRouterLsa, OSPF_LSA_ROUTER,
    OSPF_ROUTER_LINK_POINT_TO_POINT, OSPF_ROUTER_LINK_STUB,
};
use crafter::protocols::ospf::packet::OspfLinkStateUpdate;
use std::net::Ipv4Addr;

fn link_state_update() -> crafter::Result<Packet> {
    let router = OspfRouterLsa::new()
        .border()
        .link(OspfRouterLink::new(
            Ipv4Addr::new(192, 0, 2, 2),
            Ipv4Addr::new(198, 51, 100, 1),
            OSPF_ROUTER_LINK_POINT_TO_POINT,
            10,
        ))
        .link(OspfRouterLink::new(
            Ipv4Addr::new(198, 51, 100, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            OSPF_ROUTER_LINK_STUB,
            20,
        ));

    let lsa = OspfLsa::new(
        OspfLsaHeader::new()
            .ls_type(OSPF_LSA_ROUTER)
            .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
            .advertising_router(Ipv4Addr::new(192, 0, 2, 1)),
        OspfLsaBody::Router(router),
    );

    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 1))
        .dst(Ipv4Addr::new(224, 0, 0, 5))
        / Ospfv2::link_state_update()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .link_state_update_body(OspfLinkStateUpdate::new().lsa(lsa));

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    Ok(packet)
}
```

## Authenticated Hello

OSPFv2 carries an authentication type and a 64-bit authentication field, plus an
optional appended cryptographic trailer. `simple_password(...)` sets AuType 1 and
writes the password into the authentication field; `crypto_md5_auth(key_id,
sequence_number, key)` sets AuType 2, fills the structured authentication field,
and appends the keyed-MD5 digest on `compile()`. HMAC-SHA cryptographic
authentication is available through `crypto_auth(...)` with an
`OspfCryptoAlgorithm`:

```rust
use crafter::prelude::*;
use crafter::protocols::ospf::packet::OspfHello;
use std::net::Ipv4Addr;

fn authenticated_hello() -> crafter::Result<Packet> {
    // Simple-password (AuType 1) Hello.
    let simple = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 1))
        .dst(Ipv4Addr::new(224, 0, 0, 5))
        / Ospfv2::hello()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .simple_password(b"ospfpass")
            .hello_body(
                OspfHello::new()
                    .network_mask(Ipv4Addr::new(255, 255, 255, 0))
                    .hello_interval(10)
                    .router_dead_interval(40),
            );

    // Cryptographic keyed-MD5 (AuType 2) Hello; the digest trailer is appended
    // on compile().
    let crypto = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 1))
        .dst(Ipv4Addr::new(224, 0, 0, 5))
        / Ospfv2::hello()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .crypto_md5_auth(1, 0, b"ospfkey")
            .hello_body(
                OspfHello::new()
                    .network_mask(Ipv4Addr::new(255, 255, 255, 0))
                    .hello_interval(10)
                    .router_dead_interval(40),
            );

    simple.compile()?;
    crypto.compile()?;
    println!("simple: {}", simple.summary());
    println!("crypto: {}", crypto.summary());
    Ok(crypto)
}
```

## Decode And Registry Dispatch

The built-in registry binds OSPF to IP protocol 89. An IPv4 packet whose
protocol is 89 decodes its payload as OSPFv2; an IPv6 packet whose next header is
89 decodes its payload as OSPFv3.

```rust
use crafter::prelude::*;
use crafter::protocols::ospf::packet::OspfHello;
use std::net::Ipv4Addr;

fn decode_ospf() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 1))
        .dst(Ipv4Addr::new(224, 0, 0, 5))
        / Ospfv2::hello()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .hello_body(OspfHello::new().network_mask(Ipv4Addr::new(255, 255, 255, 0)));

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;

    if let Some(ospf) = decoded.layer::<Ospfv2>() {
        println!("{}", ospf.summary());
    }

    Ok(())
}
```

The decoder preserves unknown LSA bodies as `Raw`, reports the per-packet
checksum and authentication status through `checksum_status()` and the
`OspfChecksumStatus` enum, and surfaces malformed OSPF framing as typed errors
with context such as the common header, a specific packet body, or an LSA field.
Truncation never becomes a silent panic.

## Offline And Live Surfaces

The offline path is the default: build packets, `compile()` them, decode the
bytes, and inspect `summary()`, `show()`, or `hexdump()` without touching a
network. OSPF runs directly over IP, so live transmission rides the standard raw
send and capture surface and the provider-backed lab/probe runners — never a
privileged raw send from the developer host. Plan with `--dry-run` first, use
documentation address space, and never commit live router identifiers,
credentials, or captures from sensitive networks.

For the agent-facing live procedure and generated-tool guidance, see
[`.agents/docs/cookbook.md`](../../.agents/docs/cookbook.md).

## Explicit Exclusions

The crate intentionally does not implement:

- The OSPF finite state machine: neighbor discovery, adjacency formation,
  Designated Router election behavior, the Hello/Dead timer engine, or
  retransmission lists.
- The Shortest Path First (SPF) computation, the routing table build, or any
  inter-area or external route summarization decisions.
- The link-state database (LSDB): flooding, LS aging, MaxAge purging, sequence
  rollover handling, or database synchronization.
- Cryptographic key management, rollover, and replay-protection policy beyond
  computing and verifying the per-packet authentication trailer.

Those are tools built on top of `crafter` packets. The crate stays focused on
constructing, decoding, preserving, and inspecting protocol-correct wire bytes.

## Standards and RFCs Implemented

Every wire fact below traces to reviewed RFC text. The library implements the
following for OSPF (intentional gaps are described in
[Explicit Exclusions](#explicit-exclusions)):

- **RFC 2328 — OSPF Version 2** — the 24-octet common header, the five packet
  types (Hello, Database Description, Link State Request, Link State Update, Link
  State Acknowledgment), the 20-octet LSA header with its Fletcher-16 LS
  checksum, and the Router (1), Network (2), Summary-IP (3), Summary-ASBR (4),
  and AS-External (5) LSA bodies. Also the Null (AuType 0), Simple Password
  (AuType 1), and Cryptographic keyed-MD5 (AuType 2) authentication trailers
  (RFC 2328 Appendix D).
- **RFC 3101 — The OSPF Not-So-Stubby Area (NSSA) Option** — the NSSA-LSA (type
  7) body and the NSSA `N/P` options handling for translated external routes.
- **RFC 5250 — The OSPF Opaque LSA Option** — the Opaque-LSA framing at
  link-local (type 9), area (type 10), and AS (type 11) flooding scope, carrying
  TLV bodies.
- **RFC 3630 — Traffic Engineering (TE) Extensions to OSPF Version 2** — the TE
  Opaque-LSA bodies (Router Address and Link TLVs with their sub-TLVs) carried in
  type-10 Opaque-LSAs.
- **RFC 7770 — Extensions to OSPF for Advertising Optional Router Capabilities**
  — the Router Information (RI) Opaque-LSA and its capability TLVs.
- **RFC 5709 — OSPFv2 HMAC-SHA Cryptographic Authentication** — HMAC-SHA-1,
  HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 cryptographic authentication as an
  extension of the RFC 2328 Cryptographic (AuType 2) trailer.
- **RFC 5340 — OSPF for IPv6 (OSPFv3)** — the base OSPFv3 surface: the 16-octet
  IPv6 common header and the Hello, Database Description, Link State Request,
  Link State Update (with Router and Network LSAs), and Link State
  Acknowledgment packet types, dispatched on IPv6 next-header 89.
