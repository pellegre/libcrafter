# ICMPv6 Wire Coverage

This page describes the ICMPv6 packet-layer support in the `crafter` crate: which
ICMPv6 message families the `Icmpv6` layer builds and decodes with typed bodies,
how the checksum is filled on `compile()`, how Neighbor Discovery options are
modeled, and which `Type` codepoints are intentionally deferred. For the full API
surface see [the API reference](../reference/api.md).

`Icmpv6` is the fixed ICMPv6 header and the front of an ICMPv6 packet. It carries
the IANA `Type` codepoint space and uses the same shape as `Icmpv4`: the bytes
after the fixed header are typed body layers composed with `/`, the checksum is
auto-filled over the IPv6 pseudo-header at `compile()`, and `summary`, `show`,
and `decode_from_l3` apply uniformly.

All wire facts on this page trace to reviewed RFC text and the
[ICMPv6 Parameters registry][iana-icmpv6]. The RFCs the ICMPv6 layer implements
are listed in [Standards and RFCs implemented](#standards-and-rfcs-implemented)
at the end of this guide.

## Coverage at a glance

| Message family | Type(s) | State | Notes |
| --- | --- | --- | --- |
| Echo Request / Reply | 128/129 | Typed | `Icmpv6::echo_request()`, `Icmpv6::echo_reply()`. |
| Errors (Dest. Unreachable / Packet Too Big / Time Exceeded / Parameter Problem) | 1–4 | Typed | `Icmpv6::destination_unreachable()`, `packet_too_big()`, `time_exceeded()`, plus `Icmpv6::new().icmp_type(...)`. |
| Multicast Listener Discovery v1 | 130–132 | Typed | `Icmpv6::mld_query()`, `mld_general_query()`, `mld_report()`, `mld_done()`. |
| Multicast Listener Discovery v2 | 130, 143 | Typed | `Icmpv6::mldv2_report()`, `mldv2_query()`, `mldv2_general_query()`. |
| Neighbor Discovery + base and extension options | 133–137 | Typed | Five NDP constructors plus a typed NDP option TLV layer. |
| Node Information Query / Response | 139/140 | Typed (**experimental**) | `Icmpv6::node_information_query()`, `node_information_response()`. |
| Extended Echo Request / Reply | 160/161 | Typed | `Icmpv6::extended_echo_request()`, `extended_echo_reply()`. |
| Unknown / deferred types | other | Preserved | Valid header plus a trailing `Raw` body; `Icmpv6::body()` returns `Icmpv6Body::Unknown`. |

## ICMPv6 construction

The `Icmpv6` layer is exported through `crafter::prelude::*`. Build a message with
a typed constructor, compose any body and options with `/`, and place it on an
IPv6 layer; `compile()` fills the checksum over the IPv6 pseudo-header:

```rust
use crafter::prelude::*;

let packet = Ipv6::new()
    .src("2001:db8::10")?
    .dst("2001:db8::1")?
    / Icmpv6::echo_request().identifier(0x1234).sequence(1)
    / Raw::from("ping");

let bytes = packet.compile()?;
println!("{}", packet.summary());
```

The Neighbor Discovery messages carry an ordered list of NDP options as a typed
TLV layer. Build options through `NdpOption` constructors and collect them in
`NdpOptions`; `compile()` auto-fills each option's length field (in 8-octet
units, with padding), and unknown option types round-trip byte-for-byte. The
modeled options span the RFC 4861 base set (Source/Target Link-Layer Address,
Prefix Information, Redirected Header, MTU) and the extension options Nonce
(RFC 3971), Route Information (RFC 4191), RDNSS / DNSSL (RFC 8106), RA Flags
Extension (RFC 5175), Captive Portal (RFC 8910), and PREF64 (RFC 8781). Router
Advertisement also exposes the RFC 4191 Default Router Preference (`Prf`) through
`Icmpv6::router_advertisement_with_preference(...)`.

On decode, `Icmpv6::body()` returns an `Icmpv6Body` view that classifies the
message (echo, error, the five NDP types, MLD, extended echo, node information)
from the header `type`; unknown types are preserved as `Icmpv6Body::Unknown` with
a trailing `Raw` body — no panic, no misparse. See
[the API reference](../reference/api.md) for the complete constructor, NDP
option, and accessor tables.

### Node Information Queries are experimental

[RFC 4620][rfc4620] ("IPv6 Node Information Queries", types 139 and 140) is an
Experimental RFC, not Standards Track, and was never widely deployed. The crate
implements the message bodies (`Icmpv6::node_information_query` /
`node_information_response`, the `NodeInformation` body layer, and the Qtype /
Code constants) so the codepoint space is covered rather than silently dropped,
but the feature is marked experimental in its module and builder rustdoc. The
variable `Data` field is carried as inspectable raw bytes rather than fully typed
for every Qtype.

## Standards and RFCs implemented

Every wire fact below traces to reviewed RFC text and the IANA ICMPv6 Parameters
registry. The library implements the following for ICMPv6 (experimental and
deferred items are marked):

- **RFC 4443 — ICMPv6 for IPv6** — the base fixed header, the error messages
  (Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem,
  types 1–4), and Echo Request/Reply (128/129).
- **RFC 2710 — Multicast Listener Discovery (MLD)** — MLD v1 Query / Report / Done
  (types 130–132).
- **RFC 3810 — Multicast Listener Discovery Version 2 (MLDv2)** — MLDv2 Query and
  Version 2 Report (types 130, 143; IANA cites RFC 9777).
- **RFC 4861 — Neighbor Discovery for IPv6** — Router/Neighbor Solicitation and
  Advertisement and Redirect (types 133–137), plus the base NDP options
  (Source/Target Link-Layer Address, Prefix Information, Redirected Header, MTU).
- **NDP option extensions** — **RFC 4191** (Route Information, Default Router
  Preference), **RFC 5175** (RA Flags Extension), **RFC 8106** (RDNSS / DNSSL),
  **RFC 3971** (Nonce), **RFC 8781** (PREF64), **RFC 8910** (Captive Portal).
- **RFC 4620 — IPv6 Node Information Queries** (**experimental**) — Node
  Information Query / Response (types 139/140); message bodies implemented, the
  variable `Data` field carried as inspectable raw bytes.
- **RFC 8335 — PROBE: A Utility for Probing Interfaces** — Extended Echo
  Request/Reply (types 160/161).

Deferred codepoints — these standards-track families are not modeled with typed
builders/decoders and are preserved as unknown (`Raw`) rather than typed:

- **RFC 2894 — Router Renumbering** (type 138) — niche / essentially undeployed
  router-management mechanism; preserved as unknown/`Raw`.
- **RFC 3122 — Inverse Neighbor Discovery** (types 141/142) — niche extension with
  little general deployment; preserved as unknown/`Raw`.

Mobile IPv6 (RFC 6275) and the SEND certificate options (RFC 3971 CGA / RSA /
certificate) are likewise out of scope and preserved as unknown options /
messages. The named `Type` constants for the deferred families already exist
(`ICMPV6_ROUTER_RENUMBERING`, `ICMPV6_INVERSE_ND_SOLICITATION`,
`ICMPV6_INVERSE_ND_ADVERTISEMENT`), so a future effort can add typed bodies under
`crafter/src/protocols/icmp/v6/message/` following the `ndp` module pattern.

[iana-icmpv6]: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
[rfc4620]: https://www.rfc-editor.org/rfc/rfc4620
