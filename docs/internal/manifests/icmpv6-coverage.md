# ICMPv6 message coverage and deferrals

This note records which ICMPv6 message families the `crafter` crate models with
typed builders and decoders, and which `Type` codepoints are intentionally
**deferred** — preserved as unknown (`Raw`) rather than typed — with the
authoritative reference and the reason for each deferral.

The IANA authority for the `Type` field is the
[ICMPv6 Parameters registry][iana-icmpv6].

## Implemented message families

| Type(s) | Message family | Reference | Status |
|---------|----------------|-----------|--------|
| 1–4 | Destination Unreachable / Packet Too Big / Time Exceeded / Parameter Problem | RFC 4443 | typed |
| 128/129 | Echo Request / Reply | RFC 4443 | typed |
| 130–132 | Multicast Listener Discovery v1 (Query / Report / Done) | RFC 2710 | typed |
| 130, 143 | Multicast Listener Discovery v2 (Query / Version 2 Report) | RFC 3810 (IANA cites RFC 9777) | typed |
| 133–137 | Neighbor Discovery (Router/Neighbor Solicitation & Advertisement, Redirect) + base and extension options | RFC 4861 (options: RFC 4191, 5175, 8106, 3971, 8781, 8910) | typed |
| 139/140 | Node Information Query / Response | RFC 4620 | typed (**experimental**) |
| 160/161 | Extended Echo Request / Reply | RFC 8335 | typed |

### Node Information Queries (RFC 4620) are experimental

[RFC 4620][rfc4620] ("IPv6 Node Information Queries", types 139 and 140) is an
**Experimental** RFC, not Standards Track, and was never widely deployed. The
crate implements the message bodies — `Icmpv6::node_information_query` /
`Icmpv6::node_information_response`, the `NodeInformation` body layer, and the
Qtype / Code constants — so the codepoint space is covered rather than silently
dropped, but the feature is marked experimental in its module and builder
rustdoc. The variable `Data` field (whose shape depends on the Qtype and Code)
is carried as inspectable raw bytes rather than fully typed for every Qtype.

## Deferred codepoints (preserved as unknown / `Raw`)

The following standards-track ICMPv6 message families are **not** modeled with
typed builders/decoders in this effort. They are low-deployment / niche on
today's networks, and modeling their full wire formats was judged out of scope
relative to the Neighbor Discovery, MLD, extended-echo, and Node Information
work. They are preserved by the crate's default ICMPv6 decode path: an
unrecognized `Type` keeps a valid `Icmpv6` header plus a single trailing `Raw`
body (no panic, no misparse), and `Icmpv6::body()` classifies it as
`Icmpv6Body::Unknown` with the raw rest-of-header preserved. This is verified by
an integration test (`crafter/tests/icmpv6_ndp.rs`).

| Type(s) | Message family | Reference | Reason for deferral |
|---------|----------------|-----------|---------------------|
| 138 | Router Renumbering | [RFC 2894][rfc2894] | Niche / essentially undeployed router-management mechanism; full Match-Prefix / Use-Prefix / Result message processing is large and out of scope. Preserved as unknown/`Raw`. |
| 141/142 | Inverse Neighbor Discovery Solicitation / Advertisement | [RFC 3122][rfc3122] | Niche extension (originally for Frame Relay / non-broadcast links) with little general deployment; the Source/Target Address List options add a separate sub-format. Preserved as unknown/`Raw`. |

Mobile IPv6 (RFC 6275) and the SEND certificate options (RFC 3971 CGA / RSA /
certificate) are likewise out of scope for this effort and are preserved as
unknown options / messages.

If a future effort needs typed support for any deferred family, the named
`Type` constants already exist (`ICMPV6_ROUTER_RENUMBERING`,
`ICMPV6_INVERSE_ND_SOLICITATION`, `ICMPV6_INVERSE_ND_ADVERTISEMENT`), so the work
is to add the message body under `crafter/src/protocols/icmp/v6/message/` and a
decode-dispatch arm, following the pattern documented in the `ndp` module.

[iana-icmpv6]: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
[rfc4620]: https://www.rfc-editor.org/rfc/rfc4620
[rfc3122]: https://www.rfc-editor.org/rfc/rfc3122
[rfc2894]: https://www.rfc-editor.org/rfc/rfc2894
