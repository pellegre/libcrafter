# QUIC Multiplexing Notes

This note records the UDP recognition boundary for the `crafter` QUIC packet
primitive. It is source-backed by `E-RFC-9443`, `E-RFC-8999`, `E-RFC-9000`, and
`E-RFC-9287` in `.agents/docs/quic-manifest.md`, plus the selected
`Multiplexing updates` row in `.agents/docs/quic-version-extension-matrix.md`.

No live traffic is authorized by this note. Packet examples and validation for
this boundary stay offline and use byte fixtures.

## Registry Policy

The built-in registry may claim a UDP payload as QUIC only when all of these
conditions are true:

- Application decoding is enabled.
- No custom UDP binding has already selected the payload.
- The source or destination UDP port is one of the conservative built-in QUIC
  ports, currently `443` or the documentation/example port `4433`.
- The payload has source-backed QUIC long-header structure.

Short-header-looking payloads are not claimed by default because a short header
does not encode the destination connection ID length. Caller or endpoint
context is required before a decoder can know where the short header ends.

Version Negotiation is the only built-in long-header recognition case that may
have the QUIC bit cleared. RFC 8999 fixes only the header-form bit for Version
Negotiation, and RFC 9287 keeps cleared QUIC-bit behavior inspectable rather
than making it a registry-wide claim for unrelated UDP payloads.

## Neighbor Protocol Boundaries

RFC 9443 updates the QUIC multiplexing context for deployments that share a UDP
socket with other protocols. In `crafter`, that evidence constrains the
classifier; it does not authorize a broad UDP demultiplexer rewrite.

The built-in QUIC classifier must not corrupt or steal payloads that look like
neighbor protocols, including:

- DTLS/TLS record shapes such as first byte `0x14` through `0x17`.
- STUN messages whose first two bits are clear and that carry the STUN magic
  cookie at bytes 4 through 7.
- RTP/RTCP packets in the `0x80..0xbf` first-byte space that do not also have a
  source-backed QUIC long-header prefix.
- ZRTP payloads.
- TURN ChannelData payloads in the `0x40..0x7f` first-byte space.
- ESP/IKE/NAT-T, DNS, DHCP, RIP, RIPng, and any custom UDP binding already
  handled elsewhere in `ProtocolRegistry`.

When those shapes arrive on `443` or `4433`, default decode preserves them as
`Raw` unless another existing protocol binding has selected them first.

## Offline Validation

Focused offline coverage is named with the `quic_multiplexing_classifier`
prefix:

- QUIC long-header and Version Negotiation fixtures are accepted.
- DTLS, STUN, RTP, ZRTP, TURN ChannelData, ambiguous short-header, and cleared
  QUIC-bit short-header fixtures are rejected by the classifier.
- Neighbor fixtures on QUIC ports remain `Raw`.
- Custom UDP bindings continue to take precedence over built-in QUIC dispatch.

Future oracle or lab coverage must start with dry-run plans and must not send
live traffic from the developer machine.
