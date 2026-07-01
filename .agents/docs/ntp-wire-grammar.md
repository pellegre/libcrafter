# NTP Wire Grammar

This note records the packet grammar that later NTP code, tests, fixtures, and
validation specs must use. It is scoped to NTP as UDP user data in `crafter` and
does not define a daemon, clock discipline, NTS-KE exchange, Autokey verifier,
scanner, or live sender.

## Evidence Boundary

`.agents/docs/ntp-rfc-manifest.md` is the authority manifest for this file. The
manifest review date is 2026-07-01, and later implementation steps must cite the
manifest plus the exact narrower source below before depending on a wire fact.

| Wire decision | Source |
| --- | --- |
| UDP-carried NTP packet boundary and the fixed packet header | RFC 5905, Sections 7.3 and 8; IANA Service Name and Transport Protocol Port Number registry, `ntp 123/udp` row |
| NTP short and timestamp field formats | RFC 5905, Section 6, Figure 3 |
| Fixed header layout, LI/VN/Mode packing, stratum, poll, precision, root delay, root dispersion, reference ID, timestamps, extension placement, and MAC placement | RFC 5905, Section 7.3, Figures 7 through 12 |
| Kiss-o'-Death use of stratum 0 reference IDs | RFC 5905, Section 7.4; IANA Network Time Protocol Parameters registry rows for Kiss-o'-Death codes |
| Leap-indicator wording | RFC 5905, Section 7.3, Figure 9, as reviewed through RFC Editor Errata 4504 in `.agents/docs/ntp-rfc-manifest.md` |
| Extension field framing, unknown field behavior, length limits, word alignment, and extension-without-MAC rules | RFC 7822, Section 3, updating RFC 5905 Section 7.5 and adding Section 7.5.1; RFC Editor Errata 3627 as recorded in `.agents/docs/ntp-rfc-manifest.md` |
| Legacy MAC tail shape and current authentication caveat | RFC 5905, Section 7.3; RFC 7822, Sections 1 and 3; RFC 8573, Sections 2 and 3 |
| UDP Checksum Complement extension body | RFC 7821, Sections 3.2 through 3.4 |
| NTS packet extension fields | RFC 8915, Sections 5.2 through 5.6 |
| Registry assignments and future corrections | RFC 9748 and the current IANA Network Time Protocol Parameters registry |
| Update relationships that do not change the base payload layout | Datatracker relationships for RFC 5905, RFC 9109, and RFC 9769, as recorded in `.agents/docs/ntp-rfc-manifest.md` |

If a later official update or verified erratum conflicts with this grammar,
stop and refresh the manifest before changing parser or serializer behavior.

## Datagram Boundary

For packet parsing, one UDP user-data payload is one candidate NTP packet. The
NTP parser starts at byte 0 of the UDP payload selected by the UDP length field
and must not read beyond that payload. UDP surplus data, link padding, capture
padding, or bytes outside the UDP user-data boundary are not part of the NTP
packet.

The minimum fixed NTP header is 48 octets: 12 32-bit words in network byte
order ending with the Transmit Timestamp field. A direct NTP parser must return
a structured truncated-buffer error when fewer than 48 octets are available.
Registry-driven UDP/123 application decoding must leave too-short payloads as
`Raw` instead of forcing an NTP decode.

## Fixed Header Layout

The first 48 octets are the fixed header from RFC 5905 Section 7.3, Figure 8.
All multi-octet integer and fixed-point fields are in network byte order.

| Offset | Size | Field | Grammar and preservation rule |
| --- | ---: | --- | --- |
| 0 | 1 | LI/VN/Mode | Packed first octet: `LI` in bits 7..6, `VN` in bits 5..3, `Mode` in bits 2..0. Preserve all raw bit values. |
| 1 | 1 | Stratum | Unsigned 8-bit packet stratum. Values 0, 1, 2..15, 16, and 17..255 are all structurally valid packet bytes and must remain inspectable. |
| 2 | 1 | Poll | Signed 8-bit log2 seconds exponent. Preserve the raw octet and expose signed interpretation only as a helper. |
| 3 | 1 | Precision | Signed 8-bit log2 seconds exponent. Preserve the raw octet and expose signed interpretation only as a helper. |
| 4 | 4 | Root Delay | NTP short-format field from RFC 5905 Section 6. Preserve the 32 raw bits; helper interpretation belongs to the fixed-point helper step. |
| 8 | 4 | Root Dispersion | NTP short-format field from RFC 5905 Section 6. Preserve the 32 raw bits; helper interpretation belongs to the fixed-point helper step. |
| 12 | 4 | Reference ID | Four raw octets whose meaning depends on stratum. Do not reject unknown reference identifiers. |
| 16 | 8 | Reference Timestamp | NTP timestamp format: 32-bit seconds followed by 32-bit fraction. Preserve the raw 64 bits. |
| 24 | 8 | Origin Timestamp | NTP timestamp format. Preserve the raw 64 bits. |
| 32 | 8 | Receive Timestamp | NTP timestamp format. Preserve the raw 64 bits. |
| 40 | 8 | Transmit Timestamp | NTP timestamp format. Preserve the raw 64 bits. |

The serializer may fill protocol defaults only for fields that the caller left
unset. Caller-provided values, including unusual LI, version, mode, stratum,
poll, precision, root fields, reference IDs, or timestamps, must survive
compilation byte-for-byte.

## First Octet

The first octet is a bit field, not three separate bytes:

```text
first = ((li & 0x03) << 6) | ((version & 0x07) << 3) | (mode & 0x07)
li = (first >> 6) & 0x03
version = (first >> 3) & 0x07
mode = first & 0x07
```

RFC 5905 defines version 4 as the current NTP version and lists mode values
0..7. The packet layer must preserve all 3-bit values rather than rejecting
reserved, private-use, older, or future-shaped values during fixed-header
decode. Labels and stricter helper semantics belong to later codepoint steps.

## Stratum And Reference ID

Stratum is a packet byte, not a parser gate. RFC 5905 Section 7.3 defines
stratum 0 as unspecified or invalid, stratum 1 as a primary server, strata 2
through 15 as secondary servers, stratum 16 as unsynchronized, and 17 through
255 as reserved. The NTP layer must keep every value available for `summary()`,
`show()`, and round-trip compilation.

The Reference ID is always four octets in the fixed header. Its display label is
stratum-dependent:

- stratum 0 uses four-character Kiss-o'-Death codes, with source-backed labels
  from RFC 5905 Section 7.4 and the IANA NTP registry;
- stratum 1 uses reference-clock identifiers, with current labels from the IANA
  NTP registry;
- secondary-server packets may carry an IPv4 address or the first four octets
  of an IPv6-address MD5 hash, as described by RFC 5905 Section 7.3.

The parser must not infer lower-layer addresses from the Reference ID or reject
unregistered, experimental, unknown, or non-ASCII bytes. It should preserve the
raw bytes and expose labels only when source-backed.

## Timestamps And Fixed-Point Fields

RFC 5905 Section 6 defines the 64-bit timestamp format as unsigned seconds plus
fraction, and the 32-bit short format as seconds plus fraction. The packet layer
records those fields as wire values. Converting them to wall-clock instants,
choosing an era, applying interleaved-mode timestamp semantics from RFC 9769, or
disciplining a local clock is outside the grammar.

## Extension Fields

Any bytes after the fixed 48-octet header may contain one or more NTP extension
fields, followed by an optional legacy MAC tail. RFC 7822 Section 3 updates RFC
5905 Section 7.5 and is the controlling source for extension field framing.

Each extension field has this 32-bit-aligned envelope:

```text
extension-field = field-type length value-and-padding
field-type      = 2 octets
length          = 2 octets, unsigned, includes field-type, length, value, and padding
value-padding   = length - 4 octets
```

Extension field parsing rules:

- `length` must be at least 16 octets for any structurally valid extension
  field.
- `length` must be a multiple of 4 octets, because all extension fields are
  padded to a word boundary.
- `length` must not exceed the remaining UDP payload bytes.
- The largest representable aligned extension field length is 65532 octets.
- Unknown field types are structurally valid when their length and alignment are
  valid; preserve the complete field bytes and do not fail solely because a type
  is unrecognized.
- When no MAC is present, RFC 7822 requires a single extension field to be at
  least 28 octets. If more than one extension field is present without a MAC,
  the last extension field must be at least 28 octets and earlier extension
  fields must be at least 16 octets each.

Malformed extension length, alignment, or availability failures must be
structured parse errors for direct NTP parsing. UDP registry dispatch should
fall back to `Raw` for UDP/123 payloads whose tail cannot be partitioned into a
valid fixed header plus source-backed extension fields and/or an optional legacy
MAC tail.

## Legacy MAC Tail

The MAC, when present, is the final packet data after the fixed header and any
extension fields. RFC 5905 Section 7.3 describes a Key Identifier followed by a
Message Digest, and RFC 7822 Sections 1 and 3 clarify that a MAC can be 4 octets
for a crypto-NAK, 20 octets, or 24 octets, with longer MACs only when agreed by
the peers. RFC 8573 deprecates MD5-based authentication and recommends AES-CMAC
when authentication is implemented.

`crafter` models this as raw packet tail data only. It must not compute, verify,
upgrade, or reject authentication material. If the tail is structurally
ambiguous, the parser should choose the source-backed interpretation that
preserves bytes without inventing cryptographic state; direct parse errors are
reserved for tails that violate explicit length, alignment, or availability
rules.

## NTS Packet Extension Fields

NTS packet data is carried as NTPv4 extension fields using the same RFC 7822
extension field envelope. RFC 8915 Section 5.2 describes the NTS packet
structure as the normal 48-octet NTP header, authenticated but not encrypted,
followed by extension fields, including an authenticator/encrypted extension
field.

The NTS extension bodies that this packet primitive may label and preserve are:

- Unique Identifier, RFC 8915 Section 5.3, Field Type `0x0104`, raw body bytes
  with source-backed minimum-length semantics left to the NTS helper step;
- NTS Cookie, RFC 8915 Section 5.4, Field Type `0x0204`, opaque cookie bytes;
- NTS Cookie Placeholder, RFC 8915 Section 5.5, Field Type `0x0304`, placeholder
  body bytes;
- NTS Authenticator and Encrypted Extension Fields, RFC 8915 Section 5.6, Field
  Type `0x0404`, body containing nonce length, ciphertext length, nonce bytes,
  ciphertext bytes, and padding.

The crate must not implement NTS-KE, TLS exporter logic, AEAD encryption or
decryption, cookie construction, replay-cache decisions, or authentication
success/failure. Unknown NTS-related body bytes remain raw packet data.

## Raw Fallback Policy

There are two parse surfaces:

- Direct NTP parsing reports structured errors for too-short buffers, malformed
  extension fields, impossible tail partitions, and truncation. Errors should
  include stable context plus required and available lengths where possible.
- Registry-driven UDP application decoding is conservative. UDP/123 payloads
  shorter than 48 octets, or payloads whose post-header tail fails the NTP shape
  rules above, remain `Raw` so unrelated or malformed traffic is not
  misidentified as NTP.

Unknown but structurally valid versions, modes, strata, reference identifiers,
extension field types, NTS bodies, MAC bytes, and source-backed payload tails are
not raw-fallback triggers. They are NTP packet data and must remain inspectable
and byte-preserving.
