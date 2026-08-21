# QUIC Packet Grammar Notes

This note records the packet-header grammar that later QUIC code must use for
version-independent recognition, QUIC v1, QUIC v2, Retry, Version Negotiation,
stateless reset handling, and coalesced UDP datagrams. It is source-backed by
`.agents/docs/quic-manifest.md` and `.agents/docs/quic-codepoints.md`; parser
and builder code must cite this note or a later generated manifest instead of
using model memory.

## Evidence Boundary

| Rule area | Evidence record |
| --- | --- |
| Version-independent packet forms, long header invariants, short header invariants, connection ID and version fields, Version Negotiation | `E-RFC-8999` in `quic-manifest.md` |
| QUIC v1 packet formats, varint length fields, packet number encoding, coalescing, stateless reset format | `E-RFC-9000` in `quic-manifest.md` |
| Retry integrity tag inputs and v1 tag size | `E-RFC-9001` in `quic-manifest.md` |
| QUIC bit greasing behavior | `E-RFC-9287` in `quic-manifest.md` |
| Compatible version negotiation behavior | `E-RFC-9368` in `quic-manifest.md` |
| QUIC v2 version value, long-header packet type remapping, Initial and Retry crypto differences | `E-RFC-9369` in `quic-manifest.md` |
| UDP multiplexing boundary for future classifier work | `E-RFC-9443` in `quic-manifest.md` |
| Version constants, reserved version rule, permanent/prepareal status | `.agents/docs/quic-codepoints.md` |

The RFC 9000 errata note in `quic-manifest.md` remains active. Later
implementation steps must re-check any affected section before coding if an
erratum touches a parser rule below.

## Recognition Model

QUIC is carried in UDP datagrams. A UDP datagram can contain one or more QUIC
packets, but the RFC 8999 invariants describe only the first packet in the
datagram. The first byte separates the invariant header form:

- Long header: bit `0x80` is set. The invariant prefix is first byte, 32-bit
  version, 8-bit destination connection ID length, destination connection ID,
  8-bit source connection ID length, source connection ID, then
  version-specific data. RFC 8999 allows each encoded connection ID length to
  represent 0 to 255 bytes; QUIC v1 and v2 packet formats restrict the length
  to at most 20 bytes for version-specific long headers.
- Short header: bit `0x80` is clear. The invariant prefix is first byte,
  destination connection ID, then version-specific data. The destination
  connection ID length is not encoded in the short header, so short-header
  decode requires caller, registry, or connection context; without that context,
  `crafter` must preserve the UDP payload as raw or ambiguous rather than guess
  a connection ID length.

The 32-bit version field is present only in long headers. Version `0x00000000`
identifies Version Negotiation. `quic-codepoints.md` marks QUIC v1
`0x00000001` and QUIC v2 `0x6b3343cf` as default-eligible permanent versions,
marks the v2 draft codepoint `0x709a50c4` as non-default, and records the
reserved version grease test `(value & 0x0f0f0f0f) == 0x0a0a0a0a`. Unknown
nonzero versions remain typed numeric values; version-independent parsing may
continue, but version-specific packet grammar must not be guessed.

## First Byte Fields

For QUIC v1 and v2 long headers, the first byte has this shape:

```text
0x80: Header Form = 1
0x40: Fixed Bit / QUIC Bit
0x30: Long Packet Type
0x0c: Reserved Bits for Initial, 0-RTT, and Handshake
0x03: Packet Number Length for Initial, 0-RTT, and Handshake
```

For QUIC v1 and v2 short headers, the first byte has this shape:

```text
0x80: Header Form = 0
0x40: Fixed Bit / QUIC Bit
0x20: Spin Bit
0x18: Reserved Bits
0x04: Key Phase
0x03: Packet Number Length
```

RFC 9000 defines the fixed bit as set for v1 packets other than Version
Negotiation; RFC 9369 keeps the same fixed-bit position for v2. RFC 9287 can
allow the QUIC bit to be cleared after the `grease_quic_bit` transport
parameter is negotiated. Because `crafter` is a packet primitive, the decoder
should expose the bit and preserve bytes; endpoint discard requirements are not
parse failures. Builders must preserve explicit user overrides, including a
cleared fixed bit or nonzero reserved bits, and should only fill defaults when
the field is unset.

The packet number length bits encode `stored_value + 1`, so packet number fields
occupy 1, 2, 3, or 4 bytes. Packet number values are header-truncated values;
full packet number reconstruction depends on endpoint state and is deferred
until the packet-number helper step.

## Long Header Packet Types

QUIC v1 maps the two long-header packet type bits as follows:

| Bits | v1 packet |
| --- | --- |
| `0b00` | Initial |
| `0b01` | 0-RTT |
| `0b10` | Handshake |
| `0b11` | Retry |

QUIC v2 deliberately remaps every long-header packet type:

| Bits | v2 packet |
| --- | --- |
| `0b00` | Retry |
| `0b01` | Initial |
| `0b10` | 0-RTT |
| `0b11` | Handshake |

The version field chooses the packet-type table. For unknown nonzero versions,
only the invariant long-header prefix is source-backed; lower first-byte bits
and all remaining data must be preserved as version-specific raw bytes.

## Version Negotiation

A Version Negotiation packet is identified by a long header with version
`0x00000000`. Only the high bit of the first byte is defined by RFC 8999; the
remaining seven bits are unused and ignored on receipt. RFC 9000 recommends
setting `0x40` for multiplexing appearance, but other versions are not required
to follow that recommendation.

The Version Negotiation layout is:

```text
first byte with Header Form = 1
Version (32) = 0x00000000
Destination Connection ID Length (8)
Destination Connection ID (0..255 bytes by invariant grammar)
Source Connection ID Length (8)
Source Connection ID (0..255 bytes by invariant grammar)
Supported Version (32) repeated
```

The supported-version list consumes the rest of the UDP datagram. It must be
non-empty and made of complete 32-bit values for endpoint acceptance; a parser
should report a structured `CrafterError` for a truncated supported-version
field. Version Negotiation has no Length or Packet Number field, no frames, and
no cryptographic protection. It consumes the entire UDP datagram and is not
coalesced with other QUIC packets. RFC 9368 compatible version negotiation uses
the Version Negotiation mechanism but its transport-parameter validation rules
are deferred to the version-information transport parameter step.

## QUIC v1 Long Headers

All v1 long headers share the invariant long-header prefix and a v1 connection
ID length limit of 20 bytes for Destination and Source Connection IDs. Values
larger than 20 bytes are endpoint-drop conditions in RFC 9000; `crafter` should
preserve explicit malformed construction and surface a validation result or
structured parse error only when the byte stream is truncated.

Initial packets use long packet type `0b00`:

```text
long header prefix
Token Length (QUIC varint)
Token (Token Length bytes)
Length (QUIC varint, counts Packet Number plus Packet Payload)
Packet Number (1..4 bytes)
Packet Payload (protected/raw bytes)
```

0-RTT packets use long packet type `0b01`, and Handshake packets use long
packet type `0b10`:

```text
long header prefix
Length (QUIC varint, counts Packet Number plus Packet Payload)
Packet Number (1..4 bytes)
Packet Payload (protected/raw bytes)
```

Retry packets use long packet type `0b11`:

```text
long header prefix
Retry Token (opaque bytes)
Retry Integrity Tag (16 bytes)
```

A Retry packet has no Packet Number, no Length field, and no frames. The lower
four bits of its first byte are unused and ignored on receipt. RFC 9000 requires
clients to discard a zero-length Retry Token, but that is endpoint behavior;
packet decode should preserve the token bytes and report only framing errors,
such as a packet too short to contain the 16-byte Retry Integrity Tag.
Verifying the v1 Retry Integrity Tag is deferred to the packet-protection
utility steps and uses `E-RFC-9001`.

## QUIC v2 Differences

QUIC v2 uses version `0x6b3343cf`, keeps the long-header and short-header
shapes from QUIC v1, and changes the long-header packet type mapping listed
above. It also changes Initial packet protection labels, Initial salt, and Retry
integrity key/nonce material; those crypto details are deferred to the packet
protection vector steps. Packet grammar code must not treat v2 as v1 with only
a different version constant, because the long-header packet type bits identify
different packets.

For compatible negotiation between v1 and v2, RFC 9369 says a Retry packet uses
the original version. That is endpoint behavior for later validation helpers;
the packet parser should classify Retry by the version value actually present
in the long header.

## Short Headers

For QUIC v1 and v2, a short header is a 1-RTT packet:

```text
first byte with Header Form = 0
Destination Connection ID (length from context, 0..20 bytes for v1/v2)
Packet Number (1..4 bytes)
Packet Payload (protected/raw bytes)
```

The short header does not encode a version, source connection ID, or connection
ID length. A UDP application recognizer must therefore be conservative: a
short-header-looking payload is not enough to claim QUIC without port,
connection ID length, registry, or caller context. The Packet Number Length,
Reserved Bits, and Key Phase fields are header-protected in normal traffic, so
default decode should preserve the protected bytes and not infer endpoint state.

Because short headers do not have a Length field, a short-header packet can
only be the final QUIC packet in a coalesced UDP datagram. A datagram whose
first packet has a short header does not trigger Version Negotiation.

## Stateless Reset Limits

Stateless Reset is not a normal QUIC packet layer. RFC 9000 makes it look like
a short-header packet to observers:

```text
Header Form = 0 and Fixed Bit = 1
Unpredictable Bits, at least 38 bits for the minimum shape
Stateless Reset Token (16 trailing bytes)
```

The minimum v1 stateless reset size is 21 bytes, and detection requires endpoint
state: compare the final 16 bytes of the UDP datagram with stateless reset
tokens associated with active connection IDs and the remote address. Without
known tokens, `crafter` may expose only a "plausible stateless reset" helper and
must not claim verification. A datagram shorter than the minimum QUIC-TLS
short-header packet size is not valid v1 protected traffic, but it still should
not panic the parser.

## Coalesced UDP Datagrams

Initial, 0-RTT, and Handshake packets include a QUIC varint Length field that
delimits the packet. That length counts the Packet Number bytes and protected
payload bytes, which lets a UDP datagram contain multiple complete QUIC packets.
Retry packets, Version Negotiation packets, and short-header packets do not have
a Length field and cannot be followed by another QUIC packet in the same UDP
datagram.

Later decode should iterate coalesced packets only where a source-backed length
field delimits the current packet. Decryption failure or unsupported protected
payload in one packet must not stop parsing of later delimited packets; preserve
protected or unknown payloads as raw bytes. Endpoint routing rules about
different connection IDs in the same datagram are validation policy, not parser
structure.

## Malformed Decode Boundaries

Malformed packet decode must return structured `CrafterError` values with
stable context, required length, and available length where applicable. Required
boundaries include:

- missing first byte;
- truncated long-header version field;
- missing or truncated Destination Connection ID length and bytes;
- missing or truncated Source Connection ID length and bytes;
- truncated QUIC varints for Initial Token Length or long-header Length;
- token length exceeding available bytes;
- long-header Length shorter than the indicated Packet Number length;
- Packet Number Length requiring more bytes than remain;
- Retry packet shorter than the 16-byte integrity tag;
- Version Negotiation supported-version list that is empty or not a multiple of
  4 bytes;
- short-header decode requested without enough bytes for the configured
  destination connection ID length and packet number length.

Protocol-invalid but byte-complete values, such as a v1 fixed bit of zero,
reserved bits set, v1/v2 connection ID length above 20, zero-length Retry Token,
reserved versions, or unknown versions, should remain inspectable instead of
being discarded. Builders must preserve caller-pinned malformed fields and only
auto-fill dependent fields when unset.

## Examples And Live Boundary

This step records grammar only and performs no live traffic. Later examples
that include UDP/IP layers must use documentation address space such as
`192.0.2.10:4433` to `198.51.100.20:4433` or `2001:db8::10` to
`2001:db8::20`. Externally executed validation, packet protection vectors, retry
tag verification, compatible version negotiation helpers, multiplexing
classifier policy, and full stateless reset token verification are deferred to
their later plan steps.
