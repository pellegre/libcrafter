# QUIC Frame Grammar Notes

This note records source-backed QUIC frame grammar for later parser, builder,
fixture, and oracle work in the `quic-protocol-bootstrap` plan. It is scoped by
`.agents/docs/quic-manifest.md`, `.agents/docs/quic-codepoints.md`, and
`.agents/docs/quic-packet-grammar.md`; implementation must cite this note or a
later generated manifest instead of relying on model memory.

## Evidence Boundary

| Rule area | Evidence record |
| --- | --- |
| QUIC frame sequence payload shape, packet-type restrictions, core frame formats, extension-frame requirements, shortest frame-type encoding | `E-RFC-9000` in `quic-manifest.md`, especially RFC 9000 Sections 12.4, 12.5, 16, 19, and 22.4 |
| QUIC Frame Types registry values, permanent/prepareal status, and no frame-type grease formula | `.agents/docs/quic-codepoints.md` |
| DATAGRAM frame type and format | `E-RFC-9221` in `quic-manifest.md`, especially RFC 9221 Section 4 |
| QUIC bit greasing boundary, not frame-type greasing | `E-RFC-9287` in `quic-manifest.md` and `grease_quic_bit` in `quic-codepoints.md` |
| Packet kinds that can contain frames | `.agents/docs/quic-packet-grammar.md` |

The RFC 9000 errata note in `quic-manifest.md` remains active. Later
implementation steps must re-check verified and held errata if they affect a
specific parser rule below.

## Frame Sequence Model

After packet protection is removed, an Initial, 0-RTT, Handshake, or 1-RTT
packet payload is a sequence of one or more complete frames:

```text
Packet Payload {
  Frame (8..) ...,
}
```

Version Negotiation, Retry, and Stateless Reset packets do not contain frames.
Frames cannot span QUIC packets. A byte-complete packet that has no frames is a
protocol violation for an endpoint, but packet-layer code should preserve
caller-pinned malformed construction and report structured `CrafterError`
values only for malformed byte streams, such as truncation or an indeterminate
frame boundary.

Every frame starts with a QUIC variable-length integer Frame Type followed by
type-dependent fields:

```text
Frame {
  Frame Type (i),
  Type-Dependent Fields (..),
}
```

Frame Type values must use the shortest possible QUIC varint encoding. Builders
must encode defaults canonically when the caller has not overridden bytes, but
must preserve explicit user overrides, including reserved values, overlong frame
type encodings, impossible packet-type placements, empty NEW_TOKEN tokens, and
out-of-range Connection ID lengths. Decoders should expose malformed but
byte-complete values where the frame boundary is known, and should return
structured `CrafterError` values with stable context, required length, and
available length for truncated varints, fixed fields, length-delimited fields,
or frame sequences.

## Packet-Type Restrictions

Use packet-type restrictions only for validation and summaries unless a later
step explicitly adds strict parse modes. Default decode should not discard a
byte-complete frame solely because it appears in a packet type where an endpoint
would close the connection.

| Frame type | Clear packet types from source evidence |
| --- | --- |
| PADDING, PING | Initial, Handshake, 0-RTT, and 1-RTT |
| ACK, ACK_ECN | Initial, Handshake, and 1-RTT; not 0-RTT |
| CRYPTO | Initial, Handshake, and 1-RTT; not 0-RTT |
| CONNECTION_CLOSE transport variant `0x1c` | Initial, Handshake, 0-RTT, and 1-RTT |
| CONNECTION_CLOSE application variant `0x1d` | 0-RTT and 1-RTT only |
| NEW_TOKEN, PATH_RESPONSE, HANDSHAKE_DONE | 1-RTT only |
| RESET_STREAM, STOP_SENDING, STREAM, flow-control frames, CONNECTION_ID frames, PATH_CHALLENGE | 0-RTT and 1-RTT only |
| DATAGRAM | RFC 9221 requires 0-RTT or 1-RTT protection |

RFC 9000 also notes that ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE,
and RETIRE_CONNECTION_ID cannot be sent in 0-RTT packets. Endpoint behavior,
connection state, remembered transport parameters, and stream-state checks are
not packet-parser responsibilities.

## Core Frame Grammar

| Type | Name | Fields | Parser boundary |
| --- | --- | --- | --- |
| `0x00` | PADDING | no fields beyond the type byte | One byte; consecutive PADDING frames are independent frames. |
| `0x01` | PING | no fields beyond the type byte | One byte. |
| `0x02` | ACK | Largest Acknowledged (i), ACK Delay (i), ACK Range Count (i), First ACK Range (i), repeated ACK Range pairs | Count-delimited; truncate on any missing varint or repeated range field. |
| `0x03` | ACK_ECN | ACK fields plus ECT0 Count (i), ECT1 Count (i), ECN-CE Count (i) | Same as ACK, plus three ECN varints. |
| `0x04` | RESET_STREAM | Stream ID (i), Application Protocol Error Code (i), Final Size (i) | Three required varints after the type. |
| `0x05` | STOP_SENDING | Stream ID (i), Application Protocol Error Code (i) | Two required varints after the type. |
| `0x06` | CRYPTO | Offset (i), Length (i), Crypto Data bytes | Length-delimited; malformed if Length exceeds remaining packet bytes. |
| `0x07` | NEW_TOKEN | Token Length (i), Token bytes | Length-delimited; empty token is byte-complete but endpoint-invalid. |
| `0x08..0x0f` | STREAM | Stream ID (i), optional Offset (i), optional Length (i), Stream Data bytes | OFF=`0x04`, LEN=`0x02`, FIN=`0x01`; without LEN, data extends to the end of the containing packet. |
| `0x10` | MAX_DATA | Maximum Data (i) | One required varint. |
| `0x11` | MAX_STREAM_DATA | Stream ID (i), Maximum Stream Data (i) | Two required varints. |
| `0x12..0x13` | MAX_STREAMS | Maximum Streams (i) | Type `0x12` is bidirectional and `0x13` is unidirectional; one required varint. |
| `0x14` | DATA_BLOCKED | Maximum Data (i) | One required varint. |
| `0x15` | STREAM_DATA_BLOCKED | Stream ID (i), Maximum Stream Data (i) | Two required varints. |
| `0x16..0x17` | STREAMS_BLOCKED | Maximum Streams (i) | Type `0x16` is bidirectional and `0x17` is unidirectional; one required varint. |
| `0x18` | NEW_CONNECTION_ID | Sequence Number (i), Retire Prior To (i), Length (8), Connection ID bytes, Stateless Reset Token (16 bytes) | Length byte selects 1..20 bytes for valid QUIC, but builders preserve overrides; truncate on missing CID bytes or reset token. |
| `0x19` | RETIRE_CONNECTION_ID | Sequence Number (i) | One required varint. |
| `0x1a` | PATH_CHALLENGE | Data (8 bytes) | Fixed 8-byte payload after the type. |
| `0x1b` | PATH_RESPONSE | Data (8 bytes) | Fixed 8-byte payload after the type. |
| `0x1c` | CONNECTION_CLOSE transport | Error Code (i), Frame Type (i), Reason Phrase Length (i), Reason Phrase bytes | Length-delimited reason; frame type is present only for `0x1c`. |
| `0x1d` | CONNECTION_CLOSE application | Error Code (i), Reason Phrase Length (i), Reason Phrase bytes | Length-delimited reason; no triggering Frame Type field. |
| `0x1e` | HANDSHAKE_DONE | no fields beyond the type byte | One byte; server-only semantics are endpoint state. |

ACK range arithmetic can underflow or describe negative packet numbers. STREAM
and CRYPTO offsets plus data lengths can exceed the QUIC 62-bit space. MAX
STREAMS and STREAMS_BLOCKED values can exceed the stream-ID-derived limit. Those
conditions are validation errors for endpoints; default packet-layer decode
should preserve byte-complete fields and let later validation helpers report
semantic errors distinctly from truncation.

## DATAGRAM Extension

DATAGRAM is a selected packet-layer extension from RFC 9221. The IANA registry
marks `0x30..0x31` as permanent and default-eligible in `quic-codepoints.md`.
The type value has shape `0b0011000X`; bit `0x01` is the LEN bit.

```text
DATAGRAM Frame {
  Type (i) = 0x30..0x31,
  [Length (i)],
  Datagram Data (..),
}
```

For type `0x30`, Length is absent and Datagram Data extends to the end of the
containing QUIC packet. For type `0x31`, Length is present and delimits
Datagram Data. Empty DATAGRAM payloads are source-backed valid bytes. DATAGRAM
frames carry application data and are protected with 0-RTT or 1-RTT keys; this
does not authorize application datagram semantics, HTTP datagrams, MASQUE, or
externally executed live traffic in this step.

## Unknown, Prepareal, And Greased Values

QUIC frames are not self-describing beyond the Frame Type. RFC 9000 says an
endpoint treats unknown frame types as `FRAME_ENCODING_ERROR`, and the selected
IANA/RFC evidence records no frame-type grease formula. Do not manufacture one
from the transport-parameter grease rule `31 * N + 27` or the version grease
rule.

`quic-codepoints.md` currently classifies these non-core frame rows as
non-default: prepareal `IMMEDIATE_ACK` `0x1f`, prepareal `ACK_FREQUENCY`
`0xaf`, and unresolved multipath rows `0x3e..0x3f` and `0x3e75..0x3e7c`.
Later source-backed steps may select individual rows. Until then:

- builders may emit caller-supplied numeric frame types and raw bytes without
  normalizing or rejecting them;
- default builders must not emit prepareal, draft, experiment, or unresolved
  multipath frames;
- decoders may preserve an unknown frame's raw bytes only when a source-backed
  grammar or caller-supplied boundary determines its extent;
- otherwise, unknown frame decode must return a structured `CrafterError`
  rather than guessing a length or corrupting following frames.

## Malformed Decode Boundaries

Frame decode must report structured errors instead of panicking for at least:

- truncated Frame Type varints, including overlong or non-shortest encodings
  once the varint helper exposes that distinction;
- missing ACK fields, incomplete ACK Range pairs, or missing ACK_ECN counts;
- missing required RESET_STREAM, STOP_SENDING, flow-control, CONNECTION_ID, or
  CONNECTION_CLOSE varints;
- CRYPTO, NEW_TOKEN, STREAM-with-LEN, CONNECTION_CLOSE reason, DATAGRAM_LEN, or
  any future length-delimited field whose advertised length exceeds available
  packet bytes;
- STREAM or DATAGRAM frames without a Length field when the containing packet
  end is unavailable;
- NEW_CONNECTION_ID length bytes whose indicated Connection ID or 16-byte
  Stateless Reset Token is truncated;
- PATH_CHALLENGE or PATH_RESPONSE frames with fewer than 8 data bytes;
- frame sequences that leave an indeterminate unknown frame before later bytes.

This step records grammar only and performs no live traffic. Any later packet
examples that include UDP/IP addresses must use documentation address space such
as `192.0.2.10:4433` to `198.51.100.20:4433` or `2001:db8::10` to
`2001:db8::20`.
