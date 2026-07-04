# SCTP Wire Grammar

This note fixes the source-backed SCTP packet grammar that later `crafter`
parser, serializer, fixture, oracle, probe, summary, and show steps must use.
It is scoped to SCTP as a typed packet layer and does not define an association
stack, retransmission engine, congestion controller, socket API, scanner,
fuzzer, daemon, or live sender.

## Evidence Boundary

`.agents/docs/sctp-rfc-manifest.md` is the authority manifest for this file, and
`.agents/docs/sctp-codepoints.md` records the current IANA codepoint authority.
The manifest review date is 2026-07-03. Later implementation steps must cite
this grammar note plus the exact RFC section, IANA row, Datatracker record, or
RFC Editor erratum used for each narrower wire fact.

| Wire decision | Source |
| --- | --- |
| Native SCTP packet envelope, common header, chunk envelope, parameter TLV envelope, error-cause envelope, padding, bundling rules, verification tag model, and CRC32c checksum | RFC 9260 Sections 3, 3.1, 3.2, 3.2.1, 3.3.10, and 6.8, with verified RFC Editor errata recorded in `.agents/docs/sctp-rfc-manifest.md` |
| Chunk types, chunk flags, parameter types, error cause codes, PPIDs, HMAC identifiers, adaptation code points, and error-detection method labels | IANA Stream Control Transmission Protocol (SCTP) Parameters registry, summarized in `.agents/docs/sctp-codepoints.md` |
| IP protocol / IPv6 next-header value | IANA Assigned Internet Protocol Numbers, value `132` for SCTP |
| UDP-encapsulated SCTP shape | RFC 6951, with UDP port `9899` used only behind a conservative shape gate |
| Zero-checksum extension context and alternate error-detection method labels | RFC 9653 and the IANA Error Detection Methods registry |
| Extension packet data such as AUTH, PR-SCTP, ASCONF, RE-CONFIG, I-DATA, I-FORWARD-TSN, PAD, and related parameters or causes | RFC 4895, RFC 3758, RFC 5061, RFC 6525, RFC 8260, RFC 4820, and current IANA rows |

If a later official update, IANA registry correction, Datatracker relationship,
or verified erratum conflicts with this grammar, stop and refresh the evidence
before changing parser or serializer behavior.

## Packet Envelope

An SCTP packet is carried natively as an IP payload with protocol number `132`
or, when explicitly admitted by RFC 6951 shape checks, as the payload of a UDP
datagram. The SCTP parser starts at the first byte of the SCTP packet and
consumes only the SCTP packet bytes selected by the enclosing layer.

The base wire shape is:

```text
sctp-packet = common-header 1*chunk
```

Later builders may provide explicit test or inspection helpers that serialize a
header-only SCTP layer, but protocol-correct defaults should build at least one
chunk when a chunk-bearing constructor is used. Direct SCTP decode must return
structured errors for buffers shorter than the fixed common header. Registry or
UDP-encapsulation dispatch must be conservative and leave unrelated or
malformed payloads as `Raw` where that path is intended to avoid false
identification.

## Common Header

The common header is the 12-octet fixed SCTP header. All multi-octet integer
fields are encoded in network byte order.

| Offset | Size | Field | Grammar and preservation rule |
| --- | ---: | --- | --- |
| 0 | 2 | Source Port | Unsigned 16-bit source port. Port `0` is invalid for ordinary SCTP traffic, but an explicit caller value must be preserved for malformed-packet construction and inspection. |
| 2 | 2 | Destination Port | Unsigned 16-bit destination port. Port `0` follows the same preservation rule as the source port. |
| 4 | 4 | Verification Tag | Unsigned 32-bit tag. Decode exposes the value; it does not enforce association-state rules. |
| 8 | 4 | Checksum | Unsigned 32-bit SCTP CRC32c field. Decode stores the wire value and exposes checksum status rather than rejecting solely because the status is invalid. |

The verification tag has packet-family rules, such as zero in INIT packets and
the T-bit exceptions for ABORT and SHUTDOWN COMPLETE. Those are packet facts for
builders, summaries, and validation helpers; the packet primitive must not
invent association state in order to accept or reject a syntactically valid
common header.

## Chunks

Chunks follow the common header in wire order. A chunk has a four-octet header
and a chunk-specific value:

```text
chunk        = chunk-type chunk-flags chunk-length chunk-value padding
chunk-type   = 1 octet
chunk-flags  = 1 octet
chunk-length = 2 octets, unsigned, includes type, flags, length, and value
chunk-value  = chunk-length - 4 octets
padding      = 0..3 zero octets, chosen so the next chunk starts on a 4-octet boundary
```

`chunk-length` does not include the padding octets. A declared chunk length
shorter than four octets, or longer than the remaining SCTP packet bytes before
required padding, is malformed and must return a structured error with context,
required length, and available length where applicable. A parser must ignore
padding as semantic chunk value data but preserve enough padding information to
round-trip bytes and show the packet accurately.

The two highest bits of the chunk type carry the unknown-chunk action class.
They are still part of the 8-bit chunk type value and must not cause a
well-formed unknown chunk to be discarded. Known chunk types should decode to
typed variants as implementation steps admit them. Unknown, reserved,
temporary, private, or future chunk types must remain byte-preserving with
their type, flags, declared value bytes, and padding.

Chunk flags are chunk-specific. IANA currently assigns DATA and I-DATA E/B/U/I
bits and ABORT and SHUTDOWN COMPLETE T bits; most other current chunk flag
subregistries have no assigned bits. Decode preserves every flag bit, and
compile preserves explicit flag overrides. A builder may default unassigned
flag bits to zero only when the caller left them unset.

## Parameters

SCTP parameters are TLV fields used inside specific chunks such as INIT, INIT
ACK, HEARTBEAT, HEARTBEAT ACK, ASCONF, and extension chunks. The base parameter
envelope is:

```text
parameter        = parameter-type parameter-length parameter-value padding
parameter-type   = 2 octets
parameter-length = 2 octets, unsigned, includes type, length, and value
parameter-value  = parameter-length - 4 octets
padding          = 0..3 zero octets, chosen so the next parameter starts on a 4-octet boundary
```

`parameter-length` does not include parameter padding. A declared parameter
length shorter than four octets, or longer than the available bytes in its
enclosing chunk value, is malformed. Parameter padding is not semantic value
data; round-trip preservation belongs beside the declared value bytes rather
than inside the typed parameter value.

Parameter type values are shared across chunks. The two highest bits of the
16-bit parameter type encode the unknown-parameter action class. Known
parameters should become typed variants only when admitted by later steps.
Unknown, reserved, temporary, private, obsolete, or future parameter types
remain structurally valid when their TLV length and enclosing chunk bounds are
valid, and they must be preserved as inspectable numeric values with raw value
bytes and padding.

## Error Causes

ERROR chunks and ABORT chunks can contain error causes. Causes use a
parameter-shaped envelope but have their own 16-bit cause-code registry:

```text
cause        = cause-code cause-length cause-info padding
cause-code   = 2 octets
cause-length = 2 octets, unsigned, includes code, length, and info
cause-info   = cause-length - 4 octets
padding      = 0..3 zero octets, chosen so the next cause starts on a 4-octet boundary
```

`cause-length` does not include cause padding. A cause length shorter than four
octets, or longer than the enclosing chunk bytes that remain for causes, is
malformed. Known cause codes should decode to typed variants as later steps
admit them. Unknown well-formed cause codes remain byte-preserving and
inspectable instead of causing the containing chunk to be dropped.

## Padding

Chunk, parameter, and cause fields are aligned to 4-octet boundaries with zero
padding bytes. The declared length field for each structure excludes that
padding. The parser computes the padding length from the declared length:

```text
padding-len = (4 - (declared-length % 4)) % 4
```

Padding bytes are transmitted bytes, so they are part of the SCTP packet for
checksum coverage and byte-for-byte round trips. They are not part of the
semantic value exposed by typed chunk, parameter, or cause helpers. Malformed
nonzero padding policy belongs to a later validation-safety step; this grammar
only fixes the boundary between declared value bytes and alignment bytes.

## CRC32c Checksum Order

The SCTP checksum is a 32-bit CRC32c over the complete SCTP packet. `compile()`
must preserve an explicit checksum override, including zero or intentionally
invalid values. When the checksum is unset, serialization uses this order:

1. Serialize the common header with the checksum field set to zero.
2. Serialize chunks in order, including each declared length and any required
   chunk, parameter, or cause padding bytes.
3. Compute the RFC 9260 CRC32c over those SCTP bytes only.
4. Write the computed value into the common header checksum field.
5. Let enclosing IPv4, IPv6, or UDP layers fill their own dependent fields
   only if those fields were unset.

Decode verifies checksum status against the received bytes but must keep the
packet inspectable when the status is invalid. RFC 9653 adds source-backed
zero-checksum context and alternate error-detection method labels; it does not
change the default CRC32c behavior for ordinary SCTP packets.

## Lower-Layer Integration

For native SCTP over IPv4 or IPv6, the enclosing IPv4 `protocol` or IPv6
`next_header` field should auto-fill to `132` only when the field is unset and
the following typed layer is SCTP. Explicit caller overrides survive unchanged,
even when they disagree with the SCTP layer that follows.

For RFC 6951 UDP encapsulation, the complete SCTP packet is the UDP payload.
UDP port `9899` is a registry hint, not proof by itself. The UDP application
decoder may expose SCTP only after a conservative shape gate confirms a
structurally decodable SCTP payload; unrelated UDP/9899 payloads remain `Raw`.
The SCTP CRC32c and the UDP checksum are separate checksums owned by their
respective layers.

## Malformed Boundaries

Direct SCTP parsing must return structured errors, not panics or silent
truncation, for these grammar failures:

- fewer than 12 octets for the common header;
- a chunk header with fewer than four available octets;
- a chunk length shorter than four octets;
- a chunk length or required padding that exceeds the remaining SCTP packet
  bytes;
- a parameter header with fewer than four available octets inside its enclosing
  chunk value;
- a parameter length shorter than four octets;
- a parameter length or required padding that exceeds its enclosing chunk
  value bytes;
- a cause header with fewer than four available octets inside its enclosing
  ERROR or ABORT chunk value;
- a cause length shorter than four octets;
- a cause length or required padding that exceeds its enclosing chunk value
  bytes.

Unknown but structurally valid chunk types, parameter types, cause codes,
flags, PPIDs, HMAC identifiers, adaptation code points, and error-detection
method identifiers are not malformed boundaries. They are SCTP packet data and
must remain inspectable and byte-preserving.

## Builder And Decode Contract

SCTP remains a `Packet` layer in `crafter`. Helpers should return or expose
typed SCTP layer values and compose through the existing `/`, `compile()`,
`decode_from_l3`, `summary()`, and `show()` surfaces. Do not add a parallel raw
byte API for SCTP workflows.

Protocol-correct defaults may fill unset dependent fields such as chunk
lengths, parameter lengths, padding, IP protocol numbers, and CRC32c checksum.
Caller-supplied values must survive unchanged, including values that are
reserved, unknown, invalid, noncanonical, or deliberately malformed for testing.
