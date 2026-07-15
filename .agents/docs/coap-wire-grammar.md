# CoAP Datagram Wire Grammar

This note is the byte-level contract for the `crafter` CoAP datagram layer.
Later parser, serializer, fixture, registry, oracle, and probe work must follow
this grammar. It describes one complete CoAP message carried by one UDP
datagram; it does not define retransmission, transactions, DTLS, or endpoint
state.

## Evidence boundary

`.agents/docs/coap-rfc-manifest.md` is the authority manifest for this file,
and `.agents/docs/coap-codepoints.md` is its reviewed IANA snapshot. The
manifest was reviewed on 2026-07-14. If a later official update or verified
erratum changes these rules, refresh those evidence documents before changing
the implementation.

| Wire decision | Source |
| --- | --- |
| Four-byte datagram header, token, options, payload marker, and UDP message boundary | [RFC 7252 Sections 3 and 3.1](https://www.rfc-editor.org/rfc/rfc7252.html#section-3) |
| Empty-message constraints | [RFC 7252 Section 4.1](https://www.rfc-editor.org/rfc/rfc7252.html#section-4.1) |
| Updated datagram token-length grammar | [RFC 8974 Section 2.1](https://www.rfc-editor.org/rfc/rfc8974.html#section-2.1) and Appendix A |
| Code and option-number assignment status | IANA CoRE Parameters snapshot in `.agents/docs/coap-codepoints.md` |
| UDP service ports | IANA Service Name and Transport Protocol Port Number snapshot in `.agents/docs/coap-codepoints.md` |

RFC 8974 updates RFC 7252: implementations using the current grammar must not
treat every TKL value from 9 through 14 as reserved. Values 9 through 12 are
direct lengths, 13 and 14 introduce extended lengths, and only 15 is reserved.

## Datagram boundary

One UDP user-data payload is exactly one candidate CoAP datagram message. The
parser starts at UDP user-data offset zero and never reads link padding,
capture padding, another datagram, or bytes beyond the UDP length. There is no
outer CoAP length field: the payload, when present, ends at the UDP user-data
boundary.

The minimum message is the four-byte fixed header. A direct parser given fewer
than four bytes returns a structured `BufferTooShort` error with context
`coap.header`, `required = 4`, and `available = datagram.len()`. Registry
dispatch leaves that UDP payload as `Raw`.

## Complete message layout

```text
byte 0                  byte 1             bytes 2..3
+--------+--------+     +----------------+  +----------------------+
| Ver(2) | T(2)   |TKL |      Code      |  | Message ID (big-end) |
+--------+--------+----+----------------+  +----------------------+
| TKL extension, when TKL is 13 or 14 ...                      |
| Token, for the decoded token length ...                       |
| zero or more ordered delta-encoded options ...                |
| 0xff payload marker, only when selected ...                   |
| payload bytes through the end of this UDP datagram ...        |
```

The fixed header is always four bytes. TKL extension bytes, if any, occur
after the Message ID and immediately before the token; they are not part of
the token.

## Fixed header and bit packing

| Offset | Size | Field | Wire rule |
| --- | ---: | --- | --- |
| 0 bits 7..6 | 2 bits | Version | Unsigned value. Version 1 is the current default. Other values are reserved by RFC 7252 but remain inspectable on explicit decode. |
| 0 bits 5..4 | 2 bits | Type | `0` Confirmable, `1` Non-confirmable, `2` Acknowledgement, `3` Reset. Every two-bit value is representable. |
| 0 bits 3..0 | 4 bits | TKL | Token-length discriminator defined below. |
| 1 | 1 byte | Code | Three-bit class followed by five-bit detail. Every byte is retained losslessly. |
| 2 | 2 bytes | Message ID | Unsigned 16-bit integer in network byte order. |

The first two header fields and TKL are packed as:

```text
byte0   = ((version & 0x03) << 6) | ((type & 0x03) << 4) | (tkl & 0x0f)
version = (byte0 >> 6) & 0x03
type    = (byte0 >> 4) & 0x03
tkl     = byte0 & 0x0f
```

The code byte is never a parser registry gate:

```text
class  = code >> 5
detail = code & 0x1f
code   = (class << 5) | detail
```

Unknown, unassigned, reserved-class, and role-inappropriate code bytes remain
typed numeric values. Semantic validation may label them, but decode and
round-trip serialization do not discard or rewrite them. Datagram code class
7 is not reinterpreted as reliable-transport signaling.

## Token-length and token boundary

Decode TKL according to RFC 8974 before locating the token:

| TKL nibble | Extension immediately after fixed header | Decoded token length |
| ---: | ---: | ---: |
| 0..12 | none | TKL |
| 13 | one unsigned byte `ext8` | `13 + ext8` (13..268) |
| 14 | two-byte unsigned `ext16` in network byte order | `269 + ext16` (269..65804) |
| 15 | none | reserved; message-format error |

After consuming the extension, exactly the decoded number of bytes forms the
token. Zero-length and non-UTF-8 tokens are valid. Token bytes are opaque and
must not be normalized.

The decoder checks each boundary before slicing:

- missing TKL-13 extension: context `coap.token-length.extended8`,
  `required = 1`, `available = bytes remaining after the fixed header`;
- missing TKL-14 extension: context `coap.token-length.extended16`,
  `required = 2`, `available = bytes remaining after the fixed header`;
- short token: context `coap.token`, `required = decoded token length`,
  `available = bytes remaining after the TKL extension`;
- TKL 15: `InvalidFieldValue` field `coap.token-length`, reason
  `reserved TKL encoding 15`.

The maximum encodable token length is 65804 bytes. A canonical compiler uses
the shortest applicable discriminator shown in the table. It reports
`coap.token-length` as invalid if an unset/canonical length cannot be encoded;
it never truncates the token.

## Ordered option sequence

Options begin immediately after the token and continue until the datagram
ends or a payload marker is encountered at an option boundary. An option
instance consists of one header byte, zero to two delta-extension bytes, zero
to two length-extension bytes, and exactly the decoded number of value bytes:

```text
option-header = (delta-nibble << 4) | length-nibble
option        = option-header delta-extension length-extension value
```

Options are delta encoded in nondecreasing option-number order. Start the
running option number at zero. For each option, add its decoded delta to the
previous number. A delta of zero represents another occurrence of the same
number. Repeated and zero-length options are structurally valid.

Both delta and length nibbles use this extension grammar:

| Nibble | Extra bytes | Decoded value |
| ---: | ---: | ---: |
| 0..12 | none | nibble value |
| 13 | one unsigned byte `ext8` | `13 + ext8` (13..268) |
| 14 | two-byte unsigned `ext16` in network byte order | `269 + ext16` (269..65804) |

The delta and length extension bytes occur in that order. The parser must not
search for `0xff` inside an extension or value; `0xff` is a payload marker only
when the parser is positioned at the beginning of the next option.

Nibble 15 has two distinct error rules:

- delta nibble 15 is reserved for the payload marker. The complete header byte
  must be exactly `0xff`; `0xf0` through `0xfe` are message-format errors;
- length nibble 15 is reserved. A header byte `0x0f` through `0xef` is a
  message-format error.

The current option-number namespace is 0 through 65535. Addition of each
decoded delta is checked before it is committed. A sum greater than 65535, or
an arithmetic overflow in an implementation accumulator, is an
`InvalidFieldValue` with field `coap.option-number` and reason
`cumulative option number exceeds 65535`. It must not wrap to a smaller option
number.

Unknown, unassigned, reserved, experimental, draft-backed, and repeated option
numbers are not grammar errors. Preserve their numeric number, occurrence
order, decoded header metadata, and opaque value bytes. Registry metadata is
for inspection and semantic validation, not structural admission.

### Option truncation and invalid-field contexts

Counts for option errors are local to the indicated slice, making them stable
regardless of the option's absolute datagram offset:

| Failure | Error contract |
| --- | --- |
| Missing delta `ext8` | `BufferTooShort`, context `coap.option.delta.extended8`, `required = 1`, `available = bytes after the option header` |
| Missing delta `ext16` | `BufferTooShort`, context `coap.option.delta.extended16`, `required = 2`, `available = bytes after the option header` |
| Missing length `ext8` | `BufferTooShort`, context `coap.option.length.extended8`, `required = 1`, `available = bytes after the header and delta extension` |
| Missing length `ext16` | `BufferTooShort`, context `coap.option.length.extended16`, `required = 2`, `available = bytes after the header and delta extension` |
| Short option body | `BufferTooShort`, context `coap.option.value`, `required = decoded option length`, `available = bytes after both extensions` |
| Delta nibble 15 in a byte other than `0xff` | `InvalidFieldValue`, field `coap.option.delta`, reason `reserved delta nibble 15 is not a payload marker` |
| Length nibble 15 | `InvalidFieldValue`, field `coap.option.length`, reason `reserved option length nibble 15` |
| Cumulative number above 65535 | `InvalidFieldValue`, field `coap.option-number`, reason `cumulative option number exceeds 65535` |

Canonical encoding stably sorts typed option occurrences by number, preserving
the relative order of repeats, then calculates a nonnegative delta and uses
the shortest applicable form. This produces the increasing wire order required
by RFC 7252 Section 3.1. `CoapOptionOrder::Wire` explicitly retains caller or
decoded order; a decreasing typed option number in that mode requires an
explicit raw or logical delta encoding and otherwise returns
`InvalidFieldValue` for `coap.option-order`. A caller-supplied raw option
encoding is emitted as supplied under the override rules below, including a
deliberately reserved nibble or inconsistent decoded metadata.

## Payload marker and payload boundary

At an option boundary, `0xff` ends the option sequence. Every remaining byte
after that payload marker is payload, through the end of the UDP datagram. A
payload is binary and may itself contain any byte values, including `0xff`.

An absent payload marker means a zero-length payload. A marker followed by no
bytes is a message-format error. The direct decoder reports that case as
`BufferTooShort` with context `coap.payload`, `required = 1`, and
`available = 0`. Registry dispatch leaves the candidate `Raw`.

The decoder records marker presence independently from payload bytes so that
inspection can distinguish valid marker-plus-payload data from an absent
marker. It does not synthesize a marker during decode.

## Unset defaults and explicit override preservation

Compilation fills only values that are unset. The generic all-unset datagram
layer has deterministic packet-primitive defaults:

| Unset value | Compile result |
| --- | --- |
| Version | `1` |
| Type | Confirmable (`0`) |
| Code | Empty (`0.00`, wire `0x00`) |
| Message ID | `0x0000`, a representable deterministic packet value; endpoint uniqueness remains caller/runtime policy |
| Token | empty |
| TKL | canonical encoding derived from the token length, therefore `0` for an unset token |
| Options | empty sequence |
| Payload | empty |
| Payload marker | absent for an empty payload; present for a non-empty payload |

The resulting all-unset value is a structurally valid Empty Confirmable
message. Request and response builders set their source-backed Code and any
builder-specific Type, while retaining the same dependent TKL, option, and
marker rules. The packet primitive never creates random Message IDs or
transaction state.

Every explicit caller value wins over those defaults and over dependent
recalculation:

- explicit version, type, code, and Message ID bits are emitted unchanged;
- an explicit TKL discriminator, extension, or logical declared length is
  emitted unchanged even when it disagrees with the actual token byte count;
  the owned token bytes are still emitted in full;
- explicitly supplied option header/extension bytes are emitted unchanged,
  including noncanonical, out-of-order, overflowing, or reserved encodings;
- an explicit payload-marker choice wins: present emits `0xff` even for an
  empty payload, while absent omits `0xff` even for a non-empty payload; owned
  payload bytes are still appended;
- explicit Code `0.00` is not rewritten when token, option, marker, or payload
  bytes make it an invalid Empty message.

These rules intentionally allow construction of malformed packets. Opt-in
semantic validation reports inconsistencies but does not repair them. A
malformed compiled packet is not promised to pass strict direct decode: for
example, payload bytes emitted without a marker are necessarily interpreted
as option-sequence bytes by the wire grammar.

For unset option encodings, canonical mode stably orders typed options by
number before deriving deltas and selecting canonical 0..12, 13, or 14 forms.
Explicit wire mode retains caller order and override metadata. For unset TKL
and marker state the compiler derives them from token and payload lengths. No
other field is inferred from a field that the caller explicitly pinned.

## Direct decode contract

Explicit CoAP datagram decode is structurally strict and panic-free. It either
consumes the complete UDP user-data slice as one typed message or returns one
of the structured errors above. Every length addition and slice boundary uses
checked arithmetic before access.

Direct decode preserves all two-bit versions, all types, all code bytes, every
in-range option number, opaque token/option/payload bytes, and the marker
state. Version values other than 1 and unknown code/option assignments are
available to inspection and semantic validation; they are not discarded
solely because registry dispatch would refuse them.

RFC 7252 Empty-message constraints are part of strict structural decode. Code
`0.00` requires a decoded token length of zero and no bytes after the Message
ID. A violation is `InvalidFieldValue` with field `coap.empty-message` and
reason `empty message contains token, options, marker, or payload`.

## Conservative UDP registry shape gate

Ports are hints, never proof of an application protocol. Registry-driven
application decode applies these rules in order:

1. If neither UDP source nor destination port is 5683 or 5684, do not attempt
   CoAP auto-dispatch.
2. If the candidate service side is UDP/5684 (`coaps`), leave the payload
   `Raw`. That port carries DTLS-protected data; ciphertext is never passed to
   the cleartext CoAP parser by default. A caller with explicit security
   context may process the transport and then invoke CoAP decode explicitly.
3. For UDP/5683, require at least the four-byte header and require Version 1.
   Reserved versions 0, 2, and 3 remain `Raw` even though explicit decode can
   preserve them.
4. Resolve TKL, its extension, and the full declared token boundary with
   checked arithmetic. Reject TKL 15 and any missing extension or token bytes.
5. Walk the complete option sequence from the computed token boundary. Reject
   reserved delta/length nibbles, truncated extensions or values, cumulative
   option-number overflow, and `0xff` without at least one following payload
   byte. Do not reject an option merely because its number is unknown.
6. Reject Code `0.00` if TKL is nonzero or if any bytes follow the Message ID.
7. Only after every check succeeds may registry decode replace `Raw` with a
   typed CoAP layer. Any gate failure is a non-error registry outcome and the
   original application bytes remain exactly `Raw`.

The shape gate accepts structurally valid unknown code bytes and unknown option
numbers so they remain lossless and inspectable. It does not authenticate,
decrypt, infer a transaction, or authorize traffic. An explicit direct parser
call is the only opt-in way to inspect a non-Version-1 cleartext candidate or
to attempt parsing bytes obtained from an explicitly handled secure transport.
