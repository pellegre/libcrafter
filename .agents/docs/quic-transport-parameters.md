# QUIC Transport Parameter Notes

Source-backed notes for later QUIC transport-parameter parser, builder,
fixture, oracle, and public API work in the `quic-protocol-bootstrap` plan.
This file is scoped by `.agents/docs/quic-manifest.md`,
`.agents/docs/quic-codepoints.md`, `.agents/docs/quic-packet-grammar.md`, and
`.agents/docs/quic-frame-grammar.md`; implementation must cite these notes or a
later generated manifest instead of relying on model memory.

This is a packet-primitive artifact. It records byte formats, registry policy,
parse/build behavior, and validation boundaries. It does not define endpoint
negotiation policy, TLS ownership, 0-RTT acceptance, application protocol
behavior, live traffic, scanning, or provider-backed execution.

## Evidence Boundary

| Rule area | Evidence record |
| --- | --- |
| Transport parameter sequence encoding, duplicate handling, reserved grease identifiers, core parameter formats, server-only parameters, default values, and QUIC Transport Parameters registry policy | `E-RFC-9000` in `quic-manifest.md`, especially RFC 9000 Sections 7.3, 7.4, 16, 18, 18.1, 18.2, and 22.3 |
| Current registered transport-parameter values, permanent/provisional status, registry update date, and non-default rows | `.agents/docs/quic-codepoints.md`, from IANA QUIC XML/HTML refreshed on 2026-06-25 |
| DATAGRAM extension transport parameter `max_datagram_frame_size` | `E-RFC-9221` in `quic-manifest.md`, especially RFC 9221 Section 3 |
| QUIC bit greasing transport parameter `grease_quic_bit` | `E-RFC-9287` in `quic-manifest.md`, especially RFC 9287 Sections 3 and 5 |
| Compatible version negotiation transport parameter `version_information` | `E-RFC-9368` in `quic-manifest.md`, especially RFC 9368 Sections 3, 4, 8, and 10.1 |
| QUIC v2 relationship to compatible version negotiation | `E-RFC-9369` in `quic-manifest.md` |

The RFC 9000 errata note in `quic-manifest.md` remains active. Later
implementation steps must re-check verified and held errata when coding a
parser rule that touches an affected section.

## Wire Encoding Model

The TLS QUIC transport parameters extension carries a byte sequence of
transport parameters. The sequence is a concatenation of tuples:

```text
Transport Parameters {
  Transport Parameter (..) ...,
}

Transport Parameter {
  Transport Parameter ID (i),
  Transport Parameter Length (i),
  Transport Parameter Value (Transport Parameter Length bytes),
}
```

`Transport Parameter ID` and `Transport Parameter Length` use QUIC
variable-length integer encoding from RFC 9000 Section 16. The value field is an
opaque byte string at the tuple layer. Known parameters then interpret the value
bytes according to their own format.

Parse behavior:

- Parse the sequence until all bytes are consumed.
- Return structured `CrafterError` values for a truncated parameter ID varint,
  truncated length varint, or value length that exceeds the remaining bytes.
- For known integer-valued parameters, parse the complete value as one QUIC
  varint and return a structured error if the value is empty, truncated, or has
  surplus bytes after the integer.
- For fixed-size known parameters, return a structured error when the value
  length is not byte-complete for the fixed format.
- Preserve the raw encoded identifier, encoded length, and value bytes for
  unknown, reserved, provisional, draft, experiment, or malformed parameters
  whenever the tuple itself is byte-complete.

Build behavior:

- Default builders should encode parameter IDs and lengths canonically with the
  QUIC varint helper.
- Known integer defaults should use canonical QUIC varints.
- Builder APIs must also be able to preserve caller-supplied raw IDs, overlong
  encodings, non-shortest varints, wrong lengths, duplicate parameters, invalid
  role-specific parameters, and byte-complete malformed values. `compile()` may
  fill unset dependent length fields but must not normalize explicit user
  overrides.

Endpoint negotiation semantics:

- Endpoint rules such as "close the connection with
  `TRANSPORT_PARAMETER_ERROR`", 0-RTT remembered values, server-only parameter
  restrictions, and application datagram enablement are validation policy.
  Default packet-layer parse should expose byte-complete data and attach
  inspectable validation facts rather than discarding the bytes.
- Packet examples in later docs or tests must use documentation address space,
  such as `192.0.2.10:4433`, `198.51.100.20:4433`, or `2001:db8::10`.
- This step performs no live traffic.

## Duplicate Handling

RFC 9000 Section 7.4 says endpoints must not send a parameter more than once in
one transport-parameters extension, and endpoints should treat duplicate receipt
as `TRANSPORT_PARAMETER_ERROR`.

For `crafter`:

- The parser should preserve duplicate parameters in input order so generated
  tools can inspect exactly what was received.
- A strict validation helper can report duplicate parameter IDs separately from
  byte truncation. Duplicate byte-complete values are not parse truncation.
- Builders must allow intentional duplicate construction when the caller asks
  for malformed or edge-case packets. Default convenience builders should not
  emit duplicates.

## Registry Policy

`quic-codepoints.md` records the current IANA QUIC Transport Parameters
registry as a 62-bit QUIC varint space. Permanent registrations from `0x00`
through `0x3f` require Standards Action or IESG Approval; permanent
registrations above `0x3f` require Specification Required. Provisional
registrations use Expert Review, and provisional Date field updates use First
Come First Served. The first unassigned codepoint is Standards Action.

Values of the form `31 * N + 27`, for integer values of `N`, are reserved for
transport-parameter greasing and must not be assigned by IANA. These are
ordinary byte-level tuples with no semantics and arbitrary value bytes. They
exercise the requirement that unknown transport parameters be ignored by
endpoints.

Default-eligible rows are permanent and selected by the reviewed evidence set.
Rows marked non-default in `quic-codepoints.md` must be preserved by numeric
codepoint but must not be emitted by defaults or exported as stable convenience
constants until a later source-backed step selects them.

## Default-Eligible Formats

| ID | Name | Value format | Packet-layer parse/build notes |
| --- | --- | --- | --- |
| `0x00` | `original_destination_connection_id` | Raw connection ID bytes, length from tuple | Server-only endpoint semantics. Preserve zero-length and over-20-byte values; validation can compare this with the first client Initial DCID later. |
| `0x01` | `max_idle_timeout` | Integer varint in milliseconds | Default value is 0 when absent. Idle-timeout behavior is endpoint policy. |
| `0x02` | `stateless_reset_token` | Exactly 16 bytes | Server-only endpoint semantics. Wrong lengths are malformed for the known parameter parser, but raw construction must remain possible. |
| `0x03` | `max_udp_payload_size` | Integer varint | Default value is 65527 when absent. Values below 1200 are endpoint-invalid, not tuple truncation. |
| `0x04` | `initial_max_data` | Integer varint | Flow-control semantics are endpoint state; packet parser exposes the integer. |
| `0x05` | `initial_max_stream_data_bidi_local` | Integer varint | Equivalent endpoint effect to MAX_STREAM_DATA for locally initiated bidirectional streams. Parser only records the integer. |
| `0x06` | `initial_max_stream_data_bidi_remote` | Integer varint | Equivalent endpoint effect to MAX_STREAM_DATA for peer-initiated bidirectional streams. Parser only records the integer. |
| `0x07` | `initial_max_stream_data_uni` | Integer varint | Equivalent endpoint effect to MAX_STREAM_DATA for unidirectional streams. Parser only records the integer. |
| `0x08` | `initial_max_streams_bidi` | Integer varint | Endpoint-invalid above `2^60`. Parser preserves byte-complete values. |
| `0x09` | `initial_max_streams_uni` | Integer varint | Endpoint-invalid above `2^60`. Parser preserves byte-complete values. |
| `0x0a` | `ack_delay_exponent` | Integer varint | Default is 3 when absent; values above 20 are endpoint-invalid. ACK delay scaling happens in frame validation, not tuple parsing. |
| `0x0b` | `max_ack_delay` | Integer varint in milliseconds | Default is 25 when absent; values `2^14` or greater are endpoint-invalid. |
| `0x0c` | `disable_active_migration` | Zero-length value | Non-empty values are malformed for this known format; migration behavior is endpoint policy. |
| `0x0d` | `preferred_address` | Fixed address/port fields, CID length byte, CID bytes, 16-byte token | Server-only endpoint semantics. See the preferred-address section below. |
| `0x0e` | `active_connection_id_limit` | Integer varint | Default is 2 when absent; values below 2 are endpoint-invalid. Parser preserves byte-complete values. |
| `0x0f` | `initial_source_connection_id` | Raw connection ID bytes, length from tuple | Preserve zero-length and over-20-byte values; validation can compare this with the first Initial SCID later. |
| `0x10` | `retry_source_connection_id` | Raw connection ID bytes, length from tuple | Server-only endpoint semantics. Present only when Retry was used at endpoint level, but parser preserves byte-complete values in all contexts. |
| `0x11` | `version_information` | Chosen Version (32 bits) followed by zero or more Available Versions (32 bits each) | Registered by RFC 9368. See the version-information section below. |
| `0x20` | `max_datagram_frame_size` | Integer varint | Registered by RFC 9221. Default 0 means no DATAGRAM support at endpoint level. Parser only records the integer and validation facts. |
| `0x2ab2` | `grease_quic_bit` | Zero-length value | Registered by RFC 9287. Non-empty values are endpoint-invalid; parser can report a known-format error while raw construction remains possible. |

## Connection ID Parameters

Connection-ID-valued transport parameters are byte strings whose length is the
tuple value length:

- `original_destination_connection_id` (`0x00`): value of the Destination
  Connection ID from the first client Initial. Server-only endpoint semantics.
- `initial_source_connection_id` (`0x0f`): value that the sender placed in the
  Source Connection ID of its first Initial.
- `retry_source_connection_id` (`0x10`): value that the server placed in the
  Source Connection ID of a Retry packet. Server-only endpoint semantics.

RFC 9000 Section 7.3 uses these parameters to authenticate connection-ID
negotiation during the handshake. For `crafter`, that comparison belongs in a
validation helper that can inspect packet headers and transport parameters
together. The transport-parameter parser should only decode and preserve the
byte values.

Zero-length values are byte-complete. Endpoint rules say that if a zero-length
connection ID is selected, the corresponding parameter is included with a
zero-length value. Builders must therefore allow zero-length connection IDs.
Long-header v1/v2 connection ID length limits are recorded in
`quic-packet-grammar.md`; this file does not add a second parser limit for raw
transport-parameter bytes.

## Stateless Reset Token

`stateless_reset_token` (`0x02`) is a known fixed-size value of exactly 16
bytes. RFC 9000 defines it as server-only and ties it to stateless reset
verification. Packet-layer support must not imply endpoint ownership of reset
tokens or live reset validation.

Parse/build behavior:

- Parse a 16-byte value as a typed stateless reset token.
- Return a structured `CrafterError` for a known-format parse when the value
  length is not 16 bytes.
- Preserve caller-supplied malformed raw bytes in construction APIs when the
  caller pins the raw tuple.
- Stateless reset packet recognition remains separate from transport parameter
  parsing and requires endpoint state to verify a token.

## Preferred Address

`preferred_address` (`0x0d`) is a server-only transport parameter with this
byte layout:

```text
Preferred Address {
  IPv4 Address (32),
  IPv4 Port (16),
  IPv6 Address (128),
  IPv6 Port (16),
  Connection ID Length (8),
  Connection ID (Connection ID Length bytes),
  Stateless Reset Token (128),
}
```

The minimum byte-complete shape is 41 bytes: 4-byte IPv4 address, 2-byte IPv4
port, 16-byte IPv6 address, 2-byte IPv6 port, 1-byte connection ID length, and
16-byte stateless reset token. The connection ID bytes sit between the length
byte and the reset token, so a parser needs at least `41 + cid_len` value bytes.
Values with extra bytes after the token are malformed for the known format.

RFC 9000 allows a server to omit one address family by sending all-zero address
and port values for that family, such as `0.0.0.0:0` or `[::]:0`. If examples
need concrete routable-looking values later, use documentation addresses such
as `192.0.2.10`, `198.51.100.20`, and `2001:db8::10`.

Endpoint semantics:

- The preferred address is used to change server address after the handshake.
- The supplied Connection ID has sequence number 1 in endpoint state.
- RFC 9000 forbids zero-length preferred-address connection IDs and forbids a
  server that chose zero-length connection IDs from sending this parameter.

Packet-layer behavior:

- Parse the byte-complete fields and surface validation facts for zero-length
  CID, over-20-byte CID, all-zero address families, and server-only placement.
- Do not perform migration, path validation, or address selection.
- Builders must preserve explicit malformed values and only auto-fill tuple
  length when unset.

## Active Connection ID Limit

`active_connection_id_limit` (`0x0e`) is an integer varint. RFC 9000 defines its
default as 2 and says values below 2 are endpoint-invalid. The value counts
connection IDs from the peer that an endpoint is willing to store, including the
handshake connection ID, the `preferred_address` connection ID, and
NEW_CONNECTION_ID frame values.

For `crafter`, parse and build the integer. Enforcement against
NEW_CONNECTION_ID frames, preferred-address sequence numbers, and peer state is
endpoint validation and should not be part of default tuple parsing.

## Max Datagram Frame Size

`max_datagram_frame_size` (`0x20`) is a permanent transport parameter from RFC
9221. It is an integer varint representing the maximum size, in bytes, of a
DATAGRAM frame including frame type, optional length field, and payload that the
sender of the parameter is willing to receive.

Packet-layer behavior:

- Parse/build as an integer varint.
- Default value is 0 when absent, which RFC 9221 uses to indicate no DATAGRAM
  support at endpoint level.
- Values greater than 0 advertise endpoint willingness to receive DATAGRAM
  frames, but actual frame sending restrictions and 0-RTT remembered-value
  checks are endpoint/application semantics.
- DATAGRAM frame parse/serialize rules remain in `quic-frame-grammar.md`.

## Version Information

`version_information` (`0x11`) is a permanent transport parameter from RFC
9368. Its value is a sequence of 32-bit big-endian QUIC version values:

```text
Version Information {
  Chosen Version (32),
  Available Versions (32) ...,
}
```

Known-format parse behavior:

- Require at least 4 value bytes for Chosen Version.
- Require the value length to be divisible by 4.
- Decode the first 32-bit value as Chosen Version.
- Decode the remaining 32-bit values as Available Versions in wire order.
- Preserve reserved version values such as `0x?a?a?a?a` as typed numeric
  versions. Do not choose a version or infer endpoint policy.
- Return structured `CrafterError` values for too-short or non-multiple-of-4
  values.

Endpoint validation facts from RFC 9368:

- Chosen Version equal to zero or any Available Version equal to zero is a
  parsing failure at endpoint level.
- Client-sent Available Versions lists compatible versions in descending
  preference and must include the Chosen Version.
- Server-sent Available Versions lists fully deployed versions for that server
  deployment; the order has no semantics and the list may be empty.
- QUIC version 1 has special handling when a client reacts to Version
  Negotiation and the server omits this parameter.

`crafter` should expose these facts for inspection, but the parser must not
perform downgrade prevention, select versions, accept/reject 0-RTT, or close
connections.

## Greasing And Unknown Parameters

There are two separate concepts that later code must keep distinct:

- Reserved transport parameter IDs of the form `31 * N + 27` from RFC 9000
  Section 18.1 and IANA registry policy. They carry arbitrary values and have
  no semantics.
- The permanent `grease_quic_bit` parameter `0x2ab2` from RFC 9287. Its value
  is empty, and it advertises endpoint willingness to receive packets with the
  QUIC bit cleared.

Unknown parameter behavior:

- Unknown byte-complete tuples are not parse failures. Preserve the numeric ID,
  encoded length, raw value, and original ordering.
- Unknown reserved grease IDs should be identifiable with a helper using
  `id >= 27 && (id - 27) % 31 == 0`.
- Default builders should not emit arbitrary unknown or reserved IDs unless the
  caller chooses them.
- Endpoint behavior says unknown parameters are ignored. `crafter` should keep
  them inspectable so generated tools can test peer behavior.

## Non-Default Registered Rows

`quic-codepoints.md` records additional registered transport parameters that
are non-default for this plan: unresolved multipath `initial_max_path_id`
(`0x3e`), provisional or experiment rows such as `discard` (`0x173e`),
`scone_supported` (`0x219e`), Google experiment rows, provisional
`min_ack_delay`, and `bdp_frame`.

Until a later source-backed step selects one of those rows:

- Preserve them as known numeric registry rows when encountered.
- Do not export stable convenience constants for them.
- Do not emit them from defaults.
- Do not infer their value format beyond raw tuple preservation unless the
  later selected source records that format.

## Malformed Decode Boundaries

Transport-parameter parsing must return structured errors instead of panicking
for at least:

- truncated parameter ID varint;
- truncated parameter length varint;
- value length larger than the remaining sequence bytes;
- known integer parameter with empty, truncated, or surplus value bytes;
- fixed-size `stateless_reset_token` with a value length other than 16;
- zero-length-value parameters `disable_active_migration` and `grease_quic_bit`
  with non-empty values in strict known-format parsing;
- `preferred_address` shorter than its fixed fields, shorter than
  `41 + cid_len`, or longer than `41 + cid_len`;
- `version_information` shorter than 4 bytes or not divisible by 4;
- unknown frame or packet context attempting to interpret transport-parameter
  bytes without a byte-complete tuple boundary.

Malformed endpoint semantics, such as duplicate parameters, server-only
parameters sent by a client, `max_udp_payload_size` below 1200,
`ack_delay_exponent` above 20, `max_ack_delay` greater than or equal to `2^14`,
`active_connection_id_limit` below 2, or zero version values inside
`version_information`, should be reported as validation findings distinct from
byte truncation.
