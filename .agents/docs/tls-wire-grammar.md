# TLS Wire Grammar

This note records the TLS-over-TCP wire grammar that later `crafter` parser,
serializer, fixture, oracle, and probe steps must use. It is agent-facing
implementation guidance, source-backed by `.agents/docs/tls-manifest.md` and
`.agents/docs/tls-codepoints.md`; user-facing crate documentation belongs under
`docs/`.

TLS remains a packet primitive. The Rust implementation must use the existing
`Packet` and `Layer` shape, typed builders, `compile()` auto-fill behavior,
structured `CrafterError` truncation reports, and raw preservation patterns
already used by MQTT, BGP, and QUIC. This file does not add live traffic
defaults, credentials, public endpoint data, sensitive captures, or
host-specific paths.

## Evidence Boundary

| Rule area | Evidence |
| --- | --- |
| TLS 1.2 presentation language, variable vectors, record protocol, handshake protocol, and Appendix A syntax | RFC 5246 sections selected in `.agents/docs/tls-manifest.md` |
| TLS 1.3 presentation language, legacy record versions, handshake syntax, extension framework, record protocol, and Appendix B syntax | RFC 8446 sections selected in `.agents/docs/tls-manifest.md` |
| ContentType, HandshakeType, ProtocolVersion notes, ExtensionType, cipher suite, group, signature scheme, and GREASE preservation policy | `.agents/docs/tls-codepoints.md` |
| Unknown-codepoint and protected-payload preservation | `.agents/docs/tls-scope.md`, `.agents/docs/tls-manifest.md` |
| Existing Rust implementation patterns | MQTT length fields, BGP structured decode errors, QUIC source-backed opaque payload preservation |

If a later implementation step finds a conflict in RFC errata, IANA registry
state, or Datatracker relationships for a grammar rule below, stop and record a
new source-backed note before changing code or fixtures.

## Record Header

TLS records begin with a five-octet record header followed by a fragment whose
byte count is declared by the header length field.

```text
TLS record header

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
| ContentType   |        ProtocolVersion         |     length    |
+---------------+---------------+---------------+---------------+
|   length      | fragment bytes...
+---------------+------------------------------------------------
```

| Field | Width | Source-backed meaning | Builder and decode rule |
| --- | --- | --- | --- |
| `content_type` | 8 bits | TLS ContentType from IANA and RFC 5246/RFC 8446/RFC 6520. Core TLS-over-TCP values are `change_cipher_spec`, `alert`, `handshake`, `application_data`, and packet-only `heartbeat`. | Builders may default from the typed record body when unset. Explicit numeric overrides, including unknown, reserved, private, GREASE-shaped, or intentionally mismatched values, must be preserved. Decode keeps unknown content types numeric and preserves the fragment bytes. |
| `legacy_record_version` / `version` | 16 bits | TLS 1.2 records carry a protocol version. TLS 1.3 records carry a legacy record version for compatibility; the negotiated TLS 1.3 value is not learned from this field. | Builders may fill version defaults only when unset. Explicit version overrides survive even if they are obsolete, unknown, GREASE-shaped, or inconsistent with typed content. Decode exposes the raw 16-bit field separately from negotiated versions. |
| `length` | 16 bits | Number of bytes in `fragment`. RFC record limits are endpoint and validation facts; the grammar delimiter is the encoded length. | `compile()` must auto-fill `length` from the encoded fragment when unset. A caller-provided length override must be emitted verbatim, including values that understate or overstate the fragment. Decode reports `CrafterError::BufferTooShort` with context, required, and available when the declared length overruns the available TCP payload for an explicit record parse. |
| `fragment` | `length` bytes | Record payload. For handshake records it can contain handshake messages or fragments; encrypted and application data stay opaque. | Typed bodies may be encoded into this region. Unknown, encrypted, and unsupported bodies are preserved as raw bytes and remain visible through `summary()` and `show()`. |

The record parser must first require the five-octet record header. A short
header is a structured truncation error for explicit TLS decode and a reason
for conservative TCP dispatch to leave bytes as `Raw`.

## Handshake Header

A TLS handshake message has a one-octet handshake type, a three-octet
big-endian length, and a body of that declared length.

```text
TLS handshake header

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
| HandshakeType |                 length (uint24)                |
+---------------+---------------+---------------+---------------+
| body bytes...
+----------------------------------------------------------------
```

| Field | Width | Source-backed meaning | Builder and decode rule |
| --- | --- | --- | --- |
| `msg_type` | 8 bits | HandshakeType from IANA and RFC 5246/RFC 8446. `client_hello`, `server_hello`, selected TLS 1.2/TLS 1.3 messages, and raw unknown bodies are in scope. | Typed constructors may set the expected type by default. Explicit type overrides must be preserved, including mismatches between a typed body and the encoded type. Unknown handshake types keep their numeric value and raw body. |
| `length` | 24 bits | Number of body bytes after the four-octet handshake header. | `compile()` must auto-fill `length` from the encoded handshake body when unset. A caller-provided length override is emitted verbatim. Decode returns a structured short-buffer error when the declared body length overruns the enclosing record fragment or explicit handshake buffer. |
| `body` | `length` bytes | Handshake body selected by `msg_type` and protocol version context. | Decode can type selected complete bodies. Unsupported, encrypted, unknown, duplicate-sensitive, or fragmented bodies remain raw-preserved. |

Handshake messages are delimited by their own length field, but TLS records do
not guarantee one-record-per-message alignment. A handshake record can contain
multiple complete handshake messages, one complete message followed by a
partial message tail, or a fragment of a larger handshake message.

## Variable-Length Vectors

TLS presentation-language vectors encode a length prefix followed by the
selected number of element bytes or element encodings. The length-prefix width
is chosen from the vector's maximum bound in the source grammar.

```text
opaque item<0..255>       = uint8 length  || length bytes
opaque item<0..65535>     = uint16 length || length bytes
opaque item<0..16777215>  = uint24 length || length bytes
```

| Grammar form | Length width | Length counts | Implementation rule |
| --- | --- | --- | --- |
| `T name<0..2^8-1>` | 1 octet | Encoded bytes inside the vector, not including the length prefix. | Auto-fill from encoded vector body when unset; preserve explicit overrides. |
| `T name<0..2^16-1>` | 2 octets | Encoded bytes inside the vector. Common for cipher suite lists, compression methods, extension lists, and many extension bodies. | Use shared checked vector codecs so truncation contexts include the vector name. |
| `T name<0..2^24-1>` | 3 octets | Encoded bytes inside the vector. Used by TLS grammar for larger opaque values such as certificate-related payloads. | Support uint24 encode/decode without widening the public wire model into ad hoc raw slicing. |
| Fixed arrays such as `Random[32]` | no prefix | Exactly the source-specified element count. | Short inputs report required and available counts. Builders emit the caller-provided bytes or selected defaults without adding a prefix. |

Vector length fields are dependent fields. `compile()` fills unset vector
lengths from their encoded child bytes, while user-set length overrides survive
even when the declared length disagrees with the child bytes. Decode must not
panic on empty vectors, oversized declared vectors, or length overruns; it
returns structured errors for truncation and preserves unknown valid values.

## Extension List Framing

TLS extensions are encoded as an outer vector of extension entries. Each entry
has a two-octet ExtensionType, a two-octet extension-data length, and that many
body bytes.

```text
extension_list = uint16 extensions_length || extension_entry*

extension_entry

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
|        ExtensionType          |       extension_data length    |
+---------------+---------------+---------------+---------------+
| extension_data bytes...
+----------------------------------------------------------------
```

| Field | Width | Source-backed meaning | Builder and decode rule |
| --- | --- | --- | --- |
| `extensions_length` | 16 bits | Total bytes occupied by all extension entries in a context that carries an extension list. | Auto-fill from encoded extension entries when unset. Preserve explicit overrides, including values that truncate or overrun the entries. |
| `extension_type` | 16 bits | IANA ExtensionType. Selected types such as SNI, ALPN, supported_versions, supported_groups, signature_algorithms, key_share, and record_size_limit may get typed bodies in later steps. | Preserve explicit numeric values. Unknown, private-use, GREASE, DTLS-only, ECH-deferred, or duplicate extension types remain inspectable and raw-preserved unless a later source-backed helper narrows behavior. |
| `extension_data_length` | 16 bits | Number of bytes in this extension entry's body. | Auto-fill from the typed or raw extension body when unset. Preserve explicit overrides. Decode reports structured truncation when the entry body extends past the enclosing extension list. |
| `extension_data` | declared bytes | Extension-specific body or opaque bytes. | Typed parsers must be context-aware where RFC 8446 makes an extension body differ between ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateRequest, NewSessionTicket, or HelloRetryRequest. Unsupported bodies remain raw. |

The extension list parser walks entries only inside the declared
`extensions_length`. Duplicate extensions are not a grammar-layer parse error;
they must remain ordered and inspectable so later validation can report policy
or endpoint errors without losing bytes.

## TLS 1.2 And TLS 1.3 Version Fields

TLS has several version-bearing fields. They are not interchangeable.

| Location | TLS 1.2 behavior | TLS 1.3 behavior | Implementation rule |
| --- | --- | --- | --- |
| Record header `ProtocolVersion` / `legacy_record_version` | Carries the record-layer protocol version, commonly `0x0303` for TLS 1.2. | Compatibility field. TLS 1.3 records generally use legacy value `0x0303`; an initial ClientHello record may use compatibility value `0x0301`. It is not the negotiated version. | Expose this as a record header field and preserve explicit overrides. Do not infer TLS 1.3 negotiation from it. |
| ClientHello `legacy_version` | TLS 1.2 ClientHello uses `0x0303` when offering TLS 1.2. | TLS 1.3 ClientHello uses legacy value `0x0303`; real offered versions are in `supported_versions`. | Builder defaults may fill `0x0303` for selected TLS 1.2/TLS 1.3 hello constructors, but caller overrides survive. |
| ServerHello `legacy_version` | TLS 1.2 ServerHello uses the selected protocol version. | TLS 1.3 ServerHello uses legacy value `0x0303`; HelloRetryRequest is represented as a ServerHello form. | Keep legacy value and any supported_versions extension separately inspectable. |
| `supported_versions` extension | Not required for TLS 1.2 base grammar. | Carries offered or selected protocol versions, including `0x0304` for TLS 1.3. | Later extension parsers must type this extension from RFC 8446 while preserving unknown, old, GREASE, and explicit numeric values. |

Version helpers may provide labels from `.agents/docs/tls-codepoints.md`, but
the wire type remains a 16-bit value. Builders must not silently rewrite old,
unknown, GREASE-shaped, or deliberately malformed version values.

## Multi-Record TCP Payloads

TLS-over-TCP decode operates on the TCP payload bytes made available by the
existing packet decoder. It does not reassemble streams across TCP segments.

```text
tcp_payload =
    tls_record
  / tls_record tls_record ...
  / tls_record ... partial_tls_record_tail
  / partial_tls_record_tail
  / non_tls_bytes
```

| Payload shape | Decode behavior |
| --- | --- |
| One complete TLS record | Decode the record header and complete fragment. If the content type is supported and the fragment is structurally complete, expose typed body details; otherwise preserve fragment bytes. |
| Multiple complete records | Iterate by record header length plus declared fragment length. Continue decoding later delimited records even when an earlier complete record has an opaque, encrypted, or unknown body. |
| Complete records followed by a partial tail | Decode complete leading records. Preserve the partial tail as raw or report a structured truncation error according to whether the caller requested explicit TLS parsing or conservative TCP dispatch. Never drop the tail silently. |
| Only a partial record | Explicit TLS parse reports the missing record-header or fragment bytes with required and available counts. Registry-driven TCP decode leaves the payload as `Raw` unless a later source-backed API exposes partial-record objects. |
| Non-TLS bytes on a common TLS port | Conservative dispatch must leave bytes as `Raw` instead of forcing a TLS layer. The shape gate should require a plausible record header and enough bytes for the declared fragment before default application decode claims TLS. |

Record lengths delimit records within a single TCP payload only. They do not
authorize TCP stream reassembly, retransmission handling, endpoint state,
handshake transcript validation, decryption, certificate validation, or
application protocol decoding.

## Auto-Fill And Override Matrix

| Wire field | Auto-fill source when unset | Required override behavior |
| --- | --- | --- |
| Record `content_type` | Typed record body, when the builder knows one. | Preserve caller-supplied content type even when it conflicts with the body. |
| Record `legacy_record_version` | Selected constructor default such as TLS 1.2/TLS 1.3 compatibility value. | Preserve explicit numeric version values. |
| Record `length` | Encoded fragment byte length. | Preserve explicit length override verbatim. |
| Handshake `msg_type` | Typed handshake constructor. | Preserve explicit numeric type, including unknown or mismatched values. |
| Handshake `length` | Encoded handshake body byte length. | Preserve explicit length override verbatim. |
| Vector length prefixes | Encoded vector body byte length. | Preserve explicit vector length override, including malformed values. |
| Extension list `extensions_length` | Encoded extension entries byte length. | Preserve explicit outer length override. |
| Extension entry `extension_data_length` | Encoded typed or raw extension body length. | Preserve explicit per-extension length override. |
| Registry-backed codepoints | Selected typed constructor values only when unset. | Preserve unknown, private-use, reserved, GREASE, discouraged, and draft-backed numeric values. |

These fields should use `Field`-style state or an equivalent local state model
so compile-time defaults are distinguishable from user-specified overrides. A
fallible helper may reject impossible local builder inputs, such as a value
that cannot fit in the source-defined prefix width, but `compile()` must not
repair a caller-pinned malformed wire field into a safer value.

## Malformed Boundaries

The TLS parser must return structured errors, not panics or silent truncation,
for these grammar failures when TLS parsing is explicit:

- fewer than five bytes for a record header;
- declared record length exceeding the available TCP payload or explicit input;
- fewer than four bytes for a handshake header inside a handshake parse;
- declared handshake length exceeding the enclosing record fragment or explicit
  handshake buffer;
- vector prefix missing or vector length exceeding the enclosing buffer;
- extension list length exceeding the enclosing handshake body;
- extension entry header split by the enclosing list boundary;
- extension entry body length exceeding the enclosing extension list;
- fixed-width fields such as randoms, uint16 values, uint24 values, or
  ExtensionType values ending before their required byte count.

For registry-driven TCP application decode, malformed or non-TLS-looking bytes
must not cause unrelated traffic to be claimed as TLS. The dispatch path should
use the conservative shape gate recorded here and preserve unmatched payloads
as `Raw`.
