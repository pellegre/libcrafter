# CoAP Error and Preservation Policy

This note freezes the error vocabulary, boundary accounting, and lossless
fallback rules for every CoAP parser and transform planned for `crafter`.
Implementations, malformed corpora, registry predicates, fixtures, and oracle
adapters must use these names exactly. Semantic validation may add findings,
but it must not replace the structural behavior defined here.

## Evidence and repository boundary

The wire facts in this policy come from the reviewed evidence already retained
in the repository:

| Area | Authority used by this policy |
| --- | --- |
| Datagram header, options, marker, and Empty messages | RFC 7252 Sections 3, 3.1, 4.1, 5.4, and 5.5, as selected by `.agents/docs/coap-rfc-manifest.md` and specified by `.agents/docs/coap-wire-grammar.md` |
| Extended token lengths | RFC 8974 Sections 2 and 2.1 and Appendix A |
| Reliable length and signaling | RFC 8323 Sections 3.2 and 5, with the RFC 8974 token update |
| CoRE Link Format | RFC 6690 Section 2 |
| OSCORE option, nonce, AAD, ciphertext, and authentication | RFC 8613 Sections 5, 6, and 8 |
| Numeric assignment status and future values | The reviewed IANA snapshot in `.agents/docs/coap-codepoints.md` |

`.agents/docs/coap-rfc-manifest.md`, `.agents/docs/coap-wire-grammar.md`, and
`.agents/docs/coap-extensions.md` remain the authority for the actual grammar.
This file assigns stable error names to those boundaries; it does not invent a
second validity model. Group OSCORE remains prepareal opaque metadata until
the source-manifest stop condition is resolved.

The shared parse error is `CrafterError` from `crafter/src/error.rs`.
Packet-protection failures use the planned `OscoreError`, but its truncation
variant must carry the same three data members and meanings as
`CrafterError::BufferTooShort`.

## Uniform error rules

### Truncation is `BufferTooShort`

Whenever a fixed-width or declared-width region is not wholly available, the
result is `BufferTooShort { context, required, available }` (or the exactly
equivalent `OscoreError` variant for a protection transform):

- `context` is one of the stable dotted names below;
- `required` is the complete byte count needed for that named region, not the
  number of additional bytes needed; and
- `available` is the number of bytes actually available in the local slice
  named by the table.

Counts are local to a region so they do not change when the same grammar is
nested at a different packet offset. All additions, conversions, and end
offsets are checked before indexing or slicing. An arithmetic overflow is an
invalid field, never a wrapped boundary or a panic.

The implementation must not substitute a generic parse string, an I/O error,
or `InvalidFieldValue` when the failure is a known short buffer. In particular,
every prefix truncation of a header, extension, token, declared body, option
value, authentication-tag-bearing ciphertext, or other length-delimited field
reports `context`, `required`, and `available`.

### Impossible encodings are `InvalidFieldValue`

`InvalidFieldValue { field, reason }` is reserved for bytes that are present
but structurally impossible under the selected grammar, or for an arithmetic
result that cannot be represented. The `field` name is stable and the `reason`
is short, nonempty, deterministic, and free of packet secrets.

Unknown, unassigned, reserved-for-future, experimental, or role-inappropriate
codepoints are not structurally impossible merely because the current IANA
snapshot does not assign semantics to them. They remain typed numeric values
or opaque bytes. Constraints such as an assigned option's permitted length,
an unusual Version/Type/Code combination, or an option interaction belong to
opt-in semantic validation unless the base grammar cannot be parsed without
choosing a different byte boundary.

### Errors never rewrite input

A failed parser returns no partially normalized layer. It does not sort
options, canonicalize integers, synthesize a payload marker, clamp a length,
replace an unknown value, or consume bytes past the last verified boundary.
The caller retains its original input. A typed conversion failure for one
option or link-format payload does not remove the enclosing raw `CoapOption`
or payload from an already decoded `Coap` message.

## Stable datagram contexts

The direct datagram parser uses the following `BufferTooShort` contexts.

| Context | Required region | `required` | `available` |
| --- | --- | ---: | ---: |
| `coap.header` | Four-byte datagram fixed header | `4` | Complete datagram length |
| `coap.token-length.extended8` | TKL-13 extension | `1` | Bytes after the fixed header |
| `coap.token-length.extended16` | TKL-14 extension | `2` | Bytes after the fixed header |
| `coap.token` | Token selected by decoded TKL | Decoded token length | Bytes after the TKL extension |
| `coap.option.header` | One option header when an option decoder is explicitly asked to decode an option | `1` | Bytes in that option slice |
| `coap.option.delta.extended8` | Delta-nibble-13 extension | `1` | Bytes after the option header |
| `coap.option.delta.extended16` | Delta-nibble-14 extension | `2` | Bytes after the option header |
| `coap.option.length.extended8` | Length-nibble-13 extension | `1` | Bytes after the header and delta extension |
| `coap.option.length.extended16` | Length-nibble-14 extension | `2` | Bytes after the header and delta extension |
| `coap.option.value` | Decoded option value | Decoded option length | Bytes after both extensions |
| `coap.payload` | At least one byte after a present `0xff` marker | `1` | Bytes after the marker, therefore `0` for the malformed case |

End of the datagram at an option boundary means that the option sequence is
complete; it is not a missing `coap.option.header`. That context is used only
by a required-one-option codec or after an enclosing grammar has established
that an option header must exist.

The corresponding stable invalid-field names are:

| Field | Structurally impossible condition |
| --- | --- |
| `coap.token-length` | Reserved TKL discriminator 15, or a canonical token length above 65804 |
| `coap.option.delta` | Delta nibble 15 in any header byte other than the payload marker `0xff` |
| `coap.option.length` | Reserved option-length nibble 15 |
| `coap.option-number` | Checked cumulative option number exceeds 65535 |
| `coap.option-order` | Canonical typed encoding is requested for a decreasing option number |
| `coap.empty-message` | Direct decode finds token, option, marker, or payload bytes on Code `0.00` |

The exact reasons already fixed by the datagram grammar remain stable:
`reserved TKL encoding 15`,
`reserved delta nibble 15 is not a payload marker`,
`reserved option length nibble 15`,
`cumulative option number exceeds 65535`, and
`empty message contains token, options, marker, or payload`.

Malformed explicit encodings are still legal compiler inputs. Compilation
emits caller-supplied TKL, option header/extension, marker, and other override
bytes unchanged. Strict direct decode is allowed to return the errors above
when those emitted bytes are later parsed.

## Stable reliable-frame and signaling contexts

One reliable decode operation receives a caller-provided slice and either
returns one complete `CoapReliable` plus its consumed byte count or a
structured error. It never waits for TCP bytes or performs stream reassembly.

| Context | Required region | `required` | `available` |
| --- | --- | ---: | ---: |
| `coap.reliable.header` | Initial Len/TKL byte | `1` | Complete caller-provided slice length |
| `coap.reliable.length.extended8` | Len-13 extension | `1` | Bytes after the Len/TKL byte |
| `coap.reliable.length.extended16` | Len-14 extension | `2` | Bytes after the Len/TKL byte |
| `coap.reliable.length.extended32` | Len-15 extension | `4` | Bytes after the Len/TKL byte |
| `coap.reliable.code` | Code byte | `1` | Bytes after the reliable-length extension |
| `coap.reliable.token-length.extended8` | TKL-13 extension | `1` | Bytes after Code |
| `coap.reliable.token-length.extended16` | TKL-14 extension | `2` | Bytes after Code |
| `coap.reliable.token` | Token selected by decoded TKL | Decoded token length | Bytes after the TKL extension |
| `coap.reliable.body` | Body selected by decoded Len | Decoded body length | Bytes after Code, TKL extension, and Token |

Once the complete declared body is available, its option and payload grammar
uses the ordinary `coap.option.*` and `coap.payload` contexts. A following
frame is outside the returned consumed boundary and never increases
`available` for a short region inside the current frame.

The stable invalid fields are `coap.reliable.length` for checked frame-size or
body-length overflow and `coap.reliable.token-length` for reserved TKL 15.
Explicit Len/TKL representations remain compiler overrides even when their
declared values disagree with the owned token or body.

Signaling messages use the same reliable frame, ordered option, and truncation
contexts. The `(signaling code, option number)` pair selects metadata only
after the bytes are structurally decoded. An assigned signaling option whose
complete value has a structurally impossible registered representation uses
`InvalidFieldValue` field `coap.signaling.option.value`. Unknown signaling
codes, unknown contextual option numbers, and opaque future parameter values
are preserved; they are not errors and are never looked up in the ordinary
datagram-option namespace.

## CoRE Link Format syntax

`CoapLinkFormat::parse` works on the complete payload byte slice. A grammar
failure uses `InvalidFieldValue` field `coap.link-format.syntax` with a stable,
non-secret reason naming the failed production, such as an absent opening
angle bracket, unterminated target, missing attribute name, invalid attribute
separator, or unterminated quoted value. These are structurally impossible
complete grammar productions, not unknown link attributes.

The parser operates on bytes and must not reject or normalize a value solely
because it is non-UTF-8. Ordered links, ordered known and unknown attributes,
and raw token or quoted forms remain lossless. A failed specialized
link-format parse leaves the original CoAP payload bytes available on the
enclosing message. Explicit `CoapLinkFormat` raw bytes win during
serialization even when its canonical typed view would fail to parse.

## OSCORE option and transform errors

### Compressed OSCORE option

An empty OSCORE option is the valid canonical all-zero base form. For a
nonempty option, parse the flags before locating the following regions.

| Context or field | Error kind and boundary |
| --- | --- |
| `coap.oscore.option.partial-iv` | `BufferTooShort`; `required` is the 0..5 length declared by `n`, `available` is bytes after the flag byte |
| `coap.oscore.option.kid-context-length` | `BufferTooShort`; `required = 1`, `available` is bytes after the Partial IV when `h` requires the length byte |
| `coap.oscore.option.kid-context` | `BufferTooShort`; `required` is the declared context length, `available` is bytes after its length byte |
| `coap.oscore.option.partial-iv-length` | `InvalidFieldValue` only when base `n` is the reserved value 6 or 7 |

When `k` is present, `kid` owns all remaining option bytes and cannot itself
be truncated relative to another field. Unknown or prepareal high flag bits,
including opaque Group OSCORE metadata, remain present in the raw
`OscoreOption`; the pairwise transform returns an unsupported/prepareal
result instead of guessing their semantics.

### Nonce and AAD inputs

Protection errors are typed `OscoreError` values. The following context names
are stable and must be reported without including the rejected bytes:

| Context or field | Policy |
| --- | --- |
| `coap.oscore.nonce.common-iv` | A short fixed-width Common IV is BufferTooShort-style with the selected AEAD nonce length as `required` and the supplied length as `available` |
| `coap.oscore.nonce.sender-id` | An identifier too long for the selected nonce construction is an invalid field; missing required sender identity is a missing-context error |
| `coap.oscore.nonce.partial-iv` | An overlong Partial IV is an invalid field; a response that needs but lacks the request Partial IV is a missing-context error |
| `coap.oscore.aad.request-kid` | Missing request KID required to bind a response is a missing-context error |
| `coap.oscore.aad.request-partial-iv` | Missing request Partial IV required to bind a response is a missing-context error |
| `coap.oscore.aad.class-i-options` | Failure to encode structurally invalid Class I option bytes is an invalid-field error; unknown structurally valid options remain encoded bytes |

Unsupported AEAD/KDF identifiers use a typed unsupported result and keep the
numeric identifier inspectable. They are not authentication failures and do
not cause a fallback to a guessed algorithm.

### Ciphertext, plaintext, and authentication

`coap.oscore.ciphertext` is the stable truncation context. Before invoking the
admitted AEAD, the ciphertext must be large enough for one encrypted original
Code byte plus the selected authentication tag. The BufferTooShort-style
result uses `required = 1 + tag length` and `available = ciphertext.len()`.
After successful authentication, an unexpectedly empty recovered plaintext
uses `coap.oscore.plaintext`, `required = 1`, and `available = 0`.

Every AEAD tag mismatch returns one redacted authentication-failure variant
with context `coap.oscore.authentication`. It must not reveal whether the key,
nonce, KID, request binding, AAD, ciphertext, or tag differed, and it must not
return unauthenticated plaintext or a partially decoded inner message.
Authentication is performed before interpreting protected plaintext fields.

All `Debug`, `Display`, summary, and error output redacts Master Secret, Master
Salt, derived keys, authentication keys, nonces when they expose context
material, and recovered plaintext. Tests assert error category and stable
context, never secret-bearing diagnostic text.

## Direct parsing versus registry dispatch

Direct entrypoints are an explicit request to treat bytes as CoAP:

- `decode_coap` and `Coap::decode` return a typed datagram or a structured
  `CrafterError`;
- `decode_coap_reliable` and `CoapReliable::decode` return one typed frame and
  consumed length or a structured `CrafterError`; and
- specialized link-format, option, and OSCORE parsers return their typed error
  rather than silently relabeling malformed bytes.

Registry auto-dispatch is a conservative classification operation, not an
error-reporting parser API. A service port is only a hint. If a UDP or TCP
candidate fails the complete shape gate, has a reserved datagram version, is
an incomplete reliable frame, or is protected traffic on a secure service
port, the registry returns the enclosing application bytes as exactly `Raw`.
It does not surface the speculative parser error, consume a prefix, or replace
the payload with a partly decoded CoAP layer.

Unknown but structurally valid codes, option numbers, and signaling values do
not fail the shape gate. UDP/5684 ciphertext and TCP/5684 protected traffic
remain `Raw` until a caller explicitly handles the secure transport and invokes
the appropriate parser or transform.

## Exact preservation contract

For every successful structural decode and recompile, these values remain
byte-exact and inspectable:

| Value | Required preservation |
| --- | --- |
| Unknown CoAP code | Complete code byte, class/detail split, and transport context |
| Unknown or repeated option | Numeric option number, occurrence order, decoded header metadata, explicit raw header/extension bytes when present, and opaque value bytes |
| Unknown Content-Format or Accept value | Original uint bytes, including a noncanonical representation, plus any decoded numeric value |
| Unknown signaling data | Signaling code byte, contextual option number, option order, raw encoding, and opaque parameter bytes |
| OSCORE ciphertext | Complete outer payload bytes, payload-marker state, OSCORE option bytes, and outer options; no normalization before authentication |
| Group metadata | Prepareal flag bits, identifiers, Partial IV, ciphertext, authentication material, signature/countersignature bytes, algorithm numbers, and other opaque fields |

Unknown registry status may change labels after a future IANA refresh, but it
must not change stored numeric values or bytes. Unknown valid data is never
converted to an `InvalidFieldValue` merely to make a typed helper convenient.
A failed typed view leaves the underlying `CoapOption`, payload, ciphertext,
or group metadata intact.

Compilation follows the same rule: every explicit caller field wins even when
malformed. Canonical defaults apply only to unset fields. Semantic validation
may report an inconsistency, but it cannot mutate the layer or prevent the
caller from compiling an intentional malformed vector.

## Mandatory malformed and preservation tests

The CoAP malformed suite follows the established pattern in
`crafter/tests/ntp_malformed.rs`:

1. Every public direct parser and every corpus case is invoked inside
   `std::panic::catch_unwind`; a panic is always a test failure.
2. Corpus fixtures name the expected error kind and exact stable context or
   field. Every BufferTooShort case asserts exact `required` and `available`
   values; every invalid-field case asserts the exact field and a nonempty,
   stable reason.
3. Prefix corpora cover every byte boundary of fixed headers, extended TKL,
   option delta/length extensions, option values, reliable Len extensions,
   reliable tokens/bodies, OSCORE option fields, and tag-bearing ciphertext.
4. Boundary arithmetic cases cover maximum extended lengths, cumulative option
   number overflow, reliable frame-size overflow, and declared lengths larger
   than the supplied slice.
5. Registry tests feed the same malformed candidates through the appropriate
   cleartext service-port path and assert an exact unchanged `Raw` payload,
   while the direct parser asserts the structured error.
6. Preservation fixtures round trip unknown codes, options, Content-Formats,
   signaling parameters, ciphertext, and prepareal group metadata and compare
   the complete bytes, ordering, marker state, and numeric values.
7. OSCORE failure tests assert one redacted authentication category for wrong
   key, nonce, request binding, AAD, ciphertext, and tag inputs and prove that
   no unauthenticated inner `Coap` value is returned.

Fuzz/property resilience may add cases, but it does not replace the named
deterministic corpus. No malformed, unknown-value, or authentication test may
send traffic; byte slices, packet compilation, pcaps, and independent official
vectors provide the offline evidence.
