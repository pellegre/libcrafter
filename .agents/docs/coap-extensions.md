# Advanced CoAP Wire Grammars

Source-backed grammar and packet-primitive boundary for CoAP extensions admitted
by `.agents/docs/coap-scope.md`. This note extends
`.agents/docs/coap-wire-grammar.md`; it does not replace the base fixed-header,
token, option-delta, payload-marker, override-preservation, or registry shape
rules defined there.

## Evidence and authority boundary

The authoritative source selection is `.agents/docs/coap-rfc-manifest.md`,
reviewed on 2026-07-14. Current numeric assignments and assignment status come
from `.agents/docs/coap-codepoints.md`, which snapshots the IANA CoRE Parameters
registry on the same date. RFCs define the wire grammars and semantics; IANA is
the current codepoint authority.

The stable sources used below are:

| Area | Wire authority |
| --- | --- |
| Base URI, representation, option ordering, and multicast metadata | RFC 7252 Sections 3.1, 3.2, 5.4, 5.10, 6.4, 6.5, 7, and 8 |
| CoRE Link Format | RFC 6690 Sections 2 through 4 |
| Observe | RFC 7641 Sections 2, 3.4, and 4.4; reliable update in RFC 8323 Section 7 |
| Block1, Block2, Size1, and Size2 | RFC 7959 Sections 2 through 4 |
| No-Response | RFC 7967 Sections 2 and 2.1 |
| FETCH, PATCH, and iPATCH | RFC 8132 Sections 2 through 4 |
| Reliable framing, signaling, and BERT | RFC 8323 Sections 3.2, 5, and 6 |
| OSCORE | RFC 8613 Sections 2 through 8 and Appendix C |
| Hop-Limit | RFC 8768 Sections 3 and 6 |
| Extended token length | RFC 8974 Sections 2, 2.1, 2.2.1, and Appendix A |
| Echo and Request-Tag | RFC 9175 Sections 2.2.1 and 3.2 through 3.8 |
| Q-Block1 and Q-Block2 | RFC 9177 Sections 4 through 7 |

The Group OSCORE source is still
`draft-ietf-core-oscore-groupcomm-28` in the RFC Editor queue. Its IANA Group
Flag assignment is inspectable provisional metadata, not authority for a
stable serializer. The group boundary below follows the explicit stop
condition in the source manifest.

## Rules shared by every extension

Advanced options use the base RFC 7252 option sequence. They do not introduce
a second TLV stream:

- preserve insertion and decoded order in the typed model; canonical message
  compilation stably orders occurrences by number before encoding each delta,
  while explicit wire-order compilation retains caller order and overrides;
- allow delta zero for repeated options and preserve repeated occurrences in
  order, even when semantic validation later reports a non-repeatable option;
- encode a typed option value using the option's `empty`, `opaque`, `uint`, or
  `string` format, while retaining the original opaque bytes and explicit raw
  header encoding when supplied;
- derive Critical, Unsafe, and NoCacheKey from the option number bits as RFC
  7252 Section 5.4.6 requires; do not maintain a special extension-only list;
- preserve unknown option numbers, content formats, signaling values, and
  syntactically valid bodies without assigning remembered semantics; and
- fill only unset fields. Explicit noncanonical, out-of-order, reserved, or
  internally inconsistent encodings are emitted unchanged and are reported by
  opt-in validation instead of being repaired.

Canonical `uint` values use the shortest network-byte-order representation;
zero is encoded as an empty option value. A decoded raw representation remains
available so a noncanonical explicit value can round trip byte-for-byte.

Extensions do not introduce a separate sorting rule. URI segments, link
attributes, block metadata, OSCORE Outer options, and signaling options retain
their typed occurrence order and use the same canonical-versus-explicit-wire
policy and delta/length codec described in the base grammar.

## URI, condition, and representation options

RFC 7252 Sections 5.10 and 6.4 split an origin-server request URI into option
values after URI percent-decoding. RFC 7252 Section 6.5 performs the inverse
composition. URI fragments are never placed on the wire.

| Option | No. | Format and length | Packet meaning |
| --- | ---: | --- | --- |
| Uri-Host | 3 | string, 1..255 bytes | Internet host; absent means the destination IP literal. |
| Uri-Port | 7 | uint, 0..2 bytes | Transport port; absent means the destination transport port. |
| Uri-Path | 11 | repeatable string, 0..255 bytes | One absolute-path segment per occurrence, excluding `/`; `.` and `..` are invalid semantic values. |
| Uri-Query | 15 | repeatable string, 0..255 bytes | One query argument per occurrence, excluding `?` and separators. |
| Proxy-Uri | 35 | string, 1..1034 bytes | Complete absolute URI for a forward proxy. |
| Proxy-Scheme | 39 | string, 1..255 bytes | Replaces the scheme when the remaining URI can be represented by Uri-* options. |

Proxy-Uri takes precedence over Uri-Host, Uri-Port, Uri-Path, and Uri-Query;
their coexistence is a semantic error, not a reason for the byte parser to
discard either value. A packet helper may compose or decompose a URI, but
proxy routing, DNS, and forwarding remain operational workflows.

Representation and conditional metadata use the following RFC 7252 forms:

| Option | No. | Format and length | Packet meaning |
| --- | ---: | --- | --- |
| If-Match | 1 | repeatable opaque, 0..8 bytes | Request precondition; an empty value is the special any-current-representation form. |
| ETag | 4 | repeatable opaque, 1..8 bytes | Representation tag in a response or validator in a request. |
| If-None-Match | 5 | empty, exactly 0 bytes | Request precondition whose presence is the complete value. |
| Location-Path | 8 | repeatable string, 0..255 bytes | One segment of the relative location returned for a created resource. |
| Content-Format | 12 | uint, 0..2 bytes | IANA Content-Format identifier for the payload; no default is inferred when absent. |
| Max-Age | 14 | uint, 0..4 bytes | Freshness lifetime in seconds; the response default is 60 when absent. |
| Accept | 17 | uint, 0..2 bytes | Preferred response Content-Format; absence expresses no preference. |
| Location-Query | 20 | repeatable string, 0..255 bytes | One query argument in the relative location. |
| Size1 | 60 | uint, 0..4 bytes | Request body size metadata or maximum acceptable request size in a 4.13 response. |

RFC 7959 adds Size2 (option 28) as a `uint` body-size estimate for Block2.
Content-Format and Accept store the numeric identifier even when the current
IANA snapshot does not name it. Location and size helpers describe packet
metadata only; caches, representation stores, and proxy behavior stay outside
`crafter`.

## CoRE Link Format discovery

RFC 6690 Section 2 carries `application/link-format` as a UTF-8 payload but
does not require a decoder to validate or normalize UTF-8. The top-level
grammar is:

```text
Link            = link-value-list
link-value-list = [ link-value *[ "," link-value ] ]
link-value      = "<" URI-Reference ">" *( ";" link-param )
link-extension  = parmname [ "=" ( ptoken / quoted-string ) ]
                 / ext-name-star "=" ext-value
```

Commas split link values only outside angle-bracket URI references and quoted
strings. Each link owns its target URI reference and ordered target
attributes. Known attributes include `rel`, `anchor`, `rev`, `hreflang`,
`media`, `title`, `title*`, `type`, `rt`, `if`, and `sz`; unknown extension
names and raw quoted or token forms remain lossless. The absence of `rel`
implies the `hosts` relation. A serializer may produce a canonical form, but a
caller-selected raw form remains available and wins under the explicit
override rule.

RFC 6690 Sections 4 and 4.1 define `/.well-known/core` as the discovery entry
point. A GET returns a link-format representation; a single Uri-Query can
filter by `href`, a defined attribute, or an extension name, with an optional
trailing `*` prefix match. Discovery helpers construct or inspect these
packets. They do not scan networks, dereference discovered links, operate a
resource directory, or retain a discovery database.

## Observe and serial ordering

RFC 7641 Section 2 defines Observe (option 6) as a `uint` of 0..3 bytes:

- value 0 in a GET requests registration;
- value 1 in a GET requests deregistration; and
- a value in a 2.xx response is the low 24 bits of a strictly increasing
  notification sequence number.

Observe is unsafe, not part of the cache key, and not repeatable. Unknown or
out-of-range raw values remain bytes on direct decode and are available to
semantic validation.

RFC 7641 Sections 3.4 and 4.4 define stateless comparison. Given the freshest
value/time `(V1, T1)` and an incoming `(V2, T2)`, the incoming notification is
newer when:

```text
(V1 < V2 && V2 - V1 < 2^23)
|| (V1 > V2 && V1 - V2 > 2^23)
|| (T2 > T1 + 128 seconds)
```

The arithmetic is modulo `2^24`; equality is not newer. A server must not
advance more than `2^23` within less than 256 seconds. The primitive exposes
the option and comparison result only. Observer lists, timers, notification
scheduling, retransmission, and cancellation state belong to generated tools.
RFC 8323 Section 7 permits an empty Observe value in 2.xx notifications over
reliable ordered transports; the reliable layer preserves that distinction.

## Block1, Block2, Size, and BERT

RFC 7959 Section 2.2 encodes Block1 (option 27) and Block2 (option 23) as a
0..3-byte `uint`:

```text
value = (NUM << 4) | (M << 3) | SZX
NUM   = value >> 4
M     = (value >> 3) & 1
SZX   = value & 7
```

`NUM` is the block number. `M` states that more blocks follow in descriptive
usage. For `SZX` 0..6, block size is `2^(SZX + 4)`, from 16 through 1024
bytes, and byte offset is `NUM * block_size`. The 20-bit `NUM` field reaches
`0xfffff`. An absent option leaves block size unspecified; an explicitly
empty option value is numeric zero and therefore means NUM 0, M 0, SZX 0.
Size1 (60) and Size2 (28) describe complete body size, not the current payload
length.

RFC 8323 Section 6 gives `SZX == 7` meaning only on reliable transports. Such
a Block1 or Block2 is a BERT option. In control usage it behaves like SZX 6
while advertising BERT capability. In descriptive usage:

- the position is `NUM * 1024`;
- a non-final (`M == 1`) BERT payload is a positive multiple of 1024 bytes;
- a final (`M == 0`) payload may contain any number of complete 1024-byte
  blocks plus a final partial block; and
- the next NUM advances by the number of represented 1024-byte blocks.

BERT support is signaled by a CSM containing Block-Wise-Transfer together
with Max-Message-Size greater than 1152. The typed block model can expose
fields, offsets, boundaries, and validation results. It does not assemble a
body, schedule blocks, retransmit, or maintain a transfer session.

## No-Response

RFC 7967 Sections 2 and 2.1 define No-Response (option 258) as an elective,
safe-to-forward, non-repeatable `uint` of zero or one byte. The value is a
response-class suppression mask:

| Bit/value | Suppresses |
| ---: | --- |
| bit 1 / 2 | 2.xx responses |
| bit 3 / 8 | 4.xx responses |
| bit 4 / 16 | 5.xx responses |

OR combines classes, so 26 suppresses all response classes defined by RFC
7252. An empty option is numeric zero and expresses interest in all responses.
Unknown bits remain visible. The packet primitive classifies the mask; actual
response suppression and token lifecycle are endpoint policy.

## FETCH, PATCH, and iPATCH

RFC 8132 assigns method codes 0.05 FETCH (`0x05`), 0.06 PATCH (`0x06`), and
0.07 iPATCH (`0x07`). PATCH is neither safe nor idempotent; iPATCH has the
same packet grammar but requires idempotent patch semantics. The patch
document is an ordinary binary CoAP payload whose media type is named by
Content-Format. Unknown and future patch Content-Formats remain numeric and
lossless.

RFC 8132 Sections 3 and 4 also assign 4.09 Conflict and 4.22 Unprocessable
Entity. Builders set the method code and Content-Format while returning a
typed CoAP layer. Applying a patch document, validating application-specific
idempotence, and mutating a resource are outside the packet primitive.

## Hop-Limit

RFC 8768 Section 3 defines Hop-Limit (option 16) as an elective,
safe-to-forward, cache-key `uint` encoded in exactly one byte. Its semantic
range is 1..255 and its default initial value is 16. A supporting proxy
decrements before forwarding and must not forward a request whose value
becomes zero; RFC 8768 Section 6 assigns response code 5.08 Hop Limit Reached.

The typed helper may return a decremented option or a typed exhausted result.
It never silently clamps 0 or a multi-byte raw value and does not forward a
packet. Explicit malformed encodings remain constructible and semantic
validation reports them.

## Echo and Request-Tag

RFC 9175 Section 2.2.1 defines Echo (option 252) as an elective,
safe-to-forward, non-cache-key, non-repeatable opaque value of 1..40 bytes.
Its content and structure are implementation-specific and must remain opaque.
The primitive stores and echoes bytes; generating freshness challenges and
deciding whether a value is fresh are endpoint policy.

RFC 9175 Section 3.2.1 defines Request-Tag (option 292) as an elective,
safe-to-forward, cache-key, repeatable opaque value of 0..8 bytes. Equal tag
bytes associate payload-bearing messages with one blockwise request body.
Presence with an empty value is distinct from absence. Inner and Outer
Request-Tag instances are independent under OSCORE: the Inner instance labels
end-to-end blockwise bodies and the Outer instance labels hop-by-hop bodies.
The model preserves those positions but does not allocate tags, decide when a
tag may be recycled, or retain transfer state.

## Q-Block

RFC 9177 Sections 4.1 and 4.2 define Q-Block1 (option 19) and Q-Block2 (option
31) as 0..3-byte `uint` values with exactly the RFC 7959 `NUM | M | SZX` bit
layout. Q-Block1 is critical, unsafe, and non-repeatable. Q-Block2 is
critical, unsafe, and repeatable only for requesting retransmission of
multiple missing blocks. Both options must be supported together.

Absence means first and only block with an unspecified size; an explicitly
empty value means numeric zero and therefore a 16-byte size. Q-Block1 pertains
to request bodies and Q-Block2 to response bodies. A Q-Block1 transfer also
uses a stable Request-Tag and Size1 across its body.

RFC 9177 Sections 4 through 7 impose these interaction checks without
changing the wire parser:

- Block1 and Q-Block1, or Block2 and Q-Block2, must not be mixed at the same
  OSCORE protection level;
- Inner and Outer levels are independent, so a Q-Block option at one level
  may coexist with a Block option at the other;
- without OSCORE, ordinary Block and Q-Block options must not be mixed in one
  message; and
- missing-block reports use the separately registered
  `application/missing-blocks+cbor-seq` payload grammar rather than repeated
  Q-Block values alone.

The layer exposes block fields, same-level interaction validation, and
stateless burst metadata. MAX_PAYLOADS scheduling, congestion control,
timeouts, retransmission, and body assembly remain generated-tool workflows.

## Extended token length

RFC 8974 Sections 2 and 2.1 update both datagram and reliable TKL grammar:

| TKL nibble | Bytes immediately before Token | Logical token length |
| ---: | ---: | ---: |
| 0..12 | none | TKL |
| 13 | one `ext8` | `13 + ext8` |
| 14 | two-byte network-order `ext16` | `269 + ext16` |
| 15 | none | reserved message-format error |

The maximum representable length is 65804. Canonical encoding selects the
shortest form. An explicit discriminator, extension, logical length, and token
byte vector remain separate override-aware data so intentional mismatches can
be emitted unchanged. Decode checks the TKL extension before locating the
token, then checks the entire declared token boundary before parsing options.

RFC 8974 Section 2.2.1 assigns CSM signaling option 6,
Extended-Token-Length, a `uint` of 0..3 bytes with base value 8 and valid
advertised range 8..65804. Capability negotiation and trial-and-error state
are operational concerns; the reliable signaling model only preserves and
inspects the option.

## Reliable CoAP framing

RFC 8323 Section 3.2 defines one reliable frame. It removes Version, Type,
and Message ID and prefixes Code, Token, options, marker, and payload with a
Len/TKL byte and optional extended length:

```text
+--------+--------------------+------+----------------+-------+---------+
|Len|TKL | extended Len bytes | Code | TKL extension | Token | body    |
+--------+--------------------+------+----------------+-------+---------+
```

The body begins at the first option bit and ends at the payload end. Len does
not count the initial Len/TKL byte, extended Len bytes, Code, TKL extension,
or Token:

| Len nibble | Extension | Body length |
| ---: | ---: | ---: |
| 0..12 | none | Len |
| 13 | one `ext8` | `13 + ext8` |
| 14 | two-byte network-order `ext16` | `269 + ext16` |
| 15 | four-byte network-order `ext32` | `65805 + ext32` |

After body length is known, frame size is checked with overflow-safe addition:

```text
1 + len_extension_bytes + 1 + tkl_extension_bytes + token_length + body_length
```

The body uses the ordinary ordered option and payload-marker grammar. The
marker counts in Len and is absent for a zero-length payload. TKL uses RFC
8974, including its 0..2-byte extension. A direct decoder consumes exactly
one complete frame and reports the consumed byte count, leaving any following
bytes for the caller. It never searches a TCP stream, buffers a partial frame,
or treats WebSocket boundaries as TCP framing.

Explicit Len, extended Len bytes, and TKL fields survive compilation even
when inconsistent with owned body or token bytes. Canonical compilation fills
only unset framing fields. Strict direct decode reports truncated length,
token, or body boundaries as structured errors.

## Reliable signaling

RFC 8323 Section 5 assigns class-7 codes only in reliable frames:

| Code | Wire | Meaning |
| --- | ---: | --- |
| 7.01 CSM | `0xe1` | Capabilities and settings |
| 7.02 Ping | `0xe2` | Peer liveness request |
| 7.03 Pong | `0xe3` | Ping response |
| 7.04 Release | `0xe4` | Orderly shutdown indication |
| 7.05 Abort | `0xe5` | Error termination indication |

The signaling option namespace is keyed by `(signaling code, option number)`
and is not the ordinary request/response option namespace:

| Context | No. | Option |
| --- | ---: | --- |
| CSM | 2 | Max-Message-Size |
| CSM | 4 | Block-Wise-Transfer |
| CSM | 6 | Extended-Token-Length (RFC 8974) |
| Ping/Pong | 2 | Custody |
| Release | 2 | Alternative-Address |
| Release | 4 | Hold-Off |
| Abort | 2 | Bad-CSM-Option |
| any signaling code | 9 | OSCORE (RFC 8613) |

Unknown signaling codes and context-specific options remain numeric with
opaque ordered values. The packet layer can build, decode, summarize, and
validate one signaling message. Connection opening, first-CSM enforcement,
Ping timeouts, shutdown, aborting a socket, TLS, and WebSocket framing are not
packet primitives.

## OSCORE transform grammar

OSCORE is an explicit `Coap -> Coap` protect transform and inverse unprotect
transform, not a transport or parallel encrypted-packet API. The outer CoAP
message remains typed and inspectable.

### OSCORE option and compressed COSE object

RFC 8613 Sections 2, 6.1, and 6.2 define option 9 as critical,
safe-to-forward, cache-key, and non-repeatable. Its value is:

```text
first byte = 000 h k nnn
value      = first-byte || Partial-IV[n]
             || (kid-context-length || kid-context)? || kid?
```

Here `n` is the three least significant bits and gives a Partial IV length of
0..5; values 6 and 7 are reserved. `k` states that `kid` is present and `h`
states that `kid context` is present. With `h`, one length byte precedes the
kid-context bytes. When present, `kid` consumes every remaining option byte
and is therefore last. Under stable RFC 8613 the three high bits are zero;
unknown or provisional flag metadata is retained but not interpreted by the
base transform. If every base flag is zero the canonical option value is
empty, not one zero byte.

RFC 8613 Section 5 represents the cryptographic object as COSE_Encrypt0:

- the COSE `protected` field is the empty byte string;
- the `unprotected` map carries Partial IV, `kid`, and `kid context` when
  required;
- header compression moves those values into the OSCORE option; and
- the outer CoAP payload is the COSE ciphertext including its authentication
  tag.

An outer OSCORE message without a payload is malformed. The outer Code is the
source-defined request/response dummy Code, while the original Code is inside
the plaintext. The registered `application/oscore` Content-Format is reserved
for other mappings and is not inserted into an OSCORE CoAP message.

### Class E, I, and U fields

RFC 8613 Section 4 divides message fields by protection:

- Class E is encrypted and integrity protected. These Inner fields are
  removed from the outer option list and placed in the plaintext.
- Class I is integrity protected but not encrypted. These Outer fields remain
  visible and their encoded option bytes enter External AAD.
- Class U is unprotected. These Outer fields remain visible and do not enter
  External AAD.

Unknown options default to Class E. RFC 8613 defines no Class I options at
publication, but the grammar retains a Class I byte sequence for future
source-backed options. Options such as Observe, Block1/Block2, Max-Age,
Size1/Size2, No-Response, Q-Block, and Request-Tag may have distinct Inner and
Outer instances under their defining rules; ordering is canonical within each
separate option sequence, never across the encrypted boundary.

RFC 8613 Section 5.3 serializes plaintext as:

```text
original Code || ordered Class E options || (0xff || original Payload)?
```

The payload marker is present only when plaintext has payload bytes.

### External AAD and nonce

RFC 8613 Section 5.4 defines canonical CBOR:

```text
aad_array = [
  oscore_version,
  [alg_aead],
  request_kid,
  request_piv,
  encoded_class_i_options,
]
external_aad = bstr .cbor aad_array
AAD = ["Encrypt0", h'', external_aad]
```

OSCORE version is 1. `request_kid` and `request_piv` bind a response to its
request. Class I options are encoded with ordinary CoAP option deltas starting
from zero.

RFC 8613 Section 5.2 constructs a nonce of the AEAD algorithm's nonce length:

1. left-pad Partial IV to exactly five bytes;
2. left-pad the Sender ID of the endpoint that generated that Partial IV to
   `nonce_length - 6` bytes;
3. prefix one byte containing the unpadded Sender ID length; and
4. XOR the resulting nonce-length byte string with the Common IV.

A response without its own Partial IV reuses the request nonce. The transform
requires the request binding inputs explicitly rather than looking them up in
global transaction state.

### Supported algorithm profile and context boundary

The admitted mandatory profile from RFC 8613 Sections 3.2 and 3.2.1 is:

| Parameter | Supported value |
| --- | --- |
| AEAD | AES-CCM-16-64-128, COSE algorithm 10; 16-byte key, 13-byte nonce, 8-byte tag |
| KDF | HKDF SHA-256 |
| Sender/Recipient ID | opaque byte string, at most 7 bytes for this AEAD |
| Partial IV | network-order Sender Sequence Number, at most 5 bytes |

Derivation uses `HKDF(Master Salt, Master Secret, info, L)`, where canonical
CBOR `info` is `[id, id_context-or-nil, alg_aead, "Key"-or-"IV", L]`.
Sender Key uses Sender ID, Recipient Key uses Recipient ID, and Common IV uses
an empty `id`; `L` is 16 for keys and 13 for the Common IV. Official byte
vectors are in RFC 8613 Appendix C and are the later transform's independent
acceptance evidence.

The caller supplies immutable context inputs and any request-binding data.
The packet primitive may derive keys, protect, authenticate, and return typed
failure for a wrong context, unsupported algorithm, malformed option, or bad
tag. It must redact Master Secret, Master Salt, derived keys, and plaintext
from diagnostics. Context provisioning, ACE, EDHOC, sequence allocation,
persistent replay windows, key rollover, and context databases remain outside
the primitive.

## Group request/response metadata

RFC 7252 Sections 8.1 and 8.2 provide the stable group wire boundary. A group
request is an ordinary CoAP datagram whose IP destination is multicast; the
CoAP Type must be Non-confirmable. Responses are unicast and match the request
by Token only because a response source differs from the request's multicast
destination. The request URI used to interpret Location-* and embedded links
is formed with the actual responding endpoint's literal address.

These are packet metadata that a typed helper may expose:

- whether the network destination is unicast or multicast;
- the request Type, Code, Message ID, Token, URI options, and payload;
- response source, destination, Code, Token, and ordinary CoAP options; and
- whether Token-only group-response matching is applicable.

The helper does not join a multicast group, select an interface or target,
send a request, implement Leisure/random response scheduling, retain Token
lifetime state, aggregate responses, or manage group membership.

## Provisional Group OSCORE boundary

The 2026-07-14 IANA snapshot assigns OSCORE flag bit position 2 as the Group
Flag and references `RFC-ietf-core-oscore-groupcomm-28`. The source manifest
records that document as an Internet-Draft in the RFC Editor queue, not a
final numbered RFC. Therefore the only stable behavior admitted now is:

- preserve the Group Flag as explicitly provisional registry metadata;
- preserve the complete raw OSCORE option, ID Context/Group Identifier,
  Sender ID/`kid`, Partial IV, ciphertext, authentication material, and any
  countersignature or algorithm metadata opaquely when encountered; and
- return an explicit unsupported/provisional Group OSCORE result rather than
  invoking the pairwise RFC 8613 transform with guessed group semantics.

Draft 28 describes group mode and pairwise mode, group identifiers in `kid
context`, mandatory sender identification, group-mode countersignatures, and
additional algorithm/context inputs. Those fields are search leads for the
planned Group OSCORE re-review, not a frozen layout, algorithm set, External
AAD, nonce, or signature serializer in this document.

Before implementing Group OSCORE, the later step must re-check Datatracker,
RFC Editor publication metadata, Errata, IANA flag assignments, and the final
numbered RFC text. If no final RFC exists or its bytes differ from draft 28,
implementation stops. Group membership, Group Manager interaction, key
distribution, credential lookup, signature policy, replay databases, and
sender scheduling are outside `crafter` in all cases.

## Transport and workflow limits

- Datagram extensions remain one typed `Coap` layer over UDP. Reliable
  extensions remain one typed `CoapReliable` frame over TCP.
- No grammar here authorizes automatic decode merely from a service port.
  Registry dispatch still requires the conservative complete-message shape
  gates, and protected ports remain `Raw` without explicit security handling.
- There is no TCP stream reassembly, WebSocket framing, DTLS/TLS handshake,
  block/Q-Block body assembly, Observe subscription engine, cache, proxy,
  discovery scanner, OSCORE context service, or group workflow.
- Offline byte, malformed, pcap, and independent-vector tests are the default.
  Live traffic requires the separately documented provider-backed safety and
  confirmation gates.
