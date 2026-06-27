# SSDP Wire Grammar

This note fixes the source-backed message grammar that later SSDP parser and
serializer steps must use. It is scoped to SSDP as a UDP application payload in
`crafter`; it does not define a discovery daemon, HTTP client, cache, retry
engine, or control-point workflow.

## Evidence Boundary

| Rule area | Evidence |
| --- | --- |
| SSDP discovery message forms, UPnP-defined request/notification/response examples, and UPnP discovery headers | OCF / UPnP Forum, "UPnP Device Architecture 2.0", Discovery chapter, available at `https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf` |
| Deployed compatibility examples for the same SSDP message family | UPnP Forum, "UPnP Device Architecture 1.1", Discovery chapter, available at `https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf` |
| HTTP message, request-line, status-line, field-line, CRLF, and message-body grammar | RFC 9112, Sections 2, 3, 4, and 6, `https://www.rfc-editor.org/rfc/rfc9112.html` |
| HTTP method token, field name, field value, status code, duplicate field ordering, and case rules | RFC 9110, Sections 5, 6, and 9, `https://www.rfc-editor.org/rfc/rfc9110.html` |
| UDP datagram boundary | RFC 768, `https://www.rfc-editor.org/rfc/rfc768.html` |

`.agents/docs/ssdp-source-manifest.md` remains the authority manifest. When a
later implementation step needs a method, header, status, multicast address,
port, or URI rule, it must cite this grammar note and then the exact source
section or registry row used for that narrower fact.

## Errata And Update Review

Review date: 2026-06-27.

- RFC 9112 remains the syntax source for the UDP-carried HTTP-like envelope.
  RFC 9931 updates RFC 9112 for HTTP/1.1 optimistic protocol transitions,
  Upgrade, and CONNECT behavior; those mechanisms are not part of SSDP over UDP
  and do not change this grammar.
- RFC 9112 verified Errata 7744 corrects the `obs-text` reference to RFC 9110
  Section 5.5. If a parser step consumes `field-vchar` or `obs-text`, use that
  corrected reference. RFC 9112 verified Errata 8284 is an appendix change note
  and does not change the start-line, header-line, CRLF delimiter, or
  message-body rules used here.
- RFC 9110 verified errata were reviewed for the grammar areas used by SSDP:
  method token, field name, field value, status-code shape, and ordered field
  preservation. None changes this note's packet grammar. Do not import errata
  or updates for unrelated HTTP semantics such as negotiation, redirects,
  caching, authentication, or TLS identity into the SSDP layer.
- RFC 768 is updated by RFC 9868 for UDP options and surplus-area behavior.
  SSDP parsing receives only UDP user data selected by the UDP layer. UDP
  option or surplus bytes, if ever exposed by lower-layer support, must not be
  appended to an SSDP body.
- RFC 3986 is updated by RFC 8820, and RFC 8141 is the current URN authority.
  These sources support URI or URN syntax only for later value-specific
  helpers. They do not change the grammar rule that SSDP header values are
  preserved byte strings at this layer.
- No reviewed Errata or update source conflicts with the CRLF-delimited,
  single-datagram SSDP envelope in this note. If a later official UPnP update,
  IANA registry change, RFC update, or verified erratum conflicts with a wire
  rule here, stop and record the conflict before changing parser or serializer
  behavior.

## Message Envelope

SSDP discovery traffic is an HTTP-like message carried in one UDP datagram. For
packet parsing, one datagram is one candidate SSDP message:

```text
ssdp-message = start-line CRLF *( header-line CRLF ) CRLF body
body         = *OCTET
```

The start line and header section use the HTTP/1.1 grammar from RFC 9112, but
the transport boundary is the UDP payload length from RFC 768, not a TCP stream
or persistent HTTP connection. The parser must not wait for more bytes after
the datagram ends.

## start-line Forms

UPnP discovery sources show three SSDP start-line families:

```text
NOTIFY * HTTP/1.1
M-SEARCH * HTTP/1.1
HTTP/1.1 200 OK
```

The request-line shape follows RFC 9112:

```text
request-line = method SP request-target SP HTTP-version
```

For UPnP-defined discovery notifications and searches, the request target is
the asterisk form (`*`) and the version token is `HTTP/1.1`. Later method and
builder steps may expose helpers for `NOTIFY` and `M-SEARCH`, but the core
message model must still be able to preserve an unknown method token when the
enclosing line has the request-line shape.

The response shape follows RFC 9112:

```text
status-line = HTTP-version SP status-code SP [ reason-phrase ]
```

UPnP discovery responses use `HTTP/1.1 200 OK`. The status code is a
three-digit value by HTTP grammar. Unknown status codes and unusual reason
phrases are preserved when the status-line is structurally valid; builders can
default to the UPnP-backed `200 OK` response only when the caller did not set a
different value.

## Header Syntax

Each header is an ordered HTTP field line:

```text
header-line = field-name ":" OWS field-value OWS
field-name  = token
```

The field name grammar and token character set come from RFC 9110 and RFC
9112. Header names are case-insensitive for lookup, but the packet layer must
preserve the caller-supplied spelling and ordering for inspection and
round-trip serialization. Empty field values are valid HTTP field values and
are required to represent SSDP lines such as an empty `EXT` field without
inventing a value.

Whitespace before the colon is malformed. Optional whitespace after the colon
or around the field value is syntactic whitespace; typed helpers may expose a
trimmed value, but raw preservation must keep enough data to show and re-emit
the original field line when requested. Header lines beginning with SP or HTAB
are obsolete folded lines under HTTP/1.1; the SSDP parser should report them as
malformed rather than unfolding them silently.

## Delimiters And Datagram Framing

The canonical delimiter is CRLF (`\r\n`). The header section ends at the first
empty CRLF line after the start line. For default UDP application decoding,
the conservative SSDP shape gate should require a complete CRLF-delimited
header section before accepting a payload as SSDP; unrelated text or binary
payloads remain `Raw`.

Bare LF, CR not followed by LF, missing final empty line, truncated header
lines, or bytes that end inside a start line are malformed SSDP candidates.
They should surface structured parse errors when SSDP parsing is explicitly
requested. Registry-driven UDP decode may instead leave a malformed candidate
as `Raw` if that is how the surrounding dispatch path preserves unrelated
traffic.

## Body Handling

UPnP discovery examples are header-only messages terminated by the empty line.
No builder should generate a non-empty body by default until a later
source-backed step admits such a body for a specific SSDP message family.

The generic HTTP message grammar permits `message-body` bytes after the header
delimiter, and the crate contract requires preservation of structurally valid
unknown payload. Therefore, if a datagram has a valid SSDP start line and
complete header section, any remaining bytes after the delimiter are preserved
as opaque body bytes. The SSDP parser must not discard, normalize, or validate
those bytes against `Content-Length` or transfer coding unless a later
SSDP-specific source document authorizes that behavior.

## Casing And Canonicalization

HTTP method names are case-sensitive tokens. UPnP discovery sources spell the
core request methods as uppercase `NOTIFY` and `M-SEARCH`; lowercase or mixed
case method tokens are unknown methods, not aliases.

HTTP field names are case-insensitive. Helper-generated SSDP headers may use
canonical project spelling in later API steps, but decoding must retain
non-canonical casing and unknown names. Header values remain byte strings at
this grammar layer; value-specific casing rules belong to later codepoint and
header-helper documents.

The serializer must preserve explicit overrides. It may fill only omitted
defaults selected by later builder steps; it must not rewrite an existing
method, version token, status code, reason phrase, header spelling, duplicate
header order, extension header, or body.

## Duplicate Headers

RFC 9110 treats fields with the same name as an ordered part of the field
section and warns that order can be significant when values are combined. SSDP
must therefore keep duplicate headers as ordered field lines. The parser must
not deduplicate, sort, merge, or reject duplicates at the grammar layer.

Typed helpers added later may define per-header accessors such as first value,
last value, or all values only when the relevant UPnP or HTTP source supports
that interpretation. Without such a source-backed helper, duplicate headers
remain preserved ordered fields.

## Extension Headers

UPnP discovery uses extension-style headers such as `MAN` and `EXT`. RFC 2774
is historical context only under `.agents/docs/ssdp-source-manifest.md`, so
generic HTTP extension processing is out of scope. The SSDP message model must
preserve these fields and any other unknown field names exactly as ordered
headers. Later helper steps may add UPnP-backed behavior for specific extension
fields, but an unknown extension header is not a parse error.

## Malformed Boundaries

The parser must return structured errors, not panics or silent truncation, for
these grammar failures:

- empty payload;
- no complete CRLF-delimited start line;
- request start line without exactly `method SP request-target SP HTTP-version`;
- response start line without `HTTP-version SP status-code` or with a
  non-three-digit status code;
- unsupported HTTP-version syntax in an otherwise SSDP-shaped line;
- invalid method or field-name token characters;
- whitespace before a header colon;
- a header line with no colon;
- obsolete folded header lines beginning with SP or HTAB;
- missing CRLF CRLF header terminator before datagram end;
- bytes that end inside a line delimiter or header field.

Malformed inputs on SSDP-related UDP ports must not force the whole UDP payload
into SSDP. The dispatch layer should accept only the conservative shape gate
defined by this note and later codepoint documents; otherwise it must preserve
the application payload as `Raw`.
