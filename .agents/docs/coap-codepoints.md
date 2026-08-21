# CoAP IANA Codepoint Snapshot

This document is the code-facing authority for CoAP constants, registry
labels, fixtures, oracle specifications, summaries, and examples. It is
derived from .agents/docs/coap-rfc-manifest.md. On disagreement, return to
that manifest and the current official registry before changing packet
behavior.

Review date: 2026-07-14.

## Sources and authority

- IANA, Constrained RESTful Environments (CoRE) Parameters, created
  2012-06-08 and last updated 2026-07-02:
  https://www.iana.org/assignments/core-parameters/core-parameters.xhtml
- IANA, Service Name and Transport Protocol Port Number Registry, last
  updated 2026-06-17:
  https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
- RFC 7252 Sections 5.4.6 and 12 for the code and option-number grammars,
  derived option properties, and original registry policy.
- RFC 8323 Section 11 for reliable-transport signaling codes, signaling
  options, and TCP service registrations.
- RFC 8613 Section 13 for the OSCORE option, Content-Format, signaling option,
  and base flag-bit assignments.
- RFC 9876 Section 4 and RFC Erratum 4954 for the current Content-Format
  registration policy.

IANA is authoritative for current assignments. RFCs define wire grammar and
semantics. A registry row backed only by an Internet-Draft, an RFC Editor queue
placeholder such as RFC-ietf-..., a temporary registration, an individual, or
an external specification is recorded because it is assigned, but it is not
automatically eligible for a stable crafter builder or default.

Snapshot status terms used below:

- assigned: a current IANA assignment backed by a published RFC or stable
  external registration;
- draft-backed: assigned by IANA, but its semantic reference is not a final
  numbered RFC;
- temporary: assigned until the expiry date shown by IANA;
- unassigned: available only through the registry's allocation procedure;
- reserved: not available for ordinary assignment or use;
- documentation: reserved for examples and documentation;
- experimental: reserved for experiments and never a production default.

## Global preservation and label policy

Registry labels are inspection metadata, not parser gates. Every structurally
valid numeric value is retained even when this snapshot calls it Unknown,
unassigned, reserved, experimental, temporary, or draft-backed.

Stable fallback labels:

    Code fallback: code-<class>.<two-digit-detail>
    Option fallback: option-<number>
    Content-Format fallback: content-format-<number>
    Signaling code fallback: signaling-7.<two-digit-detail>
    Signaling option fallback: signaling-option-<number>
    OSCORE flag fallback: oscore-flag-<bit>
    Service fallback: port-<number>/<transport>

Decoders must preserve the numeric value and opaque body bytes. Builders must
preserve explicit caller values, including values that are invalid for a
particular message role. Semantic validation may report a registry status or
unsupported meaning, but compile and round-trip behavior must not rewrite it.

## CoAP Codes

The wire value is one octet. In the customary C.DD notation, C is the
three-bit class, DD is the five-bit detail, and:

    wire = (class << 5) | detail
    class = wire >> 5
    detail = wire & 0x1f

### Code-class space

| Code range | Wire range | Label | Status | Reference |
| --- | ---: | --- | --- | --- |
| 0.00 | 0x00 | Empty | assigned | RFC 7252 Section 4.1 |
| 0.01-0.31 | 0x01-0x1f | Request method space | assigned sub-registry | RFC 7252 Section 12.1.1 |
| 1.00-1.31 | 0x20-0x3f | Reserved | reserved | RFC 7252 |
| 2.00-5.31 | 0x40-0xbf | Response space | assigned sub-registry, with gaps | RFC 7252 Section 12.1.2 |
| 6.00-7.31 | 0xc0-0xff | Reserved in base CoAP | reserved; class 7 has a reliable signaling sub-registry | RFC 7252; RFC 8323 |

Reserved ranges can only be allocated under RFC 8126 Section 4.3. Unknown,
reserved, and role-inappropriate code bytes remain a lossless CoapCode value.
Datagram decoding does not reinterpret a class-7 code as a reliable signaling
message.

### Method Codes

Allocation policy: IETF Review or IESG Approval.

| Code | Wire | Label | Status | Reference |
| --- | ---: | --- | --- | --- |
| 0.01 | 0x01 | GET | assigned | RFC 7252 |
| 0.02 | 0x02 | POST | assigned | RFC 7252 |
| 0.03 | 0x03 | PUT | assigned | RFC 7252 |
| 0.04 | 0x04 | DELETE | assigned | RFC 7252 |
| 0.05 | 0x05 | FETCH | assigned | RFC 8132 |
| 0.06 | 0x06 | PATCH | assigned | RFC 8132 |
| 0.07 | 0x07 | iPATCH | assigned | RFC 8132 |
| 0.08-0.31 | 0x08-0x1f | Unassigned | unassigned | IANA CoAP Method Codes |

### Response Codes

Allocation policy: IETF Review or IESG Approval.

| Code | Wire | Label | Status | Reference |
| --- | ---: | --- | --- | --- |
| 2.00 | 0x40 | Unassigned | unassigned | IANA CoAP Response Codes |
| 2.01 | 0x41 | Created | assigned | RFC 7252 |
| 2.02 | 0x42 | Deleted | assigned | RFC 7252 |
| 2.03 | 0x43 | Valid | assigned | RFC 7252 |
| 2.04 | 0x44 | Changed | assigned | RFC 7252 |
| 2.05 | 0x45 | Content | assigned | RFC 7252 |
| 2.06-2.30 | 0x46-0x5e | Unassigned | unassigned | IANA CoAP Response Codes |
| 2.31 | 0x5f | Continue | assigned | RFC 7959 |
| 3.00-3.31 | 0x60-0x7f | Reserved | reserved | RFC 7252 |
| 4.00 | 0x80 | Bad Request | assigned | RFC 7252 |
| 4.01 | 0x81 | Unauthorized | assigned | RFC 7252 |
| 4.02 | 0x82 | Bad Option | assigned | RFC 7252 |
| 4.03 | 0x83 | Forbidden | assigned | RFC 7252 |
| 4.04 | 0x84 | Not Found | assigned | RFC 7252 |
| 4.05 | 0x85 | Method Not Allowed | assigned | RFC 7252 |
| 4.06 | 0x86 | Not Acceptable | assigned | RFC 7252 |
| 4.07 | 0x87 | Unassigned | unassigned | IANA CoAP Response Codes |
| 4.08 | 0x88 | Request Entity Incomplete | assigned | RFC 7959 |
| 4.09 | 0x89 | Conflict | assigned | RFC 8132 |
| 4.10-4.11 | 0x8a-0x8b | Unassigned | unassigned | IANA CoAP Response Codes |
| 4.12 | 0x8c | Precondition Failed | assigned | RFC 7252 |
| 4.13 | 0x8d | Request Entity Too Large | assigned | RFC 7252; RFC 7959 |
| 4.14 | 0x8e | Unassigned | unassigned | IANA CoAP Response Codes |
| 4.15 | 0x8f | Unsupported Content-Format | assigned | RFC 7252 |
| 4.16-4.21 | 0x90-0x95 | Unassigned | unassigned | IANA CoAP Response Codes |
| 4.22 | 0x96 | Unprocessable Entity | assigned | RFC 8132 |
| 4.23-4.28 | 0x97-0x9c | Unassigned | unassigned | IANA CoAP Response Codes |
| 4.29 | 0x9d | Too Many Requests | assigned | RFC 8516 |
| 4.30-4.31 | 0x9e-0x9f | Unassigned | unassigned | IANA CoAP Response Codes |
| 5.00 | 0xa0 | Internal Server Error | assigned | RFC 7252 |
| 5.01 | 0xa1 | Not Implemented | assigned | RFC 7252 |
| 5.02 | 0xa2 | Bad Gateway | assigned | RFC 7252 |
| 5.03 | 0xa3 | Service Unavailable | assigned | RFC 7252 |
| 5.04 | 0xa4 | Gateway Timeout | assigned | RFC 7252 |
| 5.05 | 0xa5 | Proxying Not Supported | assigned | RFC 7252 |
| 5.06-5.07 | 0xa6-0xa7 | Unassigned | unassigned | IANA CoAP Response Codes |
| 5.08 | 0xa8 | Hop Limit Reached | assigned | RFC 8768 |
| 5.09-5.31 | 0xa9-0xbf | Unassigned | unassigned | IANA CoAP Response Codes |

## Datagram CoAP Option Numbers

This is the ordinary request/response option-number space. It is distinct from
the reliable signaling option space below, even when the same number appears
in both.

### Derived option properties

RFC 7252 Section 5.4.6 derives properties from the least-significant bits of
the number. Do not maintain separate critical, unsafe, or cache-key lists:

    critical = (number & 1) != 0
    unsafe = (number & 2) != 0
    no_cache_key = (number & 0x1e) == 0x1c

An even number is elective; an odd number is critical. Bit 1 clear means
Safe-to-Forward. NoCacheKey is meaningful for Safe-to-Forward options; all
other safe options participate in the cache key. These formulas also apply to
future and unknown numbers.

### Allocation ranges

| Number range | Status | Registration procedure | Reference |
| ---: | --- | --- | --- |
| 0-255 | registry range | IETF Review or IESG Approval | RFC 7252 Section 12.2 |
| 256-2047 | registry range | Specification Required | IANA CoAP Option Numbers |
| 2048-64999 | registry range | Expert Review | IANA CoAP Option Numbers |
| 65000-65535 | experimental | Experimental use; no operational use | RFC 7252 |

### Current rows

| Number or range | Label | Status | Reference |
| ---: | --- | --- | --- |
| 0 | Reserved | reserved | RFC 7252 |
| 1 | If-Match | assigned | RFC 7252; RFC 8613 |
| 2 | Unassigned | unassigned | IANA |
| 3 | Uri-Host | assigned | RFC 7252; RFC 8613 |
| 4 | ETag | assigned | RFC 7252; RFC 8613 |
| 5 | If-None-Match | assigned | RFC 7252; RFC 8613 |
| 6 | Observe | assigned | RFC 7641; RFC 8613 |
| 7 | Uri-Port | assigned | RFC 7252; RFC 8613 |
| 8 | Location-Path | assigned | RFC 7252; RFC 8613 |
| 9 | OSCORE | assigned | RFC 8613 |
| 10 | Unassigned | unassigned | IANA |
| 11 | Uri-Path | assigned | RFC 7252; RFC 8613 |
| 12 | Content-Format | assigned | RFC 7252; RFC 8613 |
| 13 | Unassigned | unassigned | IANA |
| 14 | Max-Age | assigned | RFC 7252; RFC 8516; RFC 8613 |
| 15 | Uri-Query | assigned | RFC 7252; RFC 8613 |
| 16 | Hop-Limit | assigned | RFC 8768 |
| 17 | Accept | assigned | RFC 7252; RFC 8613 |
| 18 | Unassigned | unassigned | IANA |
| 19 | Q-Block1 | assigned | RFC 9177 |
| 20 | Location-Query | assigned | RFC 7252; RFC 8613 |
| 21 | EDHOC | assigned | RFC 9668 |
| 22 | Unassigned | unassigned | IANA |
| 23 | Block2 | assigned | RFC 7959; RFC 8323; RFC 8613 |
| 24-26 | Unassigned | unassigned | IANA |
| 27 | Block1 | assigned | RFC 7959; RFC 8323; RFC 8613 |
| 28 | Size2 | assigned | RFC 7959; RFC 8613 |
| 29-30 | Unassigned | unassigned | IANA |
| 31 | Q-Block2 | assigned | RFC 9177 |
| 32-34 | Unassigned | unassigned | IANA |
| 35 | Proxy-Uri | assigned | RFC 7252; RFC 8613 |
| 36-38 | Unassigned | unassigned | IANA |
| 39 | Proxy-Scheme | assigned | RFC 7252; RFC 8613 |
| 40-59 | Unassigned | unassigned | IANA |
| 60 | Size1 | assigned | RFC 7252; RFC 8613 |
| 61-127 | Unassigned | unassigned | IANA |
| 128 | Reserved | reserved | RFC 7252 |
| 129-131 | Unassigned | unassigned | IANA |
| 132 | Reserved | reserved | RFC 7252 |
| 133-135 | Unassigned | unassigned | IANA |
| 136 | Reserved | reserved | RFC 7252 |
| 137-139 | Unassigned | unassigned | IANA |
| 140 | Reserved | reserved | RFC 7252 |
| 141-234 | Unassigned | unassigned | IANA |
| 235 | Proxy-Cri | draft-backed | RFC-ietf-core-href-29 |
| 236-238 | Unassigned | unassigned | IANA |
| 239 | Proxy-Scheme-Number | draft-backed | RFC-ietf-core-href-29 |
| 240-251 | Unassigned | unassigned | IANA |
| 252 | Echo | assigned | RFC 9175 |
| 253-257 | Unassigned | unassigned | IANA |
| 258 | No-Response | assigned | RFC 7967; RFC 8613 |
| 259-291 | Unassigned | unassigned | IANA |
| 292 | Request-Tag | assigned | RFC 9175 |
| 293-2048 | Unassigned | unassigned | IANA |
| 2049 | OCF-Accept-Content-Format-Version | assigned, external | Michael Koster registration |
| 2050-2052 | Unassigned | unassigned | IANA |
| 2053 | OCF-Content-Format-Version | assigned, external | Michael Koster registration |
| 2054 | Unassigned | unassigned | IANA |
| 2055 | SCP82-Params | assigned, external | GlobalPlatform GPC SPE 207 |
| 2056 | X-Admin-Protocol | assigned, external | GSMA SGP.32 v1.3 |
| 2057-64999 | Unassigned | unassigned | IANA |
| 65000-65535 | Reserved for Experimental Use | experimental | RFC 7252 |

Unknown option numbers retain their number, ordered occurrence, and opaque
value bytes. Draft-backed and external rows are labels, not permission to
implement semantics outside the reviewed CoAP scope.

## CoAP Content-Formats

Content-Format IDs are unsigned integers in the registry domain 0-65535. The
current allocation policy, as updated by RFC 9876, is:

| ID range | Status | Registration procedure | Reference |
| ---: | --- | --- | --- |
| 0-255 | registry range | Expert Review, including temporary registrations | RFC 9876 Section 4.1.3 |
| 256-9999 | registry range | IETF Review with Expert Review, or IESG Approval with Expert Review | RFC 9876 Section 4.1.3 |
| 10000-19999 | registry range | Expert Review | RFC 9876 Section 4.1.3 |
| 20000-32999 | registry range | First Come First Served under the IANA media-type, parameter, and coding conditions | RFC 9876 |
| 33000-64997 | registry range | Expert Review | RFC 9876 Section 4.1.3 |
| 64998-64999 | Reserved for Documentation | documentation | RFC 9876 |
| 65000-65535 | Reserved for Experimental Use | experimental; no operational use | RFC 7252 |

Temporary 0-255 registrations are approved by designated experts and do not
use the RFC 7120 renewal process. Their expiry remains significant metadata.

### Current rows

The Content Coding column says none when the IANA row is empty. Parameters are
part of the registered Content-Format identity.

| ID or range | Media type and parameters | Content Coding | Status | Reference |
| ---: | --- | --- | --- | --- |
| 0 | text/plain; charset=utf-8 | none | assigned | RFC 2046; RFC 3676; RFC 5147 |
| 1-15 | Unassigned | none | unassigned | IANA |
| 16 | application/cose; cose-type="cose-encrypt0" | none | assigned | RFC 9052 |
| 17 | application/cose; cose-type="cose-mac0" | none | assigned | RFC 9052 |
| 18 | application/cose; cose-type="cose-sign1" | none | assigned | RFC 9052 |
| 19 | application/ace+cbor | none | assigned | RFC 9200 |
| 20 | Unassigned | none | unassigned | IANA |
| 21 | image/gif | none | assigned | W3C GIF89a |
| 22 | image/jpeg | none | assigned | ISO/IEC 10918-5 |
| 23 | image/png | none | assigned | W3C PNG |
| 24-39 | Unassigned | none | unassigned | IANA |
| 40 | application/link-format | none | assigned | RFC 6690 |
| 41 | application/xml | none | assigned | RFC 3023 |
| 42 | application/octet-stream | none | assigned | RFC 2045; RFC 2046 |
| 43-46 | Unassigned | none | unassigned | IANA |
| 47 | application/exi | none | assigned | W3C EXI 1.0 Second Edition |
| 48-49 | Unassigned | none | unassigned | IANA |
| 50 | application/json | none | assigned | RFC 8259 |
| 51 | application/json-patch+json | none | assigned | RFC 6902 |
| 52 | application/merge-patch+json | none | assigned | RFC 7396 |
| 53-59 | Unassigned | none | unassigned | IANA |
| 60 | application/cbor | none | assigned | RFC 8949 |
| 61 | application/cwt | none | assigned | RFC 8392 |
| 62 | application/multipart-core | none | assigned | RFC 8710 |
| 63 | application/cbor-seq | none | assigned | RFC 8742 |
| 64 | application/edhoc+cbor-seq | none | assigned | RFC 9528 |
| 65 | application/cid-edhoc+cbor-seq | none | assigned | RFC 9528 |
| 66-95 | Unassigned | none | unassigned | IANA |
| 96 | application/cose; cose-type="cose-encrypt" | none | assigned | RFC 9052 |
| 97 | application/cose; cose-type="cose-mac" | none | assigned | RFC 9052 |
| 98 | application/cose; cose-type="cose-sign" | none | assigned | RFC 9052 |
| 99-100 | Unassigned | none | unassigned | IANA |
| 101 | application/cose-key | none | assigned | RFC 9052 |
| 102 | application/cose-key-set | none | assigned | RFC 9052 |
| 103-109 | Unassigned | none | unassigned | IANA |
| 110 | application/senml+json | none | assigned | RFC 8428 |
| 111 | application/sensml+json | none | assigned | RFC 8428 |
| 112 | application/senml+cbor | none | assigned | RFC 8428 |
| 113 | application/sensml+cbor | none | assigned | RFC 8428 |
| 114 | application/senml-exi | none | assigned | RFC 8428 |
| 115 | application/sensml-exi | none | assigned | RFC 8428 |
| 116-139 | Unassigned | none | unassigned | IANA |
| 140 | application/yang-data+cbor; id=sid | none | assigned | RFC 9254 |
| 141-255 | Unassigned | none | unassigned | IANA |
| 256 | application/coap-group+json | none | assigned | RFC 7390 |
| 257 | application/concise-problem-details+cbor | none | assigned | RFC 9290 |
| 258 | application/swid+cbor | none | assigned | RFC 9393 |
| 259 | application/pkixcmp | none | assigned | RFC 9482; RFC 9811 |
| 260 | application/yang-sid+json | none | assigned | RFC 9595 |
| 261 | application/ace-groupcomm+cbor | none | assigned | RFC 9594 |
| 262 | application/ace-trl+cbor | none | assigned | RFC 9770 |
| 263 | application/eat+cwt | none | assigned | RFC 9782 |
| 264 | application/eat+jwt | none | assigned | RFC 9782 |
| 265 | application/eat-bun+cbor | none | assigned | RFC 9782 |
| 266 | application/eat-bun+json | none | assigned | RFC 9782 |
| 267 | application/eat-ucs+cbor | none | assigned | RFC 9782 |
| 268 | application/eat-ucs+json | none | assigned | RFC 9782 |
| 269 | application/coap-eap | none | assigned | RFC 9820 |
| 270 | application/suit-report+cose | none | draft-backed | RFC-ietf-suit-report-19 |
| 271 | application/dots+cbor | none | assigned | RFC 9132 |
| 272 | application/missing-blocks+cbor-seq | none | assigned | RFC 9177 |
| 273 | application/cmw+cbor | none | draft-backed | RFC-ietf-rats-msg-wrap-22 Sections 3.1-3.3 |
| 274 | application/cmw+json | none | draft-backed | RFC-ietf-rats-msg-wrap-22 Sections 3.1 and 3.3 |
| 275 | application/cmw+cose | none | draft-backed | RFC-ietf-rats-msg-wrap-22 Section 4.1 |
| 276 | application/cmw+jws | none | draft-backed | RFC-ietf-rats-msg-wrap-22 Section 4.2 |
| 277 | application/scitt-statement+cose | none | assigned | RFC 9943 |
| 278 | application/scitt-receipt+cose | none | assigned | RFC 9943 |
| 279 | application/statuslist+cwt | none | draft-backed | RFC-ietf-oauth-status-list-21 |
| 280 | application/pkcs7-mime; smime-type=server-generated-key | none | assigned | RFC 7030; RFC 8551; RFC 9148 |
| 281 | application/pkcs7-mime; smime-type=certs-only | none | assigned | RFC 8551; RFC 9148 |
| 282-283 | Unassigned | none | unassigned | IANA |
| 284 | application/pkcs8 | none | assigned | RFC 5958; RFC 8551; RFC 9148 |
| 285 | application/csrattrs | none | assigned | RFC 7030; RFC 9148 |
| 286 | application/pkcs10 | none | assigned | RFC 5967; RFC 8551; RFC 9148 |
| 287 | application/pkix-cert | none | assigned | RFC 2585; RFC 9148 |
| 288-289 | Unassigned | none | unassigned | IANA |
| 290 | application/aif+cbor | none | assigned | RFC 9237 |
| 291 | application/aif+json | none | assigned | RFC 9237 |
| 292 | application/aif+cbor; toid=CRI-local-part | none | draft-backed | RFC-ietf-core-href-29 |
| 293 | application/sd-cwt | none | temporary; expires 2026-12-08 | draft-ietf-spice-sd-cwt-06 Section 5 |
| 294 | application/kb+cwt | none | temporary; expires 2026-12-08 | draft-ietf-spice-sd-cwt-06 Section 8.1 |
| 295 | application/measured-component+cbor | none | draft-backed | RFC-ietf-rats-eat-measured-component-12 |
| 296 | application/measured-component+json | none | draft-backed | RFC-ietf-rats-eat-measured-component-12 |
| 297 | application/aif+cbor; toid=oscore-gname; tperm=oscore-gperm | none | draft-backed | RFC-ietf-ace-key-groupcomm-oscore-21 |
| 298 | application/aif+json; toid=oscore-gname; tperm=oscore-gperm | none | draft-backed | RFC-ietf-ace-key-groupcomm-oscore-21 |
| 299-309 | Unassigned | none | unassigned | IANA |
| 310 | application/senml+xml | none | assigned | RFC 8428 |
| 311 | application/sensml+xml | none | assigned | RFC 8428 |
| 312-319 | Unassigned | none | unassigned | IANA |
| 320 | application/senml-etch+json | none | assigned | RFC 8790 |
| 321 | Unassigned | none | unassigned | IANA |
| 322 | application/senml-etch+cbor | none | assigned | RFC 8790 |
| 323-339 | Unassigned | none | unassigned | IANA |
| 340 | application/yang-data+cbor | none | assigned | RFC 9254 |
| 341 | application/yang-data+cbor; id=name | none | assigned | RFC 9254 |
| 342-431 | Unassigned | none | unassigned | IANA |
| 432 | application/td+json | none | assigned | W3C Web of Things Thing Description 1.1 |
| 433 | application/tm+json | none | assigned | W3C Web of Things Thing Description 1.1 |
| 434 | application/sdf+json | none | assigned | RFC 9880 |
| 435-552 | Unassigned | none | unassigned | IANA |
| 553 | application/dns-message | none | assigned | RFC 8484; RFC 9953 Section 4.1 |
| 554-600 | Unassigned | none | unassigned | IANA |
| 601 | application/uccs+cbor | none | assigned | RFC 9781 Section 6.4 |
| 602-835 | Unassigned | none | unassigned | IANA |
| 836 | application/voucher+cose | none | temporary; expires 2027-04-12 | draft-ietf-anima-constrained-voucher-23 |
| 837-1541 | Unassigned | none | unassigned | IANA |
| 1542-1543 | Reserved, do not use | none | reserved | OMA LightweightM2M 1.0 |
| 1544-9999 | Unassigned | none | unassigned | IANA |
| 10000 | application/vnd.ocf+cbor | none | assigned, external | Michael Koster registration |
| 10001 | application/oscore | none | assigned | RFC 8613 |
| 10002 | application/javascript | none | assigned | RFC 4329 |
| 10003 | application/eat+cwt; eat_profile="tag:psacertified.org,2023:psa#tfm" | none | assigned | RFC 9783 |
| 10004 | application/eat+cwt; eat_profile="tag:psacertified.org,2019:psa#legacy" | none | assigned | RFC 9783 |
| 10005 | application/eat+cwt; eat_profile=2.16.840.1.113741.1.16.1 | none | assigned, mixed reference | RFC 9782; draft-cds-rats-intel-corim-profile-05 |
| 10006 | application/vnd.oms.cellular-cose-content+cbor | none | assigned, external | OMS Group |
| 10007 | application/syslog-msg | none | assigned | IANA Media Types registration |
| 10008-10569 | Unassigned | none | unassigned | IANA |
| 10570 | application/toc+cbor | none | assigned, external | TCG CE-Binding Section 6.3.1 |
| 10571 | application/ce+cbor | none | assigned, external | TCG CE-Binding Section 6.3.2 |
| 10572 | application/toc+cbor; profile=2.16.840.1.113741.1.16.1 | none | assigned, mixed reference | TCG DICE Concise Evidence Binding for SPDM; draft-cds-rats-intel-corim-profile-05 |
| 10573 | application/ce+cbor; profile=2.16.840.1.113741.1.16.1 | none | assigned, mixed reference | TCG DICE Concise Evidence Binding for SPDM; draft-cds-rats-intel-corim-profile-05 |
| 10574-11049 | Unassigned | none | unassigned | IANA |
| 11050 | application/json | deflate | assigned | RFC 8259; RFC 9110 Section 8.4.1.2 |
| 11051-11059 | Unassigned | none | unassigned | IANA |
| 11060 | application/cbor | deflate | assigned | RFC 8949; RFC 9110 Section 8.4.1.2 |
| 11061-11541 | Unassigned | none | unassigned | IANA |
| 11542 | application/vnd.oma.lwm2m+tlv | none | assigned, external | OMA LightweightM2M 1.0 |
| 11543 | application/vnd.oma.lwm2m+json | none | assigned, external | OMA LightweightM2M 1.0 |
| 11544 | application/vnd.oma.lwm2m+cbor | none | assigned, external | OMA LightweightM2M 1.2 |
| 11545-11999 | Unassigned | none | unassigned | IANA |
| 12000 | text/plain;charset=utf-8 | zstd | assigned, external | Benjamin Valentin registration |
| 12001-12040 | Unassigned | none | unassigned | IANA |
| 12041 | application/xml | zstd | assigned, external | Benjamin Valentin registration |
| 12042-12049 | Unassigned | none | unassigned | IANA |
| 12050 | application/json | zstd | assigned, external | Benjamin Valentin registration |
| 12051-19999 | Unassigned | none | unassigned | IANA |
| 20000 | text/css | none | assigned | RFC 2318 |
| 20001 | application/vnd.as207960.vas.config+jer | none | assigned, external | AS207960 Cyfyngedig |
| 20002 | application/vnd.as207960.vas.config+uper | none | assigned, external | AS207960 Cyfyngedig |
| 20003 | application/vnd.as207960.vas.tap+jer | none | assigned, external | AS207960 Cyfyngedig |
| 20004 | application/vnd.as207960.vas.tap+uper | none | assigned, external | AS207960 Cyfyngedig |
| 20005-29999 | Unassigned | none | unassigned | IANA |
| 30000 | image/svg+xml | none | assigned | W3C SVG media-type registration |
| 30001-64997 | Unassigned | none | unassigned | IANA |
| 64998-64999 | Reserved for Documentation | none | documentation | RFC 9876 |
| 65000-65535 | Reserved for Experimental Use | none | experimental | RFC 7252 |

An unknown ID in the registry domain remains a typed numeric Content-Format.
An explicit integer outside that semantic domain remains available through the
opaque option model and is reported by opt-in validation rather than rewritten.
Temporary and draft-backed labels must not be promoted to stable semantics
without a new IANA and source-manifest review.

## CoAP Signaling Codes

This class-7 sub-registry applies only to reliable CoAP messages. It does not
change the RFC 7252 reservation of class 7 for base datagram messages.
Allocation policy: IETF Review or IESG Approval.

| Code | Wire | Label | Status | Reference |
| --- | ---: | --- | --- | --- |
| 7.00 | 0xe0 | Unassigned | unassigned | IANA |
| 7.01 | 0xe1 | CSM | assigned | RFC 8323 |
| 7.02 | 0xe2 | Ping | assigned | RFC 8323 |
| 7.03 | 0xe3 | Pong | assigned | RFC 8323 |
| 7.04 | 0xe4 | Release | assigned | RFC 8323 |
| 7.05 | 0xe5 | Abort | assigned | RFC 8323 |
| 7.06-7.31 | 0xe6-0xff | Unassigned | unassigned | IANA |

Unknown signaling details remain a lossless class/detail value when the
reliable frame is structurally valid.

## CoAP Signaling Option Numbers

Signaling options use their own contextual number space. The key is the pair
(signaling code, option number); ordinary datagram option labels must never be
substituted.

| Number range | Status | Registration procedure | Reference |
| ---: | --- | --- | --- |
| 0-255 | registry range | IETF Review or IESG Approval | RFC 8323 |
| 256-2047 | registry range | Specification Required | IANA |
| 2048-64999 | registry range | Expert Review | IANA |
| 65000-65535 | experimental | Experimental use; no operational use | IANA |

| Applies to | Number | Label | Status | Reference |
| --- | ---: | --- | --- | --- |
| 7.01 CSM | 2 | Max-Message-Size | assigned | RFC 8323 |
| 7.01 CSM | 4 | Block-Wise-Transfer | assigned | RFC 8323 |
| 7.01 CSM | 6 | Extended-Token-Length | assigned | RFC 8974 |
| 7.02 Ping, 7.03 Pong | 2 | Custody | assigned | RFC 8323 |
| 7.04 Release | 2 | Alternative-Address | assigned | RFC 8323 |
| 7.04 Release | 4 | Hold-Off | assigned | RFC 8323 |
| 7.05 Abort | 2 | Bad-CSM-Option | assigned | RFC 8323 |
| 7.xx all signaling codes | 9 | OSCORE | assigned | RFC 8613 |
| any other code/number pair | any registry-domain number | Unknown | unassigned unless later registered | IANA |

Unknown signaling options preserve the signaling code, number, occurrence
order, and opaque bytes. A number known in one signaling context remains
Unknown in another context unless IANA assigns that pair.

## OSCORE-related CoRE parameters

The CoRE registry exposes OSCORE in several independent spaces:

| Space | Value | Label | Status | Reference |
| --- | ---: | --- | --- | --- |
| Datagram option | 9 | OSCORE | assigned | RFC 8613 |
| Signaling option | 9 | OSCORE for 7.xx | assigned | RFC 8613 |
| Content-Format | 10001 | application/oscore | assigned | RFC 8613 |

COSE algorithms and header parameters live in separate IANA COSE registries.
They are not silently frozen by this CoRE snapshot. An OSCORE implementation
step must review those registries and its admitted algorithm profile before
exporting algorithm constants.

### OSCORE Flag Bits

Allocation policy: Expert Review. The status distinguishes published RFC 8613
base fields from draft-backed extension assignments.

| Bit position | Label | Meaning | Status | Reference |
| ---: | --- | --- | --- | --- |
| 0 | Reserved | no base meaning | reserved | RFC 8613 |
| 1 | Reserved | no base meaning | reserved | RFC 8613 |
| 2 | Group Flag | group-mode protection | draft-backed | RFC-ietf-core-oscore-groupcomm-28 |
| 3 | Kid Context Flag | kid context is present | assigned | RFC 8613 |
| 4 | Kid Flag | kid is present | assigned | RFC 8613 |
| 5-7 | Partial IV Length | three-bit field encoding lengths 0 through 5 | assigned | RFC 8613 |
| 8 | Extension-2 Flag | introduces a third option byte | draft-backed | draft-ietf-core-oscore-key-update-03 |
| 9-14 | Unassigned | no registered meaning | unassigned | IANA |
| 15 | Nonce Flag | nonce is present | draft-backed | draft-ietf-core-oscore-key-update-03 |
| 16 | Extension-3 Flag | introduces a fourth option byte | draft-backed | draft-ietf-core-oscore-key-update-03 |
| 17-23 | Unassigned | no registered meaning | unassigned | IANA |
| 24 | Extension-4 Flag | introduces a fifth option byte | draft-backed | draft-ietf-core-oscore-key-update-03 |
| 25-31 | Unassigned | no registered meaning | unassigned | IANA |
| 32 | Extension-5 Flag | introduces a sixth option byte | draft-backed | draft-ietf-core-oscore-key-update-03 |
| 33-39 | Unassigned | no registered meaning | unassigned | IANA |
| 40 | Extension-6 Flag | introduces a seventh option byte | draft-backed | draft-ietf-core-oscore-key-update-03 |
| 41-47 | Unassigned | no registered meaning | unassigned | IANA |
| 48 | Extension-7 Flag | introduces an eighth option byte | draft-backed | draft-ietf-core-oscore-key-update-03 |
| 49-63 | Unassigned | no registered meaning | unassigned | IANA |

The Group Flag and key-update extension rows are prepareal metadata under
the source-manifest boundary. They are not stable serializer authority.
Unknown, unassigned, reserved, or unsupported flag material remains lossless
and inspectable; a protection transform may return an explicit unsupported
algorithm or unsupported extension error rather than guessing semantics.

## Service names and transport ports

These are IANA service rows, not live-send permission and not sufficient
evidence for application dispatch by themselves.

| Service | Port | Transport | Label | Status | Reference |
| --- | ---: | --- | --- | --- | --- |
| coap | 5683 | UDP | Constrained Application Protocol | assigned | RFC 7252 |
| coap | 5683 | TCP | Constrained Application Protocol (CoAP) | assigned | RFC 8323 |
| coaps | 5684 | UDP | DTLS-secured CoAP | assigned | RFC 7252 |
| coaps | 5684 | TCP | Constrained Application Protocol (CoAP) | assigned | RFC 7301; RFC 8323 |

The cleartext UDP and TCP rows may be used only as conservative registry
dispatch hints after the respective complete-message shape checks pass.
UDP/5684 and TCP/5684 carry protected traffic and remain Raw without an
explicit security context and explicit decode or transform. Unknown ports
remain ordinary transport values; direct CoAP decode remains available to a
caller that already knows the payload type.

Port assignments do not authorize traffic. Offline and dry-run behavior stays
the default, and any live CoAP validation remains externally executed and
explicitly confirmed under the repository safety policy.
