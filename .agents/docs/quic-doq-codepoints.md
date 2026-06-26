# DNS-over-QUIC Codepoint Notes

This note records DNS-over-QUIC error-code evidence for QUIC-adjacent generated
tools. It is source-backed by `E-RFC-9250` in
`.agents/docs/quic-manifest.md` and the IANA Domain Name System (DNS)
Parameters registry, refreshed from the live IANA page on 2026-06-26.

This file does not authorize a DNS-over-QUIC client, server, stream engine,
resolver, scanner, or endpoint workflow in `crafter`. DoQ payloads remain
application data carried over QUIC streams; the packet primitive only records
codepoint facts.

## Sources

| Evidence | Use |
| --- | --- |
| RFC 9250, especially Sections 4.3 and 8.4 | Defines DNS-over-QUIC error code names, meanings, and registry creation. |
| IANA Domain Name System (DNS) Parameters, `DNS-over-QUIC Error Codes` registry | Current registry rows, status, registration policy, and references. |
| `.agents/docs/quic-version-extension-matrix.md` DoQ row | Scope boundary: record error-code numbers only; do not implement endpoint behavior. |

## Registry Policy

The IANA DNS-over-QUIC Error Codes registry is a 62-bit space. The live IANA
registry records these registration ranges:

| Range | Procedure |
| --- | --- |
| provisional, greater than `0x3f` | Expert Review |
| provisional registration Date field update | First Come First Served |
| permanent, `0x00..0x3f` | Standards Action or IESG Approval |
| permanent, greater than `0x3f` | Specification Required |

## Registered Error Codes

| Value | Mnemonic | Description | Status | Reference |
| --- | --- | --- | --- | --- |
| `0x0` | `DOQ_NO_ERROR` | No error | permanent | RFC 9250 Section 4.3 |
| `0x1` | `DOQ_INTERNAL_ERROR` | Implementation error | permanent | RFC 9250 Section 4.3 |
| `0x2` | `DOQ_PROTOCOL_ERROR` | Generic protocol violation | permanent | RFC 9250 Section 4.3 |
| `0x3` | `DOQ_REQUEST_CANCELLED` | Request cancelled by client | permanent | RFC 9250 Section 4.3 |
| `0x4` | `DOQ_EXCESSIVE_LOAD` | Closing a connection for excessive load | permanent | RFC 9250 Section 4.3 |
| `0x5` | `DOQ_UNSPECIFIED_ERROR` | No error reason specified | permanent | RFC 9250 Section 4.3 |
| `0xd098ea5e` | `DOQ_ERROR_RESERVED` | Alternative error code used for tests | permanent | RFC 9250 Section 4.3 |

## Crate Boundary

- Do not add a DoQ endpoint, DNS resolver, stream scheduler, or QUIC connection
  state machine to `crafter`.
- Do not make UDP or QUIC packet dispatch select DNS-over-QUIC by port or ALPN.
- If generated tools need DoQ names, they should consume this note or define
  tool-local constants from the table above.
- If crate constants are added in a future step, keep them as codepoint labels
  only and avoid parser behavior that interprets QUIC stream bytes as DNS.

## Validation

The Clew step validates this note offline with:

```sh
test -f .agents/docs/quic-doq-codepoints.md
rg -n "DNS-over-QUIC|DOQ_NO_ERROR|RFC 9250" .agents/docs/quic-doq-codepoints.md
```
