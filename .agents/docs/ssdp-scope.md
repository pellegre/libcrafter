# SSDP implementation scope

This note splits the SSDP work into the smallest packet-layer surface that must
land first and the advanced wire-level features that can build on it later. It
is derived from `.agents/docs/ssdp-source-manifest.md`,
`.agents/docs/ssdp-wire-grammar.md`, and `.agents/docs/ssdp-codepoints.md`.
Those documents remain the source-evidence gate for methods, headers, service
ports, multicast groups, HTTP-like grammar, URI values, and validation rules.

Public source authority for this scope is limited to the OCF / UPnP Device
Architecture 2.0 discovery text, UPnP Device Architecture 1.1 compatibility
text, UPnP Device Architecture 1.1 Annex A for IPv6 mapping, current RFC
9110/9112 HTTP syntax support, RFC 768 UDP support, RFC 3986/RFC 8141 URI and
URN support where helpers need it, multicast RFCs, IANA service and multicast
registries, IANA HTTP registries, IETF Datatracker update metadata, and RFC
Editor errata as classified by the SSDP source manifest.

`crafter` remains a packet primitive. SSDP support must compose with the
existing `Packet` abstraction and `ProtocolRegistry` UDP application path; it
must not create a discovery workflow, scanner, cache, daemon, control point, or
HTTP stack.

## Minimal packet support

Minimal support is the first shippable SSDP packet layer. It is complete only
when these pieces work together and preserve explicit caller overrides:

| Area | Scope |
| --- | --- |
| Parse | Decode one UDP payload as a conservative SSDP candidate using the source-backed HTTP-like start-line, ordered header, CRLF delimiter, and opaque body grammar. Structurally valid unknown methods, status codes, reason phrases, headers, extension fields, and body bytes are preserved. Malformed explicit parses return structured errors. |
| Serialize | Emit the stored start line, ordered headers, delimiter, and body without lossy normalization. Defaults may be filled only by builders when the caller left a field unset. |
| Builders | Provide source-backed request, notification, and response builders for the admitted UPnP discovery forms while retaining escape hatches for explicit malformed or unknown values. |
| Decode | Register SSDP as a UDP application decode target only behind the conservative shape gate, so unrelated text or binary UDP payloads on SSDP-related ports remain `Raw`. |
| Summary | Add concise `summary()` output that identifies SSDP request and response families without hiding unknown preserved values. |
| Show | Add detailed `show()` output for start line, ordered headers, duplicate fields, extension fields, and body length or bytes according to existing inspection conventions. |
| UDP registration | Bind the default UDP SSDP service only to source-backed IANA and UPnP values recorded in `.agents/docs/ssdp-codepoints.md`; custom bindings and application-decoding toggles must continue to take precedence. |
| Fixtures | Add deterministic valid, boundary, malformed, summary, and pcap fixtures using documentation-safe addresses and synthetic packet data. |
| Offline validation | Cover parser, serializer, builders, round trips, raw fallback, structured errors, pcap persistence, and reference agreement without sending live traffic. |

The minimal layer may name core constants such as the UDP service port, SSDP
methods, `HTTP/1.1`, `200 OK`, and UPnP discovery header names only when the
code cites the source-backed codepoint table. It must not reject structurally
valid unknown values merely because they are absent from an IANA HTTP registry.

## Advanced wire-level support

Advanced support is still packet and validation work, not a discovery product.
It can be implemented after the minimal layer is stable:

| Area | Scope |
| --- | --- |
| Typed headers | Add source-backed helpers for target identifiers, `LOCATION`, `CACHE-CONTROL`, `MAN`, `EXT`, `MX`, `SERVER`, UPnP extension fields, IPv6 extension fields, and vendor or working-committee header forms. Helpers expose structured access but preserve original spelling, order, duplicates, and unknown values. |
| Multicast helpers | Add IPv4 and IPv6 SSDP multicast constants and packet helpers backed by UPnP, IANA, and multicast RFC evidence. Helpers may assemble documentation-safe packet stacks, but they must not manage multicast membership, routing policy, retries, or live sends. |
| Oracle | Add SSDP layer and feature specs, generator support, backend normalization, malformed cases, pcap cases, and offline/persisted validation records. Reference-backend gaps are recorded explicitly instead of being hidden. |
| Probe | Add controlled SSDP behavior probes as dry-run-first generated-tool validation. Probe code may plan discovery-like exchanges but must keep target roles, capability assumptions, and artifacts outside the crate API. |
| Lab dry-runs | Add provider-backed lab, oracle, and probe dry-run plans for disposable endpoint roles. Any real packet exchange remains a protected manual workflow with explicit confirmation, artifact collection, and teardown. |
| Examples | Add packet construction, decode, and dry-run send-plan examples that use `crafter::prelude::*`, documentation address space, and no live defaults. |
| Docs | Add user-facing SSDP packet guide material under `docs/` and generated-tool operating guidance under `.agents/docs/`, keeping source authority and implementation status traceable. |

Advanced helpers must not widen the minimal parser's acceptance rules unless a
public source document and the SSDP source manifest authorize the new behavior.

## Non-goals

- No SSDP scanner, UPnP control point, device daemon, service cache, retry
  scheduler, advertisement lifetime manager, or discovery workflow in the
  `crafter` crate.
- No generic HTTP client, HTTP server, proxy, cache, TCP HTTP surface, Upgrade,
  CONNECT, transfer-coding, or generic HTTP extension framework.
- No UPnP eventing implementation, Device Protection implementation, device or
  service catalog, XML description parser, SOAP control layer, or full UPnP
  stack.
- No multicast membership management, interface selection policy, route
  management, TTL or hop-limit policy engine, or live transmission default.
- No automatic live traffic from examples, tests, oracle, probe, or lab steps;
  live validation requires explicit protected confirmation and disposable
  provider-backed endpoints.
- No rejection of unknown but structurally valid SSDP methods, status lines,
  headers, extension values, URI-like values, duplicate fields, or body bytes
  solely because no typed helper knows them.
- No tracked credentials, public provider addresses, live host identifiers,
  sensitive packet captures, local absolute paths, or private helper names in
  SSDP source, docs, fixtures, or validation records.
- No implementation of ambiguous draft-only behavior, obsolete global-scope
  multicast helpers, TCP SSDP service behavior, or vendor extensions until a
  later source-backed scope decision admits them explicitly.
