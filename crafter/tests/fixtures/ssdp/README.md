# SSDP fixture catalog

This directory is reserved for deterministic SSDP fixtures. The planned cases
below are fixture intent, not generated packet data. All future bytes and pcaps
must use documentation-safe addresses, synthetic UUIDs, synthetic header
values, and source-backed expectations.

Source evidence for this catalog comes from public UPnP Device Architecture
discovery text, UPnP Annex A IPv6 mapping, RFC 9110 and RFC 9112 HTTP syntax,
RFC 768 UDP datagram behavior, RFC 3986 and RFC 8141 URI or URN syntax where a
typed helper needs it, RFC 5737 and RFC 3849 documentation address space, IANA
service and multicast registries, IANA HTTP registries, IETF Datatracker
metadata, and RFC Editor errata as classified in the SSDP source notes.

## Planned cases

| Case | Planned fixture role | Source evidence notes |
| --- | --- | --- |
| request | `bytes/ssdp-m-search-basic.hex` for a minimal `M-SEARCH * HTTP/1.1` datagram with `HOST`, `MAN`, `MX`, and `ST` headers. | UPnP Device Architecture discovery defines `M-SEARCH`, the `*` request target, `HTTP/1.1`, and search headers; RFC 9112 supplies request-line and CRLF message framing; RFC 9110 supplies token and field syntax. |
| notification | `bytes/ssdp-notify-alive-basic.hex` for a minimal `NOTIFY * HTTP/1.1` availability advertisement with `HOST`, `CACHE-CONTROL`, `LOCATION`, `NT`, `NTS`, `SERVER`, and `USN`. | UPnP Device Architecture discovery defines `NOTIFY`, `ssdp:alive`, advertisement headers, and target/USN forms; RFC 3986 and RFC 8141 support URI and URN syntax only for source-backed helper checks. |
| response | `bytes/ssdp-response-ok-basic.hex` for `HTTP/1.1 200 OK` with response headers including empty `EXT`. | UPnP Device Architecture discovery defines search responses and empty `EXT`; RFC 9112 supplies status-line framing; RFC 9110 and the IANA HTTP Status Code Registry support the generic `200` status shape. |
| extension-header | `bytes/ssdp-extension-man-ext.hex` and an IPv6 namespace example for `OPT` plus namespace-prefixed `NLS`. | UPnP discovery text backs `MAN` and `EXT`; UPnP Annex A backs IPv6 extension header forms. RFC 2774 is historical context only and must not authorize generic extension processing. |
| unknown-header | `bytes/ssdp-unknown-header-preserved.hex` with a vendor-style or otherwise unknown token field name. | RFC 9110 field-name syntax and UPnP vendor or working-committee header guidance require preserving unknown structurally valid fields; IANA HTTP field registry absence is not a rejection rule. |
| duplicate-header | `bytes/ssdp-duplicate-headers-preserved.hex` with repeated field names in a meaningful order. | RFC 9110 field ordering rules require ordered preservation; SSDP grammar policy forbids deduplicating, sorting, merging, or rejecting duplicate headers at the packet layer. |
| body | `bytes/ssdp-valid-with-body.hex` with a valid start line, complete header section, and opaque bytes after the empty line. | RFC 9112 message-body grammar permits bytes after the header delimiter, while UPnP examples are header-only. Builders should not generate bodies by default, but parsing must preserve body bytes in structurally valid messages. |
| malformed | `malformed/ssdp-decode-corpus.hex` for empty payloads, bad start lines, invalid tokens, missing CRLF CRLF, bad header colons, obsolete folded lines, non-three-digit status codes, and truncation. | RFC 9112 and RFC 9110 define the line, token, status-code, and field syntax; crate policy requires structured errors rather than panics or silent truncation for malformed SSDP inputs. |
| unrelated UDP | `bytes/udp-1900-unrelated-raw.hex` for text and binary UDP payloads on the SSDP service port that fail the conservative SSDP shape gate. | RFC 768 provides the UDP payload boundary; IANA registers `ssdp/udp` port 1900, but the SSDP grammar requires a complete HTTP-like envelope before application decode accepts the payload as SSDP. |
| IPv4 stack | `bytes/ipv4-udp-ssdp-m-search.hex` for a documentation-address IPv4/UDP stack carrying the request payload. | RFC 791 and RFC 5737 provide safe IPv4 packet/address context; RFC 768 provides UDP; UPnP discovery plus IANA service and IPv4 multicast registries back the default SSDP port and IPv4 multicast destination. |
| IPv6 stack | `bytes/ipv6-udp-ssdp-m-search.hex` for a documentation-address IPv6/UDP stack carrying an SSDP request or notification. | RFC 8200 and RFC 3849 provide safe IPv6 packet/address context; UPnP Annex A plus IANA IPv6 multicast assignments back `ff02::c` and `ff05::c` fixture variants. |
| raw pcap | `pcaps/raw-ipv4-udp-ssdp-m-search.pcap` and `pcaps/raw-ipv6-udp-ssdp-m-search.pcap` for classic pcap records with RawIp link type and deterministic timestamps. | Classic pcap tests exercise offline persistence; source evidence comes from the same IPv4, IPv6, UDP, UPnP, and IANA sources as the byte fixtures. No live captures are fixture sources. |
| link pcap | `pcaps/ethernet-ipv4-udp-ssdp-notify.pcap` for a classic Ethernet-link pcap with documentation MACs and documentation IPv4 addresses. | Link pcap coverage validates link-type decoding around the same source-backed SSDP payload; packet data must be synthetic and deterministic, not captured from a live network. |

## Promotion rules

- Add fixture bytes only after the SSDP parser, serializer, registry binding,
  and pcap support steps can consume the case through public crate entrypoints.
- Keep case names lowercase and dash-separated, and record every committed byte
  or pcap fixture in the matching Rust fixture catalog.
- Preserve unknown methods, statuses, headers, duplicates, extension fields,
  and body bytes whenever the enclosing message is structurally valid.
- Keep malformed cases minimal enough to make the failing field obvious, and
  assert structured error categories rather than display strings.
- Do not promote provider-backed artifacts, live captures, credentials, public
  endpoint addresses, host identifiers, or local paths into this fixture tree.

## Committed advanced fixtures

- `advanced_extension_headers.hex`: request payload with IPv6 HOST, `OPT`, and
  namespace-prefixed `01-NLS` headers.
- `advanced_duplicate_headers.hex`: request payload preserving duplicate `ST`
  and unknown `X-DUP` header order.
- `advanced_body_bytes.hex`: response payload preserving opaque body bytes after
  the CRLF header delimiter.
- `advanced_multicast_ipv6.hex`: request payload with the source-backed
  site-local IPv6 SSDP HOST literal.
- `advanced_unknown_preservation.hex`: structurally valid unknown request
  method, target, version, and vendor-style header preservation.
