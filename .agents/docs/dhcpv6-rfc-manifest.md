# DHCPv6 RFC Manifest

This manifest records the public source evidence for DHCPv6 packet-layer work
in `crafter`. It is a wire manifest, not a DHCP product plan: `crafter` may
build, compile, decode, summarize, show, and validate DHCPv6 packets, but it
does not implement a DHCP client, server, relay daemon, lease database, policy
engine, scanner, or failover service.

Only facts backed by the RFC and IANA sources below may be used downstream in
code, tests, fixtures, examples, docs, oracle specs, or probe expectations.
Unknown but well-formed DHCPv6 message types, option codes, status codes, DUID
types, and nested option payloads remain packet data and must be preserved.
Malformed buffers must produce structured errors, not panics.

Date checked: 2026-06-26.

## Public Source Checks

- RFC Editor RFC 9915 page: <https://www.rfc-editor.org/info/rfc9915/>
- RFC 9915 text: <https://www.rfc-editor.org/rfc/rfc9915.txt>
- IANA Dynamic Host Configuration Protocol for IPv6 (DHCPv6) registry:
  <https://www.iana.org/assignments/dhcpv6-parameters/>

Official source snapshot:

- **RFC 9915**, "Dynamic Host Configuration Protocol for IPv6 (DHCPv6)", is
  the current core DHCPv6 specification. RFC Editor lists it as STD 102 /
  Internet Standard, published in January 2026, and as obsoleting RFC 8415.
- **IANA Dynamic Host Configuration Protocol for IPv6 (DHCPv6)** was last
  updated on 2026-03-10. Its registries are the current authority for DHCPv6
  message types, option codes, status codes, DUID types, relay option
  permissions, supported transport bits, RADIUS attributes permitted in the
  DHCPv6 RADIUS option, and DHCPv6 options permitted in the RADIUS
  DHCPv6-Options attribute.

## Classification Terms

- **Core wire behavior**: defines packet bytes that `crafter` should construct,
  auto-fill, decode, preserve, summarize, or validate.
- **Registry authority**: IANA is authoritative for numeric assignments,
  labels, status, singleton metadata, and placement metadata.
- **Packet-data extension**: source-backed bytes and codepoints that should be
  constructible, decoded where practical, and byte-preserved, without adding a
  client/server/relay workflow or state machine.
- **Controlled behavior validation**: later oracle or probe work may exercise a
  behavior through offline, dry-run, or provider-backed lab paths. That does not
  make the behavior a crate runtime service.
- **Obsolete or historical**: retained only for lineage or explicit obsolete
  codepoint preservation.

## Core Wire Sources

### RFC 9915 - DHCPv6 core

Classification: core wire behavior.
Source: <https://www.rfc-editor.org/rfc/rfc9915.html>

Downstream use:

- Section 7.2 defines the UDP port model: clients listen on 546; servers and
  relay agents listen on 547; clients send to destination port 547; servers and
  relay agents use destination 546 for client messages and destination 547 for
  relay messages. `Udp::dhcpv6_client()` and `Udp::dhcpv6_server()` helpers
  should reflect these defaults while preserving explicit caller overrides.
- Section 7.3 defines the core client/server and relay message type names and
  points to the IANA registry for current and future assignments.
- Sections 8 and 9 define the two DHCPv6 header shapes:
  client/server messages are `msg-type` plus a 24-bit transaction ID plus
  serial options; Relay-forward and Relay-reply are `msg-type`, `hop-count`,
  16-octet `link-address`, 16-octet `peer-address`, and serial options.
- Section 11 defines DUIDs as a 2-octet type followed by variable identifier
  bytes, with DUID-LLT, DUID-EN, DUID-LL, and DUID-UUID source-backed types.
  Decoders must treat DUIDs as opaque identifiers for equality and must not
  reject unknown DUID types.
- Section 21.1 defines the generic DHCPv6 option TLV envelope as a 16-bit
  option code, a 16-bit option length, and option data.
- Sections 21.2 through 21.13 define the initial typed options needed for the
  first DHCPv6 packet surface: Client ID, Server ID, IA_NA, IA_TA obsolete
  preservation, IA Address, ORO, Preference, Elapsed Time, Relay Message,
  Authentication, Status Code, and related fields.
- Sections 21.14 through 21.25 define Rapid Commit, User Class, Vendor Class,
  Vendor Options, Interface ID, Reconfigure Message, Reconfigure Accept,
  Information Refresh Time, SOL_MAX_RT, and INF_MAX_RT packet fields.
- Appendices B and C give option appearance tables for top-level messages and
  nested option containers. They are placement metadata for validation helpers
  and summaries, not a reason to reject constructible malformed packets.

Out of scope for the crate: retransmission timers, lease selection, address
management, DNS update policy, relay forwarding behavior, server selection,
client state machines, and any long-running DHCP service.

### RFC 6355 - DUID-UUID

Classification: packet-data extension to RFC 9915 DUIDs.
Source: <https://www.rfc-editor.org/rfc/rfc6355.html>

Downstream use: DUID type 4 is a typed 16-octet UUID payload. Unknown DUID
types remain raw DUID packet data.

## IANA Registry Authority

### DHCPv6 registry collection

Classification: registry authority.
Source: <https://www.iana.org/assignments/dhcpv6-parameters/>
Registry last updated by IANA: 2026-03-10.

`crafter` should use IANA rows for names and metadata while preserving
unassigned, obsolete, or future values when their enclosing packet data is
well-formed.

| Registry | Downstream use |
| --- | --- |
| Message Types | 8-bit message type labels. Core RFC 9915 values are 1 SOLICIT through 13 RELAY-REPL. Values 14 through 23 are leasequery, reconfigure, DHCPv4-over-DHCPv6, active leasequery, and STARTTLS extensions. Values 24 through 35 are failover messages. Values 36 and 37 are address-registration messages. Values 38 through 255 are currently unassigned. |
| Option Codes | 16-bit option code labels plus Client ORO and Singleton Option metadata. Core RFC 9915 options include Client ID through INF_MAX_RT; current extension rows reach OPTION_IALOCATOR at code 150, with 151 through 65535 unassigned. |
| Status Codes | 16-bit status labels. RFC 9915 defines Success through NoPrefixAvail, with UseMulticast marked obsolete. Leasequery, active leasequery, failover, and later extension status values must be preserved even when not initially typed. |
| DUIDs | DUID type labels: 1 DUID-LLT, 2 DUID-EN, 3 DUID-LL, and 4 DUID-UUID. Other type values remain raw DUIDs. |
| Options Permitted in the Relay-Supplied Options Option | Relay option placement metadata from RFC 6422/RFC 9915. The current public row permits OPTION_ERP_LOCAL_DOMAIN_NAME (65). |
| Supported Transport | Bit metadata for supported-transport option payloads. Current row: bit 0 is DomTLS, DNS over mutually authenticated TLS, from RFC 9527. |
| RADIUS Attributes Permitted in DHCPv6 RADIUS Option | Type metadata for RFC 7037/RFC 9915 RADIUS option payloads, including Vendor-Specific, Delegated-IPv6-Prefix, DS-Lite-Tunnel-Name, Framed-IPv6-Address, DNS-Server-IPv6-Address, Delegated-IPv6-Prefix-Pool, Stateful-IPv6-Address-Pool, and DHCPv6-Options. |
| DHCPv6 Options Permitted in the RADIUS DHCPv6-Options Attribute | Option metadata for RFC 9445 payloads. Current row permits OPTION_V6_DNR (144). |

## Extension Source Map

The following RFC families are source-backed for packet data and registry
metadata. They do not authorize DHCP workflow code in `crafter`. Implement
typed structures only when a later plan step names that packet field; otherwise
preserve the TLV bytes and expose registry labels.

| Source | Classification | Packet-layer use |
| --- | --- | --- |
| RFC 3319, RFC 3646, RFC 3898, RFC 4075, RFC 4280, RFC 4704, RFC 4833, RFC 5192, RFC 5223, RFC 5417, RFC 5678, RFC 5908, RFC 5970, RFC 6011, RFC 6153 | Packet-data extension | Service-discovery, DNS, domain, SIP, timezone, NTP, boot, and related option formats. |
| RFC 3633 as incorporated by RFC 9915 | Core wire behavior for prefix delegation packet fields | IA_PD and IAPREFIX are packet-layer containers for prefix delegation. Controlled prefix-delegation validation is named later in the plan, but server assignment policy remains out of scope. |
| RFC 4649, RFC 4580, RFC 6422, RFC 6440, RFC 6607, RFC 6939, RFC 6977, RFC 8357 | Packet-data extension, with relay validation named later in the plan where applicable | Relay, subscriber, remote ID, relay-supplied option, VSS, client link-layer address, relay source-port, and reconfigure-request metadata. |
| RFC 5007, RFC 5460, RFC 7653 | Packet-data extension; controlled leasequery validation is named later in the plan | Leasequery, Bulk Leasequery, Active Leasequery, and STARTTLS message, option, and status codepoints. No lease database, stream service, TLS engine, or long-running query workflow belongs in the crate. |
| RFC 6334, RFC 6603, RFC 6731, RFC 7083, RFC 7078, RFC 7291, RFC 7341, RFC 7598, RFC 7600, RFC 8026, RFC 8115, RFC 8539 | Packet-data extension | Prefix-control, softwire, transition, PCP, address-selection, DHCPv4-over-DHCPv6, and S46 option TLVs. |
| RFC 7037 and RFC 9445 | Packet-data extension | DHCPv6 RADIUS option payload metadata and DHCPv6 options embedded in RADIUS attributes. No RADIUS client/server behavior is in scope. |
| RFC 7774, RFC 7839, RFC 8520, RFC 8572, RFC 8910, RFC 8947, RFC 8948, RFC 8973, RFC 9463, RFC 9527, RFC 9686 | Packet-data extension; address-registration validation is named later in the plan | MPL, access-network identifier, MUD URL, SZTP redirect, captive portal, link-layer address assignment, DOTS, DNR, registered-domain/service binding, supported transport, and address-registration packet fields. |
| RFC 8156 | Packet-data extension | Failover message, option, and status codepoints are inspectable packet data only. No failover relationship state machine, pool accounting, or peer protocol service belongs in the crate. |

## Obsolete And Compatibility Sources

- RFC 8415 is obsoleted by RFC 9915. Use it only for lineage notes when
  explaining changed behavior.
- RFC 3315 and RFC 3633 are older DHCPv6 and prefix-delegation sources. RFC
  9915 is the current core reference; retain older references only where IANA
  rows still cite them or where RFC 9915 incorporates their packet fields.
- RFC 9915 marks IA_TA, Server Unicast, UseMulticast, and their related
  behavior obsolete. `crafter` should still preserve these values as packet
  data when present and should not silently reinterpret or reject them.

## Implementation Notes For Later Steps

- DHCPv6 options are serial TLVs with no padding. A length that exceeds
  available bytes is a structured malformed option error.
- Unknown message types, option codes, status codes, and DUID types are normal
  registry outcomes. Preserve their numeric value and raw bytes.
- Singleton and placement metadata are inspection and validation facts. They
  must not block construction of duplicate singleton options or questionable
  placements; generated tools may intentionally need malformed packets.
- Live DHCPv6 validation must use explicit provider-backed lab opt-in. This
  manifest records public standards only and contains no live captures,
  credentials, hostnames, or network identifiers.
