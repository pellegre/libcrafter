# mDNS Public API Design

## Compatibility Contract

mDNS support stays inside the existing DNS packet layer. Public helpers build or
inspect `Dns`, `DnsQuestion`, `DnsRecord`, `DnsRecordData`, `DnsName`, `Udp`,
`Ipv4`, `Ipv6`, `Ethernet`, and `Packet` values. Decoding UDP/5353 must append
the existing `Dns` layer, not a new `Mdns` layer.

Existing `Dns`, `DnsQuestion`, `DnsRecord`, `DnsRecordData`, and `DnsName`
callers keep their current names, module paths, constructors, raw fields, and
UDP/53 behavior. mDNS adds helpers and exports; it does not rename or replace
the DNS surface.

Explicit overrides remain valid. Helper defaults may set RFC-backed mDNS packet
fields such as UDP/5353, id zero, QR/AA bits, multicast destinations, QU, or
cache-flush, but callers can still chain existing setters such as `Dns::id`,
`Dns::flags`, `DnsQuestion::qclass`, `DnsRecord::new`, `Udp::sport`,
`Udp::dport`, `Ipv4::ttl`, `Ipv4::dst`, `Ipv6::hop_limit`, `Ipv6::dst`, and
`Ethernet::dst` to build unusual or malformed packets where the current DNS
layer permits them.

This design explicitly rejects a second packet abstraction and any resolver,
cache, browser, scanner, responder daemon, conflict state machine, or service
registration API in `crafter`.

## Module Paths And Exports

Add a public mDNS helper module at:

- `crafter::protocols::dns::mdns`

The implementation can use private submodules, but the public path should stay
under `crafter::protocols::dns::mdns` so callers do not have to choose between
parallel DNS and mDNS packet models.

Re-export the stable helper surface through the same paths as DNS:

- `crafter::protocols::dns::mdns::*` for module-qualified use.
- `crafter::protocols::exports::*` for curated crate-wide protocol exports.
- `crafter::*`, `crafter::core::*`, and `crafter::prelude::*` for generated
  tools that start with `use crafter::prelude::*;`.

Do not re-export a public `Mdns` packet layer type because the packet layer type
is `Dns`.

## Public Constants

Expose constants in `crafter::protocols::dns::mdns` and prelude exports:

- `MDNS_PORT: u16 = 5353`
- `MDNS_IPV4_MULTICAST: Ipv4Addr = 224.0.0.251`
- `MDNS_IPV6_LINK_LOCAL_MULTICAST: Ipv6Addr = ff02::fb`
- `MDNS_IPV4_ETHERNET_MULTICAST: MacAddr = 01:00:5e:00:00:fb`
- `MDNS_IPV6_ETHERNET_MULTICAST: MacAddr = 33:33:00:00:00:fb`
- `MDNS_CLASS_BIT: u16 = 0x8000`
- `MDNS_CLASS_MASK: u16 = 0x7fff`
- `MDNS_RESPONSE_HOP_LIMIT: u8 = 255`
- `MDNS_GOODBYE_TTL: u32 = 0`
- `DNS_SD_DEFAULT_DOMAIN: &str = "local."`
- `DNS_SD_SERVICE_ENUMERATION_NAME: &str = "_services._dns-sd._udp.local."`

The response hop-limit constant is the source-backed response default. Query
helpers may target the multicast addresses, but this design does not claim a
sourced default query TTL/hop-limit beyond caller-overridable packet builder
values.

## Class-Bit Helpers

Keep raw class fields as `u16`. Add helpers that mask bit 15 while preserving
the stored raw value:

- `mdns::class_base(raw_class: u16) -> u16`
- `mdns::class_with_bit(base_class: u16, enabled: bool) -> u16`
- `mdns::class_bit(raw_class: u16) -> bool`

Extend `DnsQuestion` for the mDNS QU bit:

- `DnsQuestion::mdns_unicast_response_preferred(self, enabled: bool) -> Self`
- `DnsQuestion::mdns_qu(self, enabled: bool) -> Self` as a short alias
- `DnsQuestion::mdns_unicast_response_preferred_value(&self) -> bool`
- `DnsQuestion::mdns_base_question_class(&self) -> u16`

Extend `DnsRecord` for the mDNS cache-flush bit:

- `DnsRecord::mdns_cache_flush(self, enabled: bool) -> Self`
- `DnsRecord::mdns_cache_flush_value(&self) -> bool`
- `DnsRecord::mdns_base_class(&self) -> u16`

These helpers must not reinterpret EDNS OPT class semantics as an ordinary
resource-record class. `DnsRecord::class()` remains the raw value for every
record.

## Message Constructors

Prefer free functions in `mdns` that return the existing `Dns` type:

- `mdns::query(question: DnsQuestion) -> Dns`
- `mdns::query_for(name: impl Into<DnsName>, qtype: u16) -> Dns`
- `mdns::response() -> Dns`
- `mdns::response_with_answers(records: impl IntoIterator<Item = DnsRecord>) -> Dns`
- `mdns::known_answer_query(question: DnsQuestion, answers: impl IntoIterator<Item = DnsRecord>) -> Dns`
- `mdns::continued_known_answer_query(question: DnsQuestion, answers: impl IntoIterator<Item = DnsRecord>) -> Dns`
- `mdns::probe(name: impl Into<DnsName>) -> Dns`
- `mdns::probe_for(name: impl Into<DnsName>, qtype: u16) -> Dns`
- `mdns::probe_with_authorities(question: DnsQuestion, proposed: impl IntoIterator<Item = DnsRecord>) -> Dns`
- `mdns::announcement(records: impl IntoIterator<Item = DnsRecord>) -> Dns`
- `mdns::goodbye_response(records: impl IntoIterator<Item = DnsRecord>) -> Dns`

Default message shapes:

- Query constructors default to id zero, opcode query, no recursion desired, and
  question sections on `Dns`.
- Response constructors default to id zero, QR set, AA set, opcode query, rcode
  no error, and answer records on `Dns`.
- Known-answer constructors place known answers in the answer section of a
  query. The continued variant sets TC to advertise more known answers.
- Probe constructors use a QU question shape and put proposed tiebreak records
  in the authority section when provided.
- Goodbye constructors set record TTLs to zero through record helpers before
  placing them in an unsolicited response.

Every constructor returns `Dns`, so callers still compose `Ipv4 / Udp / Dns`,
`Ipv6 / Udp / Dns`, or `Ethernet / Ipv4 / Udp / Dns` with `/` and compile a
normal `Packet`.

## Transport Constructors

Add transport helpers that return ordinary layers or `Packet` stacks:

- `mdns::udp() -> Udp`
- `mdns::udp_unicast_reply(source_port: u16, destination_port: u16) -> Udp`
- `mdns::ipv4_multicast(source: Ipv4Addr) -> Ipv4`
- `mdns::ipv4_response(source: Ipv4Addr) -> Ipv4`
- `mdns::ipv6_multicast(source: Ipv6Addr) -> Ipv6`
- `mdns::ipv6_response(source: Ipv6Addr) -> Ipv6`
- `mdns::ethernet_ipv4_multicast(source: MacAddr) -> Ethernet`
- `mdns::ethernet_ipv6_multicast(source: MacAddr) -> Ethernet`
- `mdns::ipv4_packet(source: Ipv4Addr, dns: Dns) -> Packet`
- `mdns::ipv6_packet(source: Ipv6Addr, dns: Dns) -> Packet`
- `mdns::ethernet_ipv4_packet(source_mac: MacAddr, source_ip: Ipv4Addr, dns: Dns) -> Packet`
- `mdns::ethernet_ipv6_packet(source_mac: MacAddr, source_ip: Ipv6Addr, dns: Dns) -> Packet`

The packet constructors should only assemble packet layers. They must not send,
receive, listen, join multicast groups, or choose host interfaces.

Add inspectors:

- `mdns::is_mdns_udp(udp: &Udp) -> bool`
- `mdns::packet_has_mdns_transport(packet: &Packet) -> bool`
- `mdns::packet_has_mdns_dns(packet: &Packet) -> bool`

`packet_has_mdns_dns` should require both a `Dns` layer and UDP/5353 transport.
Plain DNS on UDP/53 remains DNS, not mDNS.

## DNS-SD Name Helpers

Expose DNS-SD helpers from the same `mdns` module. They should return
`Result<DnsName>` when composition can fail due to DNS label or name length
limits.

- `mdns::dns_sd_service_name(service: &str, protocol: &str, domain: impl Into<DnsName>) -> Result<DnsName>`
- `mdns::dns_sd_tcp_service_name(service: &str, domain: impl Into<DnsName>) -> Result<DnsName>`
- `mdns::dns_sd_udp_service_name(service: &str, domain: impl Into<DnsName>) -> Result<DnsName>`
- `mdns::dns_sd_instance_name(instance: &str, service: &str, protocol: &str, domain: impl Into<DnsName>) -> Result<DnsName>`
- `mdns::dns_sd_tcp_instance_name(instance: &str, service: &str, domain: impl Into<DnsName>) -> Result<DnsName>`
- `mdns::dns_sd_udp_instance_name(instance: &str, service: &str, domain: impl Into<DnsName>) -> Result<DnsName>`
- `mdns::dns_sd_subtype_name(subtype: &str, service: &str, protocol: &str, domain: impl Into<DnsName>) -> Result<DnsName>`
- `mdns::dns_sd_service_enumeration_name(domain: impl Into<DnsName>) -> Result<DnsName>`

String helpers are for RFC 6763 DNS-SD service and instance labels. Callers that
need arbitrary non-text DNS labels should keep using `DnsName::from_labels` and
the lower-level `DnsQuestion` and `DnsRecord` constructors so wire bytes round
trip without a second parser.

## DNS-SD And Bonjour-Style Record Helpers

Build DNS-SD packet shapes with ordinary `DnsRecord` and `DnsRecordData`
values:

- `mdns::browse_question(service_name: impl Into<DnsName>) -> DnsQuestion`
- `mdns::service_enumeration_question(domain: impl Into<DnsName>) -> DnsQuestion`
- `mdns::service_ptr(name: impl Into<DnsName>, instance: impl Into<DnsName>, ttl: u32) -> DnsRecord`
- `mdns::subtype_ptr(subtype_name: impl Into<DnsName>, instance: impl Into<DnsName>, ttl: u32) -> DnsRecord`
- `mdns::srv(instance: impl Into<DnsName>, target: impl Into<DnsName>, port: u16, ttl: u32) -> DnsRecord`
- `mdns::srv_with_priority(instance: impl Into<DnsName>, target: impl Into<DnsName>, priority: u16, weight: u16, port: u16, ttl: u32) -> DnsRecord`
- `mdns::txt(instance: impl Into<DnsName>, strings: impl IntoIterator<Item = impl AsRef<[u8]>>, ttl: u32) -> DnsRecord`
- `mdns::a(host: impl Into<DnsName>, address: Ipv4Addr, ttl: u32) -> DnsRecord`
- `mdns::aaaa(host: impl Into<DnsName>, address: Ipv6Addr, ttl: u32) -> DnsRecord`
- `mdns::cache_flush(record: DnsRecord) -> DnsRecord`
- `mdns::shared_record(record: DnsRecord) -> DnsRecord`
- `mdns::goodbye(record: DnsRecord) -> DnsRecord`

For Bonjour-like responses, expose small composition helpers that still return
plain DNS records or messages:

- `mdns::browse_response(ptr_records: impl IntoIterator<Item = DnsRecord>, additionals: impl IntoIterator<Item = DnsRecord>) -> Dns`
- `mdns::resolve_response(records: impl IntoIterator<Item = DnsRecord>, additionals: impl IntoIterator<Item = DnsRecord>) -> Dns`
- `mdns::announce_response(records: impl IntoIterator<Item = DnsRecord>, additionals: impl IntoIterator<Item = DnsRecord>) -> Dns`

These helpers should not perform service discovery, network probing, cache
suppression, or conflict resolution. They only put caller-supplied records into
the sections expected for mDNS and DNS-SD wire packets.

## Decode, Summary, And Show

UDP/5353 built-in dispatch should decode payload bytes as `Dns` when no custom
registry binding overrides the port. UDP/53 dispatch remains unchanged.

`Dns` summary and `show()` output should expose mDNS-specific state without
renaming the layer:

- QU on `DnsQuestion` when the class bit is set.
- Cache-flush on `DnsRecord` when the class bit is set.
- Base class and raw class values for questions and records.
- UDP/5353 transport-visible mDNS state at the `Packet` or UDP inspection
  level, not by changing the `Dns` layer name.

Malformed buffers continue to return structured DNS decode errors. Unknown
records continue to use `DnsRecordData::Raw`.

## Rejected Public Designs

- No `MdnsPacket`, `MdnsLayer`, or alternate `/` composition surface.
- No resolver, cache, service browser, service registry, responder daemon, or
  scanner.
- No persistent known-answer cache or probe conflict state in the crate.
- No hidden live traffic from helper constructors. Live behavior belongs in the
  explicit send, probe, oracle, and provider-backed lab surfaces.
