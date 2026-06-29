# mDNS Gap Plan

## Inventory sources

- `crafter/src/protocols/dns/` contains the existing `Dns` packet layer, DNS
  constants, name codec, record model, EDNS, DNSSEC, SVCB/HTTPS, summaries, and
  unit tests.
- `crafter/src/registry.rs` owns built-in UDP application dispatch. It currently
  dispatches DNS on UDP/53 only.
- `crafter/src/protocols/transport/udp/datagram.rs` identifies DNS as a UDP
  application layer for UDP payload sizing and surplus handling.
- `tools/oracle` has the DNS layer and feature specs, Scapy/Wireshark DNS
  backends, raw DNS byte helpers, and the Rust materializer.
- `tools/probe` has DNS behavior planning, a controlled UDP DNS responder, lab
  capability derivation, and a Rust stimulus adapter for DNS over IPv4 unicast.
- `tools/lab` exposes provider substrate capabilities, including multicast, but
  no mDNS-specific capability names yet.

## Current DNS crate support

The DNS packet primitive is already the right base for mDNS. `Dns` is a normal
`Packet` layer with `/` composition, `compile()`, decode, `summary()`, and
`show()` through the generic layer surface. It keeps one typed message with
question, answer, authority, and additional vectors. Header counts are filled
from those vectors, while user-set id and flags are preserved.

Public DNS APIs are exported through `crafter::protocols::exports`, crate root,
`crafter::core`, and `crafter::prelude`. The surface includes `Dns`,
`DnsQuestion`, `DnsRecord`, `DnsRecordData`, `DnsName`, `EdnsOption`,
`DnsTypeBitmaps`, `SvcParam`, `SvcParams`, DNS class/type/opcode/rcode/header
constants, `dns_type_name`, `edns_option_code_name`, and
`svcb_param_key_name`. There are no `MDNS_*` constants, no mDNS constructors,
and no DNS-SD or Bonjour helpers.

`Dns::new()` defaults to id 0 and RD set, and `Dns::query`,
`Dns::a_query`, and `Dns::aaaa_query` build ordinary recursive DNS query
shapes. That is compatible with raw packet construction, but not an mDNS
default: mDNS needs helpers that default to id 0, opcode query, RD/RA/AD/CD/RCODE
clear, response AA set where appropriate, UDP/5353, multicast addresses, and
still permit explicit overrides.

`DnsRecordData` already covers the records needed for DNS-SD packet shapes:
A, AAAA, PTR via `Name`, SRV, TXT, and raw fallback. `DnsRecord::srv` and
`DnsRecord::new(... DNS_TYPE_PTR ..., DnsRecordData::name(...))` can build the
wire bytes manually. What is missing is ergonomic DNS-SD and Bonjour-oriented
record-set construction: browse PTRs, service enumeration, subtype PTRs,
resolve SRV/TXT, TXT byte helpers, address additionals, known-answer lists,
goodbye TTL-zero records, probe authority records, and announcement responses.

Unknown RR types already decode as `DnsRecordData::Raw`, so no new raw-preserve
mechanism is needed for mDNS. Malformed DNS decode already returns structured
errors for short headers, truncated names, compression pointer errors, bad
RDLENGTH values, malformed EDNS/DNSSEC/SVCB structures, and trailing bytes.

## Names and escaping

`DnsName` is byte-preserving and already fits the mDNS/DNS-SD name requirement.
It stores exact wire labels, exposes canonical trailing-dot presentation, parses
`\DDD` and literal-character escapes, preserves non-UTF-8 bytes, validates the
63-octet label and 255-octet name limits, decodes compression pointers, and
emits deterministic uncompressed names.

Gaps are helper-level, not codec-level. DNS-SD instance helpers must compose
instance, service, protocol, subtype, and domain labels without losing escaped
dots, backslashes, mixed case, UTF-8 bytes, or generic DNS non-text labels where
callers provide a `DnsName`. These helpers should reuse `DnsName` instead of
introducing a second string parser.

## UDP dispatch and packet shape

`Udp::new()` defaults both ports to 53. UDP length and checksum autofill already
work for `Udp / Dns`, and `is_udp_application_layer` treats `Dns` as a UDP
application payload. A caller can manually build UDP/5353 today by setting
ports, but decode will not type that payload as DNS/mDNS unless the caller
registers a custom UDP binding.

The built-in registry has two DNS paths, both tied to `DNS_PORT`:
`with_builtin_bindings()` binds UDP port 53 to `append_dns_packet`, and
`decode_udp_application()` also falls through to DNS when either source or
destination port is 53. UDP/5353 is not a built-in DNS/mDNS dispatch point.
There is an existing registry test proving that custom UDP port 5353 bindings
work, which means built-in mDNS dispatch must be added carefully so user custom
bindings still override built-ins as intended.

The mDNS dispatch gap can be filled by extending registry DNS dispatch to
recognize UDP/5353, preserving UDP/53 behavior unchanged. The decoded layer can
remain `Dns`; later summary/show helpers can expose that a DNS message was seen
on mDNS transport by inspecting context or adding mDNS helper APIs.

## Class handling

`DnsQuestion` stores `question_class` as a raw `u16`, and `DnsRecord` stores
`class` as a raw `u16`. The current getters and setters preserve the full value.
This is the correct raw storage for mDNS, but there are no helpers for the top
bit. For mDNS questions, bit 15 is the unicast-response-preferred (QU) bit. For
mDNS resource records, bit 15 is the cache-flush bit. The base DNS class remains
the low 15 bits in both cases.

This should be an extension of `DnsQuestion` and `DnsRecord`: add constants for
the mask and helpers that report/set the base class and mDNS bit without
discarding the raw class value. EDNS OPT records already reuse the class field
for UDP payload size; mDNS cache-flush helpers should either document that OPT is
not a normal resource record or avoid implying OPT class semantics.

## Fixtures and crate tests

Current fixture coverage includes IPv4 UDP DNS query/response bytes, SOA/SRV,
DNSSEC, SVCB/HTTPS, EDNS OPT, raw unknown records, section placement, summaries,
and pcap fixtures for other protocols. DNS resilience tests cover malformed
names and RDATA. There are no mDNS fixtures for UDP/5353, IPv4 multicast
224.0.0.251, IPv6 ff02::fb, Ethernet multicast destinations, QU questions,
cache-flush records, goodbyes, known answers, probes, announcements, service
browse/resolve, Bonjour-style PTR/SRV/TXT/A/AAAA sets, or mDNS summaries.

Future fixture work should add deterministic crate fixtures under
`crafter/tests/fixtures/` and keep them documentation-safe. Existing DNS fixture
patterns can be reused; no new fixture harness is needed.

## Oracle coverage

The oracle DNS layer spec (`tools/oracle/specs/layers/dns.yaml`) models DNS over
UDP with header fields, questions, all four sections, typed records, EDNS,
DNSSEC, SVCB/HTTPS, raw records, and normalized names. The DNS feature spec
(`tools/oracle/specs/features/dns-behavior.yaml`) covers ordinary DNS record
behavior, compressed-name normalization, raw fallback, malformed inputs, and
section placement. DNS cases are listed in the IPv4 DNS stack and Scapy coverage
matrix. The Scapy DNS backend and `dns_raw.py` can materialize typed DNS and
raw byte cases; the Wireshark DNS backend is parser-only normalization; the Rust
materializer builds `Dns` packets from oracle plans.

There is no mDNS oracle layer, feature, stack, profile, fixture list, generator
behavior, Scapy mDNS defaulting, Wireshark mDNS normalization, or Rust
materializer path for mDNS plan fields. The first oracle changes should be new
or extended specs that define UDP/5353, multicast transport metadata, mDNS class
bits, DNS-SD packet shapes, and malformed mDNS cases. Backend code should follow
the specs, not precede them.

## Probe and lab coverage

The DNS probe plugin plans eleven DNS cases: the `dns-query` smoke case plus ten
behavior cases for A, AAAA, CNAME, NXDOMAIN, NODATA, TXT, MX, SRV, EDNS OPT,
and repeated transaction IDs. They require `dns_service`, derived from IPv4
unicast plus controlled services. The target service is a generated Python UDP
DNS responder bound to a target IPv4 address on port 53. The Rust adapter builds
`Ipv4 / Udp / Dns` packets, dry-runs through `SocketSender`, and validates live
responses by peer IPv4 addresses, UDP ports, DNS id, QR/rcode, question, answer
content, and EDNS metadata.

There are no mDNS probe cases, no multicast capture filters, no UDP/5353
controlled mDNS responder, no DNS-SD response validation, no IPv6 link-local
scope handling, and no protected live mDNS flow. Lab/provider capability data
has generic substrate bits such as `multicast`, `ipv4_unicast`,
`ipv6_unicast`, `link_layer_send`, `link_layer_capture`, `controlled_services`,
provider MAC/interface metadata, and provider-specific defaults. Existing
protocols derive SSDP and IGMP multicast capabilities, but no
`mdns_ipv4_multicast`, `mdns_ipv6_multicast`, `mdns_link_local_scope`, or
`mdns_controlled_responder` capability exists.

mDNS probe work should add mDNS-specific cases and capabilities rather than
stretching `dns_service`, because mDNS needs multicast delivery/capture,
UDP/5353, optional unicast replies, link-local scope, and DNS-SD responder
state that ordinary unicast DNS does not require.

## Documentation coverage

`docs/guide/dns.md` documents DNS wire coverage and explicitly keeps resolver,
cache, server, and live DNS workflow behavior out of scope. README and docs list
DNS, but not mDNS. `docs/operations/validation.md` and `docs/operations/probe.md`
describe DNS oracle/probe validation over controlled UDP DNS service behavior,
not multicast DNS or DNS-SD.

mDNS needs user-facing docs that present it as DNS wire messages over
UDP/5353 inside the existing packet abstraction, plus validation docs for
offline oracle, pcap fixtures, provider dry-runs, capability skips, and guarded
live runs.

## Gap ownership

Gaps that should be filled by extending existing DNS types and dispatch:

- Add mDNS constants and public exports near the existing DNS constants.
- Add QU/cache-flush raw-class helpers on `DnsQuestion` and `DnsRecord`.
- Add UDP/5353 built-in decode dispatch while preserving UDP/53 DNS behavior.
- Update `summary()`/`show()` to make mDNS class bits and transport-visible
  mDNS state inspectable.
- Reuse `DnsName`, `DnsRecordData`, `DnsRecord`, and `Dns` for all mDNS and
  DNS-SD wire messages.
- Extend existing fixture, resilience, and oracle materializer patterns.

Gaps that need mDNS-specific helper modules while keeping `Dns` central:

- `crafter/src/protocols/dns/mdns.rs` for mDNS port, multicast address,
  Ethernet multicast, TTL/hop-limit, header-default, class-bit, query,
  response, known-answer, goodbye, probe, and announcement helpers.
- A DNS-SD helper module for service type, subtype, browse, enumerate, and
  instance-name construction.
- A Bonjour-style helper module or submodule for PTR/SRV/TXT/A/AAAA record-set
  builders and additional-record sets.
- mDNS oracle specs/profiles/backends and probe/lab cases, because they need
  multicast, UDP/5353, DNS-SD, and provider capability contracts that ordinary
  DNS does not have.

No gap requires a new resolver, scanner, daemon, persistent cache, service
registration state machine, or separate packet abstraction.
