# mDNS Public API Design

## Compatibility Contract

mDNS support stays inside the existing DNS packet layer. Public helpers build
or inspect `Dns`, `DnsQuestion`, `DnsRecord`, `DnsRecordData`, `DnsName`, `Udp`,
`Ipv4`, `Ipv6`, `Ethernet`, and `Packet` values. Decoding UDP/5353 appends the
existing `Dns` layer; there is no parallel `Mdns` layer.

Existing DNS callers keep their names, module paths, constructors, raw fields,
and UDP/53 behavior. mDNS adds helpers and exports without replacing the DNS
surface. Explicit overrides remain valid so callers can still construct unusual
or intentionally malformed packets.

The implementation does not add a resolver, cache, browser, scanner, responder
daemon, conflict state machine, service registry, or network execution runtime.

## Module And Export Surface

The public helper module is `crafter::protocols::dns::mdns`. Stable helpers are
also re-exported through the normal protocol exports and prelude. The packet
layer type remains `Dns`.

The module exposes the standard UDP port, IPv4 and IPv6 multicast addresses,
their Ethernet multicast mappings, the mDNS class-bit mask, response hop limit,
goodbye TTL, default DNS-SD domain, and service-enumeration name.

## Class-Bit Helpers

Question and resource-record class fields remain raw `u16` values. Helpers
expose the lower 15-bit base class and bit 15 as the question QU bit or record
cache-flush bit without changing the stored wire value. EDNS OPT class semantics
are not reinterpreted as ordinary record classes.

## Message Constructors

Message helpers return the existing `Dns` type for:

- ordinary queries and responses;
- known-answer queries and continued known-answer queries;
- probes with optional authority records;
- announcements; and
- goodbye responses.

Defaults follow the source-backed mDNS header and section shapes, while the
normal DNS setters remain available for explicit overrides. Callers compose the
result through the standard `Ipv4 / Udp / Dns`, `Ipv6 / Udp / Dns`, or Ethernet
packet stacks.

## Transport Constructors

Transport helpers return ordinary `Udp`, `Ipv4`, `Ipv6`, `Ethernet`, or `Packet`
values. They set documented multicast destinations and response defaults, but
they never send, receive, listen, join multicast groups, select a machine, or
choose a host interface.

Inspectors distinguish mDNS transport by requiring UDP/5353 together with a
`Dns` layer. Plain DNS on UDP/53 remains DNS.

## DNS-SD Helpers

DNS-SD name helpers construct service, instance, subtype, and service-enumeration
names and return `Result<DnsName>` when DNS label or total-name limits can be
exceeded. Callers that need arbitrary non-text labels retain the lower-level
`DnsName::from_labels`, `DnsQuestion`, and `DnsRecord` APIs.

Record helpers produce ordinary `DnsRecord` values for browse PTR, subtype PTR,
SRV, TXT, A, AAAA, shared, cache-flush, and goodbye records. Composition helpers
assemble browse, resolve, and announcement responses from caller-supplied records
without performing service discovery, scheduling, caching, or conflict
resolution.

## Decode, Summary, And Show

Built-in UDP/5353 dispatch decodes accepted payloads as `Dns` unless a custom
registry binding overrides the port. UDP/53 behavior is unchanged. Inspection
shows QU/cache-flush state alongside base and raw classes, while malformed
buffers retain structured DNS errors and unknown records remain raw.

## Rejected Public Designs

- No `MdnsPacket`, `MdnsLayer`, or alternate composition surface.
- No resolver, cache, browser, registry, responder daemon, or scanner.
- No persistent known-answer cache or probe-conflict state.
- No hidden live traffic or infrastructure selection from constructors.
