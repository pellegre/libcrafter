# mDNS And DNS-SD Wire Coverage

This page describes multicast DNS support in the `crafter` crate: how mDNS
messages stay inside the existing DNS packet layer, how DNS-SD and
Bonjour-oriented packet shapes are built, and where the offline/live boundary
sits.

`crafter` treats mDNS as DNS wire messages carried over UDP/5353. It builds,
compiles, decodes, summarizes, and shows through the same `Packet`, `Dns`,
`DnsQuestion`, `DnsRecord`, `DnsRecordData`, and `DnsName` types used for DNS.
It is not a resolver, responder daemon, service registry, cache, scanner,
conflict-resolution engine, or retransmission scheduler. Those workflows belong
in generated tools that choose their targets and safety gates explicitly.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| UDP/5353 dispatch | Supported | UDP source or destination port 5353 decodes as DNS with mDNS context; UDP/53 DNS behavior is unchanged. |
| Multicast defaults | Supported | Helpers expose UDP/5353, IPv4 `224.0.0.251`, IPv6 `ff02::fb`, Ethernet multicast addresses, and response TTL/hop-limit 255. |
| Header defaults | Supported | mDNS query helpers default to ID zero and no RD bit; response helpers default to QR and AA. Explicit caller overrides are preserved. |
| QU and cache-flush bits | Supported | The top class bit is inspectable without losing the raw class field or the lower 15-bit base class. |
| DNS-SD names | Supported | Service, instance, subtype, and service-enumeration helpers build byte-preserving `DnsName` values. |
| Bonjour-style records | Supported | PTR, SRV, TXT, A, and AAAA helpers build ordinary DNS records for browse, resolve, and announce packet shapes. |
| Known answers, probes, goodbyes | Supported as packets | Helpers place known answers, probe tiebreak records, cache-flush records, and TTL-zero goodbyes in the DNS sections used on the wire. |
| Resolver behavior | Out of scope | No cache, responder state, suppression decision, conflict state machine, service registration, or retry timing is implemented. |
| Live behavior | Protected | Use offline fixtures, dry-run plans, oracle/probe dry-runs, or externally executed labs; examples and tests do not send live multicast traffic. |

## Basic Packet Construction

Use `crafter::prelude::*` and the `mdns` helper module. The helpers return
ordinary packet layers, so `/` composition, `compile()`, `decode_from_l3`,
`summary()`, and `show()` work exactly as they do for other protocols.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let service = mdns::dns_sd_tcp_service_name("ipp", DNS_SD_DEFAULT_DOMAIN)?;
    let question = DnsQuestion::new(service, DNS_TYPE_PTR).mdns_qu(true);
    let dns = mdns::query(question);

    let packet = mdns::mdns_ipv4_packet(Ipv4Addr::new(192, 0, 2, 10), dns);
    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;

    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    Ok(())
}
```

The same message can be assembled layer by layer when a generated tool needs to
override a field deliberately:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let packet = Ipv4::new()
    .src(Ipv4Addr::new(192, 0, 2, 10))
    .dst(MDNS_IPV4_MULTICAST)
    .ttl(MDNS_RESPONSE_TTL)
    / mdns::udp()
    / Dns::mdns_query_for("printer.local.", DNS_TYPE_A).id(0x1234);
```

`compile()` still fills IP protocol numbers, UDP lengths, checksums, and DNS
section counts where the caller left them unset. Values set by the caller,
including unusual DNS IDs, flags, ports, classes, TTLs, and record data, are
preserved.

## Multicast Defaults

The public constants and transport builders are exported through the prelude and
through `crafter::protocols::dns::mdns`:

| Helper or constant | Value or behavior |
| --- | --- |
| `MDNS_PORT` | UDP port 5353. |
| `mdns::udp()` / `mdns::mdns_udp()` | UDP source and destination port 5353. |
| `MDNS_IPV4_MULTICAST` | IPv4 destination `224.0.0.251`. |
| `MDNS_IPV6_LINK_LOCAL_MULTICAST` | IPv6 destination `ff02::fb`. |
| `MDNS_IPV4_ETHERNET_MULTICAST` | Ethernet destination `01:00:5e:00:00:fb`. |
| `MDNS_IPV6_ETHERNET_MULTICAST` | Ethernet destination `33:33:00:00:00:fb`. |
| `MDNS_RESPONSE_TTL` / `MDNS_RESPONSE_HOP_LIMIT` | Response IP TTL or IPv6 hop-limit 255. |

Convenience stack builders include `mdns::mdns_ipv4_packet`,
`mdns::mdns_ipv6_packet`, `mdns::mdns_ethernet_ipv4_packet`, and
`mdns::mdns_ethernet_ipv6_packet`. The alias forms `mdns::ipv4_packet`,
`mdns::ipv6_packet`, `mdns::ethernet_ipv4_packet`, and
`mdns::ethernet_ipv6_packet` use the same defaults.

Unicast replies can be represented with explicit ports:

```rust
use crafter::prelude::*;

let reply_udp = mdns::udp_unicast_reply(MDNS_PORT, 49_152);
assert_eq!(reply_udp.source_port_value(), MDNS_PORT);
assert_eq!(reply_udp.destination_port_value(), 49_152);
```

## mDNS Class Bits

mDNS reuses the top bit of the DNS class field. The meaning depends on whether
the field belongs to a question or a resource record:

- In a question, bit `0x8000` is the unicast-response-preferred bit, also called
  QU.
- In a resource record, bit `0x8000` is the cache-flush bit.
- The lower 15 bits remain the base DNS class.

The raw class remains available for malformed-packet work, while mDNS helpers
expose the masked value:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let question = DnsQuestion::a("printer.local.").mdns_qu(true);
assert_eq!(question.question_class(), MDNS_CLASS_BIT | DNS_CLASS_IN);
assert_eq!(question.mdns_base_question_class(), DNS_CLASS_IN);
assert!(question.mdns_unicast_response_preferred_value());

let record = DnsRecord::a("printer.local.", Ipv4Addr::new(192, 0, 2, 55), 120)
    .mdns_cache_flush(true);
assert_eq!(record.class(), MDNS_CLASS_BIT | DNS_CLASS_IN);
assert_eq!(record.mdns_base_class(), DNS_CLASS_IN);
assert!(record.mdns_cache_flush_value());
```

`mdns::cache_flush(record)` sets the resource-record bit,
`mdns::shared_record(record)` clears it, and `mdns::goodbye(record)` sets the
record TTL to `MDNS_GOODBYE_TTL` without changing the owner name, type, class,
cache-flush bit, or RDATA.

## DNS-SD Names

DNS-SD helpers return `DnsName`, so names preserve exact wire-label bytes while
also exposing the stable trailing-dot presentation form.

```rust
use crafter::prelude::*;

let service = mdns::dns_sd_tcp_service_name("ipp", DNS_SD_DEFAULT_DOMAIN)?;
assert_eq!(service.presentation(), "_ipp._tcp.local.");

let instance =
    mdns::dns_sd_tcp_instance_name("Office\\032Printer", "ipp", DNS_SD_DEFAULT_DOMAIN)?;
assert_eq!(
    instance.presentation(),
    "Office\\032Printer._ipp._tcp.local."
);

let subtype = mdns::dns_sd_subtype_name("printer", "ipp", "tcp", DNS_SD_DEFAULT_DOMAIN)?;
assert_eq!(subtype.presentation(), "_printer._sub._ipp._tcp.local.");

let enumeration = mdns::dns_sd_service_enumeration_name(DNS_SD_DEFAULT_DOMAIN)?;
assert_eq!(enumeration.presentation(), DNS_SD_SERVICE_ENUMERATION_NAME);
# Ok::<(), crafter::CrafterError>(())
```

String helpers parse each service, protocol, subtype, and instance component as
one DNS label. Use the `_from_labels` variants when a packet test needs exact
label bytes:

```rust
use crafter::prelude::*;

let raw = mdns::dns_sd_instance_name_from_labels(
    [0x00u8, 0xff],
    b"_ipp",
    b"_tcp",
    DNS_SD_DEFAULT_DOMAIN,
)?;
assert_eq!(raw.presentation(), "\\000\\255._ipp._tcp.local.");
# Ok::<(), crafter::CrafterError>(())
```

For DNS-SD semantics, service instance labels are text labels. The raw-label
helpers are for DNS wire preservation and fixture work.

## Bonjour Browse And Resolve Shapes

Bonjour-style DNS-SD packet shapes are ordinary DNS records. A browse query is a
PTR question for the service type:

```rust
use crafter::prelude::*;

let service = mdns::dns_sd_tcp_service_name("ipp", DNS_SD_DEFAULT_DOMAIN)?;
let browse = mdns::query(DnsQuestion::new(service.clone(), DNS_TYPE_PTR).mdns_qu(true));
assert_eq!(browse.questions()[0].name(), "_ipp._tcp.local.");
# Ok::<(), crafter::CrafterError>(())
```

A browse response can carry the shared PTR answer plus SRV, TXT, and address
records as answer or additional-section data:

```rust
use crafter::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

let service = mdns::dns_sd_tcp_service_name("ipp", DNS_SD_DEFAULT_DOMAIN)?;
let instance =
    mdns::dns_sd_tcp_instance_name("Office\\032Printer", "ipp", DNS_SD_DEFAULT_DOMAIN)?;
let target = "office-printer.local.";

let ptr = mdns::service_ptr(service.clone(), instance.clone(), 4_500);
let srv = mdns::srv(instance.clone(), target, 631, 120).mdns_cache_flush(true);
let txt = mdns::txt(instance.clone(), [b"txtvers=1".as_slice()], 120)
    .mdns_cache_flush(true);
let a = mdns::a(target, Ipv4Addr::new(192, 0, 2, 55), 120).mdns_cache_flush(true);
let aaaa = mdns::aaaa(
    target,
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x55),
    120,
)
.mdns_cache_flush(true);

let response = mdns::response_with_answers([ptr, srv, txt])
    .mdns_additional_record(a)
    .mdns_additional_record(aaaa);
# let _ = response;
# Ok::<(), crafter::CrafterError>(())
```

Resolving a selected instance asks for SRV and TXT at the same service-instance
name:

```rust
use crafter::prelude::*;

let instance =
    mdns::dns_sd_tcp_instance_name("Office\\032Printer", "ipp", DNS_SD_DEFAULT_DOMAIN)?;
let resolve = mdns::query(DnsQuestion::new(instance.clone(), DNS_TYPE_SRV))
    .question(DnsQuestion::new(instance, DNS_TYPE_TXT));
# let _ = resolve;
# Ok::<(), crafter::CrafterError>(())
```

An unsolicited announcement for unique records can be built with cache-flush
answers:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let instance =
    mdns::dns_sd_tcp_instance_name("Office\\032Printer", "ipp", DNS_SD_DEFAULT_DOMAIN)?;
let target = "office-printer.local.";

let announcement = mdns::announcement([
    mdns::srv(instance.clone(), target, 631, 120),
    mdns::txt(instance, [b"txtvers=1".as_slice()], 120),
    mdns::a(target, Ipv4Addr::new(192, 0, 2, 55), 120),
]);

assert!(announcement.answers().iter().all(DnsRecord::mdns_cache_flush_value));
# Ok::<(), crafter::CrafterError>(())
```

If a response needs shared PTR records and unique records together, build it
with `mdns::response_with_answers` and set the cache-flush bit only on the
unique records.

## Known Answers, Probes, And Goodbyes

Known-answer queries put known records in the DNS answer section. The helper
does not implement cache suppression; it only creates the packet shape:

```rust
use crafter::prelude::*;

let service = mdns::dns_sd_tcp_service_name("ipp", DNS_SD_DEFAULT_DOMAIN)?;
let instance =
    mdns::dns_sd_tcp_instance_name("Office\\032Printer", "ipp", DNS_SD_DEFAULT_DOMAIN)?;

let known = mdns::known_answer_query(
    DnsQuestion::new(service.clone(), DNS_TYPE_PTR),
    [mdns::service_ptr(service, instance, 300)],
);
assert_eq!(known.questions().len(), 1);
assert_eq!(known.answers().len(), 1);
# Ok::<(), crafter::CrafterError>(())
```

Use `mdns::continued_known_answer_query` when the packet shape should set TC for
a continued known-answer list.

Unique-record probes use QU questions and may carry proposed records in the
authority section:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let proposed = mdns::a("printer.local.", Ipv4Addr::new(192, 0, 2, 77), 120);
let probe = mdns::probe_with_authorities(DnsQuestion::a("printer.local."), [proposed]);

assert!(probe.questions()[0].mdns_unicast_response_preferred_value());
assert_eq!(probe.authorities().len(), 1);
```

Goodbye responses are unsolicited responses whose records carry TTL zero:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

let record = mdns::cache_flush(DnsRecord::a(
    "printer.local.",
    Ipv4Addr::new(192, 0, 2, 77),
    120,
));
let goodbye = mdns::goodbye_response([record]);

assert_eq!(goodbye.answers()[0].ttl(), MDNS_GOODBYE_TTL);
assert!(goodbye.answers()[0].mdns_cache_flush_value());
```

The crate does not decide when to suppress answers, resolve conflicts, retry
probes, or expire cache entries. It exposes the packet fields needed by tools
that implement those behaviors outside the packet primitive.

## Decode, Summary, And Show

The default registry decodes UDP/5353 payloads as DNS/mDNS when either source or
destination port is 5353. `summary()` and `show()` include mDNS context,
question QU state, cache-flush state, and the masked base class. Plain DNS on
UDP/53 remains DNS.

Malformed mDNS payloads return structured decode errors using the same DNS error
model as ordinary DNS. Structurally valid records with unknown types preserve
their RDATA as `DnsRecordData::Raw`.

## Offline First

The checked-in mDNS examples and fixtures are synthetic. They use documentation
addresses, synthetic `.local.` names, and deterministic classic pcap fixtures;
they are not captures from a production network or a real Bonjour deployment.

Generated tools should default to local construction, decode, pcap fixtures, or
dry-run send plans:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet = mdns::mdns_ipv4_packet(
        Ipv4Addr::new(192, 0, 2, 10),
        Dns::mdns_query_for("printer.local.", DNS_TYPE_A),
    );

    let plan = packet.send_dry_run(SendOptions::new().iface("dry-run0").network_layer())?;
    println!("mode: dry-run");
    println!("target: {:?}", plan.target());
    println!("bytes: {}", plan.len());
    Ok(())
}
```

The fixture suite covers IPv4 and IPv6 UDP/5353 packets, Bonjour-style browse
and resolve responses, known answers, cache-flush records, goodbyes, compressed
name decode, malformed mDNS buffers, and classic pcap read/write round trips.

## External Execution Boundary

Use the tracked deterministic validation surfaces first:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
tools/oracle/run pcap --profile smoke --seed 1 --count 10
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

These commands do not select infrastructure or send packets. Any authorized use
of concrete interfaces, peers, radios, or targets is owned by external operator
tooling, which supplies runtime inputs and collects artifacts. libcrafter does
not provision machines, configure responders, manage credentials, or perform
remote cleanup.

## Evidence

The mDNS and DNS-SD facts used by these helpers come from reviewed public
sources:

- RFC 6762 defines multicast DNS as DNS-like UDP messages on port 5353, the
  IPv4 and IPv6 multicast destinations, header defaults, QU and cache-flush
  class bits, known-answer sections, probe shapes, announcements, goodbyes, and
  response TTL/hop-limit 255.
- RFC 6763 defines DNS-Based Service Discovery names, browse and resolve
  packet shapes, PTR/SRV/TXT/A/AAAA relationships, subtype names, service
  enumeration, and DNS-SD TXT wire data.
- RFC 1035, RFC 2782, RFC 3596, and the IANA DNS Parameters registries provide
  the base DNS message, class, and RR type values used by mDNS and DNS-SD.
- RFC 1112 and RFC 2464 provide the multicast-to-Ethernet derivations for the
  exported IPv4 and IPv6 Ethernet multicast destination constants.

Bonjour compatibility in this crate means RFC 6763 DNS-SD packet shapes that
match Bonjour-style browse, resolve, and announce traffic. No Apple-specific
behavior is implemented or documented without a separate Apple source review.
