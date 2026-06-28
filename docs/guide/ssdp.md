# SSDP Wire Coverage

This page describes the Simple Service Discovery Protocol support in
`crafter`: how to build SSDP discovery datagrams as packet layers, decode
HTTP-like SSDP payloads from UDP, validate fixture pcaps offline, and inspect
dry-run send plans without starting a discovery workflow.

`crafter` treats SSDP as packet bytes carried by UDP port 1900. It can build,
compile, decode, summarize, show, and preserve SSDP messages as typed layers
inside the normal `Packet` abstraction. It is not a scanner, discovery daemon,
service cache, retry workflow, UPnP control point, HTTP client, or device
implementation. Those behaviors belong in generated tools built on top of the
packet primitive.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| Requests | Supported | `M-SEARCH * HTTP/1.1`, `NOTIFY * HTTP/1.1`, and valid unknown request methods are preserved. |
| Responses | Supported | `HTTP/1.1 200 OK` helper plus valid unknown status lines and reason phrases. |
| Headers | Supported | Ordered headers, duplicate headers, known SSDP names, extension names, unknown names, empty values, and original spelling are preserved. |
| Bodies | Supported as bytes | Opaque body bytes after the CRLF header delimiter are preserved, but builders do not add bodies by default. |
| UDP dispatch | Supported | UDP/1900 payloads decode as SSDP only when the conservative HTTP-like shape gate accepts them; unrelated payloads remain `Raw`. |
| Multicast helpers | Supported | IPv4 and IPv6 helper functions build documentation-safe multicast packet stacks with source-backed defaults and explicit override variants. |
| Pcap fixtures | Supported | Synthetic RawIp and Ethernet classic pcap fixtures validate offline read, decode, and write round trips. |
| Live behavior | Out of crate scope | Use offline fixtures, dry-run plans, oracle/probe dry-runs, or protected provider-backed labs. |

## Public API

SSDP is exported through `crafter::prelude::*`. Compose it like any other packet
layer:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet = ssdp_ipv4_multicast_packet(
        Ipv4Addr::new(192, 0, 2, 10),
        Ssdp::m_search_all().mx(2),
    );

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;

    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    println!("{}", bytes.hexdump());
    Ok(())
}
```

`compile()` fills the enclosing IPv4 or IPv6 protocol fields, UDP lengths, and
UDP checksums when the caller leaves them unset. SSDP itself serializes the
caller-provided start line, headers, header order, duplicate fields, and body
bytes exactly. Explicit caller overrides survive, including intentionally odd
UDP ports, multicast hop limits, unknown methods, unknown headers, or
non-canonical header spelling.

The convenience layer constructor is `Ssdp::udp()`, which sets the destination
port to `SSDP_UDP_PORT` (`1900`). Use ordinary `Udp` setters when a protocol
test needs a deliberate override.

## Message Shapes

Use the common builders for the source-backed SSDP shapes:

```rust
use crafter::prelude::*;

let search = Ssdp::m_search_all().mx(1);

let notify = Ssdp::notify_alive()
    .notification_type(SsdpTarget::rootdevice())
    .unique_service_name(SsdpUsn::rootdevice("device-1"))
    .location(SsdpLocation::new("http://192.0.2.10:8000/rootDesc.xml")?)
    .max_age(1_800)
    .server("ExampleOS/1.0 UPnP/2.0 libcrafter/0.3")
    .boot_id(1)
    .config_id(1);

let response = Ssdp::response_ok_with_ext()
    .search_target(SsdpTarget::all())
    .unique_service_name(SsdpUsn::target("device-1", SsdpTarget::all()));

# Ok::<(), crafter::CrafterError>(())
```

The lower-level constructors remain available when a generated tool needs to
preserve unusual but structurally valid values:

```rust
use crafter::prelude::*;

let message = Ssdp::request(
    SsdpMethod::try_from("X-SEARCH").expect("valid unknown method"),
    SsdpRequestTarget::try_from("/device.xml").expect("valid target"),
    SsdpVersion::try_from("HTTP/1.1").expect("valid version"),
)
.with_raw_header("X-DEVICE.UPNP.ORG", "opaque value")?
.with_body([0xde, 0xad, 0xbe, 0xef]);

assert_eq!(Ssdp::parse(&message.to_bytes())?, message);
# Ok::<(), crafter::CrafterError>(())
```

SSDP header helpers append headers instead of deduplicating them. Use
`headers().get_first(...)`, `headers().get_all(...)`, and `show()` when a tool
needs to inspect preserved values.

## Decode And Raw Fallback

SSDP payload decode is conservative. A UDP/1900 payload must have a complete
CRLF-delimited start line and header section before registry dispatch accepts it
as SSDP. Structurally valid SSDP messages decode into `Ssdp`; unrelated text or
binary UDP payloads stay as `Raw`.

```rust
use crafter::prelude::*;

let bytes = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
let ssdp = Ssdp::parse(bytes)?;
let packet = Packet::from_layer(ssdp);

println!("{}", packet.summary());
println!("{}", packet.show());
# Ok::<(), crafter::CrafterError>(())
```

Malformed SSDP inputs return structured parse errors instead of panicking or
silently truncating. Unknown but valid methods, status codes, reason phrases,
header names, header values, duplicate headers, extension headers, and body
bytes remain inspectable.

The `ssdp_decode` example reads tracked payload fixtures and prints summaries
without opening a live capture:

```sh
cargo run -p crafter --example ssdp_decode
```

## Pcap Fixtures

The checked-in SSDP pcaps are synthetic and use documentation addresses and
documentation MAC addresses. They exercise the classic pcap paths without using
live captures:

- `crafter/tests/fixtures/ssdp/raw-ipv4-udp-ssdp-m-search.pcap`
- `crafter/tests/fixtures/ssdp/ethernet-ipv4-udp-ssdp-m-search.pcap`

Read them offline with `PcapReader`:

```rust
use crafter::prelude::*;
use crafter::wire::backend::pcap::PcapReader;

fn main() -> crafter::Result<()> {
    let packets = PcapReader::open(
        "crafter/tests/fixtures/ssdp/raw-ipv4-udp-ssdp-m-search.pcap",
    )?
    .collect_packets()?;

    for record in packets {
        let packet = record.packet();
        println!("{}", packet.summary());
        assert!(packet.layer::<Ssdp>().is_some());
    }

    Ok(())
}
```

Offline round-trip tests also write SSDP packets through the pcap writer and
read them back through `PacketWire`. Keep new fixture data deterministic and
synthetic; do not promote provider artifacts, public endpoint addresses, host
identifiers, credentials, or sensitive packet captures into tracked files.

## Dry-Run First

Examples and generated tools should default to offline construction, decode, pcap
fixtures, or dry-run send plans. Use documentation addresses and synthetic
device identifiers:

```rust
use crafter::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() -> crafter::Result<()> {
    let ipv4_search = ssdp_ipv4_multicast_packet(
        Ipv4Addr::new(192, 0, 2, 10),
        Ssdp::m_search_all().mx(1),
    );
    let ipv6_search = ssdp_ipv6_multicast_packet(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10),
        Ssdp::m_search()
            .host(SSDP_IPV6_SITE_LOCAL_HOST)
            .man_discover()
            .mx(1)
            .search_target(SSDP_ST_ALL),
    );

    let ipv4_plan = ipv4_search.send_dry_run(
        SendOptions::new().iface("dry-run0").network_layer(),
    )?;
    let ipv6_plan = ipv6_search.send_dry_run(
        SendOptions::new().iface("dry-run0").network_layer(),
    )?;

    println!("mode: dry-run");
    println!("ipv4 target: {:?}", ipv4_plan.target());
    println!("ipv4 bytes: {}", ipv4_plan.len());
    println!("ipv6 target: {:?}", ipv6_plan.target());
    println!("ipv6 bytes: {}", ipv6_plan.len());
    Ok(())
}
```

The `ssdp_search_plan` example builds IPv4 and IPv6 M-SEARCH packets and
inspects dry-run network-layer send plans only:

```sh
cargo run -p crafter --example ssdp_search_plan -- --iface dry-run0
```

The `ssdp_notify` example compiles and decodes notification packets offline:

```sh
cargo run -p crafter --example ssdp_notify
```

Live SSDP validation belongs behind provider-backed endpoint, oracle, probe, or
lab workflows. Start with dry-run commands and keep all generated artifacts
under ignored `target/` paths:

```sh
tools/oracle/run live --backend scapy --provider local-dry-run --dry-run --family ssdp --profile smoke --seed 1905 --count 3 --out target/oracle/ssdp-live-local-dry-run

python3 tools/probe/engine/run.py --protocol ssdp --provider local-dry-run --dry-run --case ssdp-live-ipv4-search-exchange --out target/probe/ssdp-dry-run
```

Do not send real multicast or unicast SSDP traffic from examples or default
generated-tool paths. A real run requires an authorized provider-backed lab,
explicit confirmation, artifact collection, and teardown.

## Non-Goals

The SSDP layer is deliberately limited to wire-level packet primitives. It does
not implement:

- a network scanner or discovery sweep;
- a discovery daemon or advertised-device process;
- a service cache, expiration timer, or retry scheduler;
- a UPnP control point or device-control workflow;
- HTTP request execution, response fetching, XML parsing, SOAP, or GENA
  eventing;
- automatic live multicast traffic.

Keep higher-level discovery behavior in generated tools that explicitly choose
their targets, safety gates, retry policy, storage, and provider-backed live
environment.
