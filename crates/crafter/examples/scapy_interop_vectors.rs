use crafter::prelude::*;
use serde::Serialize;
use serde_json::{json, Value};
use std::env;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

const SRC_MAC: &str = "02:00:5e:00:53:01";
const DST_MAC: &str = "02:00:5e:00:53:02";
const SRC_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DST_IPV4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const GW_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const DNS_IPV4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 53);

#[derive(Serialize)]
struct Manifest {
    schema_version: u8,
    direction: &'static str,
    generator: &'static str,
    cases: Vec<Vector>,
}

#[derive(Serialize)]
struct Vector {
    name: &'static str,
    family: &'static str,
    direction: &'static str,
    root: &'static str,
    root_decoder: &'static str,
    expected_stack: Vec<&'static str>,
    strict_bytes: bool,
    length: usize,
    hex: String,
    summary: &'static str,
    field_assertions: Vec<FieldAssertion>,
}

#[derive(Serialize)]
struct FieldAssertion {
    layer: &'static str,
    fields: Value,
}

fn main() -> ExampleResult<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage();
        return Ok(());
    }

    let manifest = build_manifest()?;
    if args.iter().any(|arg| arg == "--list") {
        for case in &manifest.cases {
            println!("{}\t{}\t{}", case.name, case.root, case.summary);
        }
        return Ok(());
    }

    if args.is_empty() || args.iter().any(|arg| arg == "--json") {
        serde_json::to_writer_pretty(io::stdout(), &manifest)?;
        println!();
        return Ok(());
    }

    Err(format!("unknown arguments: {}", args.join(" ")).into())
}

fn print_usage() {
    println!(
        "usage: cargo run -p crafter --example scapy_interop_vectors -- [--list|--json]\n\nEmit deterministic libcrafter packet vectors for Scapy parser validation."
    );
}

fn build_manifest() -> ExampleResult<Manifest> {
    Ok(Manifest {
        schema_version: 1,
        direction: "libcrafter_to_scapy",
        generator: "crafter example scapy_interop_vectors",
        cases: vec![
            ethernet_raw()?,
            arp_request()?,
            ipv4_icmp()?,
            icmpv4_echo_reply()?,
            ipv6_icmp()?,
            dns_query()?,
            dhcp_discover()?,
            vlan_ipv4_udp()?,
            crafter_raw_payload()?,
            crafter_ethernet_unknown_ethertype()?,
            crafter_arp_reply()?,
            crafter_vlan_boundary_fields()?,
            crafter_linux_cooked_ipv4_udp()?,
            crafter_null_loopback_ipv4_little_endian()?,
            crafter_ipv4_boundary_fields()?,
            crafter_ipv4_unknown_protocol_raw()?,
            crafter_ipv4_fragment_mf_offset()?,
            crafter_ipv4_ttl_255()?,
            crafter_ipv4_options()?,
            crafter_ipv4_source_route_traceroute()?,
            crafter_ipv6_boundary_fields()?,
            crafter_ipv6_unknown_next_header_raw()?,
            crafter_ipv6_fragment_udp()?,
            crafter_ipv6_routing_generic()?,
            crafter_ipv6_mobile_routing()?,
            crafter_ipv6_segment_routing_udp()?,
            crafter_ipv6_routing_tcp_raw()?,
            crafter_ipv6_routing_icmpv6()?,
            crafter_udp_ipv4_checksum_payload()?,
            crafter_udp_ipv6_checksum_payload()?,
            crafter_tcp_all_flags_payload()?,
            crafter_tcp_common_options()?,
            crafter_tcp_advanced_options()?,
        ],
    })
}

#[allow(dead_code)]
pub(crate) fn manifest_json() -> std::result::Result<Value, Box<dyn Error>> {
    Ok(serde_json::to_value(build_manifest()?)?)
}

fn ethernet_raw() -> ExampleResult<Vector> {
    let packet = Ethernet::new()
        .src(parse_mac(SRC_MAC)?)
        .dst(parse_mac(DST_MAC)?)
        .ethertype(0x9000)
        / Raw::from("libcrafter-ethernet");

    vector(
        "ethernet",
        "link",
        "link:ethernet",
        vec!["Ether", "Raw"],
        "02:00:5e:00:53:01 > 02:00:5e:00:53:02 (0x9000) / Raw",
        packet,
        vec![
            fields(
                "Ether",
                json!({
                    "dst": DST_MAC,
                    "src": SRC_MAC,
                    "type": 36864
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"libcrafter-ethernet")
                }),
            ),
        ],
    )
}

fn arp_request() -> ExampleResult<Vector> {
    let src_mac = parse_mac(SRC_MAC)?;
    let packet = Ethernet::new()
        .src(src_mac)
        .dst(MacAddr::BROADCAST)
        .ethertype(ETHERTYPE_ARP)
        / Arp::who_has(SRC_IPV4, Ipv4Addr::new(192, 0, 2, 1), src_mac);

    vector(
        "arp-request",
        "link",
        "link:ethernet",
        vec!["Ether", "ARP"],
        "Ether / ARP who has 192.0.2.1 says 192.0.2.10",
        packet,
        vec![
            fields(
                "Ether",
                json!({
                    "dst": "ff:ff:ff:ff:ff:ff",
                    "src": SRC_MAC,
                    "type": 2054
                }),
            ),
            fields(
                "ARP",
                json!({
                    "hwtype": 1,
                    "ptype": 2048,
                    "hwlen": 6,
                    "plen": 4,
                    "op": 1,
                    "hwsrc": SRC_MAC,
                    "psrc": "192.0.2.10",
                    "hwdst": "00:00:00:00:00:00",
                    "pdst": "192.0.2.1"
                }),
            ),
        ],
    )
}

fn ipv4_icmp() -> ExampleResult<Vector> {
    let packet = Ipv4::new()
        .src(SRC_IPV4)
        .dst(DST_IPV4)
        .id(0x1234)
        .dont_fragment(true)
        / Icmp::echo_request().id(0x4242).seq(1)
        / Raw::from("libcrafter-icmp");

    vector(
        "ipv4-icmp",
        "icmp",
        "l3:ipv4",
        vec!["IP", "ICMP", "Raw"],
        "IP / ICMP 192.0.2.10 > 198.51.100.20 echo-request 0 / Raw",
        packet,
        vec![
            fields(
                "IP",
                json!({
                    "version": 4,
                    "ihl": 5,
                    "tos": 0,
                    "len": 43,
                    "id": 4660,
                    "flags": "DF",
                    "frag": 0,
                    "ttl": 64,
                    "proto": 1,
                    "chksum": 15436,
                    "src": "192.0.2.10",
                    "dst": "198.51.100.20",
                    "options": []
                }),
            ),
            fields(
                "ICMP",
                json!({
                    "type": 8,
                    "code": 0,
                    "chksum": 42960,
                    "id": 16962,
                    "seq": 1,
                    "unused": bytes_field(b"")
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"libcrafter-icmp")
                }),
            ),
        ],
    )
}

fn icmpv4_echo_reply() -> ExampleResult<Vector> {
    let packet = Ipv4::new()
        .src(DST_IPV4)
        .dst(SRC_IPV4)
        .id(0x1260)
        .dont_fragment(true)
        / Icmp::echo_reply().id(0x4243).seq(3)
        / Raw::from("libcrafter-icmp-reply");

    vector(
        "icmpv4-echo-reply",
        "icmp",
        "l3:ipv4",
        vec!["IP", "ICMP", "Raw"],
        "IP / ICMP echo-reply / Raw",
        packet,
        vec![fields(
            "Raw",
            json!({
                "load": bytes_field(b"libcrafter-icmp-reply")
            }),
        )],
    )
}

fn ipv6_icmp() -> ExampleResult<Vector> {
    let src = "2001:db8:1::10".parse::<Ipv6Addr>()?;
    let dst = "2001:db8:2::20".parse::<Ipv6Addr>()?;
    let packet = Ipv6::new().src(src).dst(dst).fl(0x12345).hlim(64)
        / Icmpv6::echo_request().id(0x4242).seq(2)
        / Raw::from("libcrafter-ipv6");

    vector(
        "ipv6-icmp",
        "icmp",
        "l3:ipv6",
        vec!["IPv6", "ICMPv6EchoRequest"],
        "IPv6 / ICMPv6 Echo Request (id: 0x4242 seq: 0x2)",
        packet,
        vec![
            fields(
                "IPv6",
                json!({
                    "version": 6,
                    "tc": 0,
                    "fl": 74565,
                    "plen": 23,
                    "nh": 58,
                    "hlim": 64,
                    "src": "2001:db8:1::10",
                    "dst": "2001:db8:2::20"
                }),
            ),
            fields(
                "ICMPv6EchoRequest",
                json!({
                    "type": 128,
                    "code": 0,
                    "cksum": 208,
                    "id": 16962,
                    "seq": 2,
                    "data": bytes_field(b"libcrafter-ipv6")
                }),
            ),
        ],
    )
}

fn dns_query() -> ExampleResult<Vector> {
    let packet = Ipv4::new().src(SRC_IPV4).dst(DNS_IPV4).id(0x1237).ttl(61)
        / Udp::new().sport(53001).dport(DNS_PORT)
        / Dns::new()
            .id(0xbeef)
            .question(DnsQuestion::new("example.com.", DNS_TYPE_A));

    vector(
        "dns-query",
        "dns",
        "l3:ipv4",
        vec!["IP", "UDP", "DNS"],
        "IP / UDP / DNS Qry b'example.com.'",
        packet,
        vec![
            fields(
                "IP",
                json!({
                    "version": 4,
                    "ihl": 5,
                    "tos": 0,
                    "len": 57,
                    "id": 4663,
                    "flags": "",
                    "frag": 0,
                    "ttl": 61,
                    "proto": 17,
                    "chksum": 32522,
                    "src": "192.0.2.10",
                    "dst": "198.51.100.53",
                    "options": []
                }),
            ),
            fields(
                "UDP",
                json!({
                    "sport": 53001,
                    "dport": 53,
                    "len": 37,
                    "chksum": 46484
                }),
            ),
            fields(
                "DNS",
                json!({
                    "id": 48879,
                    "qr": 0,
                    "opcode": 0,
                    "aa": 0,
                    "tc": 0,
                    "rd": 1,
                    "ra": 0,
                    "z": 0,
                    "ad": 0,
                    "cd": 0,
                    "rcode": 0,
                    "qdcount": 1,
                    "ancount": 0,
                    "nscount": 0,
                    "arcount": 0,
                    "qd": ["DNSQR"],
                    "an": [],
                    "ns": [],
                    "ar": []
                }),
            ),
        ],
    )
}

fn dhcp_discover() -> ExampleResult<Vector> {
    let src_mac = parse_mac(SRC_MAC)?;
    let packet = Ethernet::new()
        .src(src_mac)
        .dst(MacAddr::BROADCAST)
        .ethertype(ETHERTYPE_IPV4)
        / Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
            .id(0x1238)
            .ttl(64)
        / Udp::dhcp_client()
        / Dhcp::discover(src_mac)
            .xid(0x3903_f326)
            .flags(0x8000)
            .hostname("libcrafter-test")
            .parameter_request_list(vec![1, 3, 6, 15]);

    vector(
        "dhcp-discover",
        "dhcp",
        "link:ethernet",
        vec!["Ether", "IP", "UDP", "BOOTP", "DHCP"],
        "Ether / IP / UDP / BOOTP / DHCP Discover",
        packet,
        vec![],
    )
}

fn vlan_ipv4_udp() -> ExampleResult<Vector> {
    let packet = Ethernet::new()
        .src(parse_mac(SRC_MAC)?)
        .dst(parse_mac(DST_MAC)?)
        .ethertype(ETHERTYPE_VLAN)
        / Dot1Q::new().prio(3).vlan(42).ethertype(ETHERTYPE_IPV4)
        / Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x123b).ttl(58)
        / Udp::new().sport(53002).dport(9999)
        / Raw::from("vlan-udp");

    vector(
        "vlan-ipv4-udp",
        "link",
        "link:ethernet",
        vec!["Ether", "Dot1Q", "IP", "UDP", "Raw"],
        "Ether / Dot1Q / IP / UDP 192.0.2.10:53002 > 198.51.100.20:9999 / Raw",
        packet,
        vec![
            fields(
                "Ether",
                json!({
                    "dst": DST_MAC,
                    "src": SRC_MAC,
                    "type": 33024
                }),
            ),
            fields(
                "Dot1Q",
                json!({
                    "prio": 3,
                    "dei": 0,
                    "vlan": 42,
                    "type": 2048
                }),
            ),
            fields(
                "IP",
                json!({
                    "version": 4,
                    "ihl": 5,
                    "tos": 0,
                    "len": 36,
                    "id": 4667,
                    "flags": "",
                    "frag": 0,
                    "ttl": 58,
                    "proto": 17,
                    "chksum": 33340,
                    "src": "192.0.2.10",
                    "dst": "198.51.100.20",
                    "options": []
                }),
            ),
            fields(
                "UDP",
                json!({
                    "sport": 53002,
                    "dport": 9999,
                    "len": 16,
                    "chksum": 45985
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"vlan-udp")
                }),
            ),
        ],
    )
}

fn crafter_raw_payload() -> ExampleResult<Vector> {
    let packet = Packet::new().push(Raw::from("raw-link-payload"));

    vector(
        "crafter-raw-payload",
        "link",
        "link:raw",
        vec!["Raw"],
        "Raw",
        packet,
        vec![fields(
            "Raw",
            json!({
                "load": bytes_field(b"raw-link-payload")
            }),
        )],
    )
}

fn crafter_ethernet_unknown_ethertype() -> ExampleResult<Vector> {
    let packet = Ethernet::new()
        .src(parse_mac(SRC_MAC)?)
        .dst(parse_mac(DST_MAC)?)
        .ethertype(0x88b5)
        / Raw::from("unknown-ethertype");

    vector(
        "crafter-ethernet-unknown-ethertype",
        "link",
        "link:ethernet",
        vec!["Ether", "Raw"],
        "Ether / Raw",
        packet,
        vec![
            fields(
                "Ether",
                json!({
                    "dst": DST_MAC,
                    "src": SRC_MAC,
                    "type": 34997
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"unknown-ethertype")
                }),
            ),
        ],
    )
}

fn crafter_arp_reply() -> ExampleResult<Vector> {
    let src_mac = parse_mac(SRC_MAC)?;
    let dst_mac = parse_mac(DST_MAC)?;
    let packet = Ethernet::new()
        .src(src_mac)
        .dst(dst_mac)
        .ethertype(ETHERTYPE_ARP)
        / Arp::is_at(SRC_IPV4, src_mac, GW_IPV4, dst_mac);

    vector(
        "crafter-arp-reply",
        "link",
        "link:ethernet",
        vec!["Ether", "ARP"],
        "Ether / ARP is at 192.0.2.10",
        packet,
        vec![
            fields(
                "Ether",
                json!({
                    "dst": DST_MAC,
                    "src": SRC_MAC,
                    "type": 2054
                }),
            ),
            fields(
                "ARP",
                json!({
                    "op": 2,
                    "hwsrc": SRC_MAC,
                    "psrc": "192.0.2.10",
                    "hwdst": DST_MAC,
                    "pdst": "192.0.2.1"
                }),
            ),
        ],
    )
}

fn crafter_vlan_boundary_fields() -> ExampleResult<Vector> {
    let packet = Ethernet::new()
        .src(parse_mac(SRC_MAC)?)
        .dst(parse_mac(DST_MAC)?)
        .ethertype(ETHERTYPE_VLAN)
        / Dot1Q::new()
            .prio(7)
            .dei(true)
            .vlan(4094)
            .ethertype(ETHERTYPE_IPV4)
        / Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x1248).ttl(57)
        / Udp::new().sport(53003).dport(10000)
        / Raw::from("vlan-boundary");

    vector(
        "crafter-vlan-boundary-fields",
        "link",
        "link:ethernet",
        vec!["Ether", "Dot1Q", "IP", "UDP", "Raw"],
        "Ether / Dot1Q / IP / UDP / Raw",
        packet,
        vec![
            fields(
                "Dot1Q",
                json!({
                    "prio": 7,
                    "dei": 1,
                    "vlan": 4094,
                    "type": 2048
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"vlan-boundary")
                }),
            ),
        ],
    )
}

fn crafter_linux_cooked_ipv4_udp() -> ExampleResult<Vector> {
    let packet = LinuxSll::new()
        .packet_type(0)
        .address_type(1)
        .source_address(parse_mac(SRC_MAC)?)
        .protocol(ETHERTYPE_IPV4)
        / Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x1249).ttl(56)
        / Udp::new().sport(53004).dport(10001)
        / Raw::from("sll-udp");

    vector(
        "crafter-linux-cooked-ipv4-udp",
        "link",
        "link:linux-cooked",
        vec!["CookedLinux", "IP", "UDP", "Raw"],
        "CookedLinux / IP / UDP / Raw",
        packet,
        vec![
            fields(
                "CookedLinux",
                json!({
                    "pkttype": 0,
                    "lladdrtype": 1,
                    "lladdrlen": 6,
                    "src": bytes_field(&[0x02, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00]),
                    "proto": 2048
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"sll-udp")
                }),
            ),
        ],
    )
}

fn crafter_null_loopback_ipv4_little_endian() -> ExampleResult<Vector> {
    let packet = NullLoopback::ipv4()
        / Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x124a).ttl(55)
        / Icmp::echo_request().id(0x4244).seq(4);

    vector(
        "crafter-null-loopback-ipv4-little-endian",
        "link",
        "link:null-loopback",
        vec!["Loopback", "IP", "ICMP"],
        "Loopback / IP / ICMP",
        packet,
        vec![
            fields(
                "Loopback",
                json!({
                    "type": 2
                }),
            ),
            fields(
                "ICMP",
                json!({
                    "type": 8,
                    "code": 0,
                    "id": 16964,
                    "seq": 4
                }),
            ),
        ],
    )
}

fn crafter_ipv4_boundary_fields() -> ExampleResult<Vector> {
    let packet = Ipv4::new()
        .src(SRC_IPV4)
        .dst(DST_IPV4)
        .id(0x1243)
        .tos(0xb8)
        .ttl(0)
        .flags(7)
        .frag(0x1fff)
        .protocol(253)
        / Raw::from("v4-boundary");
    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    vector(
        "crafter-ipv4-boundary-fields",
        "ipv4",
        "l3:ipv4",
        vec!["IP", "Raw"],
        "IP / Raw",
        packet,
        vec![
            fields(
                "IP",
                json!({
                    "version": 4,
                    "ihl": 5,
                    "tos": 184,
                    "len": u16_at(bytes, 2),
                    "id": 4675,
                    "flags": "MF+DF+evil",
                    "frag": 8191,
                    "ttl": 0,
                    "proto": 253,
                    "chksum": u16_at(bytes, 10),
                    "src": "192.0.2.10",
                    "dst": "198.51.100.20"
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"v4-boundary")
                }),
            ),
        ],
    )
}

fn crafter_ipv4_unknown_protocol_raw() -> ExampleResult<Vector> {
    let packet = Ipv4::new()
        .src(SRC_IPV4)
        .dst(DST_IPV4)
        .id(0x1244)
        .ttl(64)
        .protocol(253)
        / Raw::from("unknown-ipv4");

    vector(
        "crafter-ipv4-unknown-protocol-raw",
        "ipv4",
        "l3:ipv4",
        vec!["IP", "Raw"],
        "IP / Raw",
        packet,
        vec![
            fields(
                "IP",
                json!({
                    "proto": 253,
                    "ttl": 64
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"unknown-ipv4")
                }),
            ),
        ],
    )
}

fn crafter_ipv4_fragment_mf_offset() -> ExampleResult<Vector> {
    let packet = Ipv4::new()
        .src(SRC_IPV4)
        .dst(DST_IPV4)
        .id(0x1245)
        .more_fragments(true)
        .frag(37)
        .protocol(253)
        / Raw::from("fragmented-tail");

    vector(
        "crafter-ipv4-fragment-mf-offset",
        "ipv4",
        "l3:ipv4",
        vec!["IP", "Raw"],
        "IP / Raw",
        packet,
        vec![
            fields(
                "IP",
                json!({
                    "flags": "MF",
                    "frag": 37,
                    "proto": 253
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"fragmented-tail")
                }),
            ),
        ],
    )
}

fn crafter_ipv4_ttl_255() -> ExampleResult<Vector> {
    let packet = Ipv4::new()
        .src(SRC_IPV4)
        .dst(DST_IPV4)
        .id(0x1246)
        .ttl(255)
        .dont_fragment(true)
        .protocol(253)
        / Raw::from("ttl255");

    vector(
        "crafter-ipv4-ttl-255",
        "ipv4",
        "l3:ipv4",
        vec!["IP", "Raw"],
        "IP / Raw",
        packet,
        vec![
            fields(
                "IP",
                json!({
                    "ttl": 255,
                    "flags": "DF",
                    "proto": 253
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"ttl255")
                }),
            ),
        ],
    )
}

fn crafter_ipv4_options() -> ExampleResult<Vector> {
    let ip = Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x1247).ttl(60);
    let ip = ip.ip_option(Ipv4Option::no_operation())?;
    let ip = ip.ip_option(Ipv4Option::record_route(4, vec![GW_IPV4]))?;
    let ip = ip.ip_option(Ipv4Option::generic(0x1e, [0xaa, 0xbb]))?;
    let ip = ip.ip_option(Ipv4Option::end_of_list())?;
    let packet = ip.protocol(253) / Raw::from("ip-options");
    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    vector(
        "crafter-ipv4-options",
        "ipv4",
        "l3:ipv4",
        vec!["IP", "Raw"],
        "IP / Raw",
        packet,
        vec![
            fields(
                "IP",
                json!({
                    "ihl": bytes[0] & 0x0f,
                    "len": u16_at(bytes, 2),
                    "proto": 253,
                    "chksum": u16_at(bytes, 10)
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"ip-options")
                }),
            ),
        ],
    )
}

fn crafter_ipv4_source_route_traceroute() -> ExampleResult<Vector> {
    let ip = Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x1248).ttl(62);
    let ip = ip.ip_option(Ipv4Option::loose_source_route(4, vec![GW_IPV4]))?;
    let ip = ip.ip_option(Ipv4Option::strict_source_route(4, vec![DST_IPV4]))?;
    let ip = ip.ip_option(Ipv4Option::traceroute(0x1234, 1, 0xffff, SRC_IPV4))?;
    let packet = ip.protocol(253) / Raw::from("srtrace");
    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    vector(
        "crafter-ipv4-source-route-traceroute",
        "ipv4",
        "l3:ipv4",
        vec!["IP", "Raw"],
        "IP / Raw",
        packet,
        vec![
            fields(
                "IP",
                json!({
                    "ihl": bytes[0] & 0x0f,
                    "len": u16_at(bytes, 2),
                    "proto": 253,
                    "chksum": u16_at(bytes, 10)
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"srtrace")
                }),
            ),
        ],
    )
}

fn crafter_ipv6_boundary_fields() -> ExampleResult<Vector> {
    let packet = Ipv6::new()
        .src(src_ipv6()?)
        .dst(dst_ipv6()?)
        .tc(0xab)
        .fl(0xfffff)
        .hlim(0)
        .nh(253)
        / Raw::from("v6-boundary");

    vector(
        "crafter-ipv6-boundary-fields",
        "ipv6",
        "l3:ipv6",
        vec!["IPv6", "Raw"],
        "IPv6 / Raw",
        packet,
        vec![
            fields(
                "IPv6",
                json!({
                    "tc": 171,
                    "fl": 1048575,
                    "plen": 11,
                    "nh": 253,
                    "hlim": 0
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"v6-boundary")
                }),
            ),
        ],
    )
}

fn crafter_ipv6_unknown_next_header_raw() -> ExampleResult<Vector> {
    let packet = Ipv6::new()
        .src(src_ipv6()?)
        .dst(dst_ipv6()?)
        .fl(0)
        .hlim(255)
        .nh(253)
        / Raw::from("unknown-ipv6");

    vector(
        "crafter-ipv6-unknown-next-header-raw",
        "ipv6",
        "l3:ipv6",
        vec!["IPv6", "Raw"],
        "IPv6 / Raw",
        packet,
        vec![
            fields(
                "IPv6",
                json!({
                    "fl": 0,
                    "nh": 253,
                    "hlim": 255
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"unknown-ipv6")
                }),
            ),
        ],
    )
}

fn crafter_ipv6_fragment_udp() -> ExampleResult<Vector> {
    let packet = Ipv6::new().src(src_ipv6()?).dst(dst_ipv6()?)
        / Ipv6FragmentHeader::new()
            .nh(IPPROTO_UDP)
            .identification(0x0102_0304)
            .more_fragments(true)
        / Udp::new().sport(53005).dport(10002)
        / Raw::from("fragudp");

    vector(
        "crafter-ipv6-fragment-udp",
        "ipv6",
        "l3:ipv6",
        vec!["IPv6", "IPv6ExtHdrFragment", "UDP", "Raw"],
        "IPv6 / IPv6ExtHdrFragment / UDP / Raw",
        packet,
        vec![
            fields(
                "IPv6ExtHdrFragment",
                json!({
                    "nh": 17,
                    "offset": 0,
                    "m": 1,
                    "id": 16909060
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"fragudp")
                }),
            ),
        ],
    )
}

fn crafter_ipv6_routing_generic() -> ExampleResult<Vector> {
    let packet = Ipv6::new().src(src_ipv6()?).dst(dst_ipv6()?)
        / Ipv6RoutingHeader::new()
            .nh(253)
            .routing_type(253)
            .segments_left(0)
        / Raw::from("route-raw");

    vector(
        "crafter-ipv6-routing-generic",
        "ipv6",
        "l3:ipv6",
        vec!["IPv6", "IPv6ExtHdrRouting", "Raw"],
        "IPv6 / IPv6ExtHdrRouting / Raw",
        packet,
        vec![
            fields(
                "IPv6ExtHdrRouting",
                json!({
                    "nh": 253,
                    "len": 0,
                    "type": 253,
                    "segleft": 0,
                    "addresses": []
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"route-raw")
                }),
            ),
        ],
    )
}

fn crafter_ipv6_mobile_routing() -> ExampleResult<Vector> {
    let packet = Ipv6::new().src(src_ipv6()?).dst(dst_ipv6()?)
        / Ipv6MobileRoutingHeader::new()
            .nh(253)
            .home_address_str("2001:db8:ffff::1")?
        / Raw::from("mobile-raw");

    vector(
        "crafter-ipv6-mobile-routing",
        "ipv6",
        "l3:ipv6",
        vec!["IPv6", "IPv6ExtHdrRouting", "Raw"],
        "IPv6 / IPv6ExtHdrRouting / Raw",
        packet,
        vec![
            fields(
                "IPv6ExtHdrRouting",
                json!({
                    "nh": 253,
                    "len": 2,
                    "type": 2,
                    "segleft": 1,
                    "addresses": ["2001:db8:ffff::1"]
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"mobile-raw")
                }),
            ),
        ],
    )
}

fn crafter_ipv6_segment_routing_udp() -> ExampleResult<Vector> {
    let packet = Ipv6::new().src(src_ipv6()?).dst(dst_ipv6()?)
        / Ipv6SegmentRoutingHeader::new()
            .push_ipv6_segment("2001:db8:ffff::1")?
            .push_ipv6_segment("2001:db8:ffff::2")?
        / Udp::new().sport(53006).dport(10003)
        / Raw::from("srhudp");

    vector(
        "crafter-ipv6-segment-routing-udp",
        "ipv6",
        "l3:ipv6",
        vec!["IPv6", "IPv6ExtHdrSegmentRouting", "UDP", "Raw"],
        "IPv6 / IPv6ExtHdrSegmentRouting / UDP / Raw",
        packet,
        vec![
            fields(
                "IPv6ExtHdrSegmentRouting",
                json!({
                    "nh": 17,
                    "len": 4,
                    "type": 4,
                    "segleft": 1,
                    "lastentry": 1,
                    "addresses": ["2001:db8:ffff::1", "2001:db8:ffff::2"]
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"srhudp")
                }),
            ),
        ],
    )
}

fn crafter_ipv6_routing_tcp_raw() -> ExampleResult<Vector> {
    let packet = Ipv6::new().src(src_ipv6()?).dst(dst_ipv6()?)
        / Ipv6RoutingHeader::new()
            .nh(IPPROTO_TCP)
            .routing_type(253)
            .segments_left(0)
        / Tcp::new()
            .sport(53007)
            .dport(443)
            .flags(TCP_FLAG_PSH | TCP_FLAG_ACK)
        / Raw::from("chain");

    vector(
        "crafter-ipv6-routing-tcp-raw",
        "ipv6",
        "l3:ipv6",
        vec!["IPv6", "IPv6ExtHdrRouting", "TCP", "Raw"],
        "IPv6 / IPv6ExtHdrRouting / TCP / Raw",
        packet,
        vec![
            fields(
                "IPv6ExtHdrRouting",
                json!({
                    "nh": 6,
                    "type": 253,
                    "segleft": 0
                }),
            ),
            fields(
                "TCP",
                json!({
                    "sport": 53007,
                    "dport": 443,
                    "flags": "PA"
                }),
            ),
            fields(
                "Raw",
                json!({
                    "load": bytes_field(b"chain")
                }),
            ),
        ],
    )
}

fn crafter_ipv6_routing_icmpv6() -> ExampleResult<Vector> {
    let packet = Ipv6::new().src(src_ipv6()?).dst(dst_ipv6()?)
        / Ipv6RoutingHeader::new()
            .nh(IPPROTO_ICMPV6)
            .routing_type(253)
            .segments_left(0)
        / Icmpv6::echo_request().id(0x4246).seq(6)
        / Raw::from("routeicmp");

    vector(
        "crafter-ipv6-routing-icmpv6",
        "ipv6",
        "l3:ipv6",
        vec!["IPv6", "IPv6ExtHdrRouting", "ICMPv6EchoRequest"],
        "IPv6 / IPv6ExtHdrRouting / ICMPv6 Echo Request",
        packet,
        vec![
            fields(
                "IPv6ExtHdrRouting",
                json!({
                    "nh": 58,
                    "type": 253,
                    "segleft": 0
                }),
            ),
            fields(
                "ICMPv6EchoRequest",
                json!({
                    "type": 128,
                    "code": 0,
                    "id": 16966,
                    "seq": 6,
                    "data": bytes_field(b"routeicmp")
                }),
            ),
        ],
    )
}

fn crafter_udp_ipv4_checksum_payload() -> ExampleResult<Vector> {
    let packet = Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x1251).ttl(63)
        / Udp::new().sport(53011).dport(33441)
        / Raw::from("odd");

    vector(
        "crafter-udp-ipv4-checksum-payload",
        "transport",
        "l3:ipv4",
        vec!["IP", "UDP", "Raw"],
        "IP / UDP / Raw",
        packet,
        vec![fields(
            "Raw",
            json!({
                "load": bytes_field(b"odd")
            }),
        )],
    )
}

fn crafter_udp_ipv6_checksum_payload() -> ExampleResult<Vector> {
    let packet = Ipv6::new().src(src_ipv6()?).dst(dst_ipv6()?).hlim(62)
        / Udp::new().sport(53017).dport(33447)
        / Raw::from("libcrafter-udp6");

    vector(
        "crafter-udp-ipv6-checksum-payload",
        "transport",
        "l3:ipv6",
        vec!["IPv6", "UDP", "Raw"],
        "IPv6 / UDP / Raw",
        packet,
        vec![fields(
            "Raw",
            json!({
                "load": bytes_field(b"libcrafter-udp6")
            }),
        )],
    )
}

fn crafter_tcp_all_flags_payload() -> ExampleResult<Vector> {
    let packet = Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x1257).ttl(58)
        / Tcp::new()
            .sport(40003)
            .dport(443)
            .reserved(7)
            .flags(
                TCP_FLAG_NS
                    | TCP_FLAG_CWR
                    | TCP_FLAG_ECE
                    | TCP_FLAG_URG
                    | TCP_FLAG_ACK
                    | TCP_FLAG_PSH
                    | TCP_FLAG_RST
                    | TCP_FLAG_SYN
                    | TCP_FLAG_FIN,
            )
            .seq(0x0405_0607)
            .ack(0x2122_2324)
            .window(4096)
            .urgptr(0xbeef)
        / Raw::from("all-flags");

    vector(
        "crafter-tcp-all-flags-payload",
        "transport",
        "l3:ipv4",
        vec!["IP", "TCP", "Raw"],
        "IP / TCP / Raw",
        packet,
        vec![fields(
            "Raw",
            json!({
                "load": bytes_field(b"all-flags")
            }),
        )],
    )
}

fn crafter_tcp_common_options() -> ExampleResult<Vector> {
    let mut tcp = Tcp::new()
        .sport(40009)
        .dport(443)
        .seq(0x1122_3344)
        .flags(TCP_FLAG_SYN)
        .window(65535);
    tcp = tcp.tcp_option(TcpOption::mss(1460))?;
    tcp = tcp.tcp_option(TcpOption::sack_permitted())?;
    tcp = tcp.tcp_option(TcpOption::timestamp(0x0102_0304, 0x0506_0708))?;
    tcp = tcp.tcp_option(TcpOption::window_scale(7))?;

    let packet = Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x1259).ttl(59) / tcp;

    vector(
        "crafter-tcp-common-options",
        "transport",
        "l3:ipv4",
        vec!["IP", "TCP"],
        "IP / TCP",
        packet,
        vec![],
    )
}

fn crafter_tcp_advanced_options() -> ExampleResult<Vector> {
    let mut tcp = Tcp::new()
        .sport(40010)
        .dport(443)
        .seq(0x090a_0b0c)
        .flags(TCP_FLAG_SYN);
    tcp = tcp.tcp_option(TcpOption::extended_data_offset_request())?;
    tcp = tcp.tcp_option(TcpOption::extended_data_offset(16))?;
    tcp = tcp.tcp_option(TcpOption::extended_data_offset_ext(16, 96))?;
    tcp = tcp.tcp_option(TcpOption::multipath_tcp(1, [0x03, 0xaa, 0xbb]))?;
    tcp = tcp.tcp_option(TcpOption::fast_open([0xde, 0xad]))?;
    tcp = tcp.tcp_option(TcpOption::generic(254, [0xaa, 0xbb]))?;

    let packet = Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x125a).ttl(53)
        / tcp
        / Raw::from("tcp-option-tail");

    vector(
        "crafter-tcp-advanced-options",
        "transport",
        "l3:ipv4",
        vec!["IP", "TCP", "Raw"],
        "IP / TCP / Raw",
        packet,
        vec![fields(
            "Raw",
            json!({
                "load": bytes_field(b"tcp-option-tail")
            }),
        )],
    )
}

fn vector(
    name: &'static str,
    family: &'static str,
    root: &'static str,
    expected_stack: Vec<&'static str>,
    summary: &'static str,
    packet: Packet,
    field_assertions: Vec<FieldAssertion>,
) -> ExampleResult<Vector> {
    let compiled = packet.compile()?;
    Ok(Vector {
        name,
        family,
        direction: "libcrafter_to_scapy",
        root,
        root_decoder: root,
        expected_stack,
        strict_bytes: true,
        length: compiled.len(),
        hex: hex_bytes(compiled.as_bytes()),
        summary,
        field_assertions,
    })
}

fn fields(layer: &'static str, fields: Value) -> FieldAssertion {
    FieldAssertion { layer, fields }
}

fn parse_mac(value: &str) -> ExampleResult<MacAddr> {
    Ok(value.parse::<MacAddr>()?)
}

fn src_ipv6() -> ExampleResult<Ipv6Addr> {
    Ok("2001:db8:1::10".parse::<Ipv6Addr>()?)
}

fn dst_ipv6() -> ExampleResult<Ipv6Addr> {
    Ok("2001:db8:2::20".parse::<Ipv6Addr>()?)
}

fn bytes_field(bytes: &[u8]) -> Value {
    json!({
        "ascii": String::from_utf8_lossy(bytes).to_string(),
        "hex": hex_bytes(bytes)
    })
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
