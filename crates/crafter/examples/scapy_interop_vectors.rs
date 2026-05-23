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
            ipv6_icmp()?,
            dns_query()?,
            vlan_ipv4_udp()?,
        ],
    })
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

fn bytes_field(bytes: &[u8]) -> Value {
    json!({
        "ascii": String::from_utf8_lossy(bytes).to_string(),
        "hex": hex_bytes(bytes)
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
