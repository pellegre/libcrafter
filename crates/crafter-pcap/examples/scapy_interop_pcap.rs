use std::env;
use std::error::Error;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crafter_core::{
    Arp, Dhcp, Dns, DnsQuestion, Ethernet, Icmpv6, Ipv4, Ipv6, LinkType, MacAddr, Packet, Raw, Udp,
    DNS_PORT, DNS_TYPE_A, ETHERTYPE_ARP, ETHERTYPE_IPV4,
};
use crafter_pcap::{PcapLinkType, PcapReader, PcapTimestamp, PcapWriter};

type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

const SRC_MAC: &str = "02:00:5e:00:53:01";
const DST_MAC: &str = "02:00:5e:00:53:02";
const SRC_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DST_IPV4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const DNS_IPV4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 53);

struct ScapyReadExpectation {
    name: &'static str,
    core_layers: &'static [&'static str],
}

struct LibcrafterWriteCase {
    name: &'static str,
    packet: Packet,
    scapy_layers: &'static [&'static str],
}

fn main() -> ExampleResult<()> {
    let mut args = env::args().skip(1);
    let mut read_scapy: Option<PathBuf> = None;
    let mut expected_hex: Option<PathBuf> = None;
    let mut write_libcrafter: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--read-scapy" => read_scapy = Some(required_path(&mut args, "--read-scapy")?),
            "--expected-hex" => expected_hex = Some(required_path(&mut args, "--expected-hex")?),
            "--write-libcrafter" => {
                write_libcrafter = Some(required_path(&mut args, "--write-libcrafter")?)
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let ran_read = read_scapy.is_some();
    let ran_write = write_libcrafter.is_some();

    if let Some(path) = read_scapy {
        let expected_path =
            expected_hex.ok_or("--read-scapy requires --expected-hex with name-tab-hex rows")?;
        validate_scapy_written_pcap(&path, &expected_path)?;
    }

    if let Some(path) = write_libcrafter {
        write_libcrafter_pcap(&path)?;
    }

    if !ran_read && !ran_write {
        print_usage();
        return Err("no pcap action requested".into());
    }

    Ok(())
}

fn print_usage() {
    println!(
        "usage: cargo run -p crafter-pcap --example scapy_interop_pcap -- \
         --read-scapy PATH --expected-hex TSV | --write-libcrafter PATH"
    );
}

fn required_path(args: &mut impl Iterator<Item = String>, option: &str) -> ExampleResult<PathBuf> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("{option} requires a path").into())
}

fn validate_scapy_written_pcap(path: &Path, expected_path: &Path) -> ExampleResult<()> {
    let expectations = scapy_read_expectations();
    let expected_hex = read_expected_hex(expected_path)?;
    if expected_hex.len() != expectations.len() {
        return Err(format!(
            "expected {} pcap records, got {} expected-hex rows",
            expectations.len(),
            expected_hex.len()
        )
        .into());
    }

    let reader = PcapReader::open(path)?;
    if reader.pcap_link_type() != PcapLinkType::Ethernet {
        return Err(format!(
            "expected Ethernet pcap link type, got {:?}",
            reader.pcap_link_type()
        )
        .into());
    }

    let records = reader.collect_records()?;
    if records.len() != expectations.len() {
        return Err(format!(
            "expected {} pcap records, got {}",
            expectations.len(),
            records.len()
        )
        .into());
    }

    for ((record, expectation), (expected_name, expected_bytes)) in records
        .iter()
        .zip(expectations.iter())
        .zip(expected_hex.iter())
    {
        if expected_name != expectation.name {
            return Err(format!(
                "expected-hex row name mismatch: expected {}, got {}",
                expectation.name, expected_name
            )
            .into());
        }
        if record.data() != expected_bytes.as_slice() {
            return Err(format!("{}: pcap record bytes differ", expectation.name).into());
        }

        let decoded = record.decode()?;
        let layers = layer_names(&decoded);
        if layers != expectation.core_layers {
            return Err(format!(
                "{}: decoded layer mismatch expected={:?} actual={:?}",
                expectation.name, expectation.core_layers, layers
            )
            .into());
        }

        println!(
            "read\t{}\t{}\t{}",
            expectation.name,
            hex_bytes(record.data()),
            layers.join(",")
        );
    }

    Ok(())
}

fn write_libcrafter_pcap(path: &Path) -> ExampleResult<()> {
    let cases = libcrafter_write_cases()?;
    let mut writer = PcapWriter::create(path, LinkType::Ethernet)?;
    for (index, case) in cases.iter().enumerate() {
        let timestamp = PcapTimestamp::micros(index as u64 + 1, (index as u32) * 100)?;
        writer.write_packet_with_timestamp(&case.packet, timestamp)?;
    }
    writer.flush()?;

    for case in &cases {
        let compiled = case.packet.compile()?;
        println!(
            "{}\t{}\t{}",
            case.name,
            hex_bytes(compiled.as_bytes()),
            case.scapy_layers.join(",")
        );
    }

    Ok(())
}

fn scapy_read_expectations() -> Vec<ScapyReadExpectation> {
    vec![
        ScapyReadExpectation {
            name: "scapy-ethernet",
            core_layers: &["Ethernet", "Raw"],
        },
        ScapyReadExpectation {
            name: "scapy-arp-request",
            core_layers: &["Ethernet", "Arp"],
        },
        ScapyReadExpectation {
            name: "scapy-ipv4-udp",
            core_layers: &["Ethernet", "Ipv4", "Udp", "Raw"],
        },
        ScapyReadExpectation {
            name: "scapy-ipv6-icmp",
            core_layers: &["Ethernet", "Ipv6", "Icmpv6", "Raw"],
        },
        ScapyReadExpectation {
            name: "scapy-dns-query",
            core_layers: &["Ethernet", "Ipv4", "Udp", "Dns"],
        },
        ScapyReadExpectation {
            name: "scapy-dhcp-discover",
            core_layers: &["Ethernet", "Ipv4", "Udp", "Dhcp"],
        },
    ]
}

fn libcrafter_write_cases() -> ExampleResult<Vec<LibcrafterWriteCase>> {
    let src_mac = parse_mac(SRC_MAC)?;
    let dst_mac = parse_mac(DST_MAC)?;
    let src_ipv6 = "2001:db8:1::10".parse::<Ipv6Addr>()?;
    let dst_ipv6 = "2001:db8:2::20".parse::<Ipv6Addr>()?;

    Ok(vec![
        LibcrafterWriteCase {
            name: "libcrafter-ethernet",
            packet: Ethernet::new().src(src_mac).dst(dst_mac).ethertype(0x9000)
                / Raw::from("libcrafter-pcap-ethernet"),
            scapy_layers: &["Ether", "Raw"],
        },
        LibcrafterWriteCase {
            name: "libcrafter-arp-request",
            packet: Ethernet::new()
                .src(src_mac)
                .dst(MacAddr::BROADCAST)
                .ethertype(ETHERTYPE_ARP)
                / Arp::who_has(SRC_IPV4, Ipv4Addr::new(192, 0, 2, 1), src_mac),
            scapy_layers: &["Ether", "ARP"],
        },
        LibcrafterWriteCase {
            name: "libcrafter-ipv4-udp",
            packet: Ethernet::new()
                .src(src_mac)
                .dst(dst_mac)
                .ethertype(ETHERTYPE_IPV4)
                / Ipv4::new().src(SRC_IPV4).dst(DST_IPV4).id(0x4101).ttl(61)
                / Udp::new().sport(53010).dport(53011)
                / Raw::from("libcrafter-pcap-ipv4"),
            scapy_layers: &["Ether", "IP", "UDP", "Raw"],
        },
        LibcrafterWriteCase {
            name: "libcrafter-ipv6-icmp",
            packet: Ethernet::new().src(src_mac).dst(dst_mac)
                / Ipv6::new().src(src_ipv6).dst(dst_ipv6).fl(0x23456).hlim(62)
                / Icmpv6::echo_request().id(0x4244).seq(4)
                / Raw::from("libcrafter-pcap-ipv6"),
            scapy_layers: &["Ether", "IPv6", "ICMPv6EchoRequest"],
        },
        LibcrafterWriteCase {
            name: "libcrafter-dns-query",
            packet: Ethernet::new()
                .src(src_mac)
                .dst(dst_mac)
                .ethertype(ETHERTYPE_IPV4)
                / Ipv4::new().src(SRC_IPV4).dst(DNS_IPV4).id(0x4102).ttl(62)
                / Udp::new().sport(53012).dport(DNS_PORT)
                / Dns::new()
                    .id(0xbeef)
                    .question(DnsQuestion::new("pcap.example.", DNS_TYPE_A)),
            scapy_layers: &["Ether", "IP", "UDP", "DNS"],
        },
        LibcrafterWriteCase {
            name: "libcrafter-dhcp-discover",
            packet: Ethernet::new()
                .src(src_mac)
                .dst(MacAddr::BROADCAST)
                .ethertype(ETHERTYPE_IPV4)
                / Ipv4::new()
                    .src(Ipv4Addr::UNSPECIFIED)
                    .dst(Ipv4Addr::BROADCAST)
                    .id(0x4103)
                    .ttl(64)
                / Udp::dhcp_client()
                / Dhcp::discover(src_mac)
                    .xid(0x3903_f326)
                    .flags(0x8000)
                    .hostname("libcrafter-pcap")
                    .parameter_request_list(vec![1, 3, 6, 15]),
            scapy_layers: &["Ether", "IP", "UDP", "BOOTP", "DHCP"],
        },
    ])
}

fn read_expected_hex(path: &Path) -> ExampleResult<Vec<(String, Vec<u8>)>> {
    let mut rows = Vec::new();
    for (line_index, line) in fs::read_to_string(path)?.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (name, hex) = line.split_once('\t').ok_or_else(|| {
            format!(
                "{}:{}: expected name-tab-hex row",
                path.display(),
                line_index + 1
            )
        })?;
        rows.push((name.to_string(), parse_hex(hex)?));
    }
    Ok(rows)
}

fn parse_mac(value: &str) -> ExampleResult<MacAddr> {
    Ok(value.parse::<MacAddr>()?)
}

fn parse_hex(hex: &str) -> ExampleResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err("hex string must have an even number of digits".into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&hex[index..index + 2], 16)?);
    }
    Ok(bytes)
}

fn layer_names(packet: &Packet) -> Vec<&'static str> {
    packet.iter().map(|layer| layer.name()).collect()
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
