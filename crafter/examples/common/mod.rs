#![allow(dead_code)]

use std::env;
use std::error::Error;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crafter::prelude::*;

pub type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

/// Documentation-safe example interface: dry-run0.
pub const EXAMPLE_IFACE: &str = "dry-run0";
/// Documentation-safe local IPv4 address: 192.0.2.10.
pub const LOCAL_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
/// Documentation-safe remote IPv4 address: 198.51.100.20.
pub const REMOTE_IPV4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
/// Documentation-safe gateway IPv4 address: 192.0.2.1.
pub const GATEWAY_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// Documentation-safe intermediary IPv4 address: 203.0.113.1.
pub const INTERMEDIARY_IPV4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
/// Documentation-safe local IPv6 address: 2001:db8::10.
pub const LOCAL_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010);
/// Documentation-safe remote IPv6 address: 2001:db8::20.
pub const REMOTE_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0020);
/// Documentation-safe local MAC address: 02:00:5e:00:53:01.
pub const LOCAL_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
/// Documentation-safe remote MAC address: 02:00:5e:00:53:02.
pub const REMOTE_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]);
/// Link type used by generated offline pcap examples.
pub const EXAMPLE_PCAP_LINK_TYPE: LinkType = LinkType::Ethernet;

pub const fn local_ipv4() -> Ipv4Addr {
    LOCAL_IPV4
}

pub const fn remote_ipv4() -> Ipv4Addr {
    REMOTE_IPV4
}

pub const fn gateway_ipv4() -> Ipv4Addr {
    GATEWAY_IPV4
}

pub const fn intermediary_ipv4() -> Ipv4Addr {
    INTERMEDIARY_IPV4
}

pub const fn local_ipv6() -> Ipv6Addr {
    LOCAL_IPV6
}

pub const fn remote_ipv6() -> Ipv6Addr {
    REMOTE_IPV6
}

pub const fn local_mac() -> MacAddr {
    LOCAL_MAC
}

pub const fn remote_mac() -> MacAddr {
    REMOTE_MAC
}

pub fn print_help_if_requested(usage: &str) -> bool {
    if env::args().any(|arg| arg == "--help" || arg == "-h") {
        println!("{usage}");
        true
    } else {
        false
    }
}

pub fn arg_value(name: &str) -> Option<String> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }

        if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
            return Some(value.to_string());
        }
    }

    None
}

pub fn arg_or(name: &str, default: &str) -> String {
    arg_value(name).unwrap_or_else(|| default.to_string())
}

pub fn flag_present(name: &str) -> bool {
    env::args().skip(1).any(|arg| arg == name)
}

pub const ADVANCED_LIVE_ACK_FLAG: &str = "--i-understand-isolated-lab";
pub const LIVE_WIRE_ENV: &str = "LIBCRAFTER_ENDPOINT";

pub fn live_wire_marker_present() -> bool {
    env::var(LIVE_WIRE_ENV)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "isolated"
            )
        })
        .unwrap_or(false)
}

pub fn require_advanced_wire_endpoint(example: &str) -> ExampleResult<()> {
    if !flag_present("--live") {
        return Ok(());
    }

    let mut missing = Vec::new();
    if !flag_present(ADVANCED_LIVE_ACK_FLAG) {
        missing.push(format!("CLI acknowledgement flag {ADVANCED_LIVE_ACK_FLAG}"));
    }
    if !live_wire_marker_present() {
        missing.push(format!("environment marker {LIVE_WIRE_ENV}=1"));
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{example} can change network traffic and is only enabled on an isolated wire endpoint; missing {}",
            missing.join(" and ")
        )
        .into())
    }
}

pub fn live_mode(example: &str) -> ExampleResult<bool> {
    let live = flag_present("--live");
    if live {
        require_advanced_wire_endpoint(example)?;
    }
    Ok(live)
}

pub fn print_advanced_safety(example: &str, live: bool) {
    println!("example: {example}");
    println!("mode: {}", if live { "wire-endpoint" } else { "dry-run" });
    if live {
        println!("safety: --live, {ADVANCED_LIVE_ACK_FLAG}, and {LIVE_WIRE_ENV}=1 were required");
    } else {
        println!("safety: no packets are transmitted without --live, {ADVANCED_LIVE_ACK_FLAG}, and {LIVE_WIRE_ENV}=1");
    }
}

pub fn print_packet_plan(label: &str, packet: &Packet) -> ExampleResult<()> {
    let compiled = packet.compile()?;
    println!("{label}: {}", packet.summary());
    println!("{label} bytes: {}", compiled.len());
    println!("{label} hexdump:\n{}", compiled.hexdump());
    Ok(())
}

pub fn print_batch_send_report(label: &str, report: &BatchSendReport) {
    println!("batch: {label}");
    println!("dry-run: {}", report.is_dry_run());
    println!("requests: {}", report.len());
    for entry in report.entries() {
        for (attempt, send) in entry.send_reports().iter().enumerate() {
            println!(
                "request {} attempt {} bytes {} target {:?}",
                entry.request_index(),
                attempt + 1,
                send.bytes_sent(),
                send.plan().target()
            );
        }
    }
}

pub fn parse_u16_arg(name: &str, default: u16) -> ExampleResult<u16> {
    Ok(match arg_value(name) {
        Some(value) => value.parse()?,
        None => default,
    })
}

pub fn parse_usize_arg(name: &str, default: usize) -> ExampleResult<usize> {
    Ok(match arg_value(name) {
        Some(value) => value.parse()?,
        None => default,
    })
}

pub fn parse_ipv4_arg(name: &str, default: Ipv4Addr) -> ExampleResult<Ipv4Addr> {
    Ok(match arg_value(name) {
        Some(value) => value.parse()?,
        None => default,
    })
}

pub fn parse_ipv6_arg(name: &str, default: Ipv6Addr) -> ExampleResult<Ipv6Addr> {
    Ok(match arg_value(name) {
        Some(value) => value.parse()?,
        None => default,
    })
}

pub fn parse_mac_arg(name: &str, default: MacAddr) -> ExampleResult<MacAddr> {
    Ok(match arg_value(name) {
        Some(value) => value.parse()?,
        None => default,
    })
}

pub fn send_options(iface: &str, live: bool, link_layer: bool) -> SendOptions {
    let options = if link_layer {
        SendOptions::new().iface(iface).link_layer()
    } else {
        SendOptions::new().iface(iface).network_layer()
    };

    if live {
        options.live()
    } else {
        options.dry_run()
    }
}

pub fn send_recv_options(iface: &str, live: bool, link_layer: bool) -> SendRecv {
    let options = if link_layer {
        SendRecv::new().iface(iface).link_layer()
    } else {
        SendRecv::new().iface(iface).network_layer()
    };

    let options = options.timeout(Duration::from_secs(1)).retries(1);
    if live {
        options.live()
    } else {
        options.dry_run()
    }
}

pub fn print_send_report(label: &str, packet: &Packet, report: &SendReport) {
    println!("example: {label}");
    println!(
        "mode: {}",
        if report.is_dry_run() {
            "dry-run"
        } else {
            "live"
        }
    );
    println!("interface: {}", report.plan().interface());
    println!("target: {:?}", report.plan().target());
    println!("bytes planned: {}", report.bytes_sent());
    println!("summary: {}", packet.summary());
    println!("hexdump:\n{}", report.plan().compiled_packet().hexdump());
}

pub fn print_send_recv_report(label: &str, packet: &Packet, report: &SendRecvReport) {
    println!("example: {label}");
    println!("attempts: {}", report.attempts());
    println!("timed out: {}", report.timed_out());
    println!(
        "effective filter: {}",
        report.effective_filter().unwrap_or("")
    );
    println!("summary: {}", packet.summary());
    if let Some(reply) = report.reply() {
        println!("reply: {}", reply.summary());
    }
}

pub fn default_target_path(file_name: &str) -> PathBuf {
    PathBuf::from("target").join(file_name)
}

pub fn ensure_parent(path: &Path) -> ExampleResult<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    Ok(())
}

pub fn example_ipv4_icmp_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &str) -> Packet {
    Ipv4::new().src(src).dst(dst).id(0x1234).dont_fragment(true)
        / Icmpv4::echo_request().id(0x4242).seq(1)
        / Raw::from(payload)
}

pub fn example_ethernet_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_mac: &str,
    dst_mac: &str,
    src_port: u16,
    dst_port: u16,
    payload: &str,
) -> ExampleResult<Packet> {
    Ok(Ethernet::new().src_str(src_mac)?.dst_str(dst_mac)?
        / Ipv4::new()
            .src(src_ip)
            .dst(dst_ip)
            .id(0x2222)
            .ipv4_protocol(Ipv4Protocol::Tcp)
        / Tcp::new()
            .sport(src_port)
            .dport(dst_port)
            .flags(TCP_FLAG_SYN | TCP_FLAG_CWR | TCP_FLAG_ECE)
        / Raw::from(payload))
}

pub fn example_pcap_packets(count: usize) -> ExampleResult<Vec<Packet>> {
    const BASE_TCP_SOURCE_PORT: u16 = 62_345;
    let src_ip = LOCAL_IPV4;
    let dst_ip = REMOTE_IPV4;
    let src_mac = LOCAL_MAC.to_string();
    let dst_mac = REMOTE_MAC.to_string();

    let mut packets = Vec::with_capacity(count);
    for offset in 0..count {
        let port_offset = u16::try_from(offset).unwrap_or(u16::MAX - BASE_TCP_SOURCE_PORT);
        let payload = format!("SomeTCPPayload-{offset}\n");
        packets.push(example_ethernet_tcp_packet(
            src_ip,
            dst_ip,
            &src_mac,
            &dst_mac,
            BASE_TCP_SOURCE_PORT.saturating_add(port_offset),
            80,
            &payload,
        )?);
    }

    Ok(packets)
}

pub fn write_example_pcap(path: &Path, count: usize) -> ExampleResult<Vec<Packet>> {
    ensure_parent(path)?;

    let packets = example_pcap_packets(count)?;
    let mut writer = PacketWire::pcap_recorder(path, EXAMPLE_PCAP_LINK_TYPE)
        .open()?
        .writer()?;
    for packet in &packets {
        writer.write_record(&PacketRecord::new(packet.clone()))?;
    }

    Ok(packets)
}
