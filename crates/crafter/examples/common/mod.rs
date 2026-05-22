#![allow(dead_code)]

use std::env;
use std::error::Error;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crafter::prelude::*;

pub type ExampleResult<T> = std::result::Result<T, Box<dyn Error>>;

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
        / Icmp::echo_request().id(0x4242).seq(1)
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
        / Ipv4::new().src(src_ip).dst(dst_ip).id(0x2222)
        / Tcp::new()
            .sport(src_port)
            .dport(dst_port)
            .flags(TCP_FLAG_SYN | TCP_FLAG_CWR | TCP_FLAG_ECE)
        / Raw::from(payload))
}

pub fn write_example_pcap(path: &Path, count: usize) -> ExampleResult<Vec<Packet>> {
    ensure_parent(path)?;

    let src_ip = Ipv4Addr::new(192, 0, 2, 10);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 20);
    let src_mac = "02:00:5e:00:53:01";
    let dst_mac = "02:00:5e:00:53:ff";

    let mut packets = Vec::new();
    packets.push(example_ethernet_tcp_packet(
        src_ip,
        dst_ip,
        src_mac,
        dst_mac,
        62345,
        80,
        "SomeTCPPayload\n",
    )?);

    for offset in 1..count.max(1) {
        packets.push(example_ethernet_tcp_packet(
            src_ip,
            dst_ip,
            src_mac,
            dst_mac,
            62345 + offset as u16,
            80,
            "SomeTCPPayload\n",
        )?);
    }

    dump_pcap(path, &packets, LinkType::Ethernet)?;
    Ok(packets)
}
