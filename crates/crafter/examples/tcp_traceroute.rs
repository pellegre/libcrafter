mod common;

use common::{
    arg_or, flag_present, parse_u16_arg, parse_usize_arg, print_help_if_requested, ExampleResult,
};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example tcp_traceroute -- [--dry-run] [--live] [--iface IFACE] [--src IP] [--host IP] [--port PORT] [--max-hops N]\n\nBuild a TCP SYN traceroute probe set. The default is dry-run.",
    ) {
        return Ok(());
    }

    let live = flag_present("--live");
    let iface = arg_or("--iface", "dry-run0");
    let src: Ipv4Addr = arg_or("--src", "192.0.2.10").parse()?;
    let host: Ipv4Addr = arg_or("--host", "198.51.100.20").parse()?;
    let port = parse_u16_arg("--port", 80)?;
    let max_hops = parse_usize_arg("--max-hops", 4)?.min(u8::MAX as usize);
    let packets = (1..=max_hops)
        .map(|ttl| {
            Ipv4::new().src(src).dst(host).ttl(ttl as u8)
                / Tcp::new()
                    .sport(40000 + ttl as u16)
                    .dport(port)
                    .seq(ttl as u32)
                    .flags(TCP_FLAG_SYN)
        })
        .collect::<Vec<_>>();
    let options = if live {
        BatchSendRecv::new()
            .iface(&iface)
            .network_layer()
            .live()
            .retries(1)
            .filter("icmp or tcp")
    } else {
        BatchSendRecv::new()
            .iface(&iface)
            .network_layer()
            .dry_run()
            .retries(1)
            .filter("icmp or tcp")
    };
    let report = send_recv_packets(&packets, options)?;

    println!("example: tcp_traceroute");
    println!("mode: {}", if live { "live" } else { "dry-run" });
    println!("host: {host}");
    println!("probes: {}", report.len());
    println!(
        "effective filter: {}",
        report.effective_filter().unwrap_or("")
    );
    for (index, packet) in packets.iter().enumerate() {
        println!("hop {}: {}", index + 1, packet.summary());
    }

    Ok(())
}
