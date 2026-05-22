mod common;

use common::{arg_or, parse_ipv4_arg, parse_u16_arg, print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example basic_send -- [--iface IFACE] [--src IP] [--dst IP] [--src-mac MAC] [--dst-mac MAC] [--sport PORT] [--dport PORT]\n\nBuild an Ethernet/IPv4/TCP packet and produce a compile-only send plan.",
    ) {
        return Ok(());
    }

    let iface = arg_or("--iface", "dry-run0");
    let src = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let dst = parse_ipv4_arg("--dst", Ipv4Addr::new(198, 51, 100, 20))?;
    let src_mac = arg_or("--src-mac", "02:00:5e:00:53:01");
    let dst_mac = arg_or("--dst-mac", "02:00:5e:00:53:ff");
    let sport = parse_u16_arg("--sport", 62345)?;
    let dport = parse_u16_arg("--dport", 80)?;

    let packet = common::example_ethernet_tcp_packet(
        src,
        dst,
        &src_mac,
        &dst_mac,
        sport,
        dport,
        "SomeTCPPayload\n",
    )?;
    let report = packet.send(SendOptions::new().iface(&iface).dry_run())?;

    println!("mode: dry-run");
    println!("interface: {}", report.plan().interface());
    println!("target: {:?}", report.plan().target());
    println!("bytes planned: {}", report.bytes_sent());
    println!("{}", packet.show());
    println!("hexdump:\n{}", report.plan().compiled_packet().hexdump());

    Ok(())
}
