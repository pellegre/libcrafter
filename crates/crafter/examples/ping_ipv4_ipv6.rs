mod common;

use common::{arg_or, flag_present, print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ping_ipv4_ipv6 -- [--live] [--iface IFACE]\n\nBuild IPv4 and IPv6 echo requests and batch them through send/receive. The default is dry-run.",
    ) {
        return Ok(());
    }

    let live = flag_present("--live");
    let iface = arg_or("--iface", "dry-run0");
    let packets = vec![
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Icmp::echo_request().id(1).seq(1)
            / Raw::from("ipv4"),
        Ipv6::new()
            .src("2001:db8::10".parse::<Ipv6Addr>()?)
            .dst("2001:db8::20".parse::<Ipv6Addr>()?)
            / Icmpv6::echo_request().id(2).seq(1)
            / Raw::from("ipv6"),
    ];
    let options = if live {
        BatchSendRecv::new()
            .iface(&iface)
            .network_layer()
            .live()
            .retries(1)
    } else {
        BatchSendRecv::new()
            .iface(&iface)
            .network_layer()
            .dry_run()
            .retries(1)
    };
    let report = send_recv_packets(&packets, options)?;

    println!("example: ping_ipv4_ipv6");
    println!("mode: {}", if live { "live" } else { "dry-run" });
    println!("requests: {}", report.len());
    println!(
        "effective filter: {}",
        report.effective_filter().unwrap_or("")
    );
    for packet in &packets {
        println!("{}", packet.summary());
    }

    Ok(())
}
