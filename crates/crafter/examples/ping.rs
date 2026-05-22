mod common;

use common::{arg_or, parse_ipv4_arg, parse_u16_arg, print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ping -- [--iface IFACE] [--src IP] [--dst IP] [--id N] [--seq N] [--payload TEXT]\n\nBuild an IPv4 ICMP echo request and produce a compile-only send plan.",
    ) {
        return Ok(());
    }

    let iface = arg_or("--iface", "dry-run0");
    let src = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let dst = parse_ipv4_arg("--dst", Ipv4Addr::new(198, 51, 100, 20))?;
    let id = parse_u16_arg("--id", 0x4242)?;
    let seq = parse_u16_arg("--seq", 1)?;
    let payload = arg_or("--payload", "HelloPing!\n");

    let packet =
        Ipv4::new().src(src).dst(dst) / Icmp::echo_request().id(id).seq(seq) / Raw::from(payload);
    let plan = packet.send_dry_run(SendOptions::new().iface(&iface).network_layer())?;

    println!("mode: dry-run");
    println!("interface: {}", plan.interface());
    println!("target: {:?}", plan.target());
    println!(
        "reply filter: {}",
        reply_filter(&packet).unwrap_or_default()
    );
    println!("{}", packet.show());
    println!("hexdump:\n{}", plan.compiled_packet().hexdump());

    Ok(())
}
