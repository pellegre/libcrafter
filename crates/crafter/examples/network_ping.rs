mod common;

use common::{
    arg_or, flag_present, parse_ipv4_arg, parse_u16_arg, print_help_if_requested,
    print_send_recv_report, send_recv_options, ExampleResult,
};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example network_ping -- [--live] [--iface IFACE] [--src IP] [--dst IP] [--id N] [--seq N]\n\nBuild an IPv4 ICMP echo request and use send/receive in dry-run mode by default.",
    ) {
        return Ok(());
    }

    let live = flag_present("--live");
    let iface = arg_or("--iface", "dry-run0");
    let src = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let dst = parse_ipv4_arg("--dst", Ipv4Addr::new(198, 51, 100, 20))?;
    let id = parse_u16_arg("--id", 0x4242)?;
    let seq = parse_u16_arg("--seq", 1)?;
    let packet = Ipv4::new().src(src).dst(dst)
        / Icmp::echo_request().id(id).seq(seq)
        / Raw::from("network-ping");
    let report = packet.send_recv_report(send_recv_options(&iface, live, false))?;

    print_send_recv_report("network_ping", &packet, &report);
    println!("hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
