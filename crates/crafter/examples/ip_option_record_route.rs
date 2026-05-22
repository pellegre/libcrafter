mod common;

use common::{parse_ipv4_arg, print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ip_option_record_route -- [--src IP] [--dst IP]\n\nBuild an IPv4 packet with a typed record-route option.",
    ) {
        return Ok(());
    }

    let src = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let dst = parse_ipv4_arg("--dst", Ipv4Addr::new(198, 51, 100, 20))?;
    let route_slot = Ipv4Addr::new(203, 0, 113, 1);
    let packet = Ipv4::new()
        .src(src)
        .dst(dst)
        .ip_option(Ipv4Option::record_route(
            4,
            vec![route_slot, Ipv4Addr::UNSPECIFIED],
        ))?
        / Icmp::echo_request().id(0x1234).seq(1)
        / Raw::from("record-route");

    println!("{}", packet.show());
    println!("hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
