mod common;

use common::{parse_ipv4_arg, print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ip_options -- [--src IP] [--dst IP]\n\nBuild an IPv4 packet with traceroute, NOP, and generic options.",
    ) {
        return Ok(());
    }

    let src = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let dst = parse_ipv4_arg("--dst", Ipv4Addr::new(198, 51, 100, 20))?;
    let ip = Ipv4::new()
        .src(src)
        .dst(dst)
        .ip_option(Ipv4Option::traceroute(7, 0, 0, src))?
        .ip_option(Ipv4Option::no_operation())?
        .ip_option(Ipv4Option::generic(0x9e, [1, 2, 3, 4]))?;
    let packet = ip / Udp::new().sport(40000).dport(33434) / Raw::from("ip-options");

    println!("{}", packet.show());
    if let Some(ip) = packet.layer::<Ipv4>() {
        println!(
            "ip options: {:?}",
            Ipv4Option::decode_all(ip.option_bytes())?
        );
    }
    println!("hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
