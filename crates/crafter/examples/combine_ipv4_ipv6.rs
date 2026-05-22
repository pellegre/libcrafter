mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example combine_ipv4_ipv6 --\n\nBuild an IPv6 packet carried inside an IPv4 packet and inspect it offline.",
    ) {
        return Ok(());
    }

    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Ipv6::new()
            .src("2001:db8::10".parse::<Ipv6Addr>()?)
            .dst("2001:db8::20".parse::<Ipv6Addr>()?)
        / Icmpv6::echo_request().id(0x6060).seq(1)
        / Raw::from("combined");

    println!("{}", packet.show());
    println!("hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
