mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example null_header --\n\nBuild and decode a BSD null/loopback IPv4 packet offline.",
    ) {
        return Ok(());
    }

    let packet = NullLoopback::ipv4()
        / Ipv4::new()
            .src(Ipv4Addr::new(127, 0, 0, 1))
            .dst(Ipv4Addr::new(127, 0, 0, 1))
        / Icmp::echo_request().id(0x1111).seq(1)
        / Raw::from("null");
    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::NullLoopback, bytes.as_bytes())?;

    println!("{}", packet.show());
    println!("decoded: {}", decoded.summary());
    println!("hexdump:\n{}", bytes.hexdump());

    Ok(())
}
