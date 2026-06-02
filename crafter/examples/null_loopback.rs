mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example null_loopback --\n\nBuild, compile, and decode a BSD null/loopback IPv4 ICMP packet offline.",
    ) {
        return Ok(());
    }

    let packet = NullLoopback::ipv4()
        / Ipv4::new()
            .src(Ipv4Addr::LOCALHOST)
            .dst(Ipv4Addr::LOCALHOST)
            .protocol(IPPROTO_ICMP)
        / Icmpv4::echo_request().id(0x1111).seq(1)
        / Raw::from("null-loopback");
    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::NullLoopback, bytes.as_bytes())?;

    println!("example: null_loopback");
    println!("mode: offline");
    println!("decoded summary: {}", decoded.summary());
    for (index, layer) in decoded.iter().enumerate() {
        println!("layer {}: {}", index + 1, layer.summary());
    }
    println!("hexdump:\n{}", bytes.hexdump());

    Ok(())
}
