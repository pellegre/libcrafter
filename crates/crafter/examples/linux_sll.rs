mod common;

use common::{local_ipv4, local_mac, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example linux_sll --\n\nBuild, compile, and decode a Linux cooked capture packet offline.",
    ) {
        return Ok(());
    }

    let packet = LinuxSll::new().source_address(local_mac())
        / Ipv4::new()
            .src(local_ipv4())
            .dst(remote_ipv4())
            .protocol(IPPROTO_UDP)
        / Udp::new().sport(53003).dport(9000)
        / Raw::from("linux-sll");
    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::LinuxSll, bytes.as_bytes())?;

    println!("example: linux_sll");
    println!("mode: offline");
    println!("decoded summary: {}", decoded.summary());
    for (index, layer) in decoded.iter().enumerate() {
        println!("layer {}: {}", index + 1, layer.summary());
    }
    println!("hexdump:\n{}", bytes.hexdump());

    Ok(())
}
