mod common;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example hello_world --\n\nBuild a documentation-safe IPv4/ICMP/Raw packet without sending traffic.",
    ) {
        return Ok(());
    }

    let packet = Ipv4::new()
        .src(local_ipv4())
        .dst(remote_ipv4())
        .ipv4_protocol(Ipv4Protocol::Icmpv4)
        / Icmpv4::echo_request().id(0x1234).seq(1)
        / Raw::from("Hello, libcrafter!");
    let compiled = packet.compile()?;

    println!("mode: offline");
    println!("summary: {}", packet.summary());
    println!("bytes: {}", compiled.len());
    println!("hexdump:\n{}", compiled.hexdump());

    Ok(())
}
