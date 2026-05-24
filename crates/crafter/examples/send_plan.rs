mod common;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult, EXAMPLE_IFACE};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example send_plan --\n\nBuild an IPv4 ICMP packet and inspect a network-layer dry-run send plan.",
    ) {
        return Ok(());
    }

    let packet = Ipv4::new()
        .src(local_ipv4())
        .dst(remote_ipv4())
        .id(0x1234)
        .dont_fragment(true)
        / Icmp::echo_request().id(0x4242).seq(1)
        / Raw::from("send-plan");
    let plan = packet.send_dry_run(SendOptions::new().iface(EXAMPLE_IFACE).network_layer())?;

    println!("example: send_plan");
    println!("mode: dry-run");
    println!("interface: {}", plan.interface());
    println!("target: {:?}", plan.target());
    println!("compiled bytes: {}", plan.len());
    println!(
        "derived reply filter: {}",
        reply_filter(&packet).unwrap_or_default()
    );
    println!("summary: {}", packet.summary());
    println!("hexdump:\n{}", plan.compiled_packet().hexdump());

    Ok(())
}
