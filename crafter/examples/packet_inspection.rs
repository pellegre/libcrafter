mod common;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example packet_inspection --\n\nInspect and mutate typed packet layers offline.",
    ) {
        return Ok(());
    }

    let mut packet = Ipv4::new()
        .src(local_ipv4())
        .dst(remote_ipv4())
        .protocol(IPPROTO_ICMP)
        / Icmpv4::echo_request().id(0x2202).seq(1)
        / Raw::from("inspect")
        / Raw::from(" me");

    if let Some(raw) = packet.layer_mut::<Raw>() {
        raw.extend_from_slice(b" and mutate");
    }

    println!("mode: offline");
    println!("summary: {}", packet.summary());
    println!("show:\n{}", packet.show());

    if let Some(ipv4) = packet.layer::<Ipv4>() {
        println!("ipv4: {} -> {}", ipv4.source(), ipv4.destination());
    }

    for (index, raw) in packet.layers::<Raw>().enumerate() {
        println!("raw layer {index}: {:?}", raw.raw_string_lossy());
    }

    let layer_names = packet
        .iter()
        .map(Layer::name)
        .collect::<Vec<_>>()
        .join(" -> ");
    println!("iter layer names: {layer_names}");
    println!(
        "raw string lossless enough for display: {:?}",
        packet.raw_string_lossy()?
    );
    println!("hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
