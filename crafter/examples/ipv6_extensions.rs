mod common;

use common::{local_ipv6, print_help_if_requested, remote_ipv6, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ipv6_extensions --\n\nBuild IPv6 segment-routing and fragment-header packets, then decode their extension headers offline.",
    ) {
        return Ok(());
    }

    println!("example: ipv6_extensions");
    println!("mode: offline");

    inspect_ipv6_packet("segment routing", &segment_routing_packet()?)?;
    inspect_ipv6_packet("fragment header", &fragment_header_packet())?;

    Ok(())
}

fn segment_routing_packet() -> ExampleResult<Packet> {
    let routing = Ipv6SegmentRoutingHeader::new()
        .push_ipv6_segment("2001:db8::30")?
        .push_ipv6_segment("2001:db8::40")?
        .segleft(1)
        .first_segment(1)
        .pflag(true)
        .tag(0x1001)
        .extra_data([0x00]);

    Ok(Ipv6::new().src(local_ipv6()).dst(remote_ipv6())
        / routing
        / Tcp::new()
            .sport(41000)
            .dport(443)
            .seq(1)
            .flags(TCP_FLAG_SYN)
        / Raw::from("segment-route"))
}

fn fragment_header_packet() -> Packet {
    Ipv6::new().src(local_ipv6()).dst(remote_ipv6())
        / Ipv6FragmentHeader::new()
            .identification(0x0102_0304)
            .more_fragments(true)
        / Udp::new().sport(5353).dport(5353)
        / Raw::from("fragment")
}

fn inspect_ipv6_packet(label: &str, packet: &Packet) -> ExampleResult<()> {
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;

    println!("packet: {label}");
    println!("decoded summary: {}", decoded.summary());
    if let Some(routing) = decoded.layer::<Ipv6SegmentRoutingHeader>() {
        println!("extension: {}", routing.summary());
        println!("segments left: {}", routing.segments_left_value());
        println!("last entry: {}", routing.last_entry_value());
        println!("flags: 0x{:02x}", routing.flags_value());
        println!("tag: 0x{:04x}", routing.tag_value());
        println!("segments: {:?}", routing.segments());
        println!("trailing data: {:02x?}", routing.raw_trailing_data_bytes());
    }
    if let Some(fragment) = decoded.layer::<Ipv6FragmentHeader>() {
        println!("extension: {}", fragment.summary());
        println!("fragment offset: {}", fragment.fragment_offset_value());
        println!("more fragments: {}", fragment.has_more_fragments());
        println!("identification: 0x{:08x}", fragment.identification_value());
    }
    println!("hexdump:\n{}", compiled.hexdump());

    Ok(())
}
