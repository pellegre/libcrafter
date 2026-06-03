mod common;

use common::{
    local_ipv4, local_mac, print_help_if_requested, remote_ipv4, remote_mac, ExampleResult,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example decode_bytes --\n\nDecode generated packet bytes from link-layer and network-layer entrypoints.",
    ) {
        return Ok(());
    }

    let l3_packet = Ipv4::new()
        .src(local_ipv4())
        .dst(remote_ipv4())
        .ipv4_protocol(Ipv4Protocol::Udp)
        / Udp::new().sport(53000).dport(9000)
        / Raw::from("decode me");
    let frame = Ethernet::new()
        .src(local_mac())
        .dst(remote_mac())
        .ethertype(ETHERTYPE_IPV4)
        / l3_packet.clone();

    let frame_bytes = frame.compile()?;
    let l3_bytes = l3_packet.compile()?;
    let decoded_frame = Packet::decode_from_link(LinkType::Ethernet, frame_bytes.as_bytes())?;
    let decoded_l3 = Packet::decode_from_l3(NetworkLayer::Ipv4, l3_bytes.as_bytes())?;

    let private_packet = Ipv4::new()
        .src(local_ipv4())
        .dst(remote_ipv4())
        .protocol(253)
        / Raw::from("private protocol payload");
    let private_bytes = private_packet.compile()?;
    let decoded_private = Packet::decode_from_l3(NetworkLayer::Ipv4, private_bytes.as_bytes())?;
    let private_raw = decoded_private
        .layer::<Raw>()
        .expect("unsupported IPv4 payload should decode as Raw");

    println!("mode: offline");
    println!("link decode summary: {}", decoded_frame.summary());
    println!("l3 decode summary: {}", decoded_l3.summary());
    println!(
        "unsupported payload raw: {:?}",
        private_raw.raw_string_lossy()
    );
    println!("frame hexdump:\n{}", frame_bytes.hexdump());

    Ok(())
}
