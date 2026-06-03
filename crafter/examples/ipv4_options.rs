mod common;

use std::net::Ipv4Addr;

use common::{
    intermediary_ipv4, local_ipv4, parse_ipv4_arg, print_help_if_requested, remote_ipv4,
    ExampleResult,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ipv4_options -- [--src IP] [--dst IP]\n\nBuild one IPv4 packet with record-route, traceroute, NOP, and generic options.",
    ) {
        return Ok(());
    }

    let src = parse_ipv4_arg("--src", local_ipv4())?;
    let dst = parse_ipv4_arg("--dst", remote_ipv4())?;
    let packet = Ipv4::new()
        .src(src)
        .dst(dst)
        .id(0x4401)
        .dont_fragment(true)
        .ipv4_option(Ipv4Option::record_route(
            4,
            vec![intermediary_ipv4(), Ipv4Addr::UNSPECIFIED],
        ))?
        .ipv4_option(Ipv4Option::traceroute(0x1001, 1, 0, src))?
        .ipv4_option(Ipv4Option::no_operation())?
        .ipv4_option(Ipv4Option::generic(0x9e, vec![0xaa, 0xbb, 0xcc, 0xdd]))?
        / Udp::new().sport(40000).dport(33434)
        / Raw::from("ipv4-options");
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let ipv4 = decoded
        .layer::<Ipv4>()
        .expect("decoded IPv4 option packet should contain Ipv4");
    let options = Ipv4Option::decode_all(ipv4.option_bytes())?;

    println!("example: ipv4_options");
    println!("mode: offline");
    println!("source: {src}");
    println!("destination: {dst}");
    println!("decoded summary: {}", decoded.summary());
    println!("raw option bytes: {}", ipv4.option_bytes().len());
    for (index, option) in options.iter().enumerate() {
        println!("ipv4 option {}: {:?}", index + 1, option);
    }
    println!("hexdump:\n{}", compiled.hexdump());

    Ok(())
}
