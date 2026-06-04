mod common;

use common::{local_ipv4, parse_ipv4_arg, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ipv4_enrichment -- [--src IP] [--dst IP]\n\nBuild and inspect an offline IPv4 packet with DSCP/ECN, options, and fragment metadata.",
    ) {
        return Ok(());
    }

    let src = parse_ipv4_arg("--src", local_ipv4())?;
    let dst = parse_ipv4_arg("--dst", remote_ipv4())?;
    let packet = Ipv4::new()
        .src(src)
        .dst(dst)
        .id(0x5201)
        .dscp(Dscp::new(46)?)
        .ecn(Ecn::Ce)
        .more_fragments(true)
        .fragment_offset(7)
        .ttl(32)
        .protocol(IPPROTO_UDP)
        .ipv4_option(Ipv4Option::router_alert(0))?
        / Raw::from("ipv4-fragment-00");

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let ipv4 = decoded
        .layer::<Ipv4>()
        .expect("decoded IPv4 enrichment packet should contain Ipv4");
    let fragment = ipv4.fragment_info();
    let options = ipv4.parsed_options()?;

    println!("example: ipv4_enrichment");
    println!("mode: offline");
    println!("source: {src}");
    println!("destination: {dst}");
    println!("decoded summary: {}", decoded.summary());
    println!(
        "ds field: 0x{:02x} (dscp={}, ecn={:?})",
        ipv4.ds_field_value(),
        ipv4.dscp_value().value(),
        ipv4.ecn_value()
    );
    println!("checksum status: {:?}", ipv4.checksum_status());
    println!(
        "fragment: id=0x{:04x} flags=0x{:x} offset={} fragmented={}",
        fragment.identification(),
        fragment.flags(),
        fragment.fragment_offset(),
        fragment.is_fragmented()
    );
    for (index, option) in options.iter().enumerate() {
        println!("ipv4 option {}: {:?}", index + 1, option);
    }
    println!("show:\n{}", decoded.show());
    println!("hexdump:\n{}", compiled.hexdump());

    Ok(())
}
