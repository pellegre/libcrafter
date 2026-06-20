mod common;

use std::net::Ipv4Addr;

use common::{local_ipv4, print_help_if_requested, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example igmp_report --\n\nBuild and decode a documentation-safe IPv4/IGMPv3 report offline.",
    ) {
        return Ok(());
    }

    let group = Ipv4Addr::new(233, 252, 0, 74);
    let record = IgmpGroupRecord::allow_new_sources(group).with_source_addresses(vec![
        Ipv4Addr::new(192, 0, 2, 74),
        Ipv4Addr::new(198, 51, 100, 74),
    ]);
    let report = IgmpReport::from_group_records(vec![record]);

    let packet = Ipv4::new()
        .src(local_ipv4())
        .dst(Ipv4Addr::new(224, 0, 0, 22))
        .ttl(1)
        .ipv4_protocol(Ipv4Protocol::Igmp)
        .ipv4_option(Ipv4Option::router_alert(0))?
        / Igmp::v3_membership_report()
        / report;
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    println!("constructed summary: {}", packet.summary());
    println!("decoded summary: {}", decoded.summary());
    println!("hexdump:\n{}", compiled.hexdump());

    Ok(())
}
