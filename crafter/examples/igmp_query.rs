mod common;

use std::net::Ipv4Addr;

use common::{local_ipv4, print_help_if_requested, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example igmp_query --\n\nBuild and decode a documentation-safe IPv4/IGMPv3 query offline.",
    ) {
        return Ok(());
    }

    let group = Ipv4Addr::new(233, 252, 0, 61);
    let query = IgmpQuery::group_and_source_specific(vec![
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(203, 0, 113, 20),
    ])
    .with_suppress_router_side_processing(true)
    .with_querier_robustness_variable(2)
    .with_qqic(125);

    let packet = Ipv4::new()
        .src(local_ipv4())
        .dst(group)
        .ttl(1)
        .ipv4_protocol(Ipv4Protocol::Igmp)
        .ipv4_option(Ipv4Option::router_alert(0))?
        / Igmp::v3_membership_query(125, group, query);
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    println!("constructed summary: {}", packet.summary());
    println!("decoded summary: {}", decoded.summary());
    println!("hexdump:\n{}", compiled.hexdump());

    Ok(())
}
