mod common;

use common::{
    arg_or, local_ipv4, local_ipv6, print_help_if_requested, ExampleResult, EXAMPLE_IFACE,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ssdp_search_plan -- [--iface IFACE]\n\nBuild SSDP M-SEARCH packets and inspect dry-run network-layer send plans only.",
    ) {
        return Ok(());
    }

    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let ipv4_search = ssdp_ipv4_multicast_packet(local_ipv4(), Ssdp::m_search_all());
    let ipv6_search = ssdp_ipv6_multicast_packet(
        local_ipv6(),
        Ssdp::m_search()
            .host(SSDP_IPV6_SITE_LOCAL_HOST)
            .man_discover()
            .mx(1)
            .search_target(SSDP_ST_ALL),
    );

    let ipv4_plan = ipv4_search.send_dry_run(SendOptions::new().iface(&iface).network_layer())?;
    let ipv6_plan = ipv6_search.send_dry_run(SendOptions::new().iface(&iface).network_layer())?;

    println!("example: ssdp_search_plan");
    println!("mode: dry-run");
    println!("interface: {iface}");
    print_plan("ipv4 m-search", &ipv4_plan)?;
    print_plan("ipv6 m-search", &ipv6_plan)?;

    Ok(())
}

fn print_plan(label: &str, plan: &SendPlan) -> ExampleResult<()> {
    println!("{label} target: {:?}", plan.target());
    println!("{label} bytes: {}", plan.len());
    if let SendTarget::NetworkLayer { network_layer, .. } = plan.target() {
        let decoded = Packet::decode_from_l3(network_layer, plan.bytes())?;
        println!("{label} decoded summary: {}", decoded.summary());
    }
    println!("{label} hexdump:\n{}", plan.compiled_packet().hexdump());
    Ok(())
}
