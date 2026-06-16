mod common;

use common::{flag_present, print_help_if_requested, ExampleResult, EXAMPLE_IFACE};
use crafter::prelude::*;
use crafter::protocols::rip::{rip_v2_multicast_response, rip_v2_whole_table_request};
use std::net::Ipv4Addr;

/// Documentation-range source address for the RIP speaker (192.0.2.0/24).
const RIP_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
/// First advertised route prefix (198.51.100.0/24).
const ROUTE_ONE_NETWORK: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 0);
/// Second advertised route prefix (198.51.100.128/25).
const ROUTE_TWO_NETWORK: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 128);
/// /24 subnet mask for the first advertised route.
const MASK_24: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
/// /25 subnet mask for the second advertised route.
const MASK_25: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 128);

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example rip_request -- [--send]\n\nBuild a RIPv2 whole-table request and a RIPv2 multicast response over documentation address space and inspect their dry-run send plans. Offline by default; --send is reserved for an explicit, gated live path and is not enabled in this example.",
    ) {
        return Ok(());
    }

    // The live path is opt-in only. Even when requested we refuse to place real
    // RIP traffic on the wire from this example: real sends must originate from a
    // provider-backed endpoint or lab session, not the developer machine.
    if flag_present("--send") {
        eprintln!(
            "refusing live send: rip_request is an offline stimulus driver; \
             run RIP against a provider-backed routing daemon via the probe/lab runners instead"
        );
        return Err("live RIP send is not enabled in this example".into());
    }

    println!("example: rip_request");
    println!("mode: dry-run");
    println!("source: {RIP_SOURCE}");

    // 1. RIPv2 whole-table request (RFC 2453 §3.9.1): a single AFI-0 / metric-16
    //    sentinel entry addressed to the 224.0.0.9 RIPv2 multicast group.
    let request = rip_v2_whole_table_request(RIP_SOURCE);
    print_plan("request", "RIPv2 whole-table request", &request)?;

    // 2. RIPv2 response (RFC 2453) advertising a couple of documentation-range
    //    routes to the 224.0.0.9 multicast group.
    let entries = vec![
        RipEntry::ipv2_route(ROUTE_ONE_NETWORK, MASK_24, 1),
        RipEntry::ipv2_route(ROUTE_TWO_NETWORK, MASK_25, 2).with_route_tag(0),
    ];
    let response = rip_v2_multicast_response(RIP_SOURCE, entries);
    print_plan("response", "RIPv2 multicast response", &response)?;

    Ok(())
}

fn print_plan(label: &str, description: &str, packet: &Packet) -> ExampleResult<()> {
    let plan = packet.send_dry_run(SendOptions::new().iface(EXAMPLE_IFACE).network_layer())?;

    println!();
    println!("{label}: {description}");
    println!("summary: {}", packet.summary());
    println!("interface: {}", plan.interface());
    println!("target: {:?}", plan.target());
    println!("compiled bytes: {}", plan.len());
    println!("show:\n{}", packet.show());
    println!("hexdump:\n{}", plan.compiled_packet().hexdump());
    Ok(())
}
