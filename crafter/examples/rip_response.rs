mod common;

use common::{flag_present, print_help_if_requested, ExampleResult, EXAMPLE_IFACE};
use crafter::prelude::*;
use crafter::protocols::rip::rip_v2_multicast_response;
use std::net::Ipv4Addr;

/// Documentation-range source address for the RIP speaker (192.0.2.0/24).
const RIP_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
/// Classful network advertised in the RIPv1 response (198.51.100.0).
const CLASSFUL_NETWORK: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 0);
/// Second classful network advertised in the RIPv1 response (203.0.113.0).
const CLASSFUL_NETWORK_TWO: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 0);
/// Subnetted prefix advertised in the RIPv2 response (198.51.100.0/24).
const ROUTE_ONE_NETWORK: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 0);
/// Second subnetted prefix advertised in the RIPv2 response (198.51.100.128/25).
const ROUTE_TWO_NETWORK: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 128);
/// /24 subnet mask for the first RIPv2 advertised route.
const MASK_24: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
/// /25 subnet mask for the second RIPv2 advertised route.
const MASK_25: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 128);
/// Documentation-range next hop for the second RIPv2 route (192.0.2.0/24).
const NEXT_HOP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 254);

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example rip_response -- [--send]\n\nBuild a RIPv1 response (classful entries) and a RIPv2 multicast response (route tag, subnet mask, next hop) over documentation address space and inspect their dry-run send plans. Offline by default; --send is reserved for an explicit, gated live path and is not enabled in this example.",
    ) {
        return Ok(());
    }

    // The live path is opt-in only. Even when requested we refuse to place real
    // RIP traffic on the wire from this example: real sends must originate from a
    // provider-backed endpoint or lab session, not the developer machine.
    if flag_present("--send") {
        eprintln!(
            "refusing live send: rip_response is an offline example; \
             run RIP against a provider-backed routing daemon via the probe/lab runners instead"
        );
        return Err("live RIP send is not enabled in this example".into());
    }

    println!("example: rip_response");
    println!("mode: dry-run");
    println!("source: {RIP_SOURCE}");

    // 1. RIPv1 response (RFC 1058 §3.1): classful route entries with the route
    //    tag, subnet mask, and next-hop fields all left at their zero defaults,
    //    matching the RIPv1 entry layout where those octets must be zero. RIPv1
    //    has no native multicast group, so the response is broadcast on UDP 520.
    let v1_entries = vec![
        RipEntry::ipv1_route(CLASSFUL_NETWORK, 1),
        RipEntry::ipv1_route(CLASSFUL_NETWORK_TWO, 2),
    ];
    let v1_response = Ipv4::new().src(RIP_SOURCE).dst(Ipv4Addr::BROADCAST)
        / Udp::new().sport(RIP_UDP_PORT).dport(RIP_UDP_PORT)
        / Rip::response().version(RIP_VERSION_1).with_entries(v1_entries);
    print_plan("v1-response", "RIPv1 broadcast response", &v1_response)?;

    // 2. RIPv2 multicast response (RFC 2453 §3.5, §4): per-entry route tag,
    //    subnet mask, and next hop are set, exercising the fields RIPv1 leaves
    //    zero. Sent to the 224.0.0.9 RIPv2 multicast group via the convenience.
    let v2_entries = vec![
        RipEntry::ipv2_route(ROUTE_ONE_NETWORK, MASK_24, 1).with_route_tag(64512),
        RipEntry::ipv2_route(ROUTE_TWO_NETWORK, MASK_25, 2)
            .with_route_tag(64513)
            .with_next_hop(NEXT_HOP),
    ];
    let v2_response = rip_v2_multicast_response(RIP_SOURCE, v2_entries);
    print_plan("v2-response", "RIPv2 multicast response", &v2_response)?;

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
