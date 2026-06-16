mod common;

use common::{flag_present, print_help_if_requested, ExampleResult, EXAMPLE_IFACE};
use crafter::prelude::*;
use std::net::Ipv6Addr;

/// Documentation-range source address for the RIPng speaker (2001:db8::/32).
const RIPNG_SOURCE: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010);
/// Documentation-range next hop advertised for the route RTEs (2001:db8::/32).
const NEXT_HOP: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x00fe);
/// First advertised IPv6 prefix (2001:db8:1::/48).
const ROUTE_ONE_PREFIX: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0);
/// Second advertised IPv6 prefix (2001:db8:2::/48).
const ROUTE_TWO_PREFIX: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 0);

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ripng_response -- [--send]\n\nBuild a RIPng response carrying a next-hop RTE followed by two route RTEs over documentation address space (2001:db8::/32) and inspect its dry-run send plan. Offline by default; --send is reserved for an explicit, gated live path and is not enabled in this example.",
    ) {
        return Ok(());
    }

    // The live path is opt-in only. Even when requested we refuse to place real
    // RIPng traffic on the wire from this example: real sends must originate
    // from a provider-backed endpoint or lab session, not the developer machine.
    if flag_present("--send") {
        eprintln!(
            "refusing live send: ripng_response is an offline example; \
             run RIPng against a provider-backed routing daemon via the probe/lab runners instead"
        );
        return Err("live RIPng send is not enabled in this example".into());
    }

    println!("example: ripng_response");
    println!("mode: dry-run");
    println!("source: {RIPNG_SOURCE}");

    // RIPng response (RFC 2080 §2.1.1, §2.2): a next-hop RTE (metric 0xFF) sets
    // the next hop for the route RTEs that follow it. Here a single next-hop RTE
    // is followed by two route RTEs over documentation-range IPv6 prefixes
    // (2001:db8::/32). The response is addressed to UDP/521 and the
    // all-RIPng-routers multicast group ff02::9.
    let response = Ipv6::new().src(RIPNG_SOURCE).dst(RIPNG_MULTICAST)
        / Udp::new().sport(RIPNG_UDP_PORT).dport(RIPNG_UDP_PORT)
        / Ripng::response().with_rtes(vec![
            RipngRte::next_hop(NEXT_HOP),
            RipngRte::route(ROUTE_ONE_PREFIX, 48, 1),
            RipngRte::route(ROUTE_TWO_PREFIX, 48, 2).route_tag(0),
        ]);
    print_plan("response", "RIPng multicast response", &response)?;

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
