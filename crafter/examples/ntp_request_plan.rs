mod common;

use common::{
    arg_or, local_ipv4, local_ipv6, print_help_if_requested, remote_ipv4, remote_ipv6,
    ExampleResult, EXAMPLE_IFACE,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ntp_request_plan -- [--iface IFACE]\n\nBuild NTP client requests and inspect dry-run network-layer send plans only.",
    ) {
        return Ok(());
    }

    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let ipv4 = ntp_ipv4_client_request(local_ipv4(), remote_ipv4());
    let ipv6 = ntp_ipv6_client_request(local_ipv6(), remote_ipv6());
    let ipv4_plan = ipv4.send_dry_run(SendOptions::new().iface(&iface).network_layer())?;
    let ipv6_plan = ipv6.send_dry_run(SendOptions::new().iface(&iface).network_layer())?;

    println!("example: ntp_request_plan");
    println!("mode: dry-run");
    println!("interface: {iface}");
    print_plan("ipv4 ntp request", &ipv4_plan)?;
    print_plan("ipv6 ntp request", &ipv6_plan)?;
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
