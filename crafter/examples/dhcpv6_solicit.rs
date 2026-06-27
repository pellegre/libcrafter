mod common;

use std::time::Duration;

use common::{
    arg_or, local_ipv6, print_help_if_requested, remote_ipv6, ExampleResult, EXAMPLE_IFACE,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dhcpv6_solicit -- [--iface IFACE]\n\nBuild a DHCPv6 Solicit and inspect a network-layer dry-run send plan.",
    ) {
        return Ok(());
    }

    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let packet = Ipv6::new().src(local_ipv6()).dst(remote_ipv6())
        / Udp::dhcpv6_client()
        / Dhcpv6::solicit(0x010203)
            .client_duid(Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x01]))
            .oro([DHCPV6_OPTION_DNS_SERVERS, DHCPV6_OPTION_DOMAIN_LIST])
            .elapsed_time(1);
    let report = packet.send_recv_report(
        SendRecv::new()
            .iface(iface.clone())
            .network_layer()
            .dry_run()
            .timeout(Duration::from_millis(250))
            .retries(1),
    )?;

    println!("example: dhcpv6_solicit");
    println!("mode: dry-run send/receive");
    println!("interface: {iface}");
    println!("attempts: {}", report.attempts());
    println!(
        "effective filter: {}",
        report.effective_filter().unwrap_or("")
    );
    println!("timed out: {}", report.timed_out());
    println!("message type: {:?}", Dhcpv6MessageType::Solicit);
    println!("transaction id: 0x010203");
    println!("summary: {}", packet.summary());
    for (attempt, send) in report.send_reports().iter().enumerate() {
        println!(
            "send attempt {}: bytes {} target {:?}",
            attempt + 1,
            send.bytes_sent(),
            send.plan().target()
        );
        println!("hexdump:\n{}", send.plan().compiled_packet().hexdump());
    }

    Ok(())
}
