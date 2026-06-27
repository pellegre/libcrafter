mod common;

use std::time::Duration;

use common::{
    arg_or, local_ipv6, print_help_if_requested, remote_ipv6, ExampleResult, EXAMPLE_IFACE,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dhcpv6_information_request -- [--iface IFACE]\n\nBuild a DHCPv6 Information-request, inspect a dry-run send/receive report, then decode the request offline.",
    ) {
        return Ok(());
    }

    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let packet = Ipv6::new().src(local_ipv6()).dst(remote_ipv6())
        / Udp::dhcpv6_client()
        / Dhcpv6::information_request(0x030405)
            .client_duid(Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x02]))
            .oro([DHCPV6_OPTION_DNS_SERVERS, DHCPV6_OPTION_DOMAIN_LIST])
            .elapsed_time(2);
    let report = packet.send_recv_report(
        SendRecv::new()
            .iface(iface.clone())
            .network_layer()
            .dry_run()
            .timeout(Duration::from_millis(250))
            .retries(1),
    )?;
    let wire = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, wire.as_bytes())?;
    let dhcpv6 = decoded
        .layer::<Dhcpv6>()
        .expect("decoded packet should contain DHCPv6");

    println!("example: dhcpv6_information_request");
    println!("mode: dry-run send/receive plus offline decode");
    println!("interface: {iface}");
    println!("attempts: {}", report.attempts());
    println!(
        "effective filter: {}",
        report.effective_filter().unwrap_or("")
    );
    println!("timed out: {}", report.timed_out());
    println!("message type: {:?}", dhcpv6.message_type_value());
    println!("transaction id: 0x{:06x}", dhcpv6.transaction_id_value());
    println!("oro: {:?}", dhcpv6.oro_value()?.unwrap_or_default());
    println!("summary: {}", decoded.summary());
    println!("hexdump:\n{}", wire.hexdump());

    Ok(())
}
