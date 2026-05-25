mod common;

use common::{
    arg_or, live_mode, local_ipv4, local_mac, print_advanced_safety, print_help_if_requested,
    print_send_report, remote_ipv4, remote_mac, ExampleResult, EXAMPLE_IFACE,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example send_packet -- [--live] [--iface IFACE]\n\nBuild network-layer and link-layer packets and send them in dry-run mode by default.",
    ) {
        return Ok(());
    }

    let live = live_mode("send_packet")?;
    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let network_packet = Ipv4::new().src(local_ipv4()).dst(remote_ipv4()).id(0x2001)
        / Udp::new().sport(49152).dport(33434)
        / Raw::from("network-layer");
    let link_packet = Ethernet::new()
        .src(local_mac())
        .dst(remote_mac())
        .ethertype(ETHERTYPE_IPV4)
        / Ipv4::new().src(local_ipv4()).dst(remote_ipv4()).id(0x2002)
        / Tcp::new()
            .sport(49153)
            .dport(80)
            .seq(0x0102_0304)
            .flags(TCP_FLAG_SYN)
        / Raw::from("link-layer");

    print_advanced_safety("send_packet", live);

    let network_options = if live {
        SendOptions::new().iface(&iface).network_layer().live()
    } else {
        SendOptions::new().iface(&iface).network_layer().dry_run()
    };
    let network_report = send_packet(&network_packet, network_options)?;
    print_send_report(
        "send_packet network-layer",
        &network_packet,
        &network_report,
    );

    let link_options = if live {
        SendOptions::new().iface(&iface).link_layer().live()
    } else {
        SendOptions::new().iface(&iface).link_layer().dry_run()
    };
    let link_report = send_packet(&link_packet, link_options)?;
    print_send_report("send_packet link-layer", &link_packet, &link_report);

    Ok(())
}
