mod common;

use common::{
    arg_or, live_mode, local_mac, parse_mac_arg, print_advanced_safety, print_help_if_requested,
    print_send_report, send_options, ExampleResult, EXAMPLE_IFACE,
};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dhcp_discover -- [--live] [--iface IFACE] [--client-mac MAC] [--hostname NAME]\n\nBuild a DHCP discover with an explicit client MAC. The default is a link-layer dry-run.",
    ) {
        return Ok(());
    }

    let live = live_mode("dhcp_discover")?;
    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let client_mac = parse_mac_arg("--client-mac", local_mac())?;
    let hostname = arg_or("--hostname", "libcrafter-rust");
    let dhcp = Dhcp::discover(client_mac)
        .xid(0x0102_0304)
        .flags(0x8000)
        .host_name(hostname);
    let packet = Ethernet::new()
        .src(client_mac)
        .dst(MacAddr::BROADCAST)
        .ethertype(ETHERTYPE_IPV4)
        / Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
            .protocol(IPPROTO_UDP)
        / Udp::new().sport(DHCP_CLIENT_PORT).dport(DHCP_SERVER_PORT)
        / dhcp;
    let dhcp = packet
        .layer::<Dhcp>()
        .expect("constructed packet should contain DHCP");
    let report = packet.send(send_options(&iface, live, true))?;

    print_advanced_safety("dhcp_discover", live);
    println!(
        "client mac: {}",
        dhcp.client_mac_value().unwrap_or(client_mac)
    );
    println!("transaction id: 0x{:08x}", dhcp.transaction_id_value());
    println!("message type: {:?}", dhcp.message_type_value());
    println!(
        "reply filter: {}",
        reply_filter(&packet).unwrap_or_default()
    );
    print_send_report("dhcp_discover", &packet, &report);

    Ok(())
}
