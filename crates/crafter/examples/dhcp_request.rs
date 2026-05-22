mod common;

use common::{
    arg_or, flag_present, parse_ipv4_arg, parse_mac_arg, print_help_if_requested,
    print_send_report, send_options, ExampleResult,
};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dhcp_request -- [--live] [--iface IFACE] [--client-mac MAC] [--requested-ip IP] [--server IP] [--hostname NAME]\n\nBuild a DHCP request over Ethernet. The default is dry-run.",
    ) {
        return Ok(());
    }

    let live = flag_present("--live");
    let iface = arg_or("--iface", "dry-run0");
    let client_mac = parse_mac_arg(
        "--client-mac",
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x10]),
    )?;
    let requested = parse_ipv4_arg("--requested-ip", Ipv4Addr::new(192, 0, 2, 100))?;
    let server = parse_ipv4_arg("--server", Ipv4Addr::new(192, 0, 2, 1))?;
    let hostname = arg_or("--hostname", "libcrafter-rust");
    let dhcp = Dhcp::request(client_mac, requested, server)
        .xid(0x0102_0304)
        .host_name(hostname);
    let packet = Ethernet::new().src(client_mac).dst(MacAddr::BROADCAST)
        / Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
        / Udp::new().sport(DHCP_CLIENT_PORT).dport(DHCP_SERVER_PORT)
        / dhcp;
    let report = packet.send(send_options(&iface, live, true))?;

    print_send_report("dhcp_request", &packet, &report);

    Ok(())
}
