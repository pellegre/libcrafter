mod common;

use common::{
    arg_or, flag_present, parse_ipv4_arg, parse_mac_arg, print_help_if_requested,
    print_send_recv_report, send_recv_options, ExampleResult,
};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example arp_ping -- [--live] [--iface IFACE] [--src IP] [--target IP] [--src-mac MAC]\n\nBuild an Ethernet ARP who-has request and use dry-run send/receive by default.",
    ) {
        return Ok(());
    }

    let live = flag_present("--live");
    let iface = arg_or("--iface", "dry-run0");
    let src_ip = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let target_ip = parse_ipv4_arg("--target", Ipv4Addr::new(192, 0, 2, 1))?;
    let src_mac = parse_mac_arg(
        "--src-mac",
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]),
    )?;
    let packet = Ethernet::new().src(src_mac).dst(MacAddr::BROADCAST)
        / Arp::who_has(src_ip, target_ip, src_mac);
    let report = packet.send_recv_report(send_recv_options(&iface, live, true))?;

    print_send_recv_report("arp_ping", &packet, &report);
    println!("hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
