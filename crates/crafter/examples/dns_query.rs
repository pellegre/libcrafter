mod common;

use common::{
    arg_or, flag_present, parse_ipv4_arg, parse_u16_arg, print_help_if_requested,
    print_send_recv_report, send_recv_options, ExampleResult,
};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dns_query -- [--dry-run] [--live] [--iface IFACE] [--src IP] [--server IP] [--sport PORT] [--name NAME] [--aaaa]\n\nBuild a DNS query over UDP. The default is dry-run.",
    ) {
        return Ok(());
    }

    let live = flag_present("--live");
    let iface = arg_or("--iface", "dry-run0");
    let src = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let server = parse_ipv4_arg("--server", Ipv4Addr::new(198, 51, 100, 53))?;
    let sport = parse_u16_arg("--sport", 53000)?;
    let name = arg_or("--name", "example.com");
    let question_type = if flag_present("--aaaa") {
        DNS_TYPE_AAAA
    } else {
        DNS_TYPE_A
    };
    let packet = Ipv4::new().src(src).dst(server)
        / Udp::new().sport(sport).dport(DNS_PORT)
        / Dns::query(name.clone(), question_type).id(0x1234);
    let report = packet.send_recv_report(send_recv_options(&iface, live, false))?;

    print_send_recv_report("dns_query", &packet, &report);
    println!("query name: {name}");
    println!("hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
