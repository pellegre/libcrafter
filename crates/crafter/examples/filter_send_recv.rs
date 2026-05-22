mod common;

use common::{
    arg_or, flag_present, parse_ipv4_arg, parse_u16_arg, print_help_if_requested,
    print_send_recv_report, send_recv_options, ExampleResult,
};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example filter_send_recv -- [--live] [--iface IFACE] [--src IP] [--dst IP] [--sport PORT] [--dport PORT] [--filter EXPR]\n\nBuild a TCP SYN and combine a user filter with the derived reply filter.",
    ) {
        return Ok(());
    }

    let live = flag_present("--live");
    let iface = arg_or("--iface", "dry-run0");
    let src = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let dst = parse_ipv4_arg("--dst", Ipv4Addr::new(198, 51, 100, 20))?;
    let sport = parse_u16_arg("--sport", 41000)?;
    let dport = parse_u16_arg("--dport", 80)?;
    let filter = arg_or("--filter", "tcp");
    let request = Ipv4::new().src(src).dst(dst)
        / Tcp::new()
            .sport(sport)
            .dport(dport)
            .seq(100)
            .flags(TCP_FLAG_SYN);
    let report = request.send_recv_report(send_recv_options(&iface, live, false).filter(filter))?;
    let synthetic_reply = Ipv4::new().src(dst).dst(src)
        / Tcp::new()
            .sport(dport)
            .dport(sport)
            .seq(200)
            .ack(101)
            .flags(TCP_FLAG_SYN | TCP_FLAG_ACK);

    print_send_recv_report("filter_send_recv", &request, &report);
    println!(
        "synthetic reply matches: {}",
        reply_matches(&request, &synthetic_reply)
    );

    Ok(())
}
