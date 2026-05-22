mod common;

use common::{
    arg_or, flag_present, parse_ipv4_arg, print_help_if_requested, print_send_report, send_options,
    ExampleResult,
};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example user_sockets -- [--live] [--iface IFACE] [--src IP] [--dst IP]\n\nUse the explicit SocketSender/RawSender API. The default is dry-run.",
    ) {
        return Ok(());
    }

    let live = flag_present("--live");
    let iface = arg_or("--iface", "dry-run0");
    let src = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let dst = parse_ipv4_arg("--dst", Ipv4Addr::new(198, 51, 100, 20))?;
    let packet = Ipv4::new().src(src).dst(dst)
        / Tcp::new().sport(41000).dport(80).flags(TCP_FLAG_SYN)
        / Raw::from("user-socket");
    let sender = RawSender::new(send_options(&iface, live, false));
    let report = sender.send(&packet)?;

    print_send_report("user_sockets", &packet, &report);

    Ok(())
}
