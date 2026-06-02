mod common;

use common::{
    arg_or, live_mode, local_ipv4, parse_ipv4_arg, parse_u16_arg, print_help_if_requested,
    remote_ipv4, send_recv_options, ExampleResult, ADVANCED_LIVE_ACK_FLAG, EXAMPLE_IFACE,
    LIVE_WIRE_ENV,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(&format!(
        "usage: cargo run -p crafter --example network_ping -- [--live] [--iface IFACE] [--src IP] [--dst IP] [--id ID] [--seq SEQ]\n\nSend one IPv4 ICMP echo request with network-layer send/receive. Live traffic requires --live, {ADVANCED_LIVE_ACK_FLAG}, and {LIVE_WIRE_ENV}=1."
    )) {
        return Ok(());
    }

    let live = live_mode("network_ping")?;
    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let src = parse_ipv4_arg("--src", local_ipv4())?;
    let dst = parse_ipv4_arg("--dst", remote_ipv4())?;
    let icmp_id = parse_u16_arg("--id", 0x4242)?;
    let icmp_seq = parse_u16_arg("--seq", 1)?;

    let packet = Ipv4::new().src(src).dst(dst).id(0x4001).dont_fragment(true)
        / Icmpv4::echo_request().id(icmp_id).seq(icmp_seq)
        / Raw::from("network-ping");
    let report = packet.send_recv_report(send_recv_options(&iface, live, false))?;

    println!("iface={iface}");
    println!("src={src}");
    println!("dst={dst}");
    println!("icmp_id={icmp_id}");
    println!("icmp_seq={icmp_seq}");
    println!("attempts: {}", report.attempts());
    println!("timed out: {}", report.timed_out());
    println!(
        "effective filter: {}",
        report.effective_filter().unwrap_or("")
    );
    match report.reply() {
        Some(reply) => println!("reply: {}", reply.summary()),
        None => println!("reply: none"),
    }

    Ok(())
}
