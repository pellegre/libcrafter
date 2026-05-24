mod common;

use std::time::Duration;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult, EXAMPLE_IFACE};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example send_recv_icmp --\n\nBuild an IPv4 ICMP echo request and inspect a dry-run send/receive report.",
    ) {
        return Ok(());
    }

    let packet = Ipv4::new()
        .src(local_ipv4())
        .dst(remote_ipv4())
        .id(0x3001)
        .dont_fragment(true)
        / Icmp::echo_request().id(0x4242).seq(7)
        / Raw::from("send-recv");
    let report = packet.send_recv_report(
        SendRecv::new()
            .iface(EXAMPLE_IFACE)
            .network_layer()
            .dry_run()
            .timeout(Duration::from_millis(250))
            .retries(1),
    )?;

    println!("example: send_recv_icmp");
    println!("mode: dry-run");
    println!("attempts: {}", report.attempts());
    println!(
        "effective filter: {}",
        report.effective_filter().unwrap_or("")
    );
    println!("timed out: {}", report.timed_out());
    match report.reply() {
        Some(reply) => println!("reply: {}", reply.summary()),
        None => println!("reply: none"),
    }
    println!("summary: {}", packet.summary());
    for (attempt, send) in report.send_reports().iter().enumerate() {
        println!(
            "send attempt {}: bytes {} target {:?}",
            attempt + 1,
            send.bytes_sent(),
            send.plan().target()
        );
    }

    Ok(())
}
