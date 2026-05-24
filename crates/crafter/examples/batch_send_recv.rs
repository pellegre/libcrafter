mod common;

use std::time::Duration;

use common::{
    local_ipv4, local_ipv6, print_help_if_requested, remote_ipv4, remote_ipv6, ExampleResult,
    EXAMPLE_IFACE,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example batch_send_recv --\n\nBuild IPv4 and IPv6 echo requests and inspect dry-run batch send/receive reports.",
    ) {
        return Ok(());
    }

    let packets = vec![
        Ipv4::new().src(local_ipv4()).dst(remote_ipv4()).id(0x6001)
            / Icmp::echo_request().id(1).seq(1)
            / Raw::from("ipv4"),
        Ipv6::new().src(local_ipv6()).dst(remote_ipv6())
            / Icmpv6::echo_request().id(2).seq(1)
            / Raw::from("ipv6"),
    ];
    let report = send_recv_packets(
        &packets,
        BatchSendRecv::new()
            .iface(EXAMPLE_IFACE)
            .network_layer()
            .dry_run()
            .timeout(Duration::from_millis(250))
            .retries(1),
    )?;

    println!("example: batch_send_recv");
    println!("mode: dry-run");
    println!("requests: {}", report.len());
    println!(
        "effective filter: {}",
        report.effective_filter().unwrap_or("")
    );
    println!("reply count: {}", report.reply_count());
    println!("timed out count: {}", report.timed_out_count());
    for entry in report.entries() {
        println!(
            "request {}: attempts {} timed out {}",
            entry.request_index(),
            entry.attempts(),
            entry.timed_out()
        );
        if let Some(reply) = entry.reply() {
            println!(
                "request {} reply: {}",
                entry.request_index(),
                reply.summary()
            );
        }
        for (attempt, send) in entry.send_reports().iter().enumerate() {
            println!(
                "request {} attempt {} bytes {} target {:?}",
                entry.request_index(),
                attempt + 1,
                send.bytes_sent(),
                send.plan().target()
            );
        }
    }
    for (index, packet) in packets.iter().enumerate() {
        println!("request {index} summary: {}", packet.summary());
    }

    Ok(())
}
