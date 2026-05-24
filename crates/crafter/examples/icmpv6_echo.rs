mod common;

use std::time::Duration;

use common::{
    arg_or, flag_present, local_ipv6, parse_ipv6_arg, parse_u16_arg, print_help_if_requested,
    remote_ipv6, ExampleResult, EXAMPLE_IFACE,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example icmpv6_echo -- [--send-recv] [--iface IFACE] [--src IPv6] [--dst IPv6] [--id N] [--seq N]\n\nBuild an IPv6 ICMPv6 echo request offline and optionally inspect a dry-run send/receive report.",
    ) {
        return Ok(());
    }

    let send_recv = flag_present("--send-recv");
    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let src = parse_ipv6_arg("--src", local_ipv6())?;
    let dst = parse_ipv6_arg("--dst", remote_ipv6())?;
    let id = parse_u16_arg("--id", 0x4242)?;
    let seq = parse_u16_arg("--seq", 1)?;
    let packet = Ipv6::new().src(src).dst(dst).hlim(64)
        / Icmpv6::echo_request().id(id).seq(seq)
        / Raw::from("icmpv6-echo");
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;
    let icmpv6 = decoded
        .layer::<Icmpv6>()
        .expect("decoded ICMPv6 echo request should contain Icmpv6");

    println!("example: icmpv6_echo");
    println!(
        "mode: {}",
        if send_recv {
            "dry-run send/receive"
        } else {
            "offline"
        }
    );
    println!("source: {src}");
    println!("destination: {dst}");
    println!("decoded summary: {}", decoded.summary());
    println!(
        "icmpv6 checksum: {}",
        icmpv6
            .checksum_value()
            .map(|checksum| format!("0x{checksum:04x}"))
            .unwrap_or_else(|| "not decoded".to_string())
    );
    println!("checksum source: IPv6 pseudo-header computed during compile");
    println!("hexdump:\n{}", compiled.hexdump());

    if send_recv {
        let report = packet.send_recv_report(
            SendRecv::new()
                .iface(iface.clone())
                .network_layer()
                .dry_run()
                .timeout(Duration::from_millis(250))
                .retries(1),
        )?;

        println!("dry-run interface: {iface}");
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
    }

    Ok(())
}
