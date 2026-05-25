mod common;

use common::{
    arg_or, local_ipv4, parse_ipv4_arg, parse_u16_arg, print_help_if_requested, remote_ipv4,
    remote_ipv6, ExampleResult, EXAMPLE_IFACE,
};
use crafter::prelude::*;
use std::time::Duration;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dns_query -- [--iface IFACE] [--src IP] [--server IP] [--sport PORT] [--name NAME] [--aaaa]\n\nBuild a DNS query over UDP, inspect a dry-run send/receive report, and decode a synthetic response offline.",
    ) {
        return Ok(());
    }

    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let src = parse_ipv4_arg("--src", local_ipv4())?;
    let server = parse_ipv4_arg("--server", remote_ipv4())?;
    let sport = parse_u16_arg("--sport", 53000)?;
    let name = arg_or("--name", "example.com");
    let question_type = if common::flag_present("--aaaa") {
        DNS_TYPE_AAAA
    } else {
        DNS_TYPE_A
    };
    let query = Ipv4::new()
        .src(src)
        .dst(server)
        .id(0x5301)
        .protocol(IPPROTO_UDP)
        / Udp::new().sport(sport).dport(DNS_PORT)
        / Dns::query(name.clone(), question_type).id(0x1234);
    let report = query.send_recv_report(
        SendRecv::new()
            .iface(iface.clone())
            .network_layer()
            .dry_run()
            .timeout(Duration::from_millis(250))
            .retries(1),
    )?;

    println!("example: dns_query");
    println!("mode: dry-run send/receive plus offline response decode");
    println!("interface: {iface}");
    println!("server: {server}");
    println!("query name: {name}");
    println!("query type: {}", dns_type_label(question_type));
    println!("attempts: {}", report.attempts());
    println!(
        "effective filter: {}",
        report.effective_filter().unwrap_or("")
    );
    println!("timed out: {}", report.timed_out());
    println!("request summary: {}", query.summary());
    for (attempt, send) in report.send_reports().iter().enumerate() {
        println!(
            "send attempt {}: bytes {} target {:?}",
            attempt + 1,
            send.bytes_sent(),
            send.plan().target()
        );
    }
    println!("request hexdump:\n{}", query.hexdump()?);

    let answer = if question_type == DNS_TYPE_AAAA {
        DnsRecord::aaaa(name.clone(), remote_ipv6(), 300)
    } else {
        DnsRecord::a(name.clone(), remote_ipv4(), 300)
    };
    let response = Ipv4::new()
        .src(server)
        .dst(src)
        .id(0x5302)
        .protocol(IPPROTO_UDP)
        / Udp::new().sport(DNS_PORT).dport(sport)
        / Dns::query(name, question_type)
            .id(0x1234)
            .response(true)
            .recursion_available(true)
            .answer(answer);
    let response_bytes = response.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, response_bytes.as_bytes())?;
    let dns = decoded
        .layer::<Dns>()
        .expect("decoded synthetic response should contain DNS");

    println!("offline response summary: {}", decoded.summary());
    for (index, answer) in dns.answers().iter().enumerate() {
        println!(
            "answer {}: {} {} ttl {} {:?}",
            index + 1,
            answer.name(),
            dns_type_label(answer.record_type()),
            answer.ttl(),
            answer.data()
        );
    }

    Ok(())
}

fn dns_type_label(record_type: u16) -> &'static str {
    match record_type {
        DNS_TYPE_A => "A",
        DNS_TYPE_AAAA => "AAAA",
        _ => "other",
    }
}
