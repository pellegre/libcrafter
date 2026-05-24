mod common;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example reply_matching --\n\nBuild synthetic request/reply pairs and test offline reply matching.",
    ) {
        return Ok(());
    }

    let icmp_request = Ipv4::new().src(local_ipv4()).dst(remote_ipv4()).id(0x4001)
        / Icmp::echo_request().id(0x4242).seq(1)
        / Raw::from("icmp");
    let icmp_reply = Ipv4::new().src(remote_ipv4()).dst(local_ipv4()).id(0x4002)
        / Icmp::echo_reply().id(0x4242).seq(1)
        / Raw::from("icmp");

    let tcp_request = Ipv4::new().src(local_ipv4()).dst(remote_ipv4()).id(0x4003)
        / Tcp::new()
            .sport(49152)
            .dport(443)
            .seq(100)
            .flags(TCP_FLAG_SYN);
    let tcp_reply = Ipv4::new().src(remote_ipv4()).dst(local_ipv4()).id(0x4004)
        / Tcp::new()
            .sport(443)
            .dport(49152)
            .seq(200)
            .ack(101)
            .flags(TCP_FLAG_SYN | TCP_FLAG_ACK);

    println!("example: reply_matching");
    println!("mode: offline");
    print_match("icmp", &icmp_request, &icmp_reply);
    print_match("tcp", &tcp_request, &tcp_reply);

    Ok(())
}

fn print_match(label: &str, request: &Packet, reply: &Packet) {
    println!("{label} request: {}", request.summary());
    println!(
        "{label} reply filter: {}",
        reply_filter(request).unwrap_or_default()
    );
    println!("{label} reply: {}", reply.summary());
    println!("{label} reply matches: {}", reply_matches(request, reply));
}
