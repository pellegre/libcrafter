mod common;

use common::{parse_ipv4_arg, print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example basic_ping_pong -- [--src IP] [--dst IP]\n\nBuild an ICMP echo request and a synthetic echo reply offline.",
    ) {
        return Ok(());
    }

    let src = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let dst = parse_ipv4_arg("--dst", Ipv4Addr::new(198, 51, 100, 20))?;
    let request =
        Ipv4::new().src(src).dst(dst) / Icmp::echo_request().id(0x4242).seq(1) / Raw::from("ping");
    let reply =
        Ipv4::new().src(dst).dst(src) / Icmp::echo_reply().id(0x4242).seq(1) / Raw::from("ping");

    println!("request: {}", request.summary());
    println!("reply: {}", reply.summary());
    println!("reply matches: {}", reply_matches(&request, &reply));
    println!("request hexdump:\n{}", request.hexdump()?);
    println!("reply hexdump:\n{}", reply.hexdump()?);

    Ok(())
}
