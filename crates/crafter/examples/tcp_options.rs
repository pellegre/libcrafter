mod common;

use common::{parse_ipv4_arg, print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example tcp_options -- [--src IP] [--dst IP]\n\nBuild a TCP SYN with common typed TCP options.",
    ) {
        return Ok(());
    }

    let src = parse_ipv4_arg("--src", Ipv4Addr::new(192, 0, 2, 10))?;
    let dst = parse_ipv4_arg("--dst", Ipv4Addr::new(198, 51, 100, 20))?;
    let tcp = Tcp::new()
        .sport(41000)
        .dport(443)
        .seq(1)
        .flags(TCP_FLAG_SYN)
        .tcp_option(TcpOption::mss(1460))?
        .tcp_option(TcpOption::window_scale(7))?
        .tcp_option(TcpOption::sack_permitted())?
        .tcp_option(TcpOption::timestamp(0x1020_3040, 0))?;
    let packet = Ipv4::new().src(src).dst(dst) / tcp;

    println!("{}", packet.show());
    if let Some(tcp) = packet.layer::<Tcp>() {
        println!("tcp options: {:?}", tcp.parsed_options()?);
    }
    println!("hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
