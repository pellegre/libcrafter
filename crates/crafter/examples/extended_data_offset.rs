mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example extended_data_offset --\n\nBuild a TCP packet with Extended Data Offset options.",
    ) {
        return Ok(());
    }

    let tcp = Tcp::new()
        .sport(41000)
        .dport(80)
        .seq(1)
        .flags(TCP_FLAG_SYN)
        .tcp_option(TcpOption::extended_data_offset_request())?
        .tcp_option(TcpOption::extended_data_offset_ext(16, 96))?
        .tcp_option(TcpOption::mss(1460))?;
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / tcp
        / Raw::from("edo");

    println!("{}", packet.show());
    println!("hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
