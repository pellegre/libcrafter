mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example sack_option --\n\nBuild a TCP ACK carrying SACK blocks.",
    ) {
        return Ok(());
    }

    let tcp = Tcp::new()
        .sport(443)
        .dport(41000)
        .seq(10_000)
        .ack(20_000)
        .flags(TCP_FLAG_ACK)
        .tcp_option(TcpOption::sack(vec![
            TcpSackBlock::new(20_100, 20_400),
            TcpSackBlock::new(20_800, 21_000),
        ]))?;
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(198, 51, 100, 20))
        .dst(Ipv4Addr::new(192, 0, 2, 10))
        / tcp;

    println!("{}", packet.show());
    println!("hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
