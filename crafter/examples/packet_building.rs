mod common;

use common::{
    local_ipv4, local_mac, print_help_if_requested, remote_ipv4, remote_mac, ExampleResult,
};
use crafter::prelude::*;

const PAYLOAD: &str = "GET / HTTP/1.0\r\n\r\n";

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example packet_building --\n\nBuild equivalent Ethernet/IPv4/TCP/Raw packets with push and / composition.",
    ) {
        return Ok(());
    }

    let pushed = Packet::new()
        .push(
            Ethernet::new()
                .src(local_mac())
                .dst(remote_mac())
                .ethertype(ETHERTYPE_IPV4),
        )
        .push(
            Ipv4::new()
                .src(local_ipv4())
                .dst(remote_ipv4())
                .protocol(IPPROTO_TCP),
        )
        .push(
            Tcp::new()
                .sport(49152)
                .dport(80)
                .seq(0x0102_0304)
                .flags(TCP_FLAG_SYN),
        )
        .push(Raw::from(PAYLOAD));

    let composed = Ethernet::new()
        .src(local_mac())
        .dst(remote_mac())
        .ethertype(ETHERTYPE_IPV4)
        / Ipv4::new()
            .src(local_ipv4())
            .dst(remote_ipv4())
            .protocol(IPPROTO_TCP)
        / Tcp::new()
            .sport(49152)
            .dport(80)
            .seq(0x0102_0304)
            .flags(TCP_FLAG_SYN)
        / Raw::from(PAYLOAD);

    let pushed_bytes = pushed.compile()?;
    let composed_bytes = composed.compile()?;
    assert_eq!(pushed_bytes.as_bytes(), composed_bytes.as_bytes());

    println!("mode: offline");
    println!("push summary: {}", pushed.summary());
    println!("slash summary: {}", composed.summary());
    println!("compiled bytes match: true");
    println!("bytes: {}", pushed_bytes.len());
    println!("hexdump:\n{}", pushed_bytes.hexdump());

    Ok(())
}
