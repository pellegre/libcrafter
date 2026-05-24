mod common;

use common::{local_ipv4, parse_ipv4_arg, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example tcp_options -- [--src IP] [--dst IP]\n\nBuild labeled TCP packets covering common options, SACK blocks, and Extended Data Offset.",
    ) {
        return Ok(());
    }

    let src = parse_ipv4_arg("--src", local_ipv4())?;
    let dst = parse_ipv4_arg("--dst", remote_ipv4())?;

    println!("example: tcp_options");
    println!("mode: offline");
    inspect_tcp_packet(
        "mss window-scale sack-permitted timestamp",
        &syn_options(src, dst)?,
    )?;
    inspect_tcp_packet("sack blocks", &sack_blocks(src, dst)?)?;
    inspect_tcp_packet("extended data offset", &extended_data_offset(src, dst)?)?;

    Ok(())
}

fn syn_options(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr) -> ExampleResult<Packet> {
    let tcp = Tcp::new()
        .sport(41000)
        .dport(443)
        .seq(1)
        .flags(TCP_FLAG_SYN)
        .tcp_option(TcpOption::mss(1460))?
        .tcp_option(TcpOption::window_scale(7))?
        .tcp_option(TcpOption::sack_permitted())?
        .tcp_option(TcpOption::timestamp(0x1020_3040, 0))?;

    Ok(Ipv4::new().src(src).dst(dst).id(0x5401) / tcp)
}

fn sack_blocks(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr) -> ExampleResult<Packet> {
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

    Ok(Ipv4::new().src(dst).dst(src).id(0x5402) / tcp)
}

fn extended_data_offset(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr) -> ExampleResult<Packet> {
    let tcp = Tcp::new()
        .sport(41000)
        .dport(80)
        .seq(1)
        .flags(TCP_FLAG_SYN)
        .tcp_option(TcpOption::extended_data_offset_request())?
        .tcp_option(TcpOption::extended_data_offset_ext(16, 96))?
        .tcp_option(TcpOption::mss(1460))?;

    Ok(Ipv4::new().src(src).dst(dst).id(0x5403) / tcp / Raw::from("edo"))
}

fn inspect_tcp_packet(label: &str, packet: &Packet) -> ExampleResult<()> {
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let tcp = decoded
        .layer::<Tcp>()
        .expect("decoded TCP option packet should contain Tcp");
    let options = tcp.parsed_options()?;

    println!("packet: {label}");
    println!("decoded summary: {}", decoded.summary());
    println!(
        "data offset: {} words ({} bytes)",
        tcp.data_offset_value(),
        tcp.header_len()
    );
    for (index, option) in options.iter().enumerate() {
        println!("tcp option {}: {:?}", index + 1, option);
    }
    println!("hexdump:\n{}", compiled.hexdump());

    Ok(())
}
