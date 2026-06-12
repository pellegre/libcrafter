mod common;

use common::{arg_value, parse_u16_arg, print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const DEFAULT_LOCAL_AS: u16 = 65_000;
const DEFAULT_PEER_AS: u16 = 65_001;
const DEFAULT_BGP_ID: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const DEFAULT_IPV4_PREFIX: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 0);
const DEFAULT_IPV6_PREFIX: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
const DEFAULT_IPV6_NEXT_HOP: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example bgp_session -- [--peer IP:PORT] [--local-as ASN] [--peer-as ASN] [--announce PREFIX]\n\nBuild an offline BGP session message plan. --peer selects future live mode but does not open a socket in this example.",
    ) {
        return Ok(());
    }

    let config = Config::from_args()?;
    if let Some(peer) = config.peer {
        return Err(format!(
            "live BGP socket mode for peer {peer} is reserved for a later example step; no socket was opened"
        )
        .into());
    }

    println!("example: bgp_session");
    println!("mode: offline");
    println!("local AS: {}", config.local_as);
    println!("peer AS: {}", config.peer_as);
    println!("BGP ID: {}", config.bgp_id);
    println!(
        "IPv4 announce: {}/{}",
        config.ipv4_prefix.0, config.ipv4_prefix.1
    );
    println!(
        "IPv6 announce: {}/{}",
        config.ipv6_prefix.0, config.ipv6_prefix.1
    );

    let messages = bgp_messages(&config)?;
    for (index, (label, packet)) in messages.iter().enumerate() {
        print_message(index + 1, label, packet)?;
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct Config {
    peer: Option<SocketAddr>,
    local_as: u16,
    peer_as: u16,
    bgp_id: Ipv4Addr,
    ipv4_prefix: (Ipv4Addr, u8),
    ipv6_prefix: (Ipv6Addr, u8),
}

impl Config {
    fn from_args() -> ExampleResult<Self> {
        let mut config = Self {
            peer: parse_peer()?,
            local_as: parse_u16_arg("--local-as", DEFAULT_LOCAL_AS)?,
            peer_as: parse_u16_arg("--peer-as", DEFAULT_PEER_AS)?,
            bgp_id: DEFAULT_BGP_ID,
            ipv4_prefix: (DEFAULT_IPV4_PREFIX, 24),
            ipv6_prefix: (DEFAULT_IPV6_PREFIX, 32),
        };

        if let Some(prefix) = arg_value("--announce") {
            match parse_prefix(&prefix)? {
                Prefix::V4(addr, len) => config.ipv4_prefix = (addr, len),
                Prefix::V6(addr, len) => config.ipv6_prefix = (addr, len),
            }
        }

        Ok(config)
    }
}

enum Prefix {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

fn parse_peer() -> ExampleResult<Option<SocketAddr>> {
    match arg_value("--peer") {
        Some(value) => Ok(Some(value.parse()?)),
        None => Ok(None),
    }
}

fn parse_prefix(value: &str) -> ExampleResult<Prefix> {
    let (addr, len) = value
        .split_once('/')
        .ok_or_else(|| format!("--announce expects CIDR form, got {value:?}"))?;
    let len: u8 = len.parse()?;
    match addr.parse::<IpAddr>()? {
        IpAddr::V4(addr) if len <= 32 => Ok(Prefix::V4(addr, len)),
        IpAddr::V6(addr) if len <= 128 => Ok(Prefix::V6(addr, len)),
        IpAddr::V4(_) => Err(format!("IPv4 prefix length must be <= 32, got {len}").into()),
        IpAddr::V6(_) => Err(format!("IPv6 prefix length must be <= 128, got {len}").into()),
    }
}

fn bgp_messages(config: &Config) -> ExampleResult<Vec<(&'static str, Packet)>> {
    let ipv4_prefix = BgpPrefix::from_ipv4(config.ipv4_prefix.0, config.ipv4_prefix.1)?;
    let ipv6_prefix = BgpPrefix::from_ipv6(config.ipv6_prefix.0, config.ipv6_prefix.1)?;

    Ok(vec![
        (
            "OPEN",
            Packet::from_layer(
                Bgp::open()
                    .my_as(config.local_as)
                    .hold_time(90)
                    .bgp_id(config.bgp_id)
                    .capabilities([
                        BgpCapability::ipv4_unicast(),
                        BgpCapability::ipv6_unicast(),
                        BgpCapability::route_refresh(),
                        BgpCapability::four_octet_as(config.local_as as u32),
                    ]),
            ),
        ),
        ("KEEPALIVE", Packet::from_layer(Bgp::keepalive())),
        (
            "UPDATE IPv4 announce",
            Packet::from_layer(
                Bgp::update()
                    .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
                    .attribute(BgpPathAttribute::as_sequence(&[config.local_as as u32]))
                    .attribute(BgpPathAttribute::next_hop(config.bgp_id))
                    .nlri(ipv4_prefix),
            ),
        ),
        (
            "UPDATE MP-BGP IPv6 announce",
            Packet::from_layer(
                Bgp::update()
                    .attribute(BgpPathAttribute::origin(BGP_ORIGIN_IGP))
                    .attribute(BgpPathAttribute::as_sequence(&[config.local_as as u32]))
                    .attribute(BgpPathAttribute::mp_reach_ipv6(
                        DEFAULT_IPV6_NEXT_HOP,
                        &[ipv6_prefix],
                    )),
            ),
        ),
        ("NOTIFICATION Cease", Packet::from_layer(Bgp::cease())),
    ])
}

fn print_message(index: usize, label: &str, packet: &Packet) -> ExampleResult<()> {
    let compiled = packet.compile()?;
    println!();
    println!("message {index}: {label}");
    println!("summary: {}", packet.summary());
    println!("bytes: {}", compiled.len());
    println!("hex: {}", compact_hex(compiled.as_bytes()));
    println!("hexdump:\n{}", compiled.hexdump());
    Ok(())
}

fn compact_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}
