mod common;

use std::net::Ipv6Addr;

use common::{local_ipv6, print_help_if_requested, remote_ipv6, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dhcpv6_prefix_delegation --\n\nBuild, compile, decode, and inspect a DHCPv6 prefix delegation Reply offline.",
    ) {
        return Ok(());
    }

    let prefix = Dhcpv6IaPrefix::new(
        300,
        600,
        56,
        Ipv6Addr::new(0x2001, 0x0db8, 0x0200, 0, 0, 0, 0, 0),
    );
    let ia_pd = Dhcpv6IaPd::new(0x0506_0708, 90, 180).ia_prefix(prefix)?;
    let packet = Ipv6::new().src(remote_ipv6()).dst(local_ipv6())
        / Udp::dhcpv6_server()
        / Dhcpv6::reply(0x050607)
            .client_duid(Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x03]))
            .server_duid(Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x04]))
            .ia_pd(ia_pd)?
            .status(Dhcpv6StatusCode::Success);
    let wire = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, wire.as_bytes())?;
    let dhcpv6 = decoded
        .layer::<Dhcpv6>()
        .expect("decoded packet should contain DHCPv6");
    let delegated = dhcpv6
        .ia_pd_value()?
        .expect("decoded reply should contain IA_PD");
    let delegated_prefix = delegated
        .options_ref()
        .iter()
        .find_map(|option| option.ia_prefix_value().transpose())
        .transpose()?
        .expect("decoded IA_PD should contain IA Prefix");

    println!("example: dhcpv6_prefix_delegation");
    println!("mode: offline");
    println!("message type: {:?}", dhcpv6.message_type_value());
    println!("ia_pd iaid: 0x{:08x}", delegated.iaid());
    println!(
        "delegated prefix: {}/{}",
        delegated_prefix.prefix(),
        delegated_prefix.prefix_length()
    );
    println!("summary: {}", decoded.summary());
    println!("hexdump:\n{}", wire.hexdump());

    Ok(())
}
