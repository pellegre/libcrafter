mod common;

use std::net::Ipv6Addr;

use common::{local_ipv6, print_help_if_requested, remote_ipv6, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dhcpv6_relay --\n\nBuild, compile, decode, and inspect a DHCPv6 Relay-forward offline.",
    ) {
        return Ok(());
    }

    let link_address = Ipv6Addr::new(0x2001, 0x0db8, 0x0100, 0, 0, 0, 0, 0);
    let relay = Dhcpv6::relay_forward(link_address, local_ipv6())
        .hop_count(1)
        .interface_id(b"access-loop-1".as_slice())
        .relay_message(
            Dhcpv6::solicit(0x0a0b0c)
                .client_duid(Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x05])),
        )?;
    let packet = Ipv6::new().src(local_ipv6()).dst(remote_ipv6()) / Udp::dhcpv6_relay() / relay;
    let wire = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, wire.as_bytes())?;
    let dhcpv6 = decoded
        .layer::<Dhcpv6>()
        .expect("decoded packet should contain DHCPv6");
    let inner = dhcpv6
        .relayed_message_value()?
        .expect("decoded relay should contain a relay message");

    println!("example: dhcpv6_relay");
    println!("mode: offline");
    println!("message type: {:?}", dhcpv6.message_type_value());
    println!(
        "hop count: {}",
        dhcpv6
            .relay()
            .expect("decoded relay should have a relay header")
            .hop_count_value()
    );
    println!(
        "interface id: {:?}",
        dhcpv6.interface_id_value().unwrap_or_default()
    );
    println!("inner message type: {:?}", inner.message_type_value());
    println!("summary: {}", decoded.summary());
    println!("hexdump:\n{}", wire.hexdump());

    Ok(())
}
