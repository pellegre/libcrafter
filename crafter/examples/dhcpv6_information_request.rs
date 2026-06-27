mod common;

use common::{local_ipv6, print_help_if_requested, remote_ipv6, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dhcpv6_information_request --\n\nBuild, compile, decode, and inspect a DHCPv6 Information-request offline.",
    ) {
        return Ok(());
    }

    let packet = Ipv6::new().src(local_ipv6()).dst(remote_ipv6())
        / Udp::dhcpv6_client()
        / Dhcpv6::information_request(0x030405)
            .client_duid(Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x06, 0x02]))
            .oro([DHCPV6_OPTION_DNS_SERVERS, DHCPV6_OPTION_DOMAIN_LIST])
            .elapsed_time(2);
    let wire = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, wire.as_bytes())?;
    let dhcpv6 = decoded
        .layer::<Dhcpv6>()
        .expect("decoded packet should contain DHCPv6");

    println!("example: dhcpv6_information_request");
    println!("mode: offline");
    println!("message type: {:?}", dhcpv6.message_type_value());
    println!("transaction id: 0x{:06x}", dhcpv6.transaction_id_value());
    println!("oro: {:?}", dhcpv6.oro_value()?.unwrap_or_default());
    println!("summary: {}", decoded.summary());
    println!("hexdump:\n{}", wire.hexdump());

    Ok(())
}
