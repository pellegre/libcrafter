mod common;

use common::{local_mac, print_help_if_requested, remote_mac, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

// Offline DHCPv4 example: relay agent information (option 82), classless static
// routes (option 121), and BOOTP option overload (option 52). Everything here
// is packet construction and inspection only -- no client, server, or live
// traffic. The packet is compiled and decoded in-process.
fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dhcp_option82 --\n\nBuild a relay-forwarded DHCP discover with option 82, classless routes, and option overload, then decode it offline.",
    ) {
        return Ok(());
    }

    let client_mac = local_mac();
    let relay_mac = remote_mac();
    let giaddr: Ipv4Addr = "192.0.2.1".parse()?;

    // A relay agent adds option 82 sub-options when forwarding a client message
    // toward the server. Registered sub-options decode to typed values; unknown
    // codes are preserved verbatim through DhcpRelaySuboption::other.
    let relay_info = DhcpRelayAgentInfo::new(vec![
        DhcpRelaySuboption::circuit_id(b"eth0:vlan100".to_vec()),
        DhcpRelaySuboption::remote_id(b"relay-1".to_vec()),
        DhcpRelaySuboption::other(254, b"vendor-bytes".to_vec()),
    ]);

    // RFC 3442 classless static routes (option 121).
    let routes = vec![
        DhcpClasslessRoute::new(24, "198.51.100.0".parse()?, "192.0.2.1".parse()?),
        DhcpClasslessRoute::new(0, Ipv4Addr::UNSPECIFIED, "192.0.2.254".parse()?),
    ];
    let routes_option = DhcpOption::typed(
        DhcpOptionKind::ClasslessStaticRoute,
        DhcpOptionValue::ClasslessRoutes(routes),
    );

    let dhcp = Dhcp::discover(client_mac)
        .xid(0x0102_0304)
        .giaddr(giaddr)
        .relay_agent_info(relay_info)
        // Push an option into the overloaded `sname` BOOTP field. compile()
        // auto-inserts the option-overload option (52) to mark the area.
        .sname_option(routes_option);

    let packet = Ethernet::new()
        .src(relay_mac)
        .dst(MacAddr::BROADCAST)
        .ethertype(ETHERTYPE_IPV4)
        / Ipv4::new()
            .src(giaddr)
            .dst(Ipv4Addr::BROADCAST)
            .ipv4_protocol(Ipv4Protocol::Udp)
        / Udp::new().sport(DHCP_SERVER_PORT).dport(DHCP_SERVER_PORT)
        / dhcp;

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes.as_bytes())?;
    let dhcp = decoded
        .layer::<Dhcp>()
        .expect("decoded packet should contain DHCP");

    println!("example: dhcp_option82");
    println!("mode: offline");
    println!("decoded summary: {}", decoded.summary());
    println!("transaction id: 0x{:08x}", dhcp.transaction_id_value());
    println!("message type: {:?}", dhcp.message_type_value());
    println!("option overload: {:?}", dhcp.option_overload());

    if let Some(Ok(info)) = dhcp.relay_agent_information() {
        for suboption in &info.suboptions {
            println!(
                "relay agent suboption (code {}): {:?}",
                suboption.code(),
                suboption
            );
        }
    }

    if let Some(Ok(routes)) = dhcp.classless_static_routes() {
        for route in &routes {
            println!("classless route: {:?}", route);
        }
    }

    println!("hexdump:\n{}", bytes.hexdump());

    Ok(())
}
