mod common;

use common::{local_mac, print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use std::net::Ipv4Addr;

// Offline DHCPv4 example: leasequery (RFC 4388), a typed client identifier
// (option 61, RFC 4361), and authentication packet fields (option 90, RFC
// 3118). These are packet fields only -- the crate never runs a leasequery
// state machine and never derives, signs, or verifies authentication. Each
// packet is compiled and decoded in-process; no client, server, or live
// traffic is involved.
fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dhcp_leasequery --\n\nBuild a DHCP leasequery request and a status-bearing reply, then decode both offline.",
    ) {
        return Ok(());
    }

    let client_mac = local_mac();
    let server_ip: Ipv4Addr = "192.0.2.1".parse()?;
    let requestor_ip: Ipv4Addr = "192.0.2.10".parse()?;

    // A requestor that knows a client identifier can query by it (RFC 4388
    // section 6.1). client_id_value carries a typed DhcpClientIdentifier.
    let client_id = DhcpClientIdentifier::ethernet_mac(client_mac.octets());
    let auth = DhcpAuthentication::new(
        DhcpAuthProtocol::Delayed,
        DhcpAuthAlgorithm::HmacMd5,
        DhcpReplayDetectionMethod::MonotonicCounter,
        0x0000_0000_0000_0001,
        b"\x00\x00\x00\x01placeholder-mac".to_vec(),
    );
    let query = Dhcp::lease_query_by_client_id(client_id)
        .xid(0x4c51_0001)
        .option(DhcpOption::authentication(auth));

    inspect("leasequery request", requestor_ip, server_ip, query)?;

    // A server answers with a lease binding and a status code (RFC 4388 /
    // RFC 6926). This is just packet data assembled from the public builders.
    let reply = Dhcp::lease_query_by_mac(client_mac)
        .op(BOOTP_REPLY)
        .xid(0x4c51_0001)
        .ciaddr("192.0.2.50".parse()?)
        .server_identifier(server_ip)
        .lease_time(3600)
        .option(DhcpOption::associated_ip(vec![
            "192.0.2.50".parse::<Ipv4Addr>()?
        ]))
        .option(DhcpOption::status_code(DhcpStatusCodeOption::new(
            DhcpStatusCode::Success,
            b"ok".to_vec(),
        )))
        .option(DhcpOption::dhcp_state(DhcpState::Active));

    inspect("leasequery reply", server_ip, requestor_ip, reply)?;

    Ok(())
}

fn inspect(label: &str, src: Ipv4Addr, dst: Ipv4Addr, dhcp: Dhcp) -> ExampleResult<()> {
    let packet = Ipv4::new()
        .src(src)
        .dst(dst)
        .ipv4_protocol(Ipv4Protocol::Udp)
        / Udp::new().sport(DHCP_SERVER_PORT).dport(DHCP_SERVER_PORT)
        / dhcp;
    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    let dhcp = decoded
        .layer::<Dhcp>()
        .expect("decoded packet should contain DHCP");

    println!("packet: {label}");
    println!("mode: offline");
    println!("decoded summary: {}", decoded.summary());
    println!("message type: {:?}", dhcp.message_type_value());

    if let Some(Ok(id)) = dhcp.client_identifier_value() {
        println!("client identifier: {id:?}");
    }
    if let Some(Ok(auth)) = dhcp.authentication() {
        println!(
            "authentication: protocol={:?} algorithm={:?} rdm={:?}",
            auth.protocol, auth.algorithm, auth.rdm
        );
    }
    if let Some(Ok(addresses)) = dhcp.associated_ip() {
        println!("associated ip: {addresses:?}");
    }
    if let Some(Ok(status)) = dhcp.status_code() {
        println!("status: {:?} ({})", status.status, status.message_lossy());
    }
    if let Some(Ok(state)) = dhcp.dhcp_state() {
        println!("dhcp state: {state:?}");
    }
    println!("hexdump:\n{}", bytes.hexdump());

    Ok(())
}
