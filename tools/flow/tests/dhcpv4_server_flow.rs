use std::net::Ipv4Addr;

use crafter_flow::flows::dhcpv4::{server_flow, DONE, WAIT_DISCOVER, WAIT_REQUEST};
use crafter_flow::{docaddr, FlowOutcome, MemoryCaptureSource, RunOptions, Runner};

fn discover_packet(client_mac: crafter::MacAddr, transaction_id: u32) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(client_mac)
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_client()
        / crafter::Dhcpv4::discover(client_mac).xid(transaction_id)
}

fn request_packet(
    client_mac: crafter::MacAddr,
    transaction_id: u32,
    requested_ip: Ipv4Addr,
    server_identifier: Ipv4Addr,
) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(client_mac)
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_client()
        / crafter::Dhcpv4::request(client_mac, requested_ip, server_identifier).xid(transaction_id)
}

fn decode_send_plan(report: &crafter::net::SendReport) -> crafter::Packet {
    crafter::Packet::decode_from_link(crafter::LinkType::Ethernet, report.plan().bytes())
        .expect("dry-run send plan decodes as Ethernet")
}

#[test]
fn dhcpv4_server_flow_completes_offline_with_offer_then_ack() {
    let server_ip = docaddr::SERVER_IPV4;
    let offered_ip = docaddr::CLIENT_IPV4;
    let transaction_id = 0x5200_0001;
    let discover = discover_packet(docaddr::CLIENT_MAC, transaction_id);
    let request = request_packet(docaddr::CLIENT_MAC, transaction_id, offered_ip, server_ip);
    let mut flow = server_flow(docaddr::LOCAL_MAC, server_ip, offered_ip);
    let mut runner = Runner::with_source(
        RunOptions::default(),
        MemoryCaptureSource::new(vec![discover, request]),
    )
    .expect("offline runner opens");

    let report = runner.run(&mut flow).expect("DHCPv4 server flow runs");

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(
        report.visited_states(),
        &[
            WAIT_DISCOVER.to_string(),
            WAIT_REQUEST.to_string(),
            DONE.to_string()
        ]
    );
    assert!(report.context_snapshot().contains("offered_ipv4"));
    assert!(report.context_snapshot().contains("assigned_ipv4"));
    assert!(report.context_snapshot().contains("server_identifier"));
    assert_eq!(report.sent_count(), 2);
    assert_eq!(runner.send_reports().len(), 2);
    assert!(runner
        .send_reports()
        .iter()
        .all(|report| report.is_dry_run()));

    let offer = decode_send_plan(&runner.send_reports()[0]);
    let offer_ethernet = offer
        .layer::<crafter::Ethernet>()
        .expect("OFFER contains Ethernet");
    let offer_dhcp = offer
        .layer::<crafter::Dhcpv4>()
        .expect("OFFER contains DHCPv4");
    assert_eq!(offer_ethernet.source(), Some(docaddr::LOCAL_MAC));
    assert_eq!(offer_ethernet.destination(), Some(docaddr::CLIENT_MAC));
    assert_eq!(
        offer_dhcp.message_type_value(),
        Some(crafter::Dhcpv4MessageType::Offer)
    );
    assert_eq!(offer_dhcp.transaction_id_value(), transaction_id);
    assert_eq!(offer_dhcp.client_mac_value(), Some(docaddr::CLIENT_MAC));
    assert_eq!(offer_dhcp.offered_ip_address(), Some(offered_ip));
    assert_eq!(offer_dhcp.server_identifier_value(), Some(server_ip));

    let ack = decode_send_plan(&runner.send_reports()[1]);
    let ack_ethernet = ack
        .layer::<crafter::Ethernet>()
        .expect("ACK contains Ethernet");
    let ack_dhcp = ack.layer::<crafter::Dhcpv4>().expect("ACK contains DHCPv4");
    assert_eq!(ack_ethernet.source(), Some(docaddr::LOCAL_MAC));
    assert_eq!(ack_ethernet.destination(), Some(docaddr::CLIENT_MAC));
    assert_eq!(
        ack_dhcp.message_type_value(),
        Some(crafter::Dhcpv4MessageType::Ack)
    );
    assert_eq!(ack_dhcp.transaction_id_value(), transaction_id);
    assert_eq!(ack_dhcp.client_mac_value(), Some(docaddr::CLIENT_MAC));
    assert_eq!(ack_dhcp.offered_ip_address(), Some(offered_ip));
    assert_eq!(ack_dhcp.server_identifier_value(), Some(server_ip));
}
