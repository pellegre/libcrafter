use std::net::Ipv4Addr;

use crafter_flow::flows::dhcpv4::{client_flow, BOUND, REQUESTING, SELECTING};
use crafter_flow::{docaddr, FlowOutcome, MemoryCaptureSource, PacketContext, RunOptions, Runner};

fn server_mac() -> crafter::MacAddr {
    crafter::MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x02])
}

fn discover_transaction_id(client_mac: crafter::MacAddr) -> u32 {
    let mut flow = client_flow(client_mac);
    let mut context = PacketContext::new();

    flow.state_mut(SELECTING)
        .expect("Selecting state exists")
        .run_entry(&mut context)
        .expect("Selecting entry succeeds")
        .expect("Selecting entry sends DISCOVER");

    context
        .get_transaction_id()
        .expect("Selecting entry stores transaction id")
}

fn offer_packet(
    transaction_id: u32,
    offered_ip: Ipv4Addr,
    server_id: Ipv4Addr,
) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(server_mac())
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(server_id)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_server()
        / crafter::Dhcpv4::offer(docaddr::CLIENT_MAC, offered_ip, server_id).xid(transaction_id)
}

fn ack_packet(
    transaction_id: u32,
    assigned_ip: Ipv4Addr,
    server_id: Ipv4Addr,
) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(server_mac())
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(server_id)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_server()
        / crafter::Dhcpv4::ack(docaddr::CLIENT_MAC, assigned_ip, server_id).xid(transaction_id)
}

#[test]
fn dhcpv4_client_flow_completes_offline_and_carries_offer_into_request() {
    let offered_ip = Ipv4Addr::new(192, 0, 2, 44);
    let server_id = docaddr::SERVER_IPV4;
    let transaction_id = discover_transaction_id(docaddr::CLIENT_MAC);
    let offer = offer_packet(transaction_id, offered_ip, server_id);
    let ack = ack_packet(transaction_id, offered_ip, server_id);
    let mut flow = client_flow(docaddr::CLIENT_MAC);
    let mut runner = Runner::with_source(
        RunOptions::default(),
        MemoryCaptureSource::new(vec![offer, ack]),
    )
    .expect("offline runner opens");

    let report = runner.run(&mut flow).expect("DHCPv4 flow completes");

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(
        report.visited_states(),
        &[
            SELECTING.to_string(),
            REQUESTING.to_string(),
            BOUND.to_string()
        ]
    );
    assert!(report.context_snapshot().contains("offered_ipv4"));
    assert!(report.context_snapshot().contains("assigned_ipv4"));
    assert!(report.context_snapshot().contains("server_identifier"));
    assert_eq!(runner.send_reports().len(), 2);

    let request_plan = runner
        .send_reports()
        .get(1)
        .expect("second send is DHCP REQUEST")
        .plan();
    let request =
        crafter::Packet::decode_from_link(crafter::LinkType::Ethernet, request_plan.bytes())
            .expect("REQUEST plan decodes as Ethernet");
    let request_dhcp = request
        .layer::<crafter::Dhcpv4>()
        .expect("REQUEST contains DHCPv4");

    assert_eq!(
        request_dhcp.message_type_value(),
        Some(crafter::Dhcpv4MessageType::Request)
    );
    assert_eq!(request_dhcp.transaction_id_value(), transaction_id);
    assert_eq!(request_dhcp.requested_ip_address_value(), Some(offered_ip));
    assert_eq!(request_dhcp.server_identifier_value(), Some(server_id));
}
