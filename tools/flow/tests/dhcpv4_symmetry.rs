use crafter_flow::flows::dhcpv4::{
    client_flow, server_flow, BOUND, DONE, REQUESTING, SELECTING, WAIT_DISCOVER, WAIT_REQUEST,
};
use crafter_flow::{
    docaddr, CaptureSource, Flow, FlowOutcome, FlowReport, FnMutator, MemoryCaptureSource, Role,
    RunOptions, Runner,
};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

type PacketLog = Rc<RefCell<Vec<crafter::Packet>>>;

struct ResponderPumpSource {
    client_packets: PacketLog,
    delivered_responses: usize,
}

impl ResponderPumpSource {
    fn new(client_packets: PacketLog) -> Self {
        Self {
            client_packets,
            delivered_responses: 0,
        }
    }
}

impl CaptureSource for ResponderPumpSource {
    fn next_packet(&mut self, _timeout: Duration) -> crafter_flow::Result<Option<crafter::Packet>> {
        let client_packets = self.client_packets.borrow().clone();
        let (_report, responder_packets) = run_responder(client_packets)?;

        if self.delivered_responses >= responder_packets.len() {
            return Ok(None);
        }

        let packet = responder_packets[self.delivered_responses].clone();
        self.delivered_responses += 1;
        Ok(Some(packet))
    }

    fn describe(&self) -> String {
        "responder pump source".to_string()
    }
}

fn graph_shape(flow: &Flow, ordered_states: [&str; 3]) -> Vec<(usize, usize, bool)> {
    ordered_states
        .iter()
        .map(|name| {
            let state = flow.state(name).expect("state exists");
            let declared_target_count = state
                .transitions()
                .iter()
                .map(|transition| transition.declared_targets().len())
                .sum();

            (
                state.transitions().len(),
                declared_target_count,
                state.declares_entry_terminal_path(),
            )
        })
        .collect()
}

fn packet_from_report(report: &crafter::net::SendReport) -> crafter::Packet {
    assert!(report.is_dry_run());
    crafter::Packet::decode_from_link(crafter::LinkType::Ethernet, report.plan().bytes())
        .expect("dry-run plan decodes as Ethernet")
}

fn packets_from_reports(reports: &[crafter::net::SendReport]) -> Vec<crafter::Packet> {
    reports.iter().map(packet_from_report).collect()
}

fn assert_dhcp_message(packet: &crafter::Packet, message_type: crafter::Dhcpv4MessageType) {
    let dhcp = packet
        .layer::<crafter::Dhcpv4>()
        .expect("packet has DHCPv4");

    assert_eq!(dhcp.message_type_value(), Some(message_type));
}

fn run_responder(
    client_packets: Vec<crafter::Packet>,
) -> crafter_flow::Result<(FlowReport, Vec<crafter::Packet>)> {
    let mut responder = server_flow(
        docaddr::LOCAL_MAC,
        docaddr::SERVER_IPV4,
        docaddr::CLIENT_IPV4,
    );
    let mut runner = Runner::with_source(
        RunOptions::default(),
        MemoryCaptureSource::new(client_packets),
    )?;
    let report = runner.run(&mut responder)?;
    let packets = packets_from_reports(runner.send_reports());

    Ok((report, packets))
}

#[test]
fn dhcpv4_client_and_responder_drive_each_other_offline() {
    let mut client = client_flow(docaddr::CLIENT_MAC);
    let responder = server_flow(
        docaddr::LOCAL_MAC,
        docaddr::SERVER_IPV4,
        docaddr::CLIENT_IPV4,
    );

    client.validate().expect("client flow validates");
    responder.validate().expect("responder flow validates");
    assert_eq!(client.role(), Role::Initiator);
    assert_eq!(responder.role(), Role::Responder);
    // The role-specific state names and actions differ, but both flows expose
    // the same two-edge DHCP graph shape: initial -> middle -> terminal.
    assert_eq!(
        graph_shape(&client, [SELECTING, REQUESTING, BOUND]),
        graph_shape(&responder, [WAIT_DISCOVER, WAIT_REQUEST, DONE])
    );

    let client_packet_log = Rc::new(RefCell::new(Vec::new()));
    let client_packet_log_for_mutator = Rc::clone(&client_packet_log);
    let client_source = ResponderPumpSource::new(Rc::clone(&client_packet_log));
    let client_tap = FnMutator::new("record-client-packets", move |packet, _iteration, _ctx| {
        client_packet_log_for_mutator
            .borrow_mut()
            .push(packet.clone());
        Ok(packet)
    });
    let mut client_runner = Runner::with_source(RunOptions::default(), client_source)
        .expect("client runner opens")
        .mutator(client_tap);

    let client_report = client_runner
        .run(&mut client)
        .expect("client runner completes");
    let client_packets = packets_from_reports(client_runner.send_reports());

    assert_eq!(client_report.outcome(), &FlowOutcome::Completed);
    assert_eq!(
        client_report.visited_states(),
        &[
            SELECTING.to_string(),
            REQUESTING.to_string(),
            BOUND.to_string()
        ]
    );
    assert!(client_report.context_snapshot().contains("assigned_ipv4"));
    assert_eq!(client_packets.len(), 2);
    assert_dhcp_message(&client_packets[0], crafter::Dhcpv4MessageType::Discover);
    assert_dhcp_message(&client_packets[1], crafter::Dhcpv4MessageType::Request);

    let (responder_report, responder_packets) =
        run_responder(client_packets.clone()).expect("responder runner completes");

    assert_eq!(responder_report.outcome(), &FlowOutcome::Completed);
    assert_eq!(
        responder_report.visited_states(),
        &[
            WAIT_DISCOVER.to_string(),
            WAIT_REQUEST.to_string(),
            DONE.to_string()
        ]
    );
    assert!(responder_report.context_snapshot().contains("offered_ipv4"));
    assert!(responder_report
        .context_snapshot()
        .contains("assigned_ipv4"));
    assert_eq!(responder_packets.len(), 2);
    assert_dhcp_message(&responder_packets[0], crafter::Dhcpv4MessageType::Offer);
    assert_dhcp_message(&responder_packets[1], crafter::Dhcpv4MessageType::Ack);

    let offer_dhcp = responder_packets[0]
        .layer::<crafter::Dhcpv4>()
        .expect("OFFER has DHCPv4");
    let ack_dhcp = responder_packets[1]
        .layer::<crafter::Dhcpv4>()
        .expect("ACK has DHCPv4");
    let request_dhcp = client_packets[1]
        .layer::<crafter::Dhcpv4>()
        .expect("REQUEST has DHCPv4");

    assert_eq!(offer_dhcp.offered_ip_address(), Some(docaddr::CLIENT_IPV4));
    assert_eq!(ack_dhcp.offered_ip_address(), Some(docaddr::CLIENT_IPV4));
    assert_eq!(
        request_dhcp.requested_ip_address_value(),
        offer_dhcp.offered_ip_address()
    );
    assert_eq!(
        request_dhcp.server_identifier_value(),
        offer_dhcp.server_identifier_value()
    );
}
