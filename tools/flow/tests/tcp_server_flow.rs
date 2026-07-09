use std::net::Ipv4Addr;

use crafter_flow::flows::tcp::{
    server_flow, CLOSED, CLOSE_WAIT, ESTABLISHED, LAST_ACK, LISTEN, SYN_RECEIVED,
};
use crafter_flow::{docaddr, FlowOutcome, MemoryCaptureSource, RunOptions, Runner};

const LISTEN_PORT: u16 = 8080;
const CLIENT_PORT: u16 = 49_153;
const CLIENT_ISS: u32 = 0x3132_3334;
const CLIENT_WINDOW: u16 = 32_768;
const CLIENT_MSS: u16 = 1_200;

fn syn_from_client(client_seq: u32) -> crafter::Packet {
    syn_from_client_with_port(CLIENT_PORT, client_seq)
}

fn syn_from_client_with_port(client_port: u16, client_seq: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(client_ipv4())
            .dst(server_ipv4())
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(client_port)
                .dport(LISTEN_PORT)
                .seq(client_seq)
                .window(CLIENT_WINDOW)
                .syn_segment()
                .tcp_option(crafter::TcpOption::maximum_segment_size(CLIENT_MSS))
                .expect("fixed client TCP MSS option encodes"),
    )
}

fn ack_from_client(client_seq: u32, ack: u32) -> crafter::Packet {
    ack_from_client_with_port(CLIENT_PORT, client_seq, ack)
}

fn ack_from_client_with_port(client_port: u16, client_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(client_ipv4())
            .dst(server_ipv4())
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(client_port)
                .dport(LISTEN_PORT)
                .seq(client_seq)
                .ack(ack)
                .window(CLIENT_WINDOW)
                .ack_segment(),
    )
}

fn data_from_client(client_seq: u32, ack: u32, payload: impl AsRef<[u8]>) -> crafter::Packet {
    data_from_client_with_port(CLIENT_PORT, client_seq, ack, payload)
}

fn data_from_client_with_port(
    client_port: u16,
    client_seq: u32,
    ack: u32,
    payload: impl AsRef<[u8]>,
) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(client_ipv4())
            .dst(server_ipv4())
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(client_port)
                .dport(LISTEN_PORT)
                .seq(client_seq)
                .ack(ack)
                .window(CLIENT_WINDOW)
                .ack_segment()
                .psh()
            / crafter::Raw::from_bytes(payload),
    )
}

fn fin_ack_from_client(client_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(client_ipv4())
            .dst(server_ipv4())
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(CLIENT_PORT)
                .dport(LISTEN_PORT)
                .seq(client_seq)
                .ack(ack)
                .window(CLIENT_WINDOW)
                .fin_ack_segment(),
    )
}

fn decode_ipv4(packet: crafter::Packet) -> crafter::Packet {
    let compiled = packet.compile().expect("TCP packet compiles");

    crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, compiled.as_bytes())
        .expect("TCP packet decodes as IPv4")
}

fn sent_packet(report: &crafter::net::SendReport) -> crafter::Packet {
    assert!(report.is_dry_run());
    crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, report.plan().bytes())
        .expect("dry-run send plan decodes as IPv4")
}

fn tcp(packet: &crafter::Packet) -> &crafter::Tcp {
    packet.layer::<crafter::Tcp>().expect("packet has TCP")
}

fn discover_server_send_next() -> (u32, u32) {
    discover_server_send_next_for(CLIENT_ISS)
}

fn discover_server_send_next_for(client_iss: u32) -> (u32, u32) {
    let mut flow = server_flow(server_ipv4(), LISTEN_PORT, None);
    let mut runner = Runner::with_source(
        RunOptions::default(),
        MemoryCaptureSource::new(vec![syn_from_client(client_iss)]),
    )
    .expect("offline runner opens with scripted TCP SYN");

    let report = runner
        .run(&mut flow)
        .expect("TCP server SYN discovery run succeeds");

    assert_eq!(report.outcome(), &FlowOutcome::TimedOut);
    assert_eq!(runner.send_reports().len(), 1);

    let syn_ack = sent_packet(&runner.send_reports()[0]);
    let tcp = tcp(&syn_ack);
    let server_iss = tcp.sequence_number_value();

    assert_eq!(tcp.source_port_value(), LISTEN_PORT);
    assert_eq!(tcp.destination_port_value(), CLIENT_PORT);
    assert_eq!(
        tcp.acknowledgment_number_value(),
        client_iss.wrapping_add(1)
    );
    assert_eq!(
        tcp.flags_value(),
        crafter::TCP_FLAG_SYN | crafter::TCP_FLAG_ACK
    );

    (server_iss, server_iss.wrapping_add(1))
}

fn run_server_exchange(
    client_iss: u32,
    client_payload: &[u8],
    response_payload: &[u8],
) -> (u32, u32, Vec<crafter::Packet>) {
    let (server_iss, server_snd_nxt) = discover_server_send_next_for(client_iss);
    let client_snd_nxt = client_iss.wrapping_add(1);
    let client_data_end = client_snd_nxt.wrapping_add(client_payload.len() as u32);
    let server_response_end = server_snd_nxt.wrapping_add(response_payload.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);
    let server_fin_end = server_response_end.wrapping_add(1);
    let source = MemoryCaptureSource::new(vec![
        syn_from_client(client_iss),
        ack_from_client(client_snd_nxt, server_snd_nxt),
        data_from_client(client_snd_nxt, server_snd_nxt, client_payload),
        fin_ack_from_client(client_data_end, server_response_end),
        ack_from_client(client_fin_end, server_fin_end),
    ]);
    let mut flow = server_flow(server_ipv4(), LISTEN_PORT, Some(response_payload.to_vec()));
    let mut runner = Runner::with_source(RunOptions::default(), source)
        .expect("offline runner opens with scripted TCP client");

    let report = runner.run(&mut flow).expect("TCP server flow runs");

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(report.final_state(), Some(CLOSED));
    assert_eq!(report.received_payload(), client_payload);

    let sent = runner
        .send_reports()
        .iter()
        .map(sent_packet)
        .collect::<Vec<_>>();
    assert_eq!(sent.len(), 4);

    (server_iss, server_snd_nxt, sent)
}

fn client_ipv4() -> Ipv4Addr {
    docaddr::CLIENT_IPV4
}

fn server_ipv4() -> Ipv4Addr {
    docaddr::SERVER_IPV4
}

#[test]
fn tcp_server_flow_completes_offline_with_client_data_response_and_graceful_close() {
    let client_payload = b"client request bytes".to_vec();
    let response_payload = b"server response bytes".to_vec();
    let (server_iss, server_snd_nxt) = discover_server_send_next();
    let client_snd_nxt = CLIENT_ISS.wrapping_add(1);
    let client_data_end = client_snd_nxt.wrapping_add(client_payload.len() as u32);
    let server_response_end = server_snd_nxt.wrapping_add(response_payload.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);
    let server_fin_end = server_response_end.wrapping_add(1);
    let source = MemoryCaptureSource::new(vec![
        syn_from_client(CLIENT_ISS),
        ack_from_client(client_snd_nxt, server_snd_nxt),
        data_from_client(client_snd_nxt, server_snd_nxt, &client_payload),
        fin_ack_from_client(client_data_end, server_response_end),
        ack_from_client(client_fin_end, server_fin_end),
    ]);
    let mut flow = server_flow(server_ipv4(), LISTEN_PORT, Some(response_payload.clone()));
    let mut runner = Runner::with_source(RunOptions::default(), source)
        .expect("offline runner opens with scripted TCP client");

    let report = runner.run(&mut flow).expect("TCP server flow runs");

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(report.final_state(), Some(CLOSED));
    assert_eq!(
        report.visited_states(),
        &[
            LISTEN.to_string(),
            SYN_RECEIVED.to_string(),
            ESTABLISHED.to_string(),
            CLOSE_WAIT.to_string(),
            LAST_ACK.to_string(),
            CLOSED.to_string(),
        ]
    );
    assert_eq!(report.received_payload(), client_payload.as_slice());
    assert_eq!(report.bytes_received(), client_payload.len());
    assert_eq!(report.bytes_sent(), response_payload.len());
    assert_eq!(report.sent_count(), 4);
    assert_eq!(runner.send_reports().len(), 4);

    let sent = runner
        .send_reports()
        .iter()
        .map(sent_packet)
        .collect::<Vec<_>>();

    let syn_ack = tcp(&sent[0]);
    assert_eq!(syn_ack.source_port_value(), LISTEN_PORT);
    assert_eq!(syn_ack.destination_port_value(), CLIENT_PORT);
    assert_eq!(syn_ack.sequence_number_value(), server_iss);
    assert_eq!(
        syn_ack.acknowledgment_number_value(),
        CLIENT_ISS.wrapping_add(1)
    );
    assert_eq!(
        syn_ack.flags_value(),
        crafter::TCP_FLAG_SYN | crafter::TCP_FLAG_ACK
    );

    let response = tcp(&sent[1]);
    let response_raw = sent[1]
        .layer::<crafter::Raw>()
        .expect("server response has Raw payload");
    assert_eq!(response.sequence_number_value(), server_snd_nxt);
    assert_eq!(response.acknowledgment_number_value(), client_data_end);
    assert_eq!(
        response.flags_value(),
        crafter::TCP_FLAG_PSH | crafter::TCP_FLAG_ACK
    );
    assert_eq!(response_raw.as_bytes(), response_payload.as_slice());

    let fin_ack = tcp(&sent[2]);
    assert_eq!(fin_ack.sequence_number_value(), server_response_end);
    assert_eq!(fin_ack.acknowledgment_number_value(), client_fin_end);
    assert_eq!(fin_ack.flags_value(), crafter::TCP_FLAG_ACK);

    let fin = tcp(&sent[3]);
    assert_eq!(fin.sequence_number_value(), server_response_end);
    assert_eq!(fin.acknowledgment_number_value(), client_fin_end);
    assert_eq!(
        fin.flags_value(),
        crafter::TCP_FLAG_FIN | crafter::TCP_FLAG_ACK
    );
}

#[test]
fn tcp_server_seq_ack_tracks_arbitrary_client_iss() {
    let client_payload = b"client bytes proving server carry-forward";
    let response_payload = b"server reply for arbitrary client iss";
    let client_iss = 0x8F00_0010;
    let alternate_client_iss = 0xA700_1234;
    let (server_iss, server_snd_nxt, sent) =
        run_server_exchange(client_iss, client_payload, response_payload);
    let (_, _, alternate_sent) =
        run_server_exchange(alternate_client_iss, client_payload, response_payload);
    let client_snd_nxt = client_iss.wrapping_add(1);
    let client_data_end = client_snd_nxt.wrapping_add(client_payload.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);

    let syn_ack = tcp(&sent[0]);
    assert_eq!(syn_ack.sequence_number_value(), server_iss);
    assert_eq!(syn_ack.acknowledgment_number_value(), client_snd_nxt);

    let response = tcp(&sent[1]);
    assert_eq!(response.sequence_number_value(), server_snd_nxt);
    assert_eq!(response.acknowledgment_number_value(), client_data_end);

    let fin_ack = tcp(&sent[2]);
    assert_eq!(
        fin_ack.sequence_number_value(),
        server_snd_nxt.wrapping_add(response_payload.len() as u32)
    );
    assert_eq!(fin_ack.acknowledgment_number_value(), client_fin_end);

    let alternate_syn_ack = tcp(&alternate_sent[0]).acknowledgment_number_value();
    let alternate_response_ack = tcp(&alternate_sent[1]).acknowledgment_number_value();
    assert_ne!(syn_ack.acknowledgment_number_value(), alternate_syn_ack);
    assert_ne!(
        response.acknowledgment_number_value(),
        alternate_response_ack
    );
    assert_eq!(alternate_syn_ack, alternate_client_iss.wrapping_add(1));
    assert_eq!(
        alternate_response_ack,
        alternate_client_iss
            .wrapping_add(1)
            .wrapping_add(client_payload.len() as u32)
    );
}

#[test]
fn tcp_server_rejects_wrong_four_tuple_and_wrong_ack_segments() {
    let client_payload = b"accepted client request".to_vec();
    let response_payload = b"accepted server response".to_vec();
    let (_server_iss, server_snd_nxt) = discover_server_send_next();
    let client_snd_nxt = CLIENT_ISS.wrapping_add(1);
    let client_data_end = client_snd_nxt.wrapping_add(client_payload.len() as u32);
    let server_response_end = server_snd_nxt.wrapping_add(response_payload.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);
    let server_fin_end = server_response_end.wrapping_add(1);
    let wrong_ack = server_snd_nxt.wrapping_add(7);
    let wrong_client_port = CLIENT_PORT.wrapping_add(1);
    let source = MemoryCaptureSource::new(vec![
        syn_from_client(CLIENT_ISS),
        ack_from_client_with_port(wrong_client_port, client_snd_nxt, server_snd_nxt),
        ack_from_client(client_snd_nxt, wrong_ack),
        ack_from_client(client_snd_nxt, server_snd_nxt),
        data_from_client_with_port(wrong_client_port, client_snd_nxt, server_snd_nxt, b"stray"),
        data_from_client(client_snd_nxt, wrong_ack, b"wrong ack payload"),
        data_from_client(client_snd_nxt, server_snd_nxt, &client_payload),
        fin_ack_from_client(client_data_end, server_response_end),
        ack_from_client(client_fin_end, server_fin_end),
    ]);
    let mut flow = server_flow(server_ipv4(), LISTEN_PORT, Some(response_payload.clone()));
    let mut runner = Runner::with_source(RunOptions::default(), source)
        .expect("offline runner opens with scripted TCP client");

    let report = runner.run(&mut flow).expect("TCP server flow runs");

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(report.final_state(), Some(CLOSED));
    assert_eq!(report.received_count(), 9);
    assert_eq!(report.received_payload(), client_payload.as_slice());
    assert_eq!(
        report.transitions_taken().len(),
        5,
        "only the valid SYN, ACK, data, FIN, and final ACK should transition"
    );

    let sent = runner
        .send_reports()
        .iter()
        .map(sent_packet)
        .collect::<Vec<_>>();
    assert_eq!(sent.len(), 4);
    let syn_ack = tcp(&sent[0]);
    assert_eq!(syn_ack.acknowledgment_number_value(), client_snd_nxt);

    let response = tcp(&sent[1]);
    let response_raw = sent[1]
        .layer::<crafter::Raw>()
        .expect("server response has Raw payload");
    assert_eq!(response.acknowledgment_number_value(), client_data_end);
    assert_eq!(response_raw.as_bytes(), response_payload.as_slice());
}
