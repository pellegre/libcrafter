use std::net::Ipv4Addr;

use crafter_flow::flows::tcp::{
    client_flow, CLOSED, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, SYN_SENT,
};
use crafter_flow::{docaddr, FlowOutcome, MemoryCaptureSource, PacketContext, RunOptions, Runner};

const REMOTE_PORT: u16 = 443;
const PEER_ISS: u32 = 0x5152_5354;
const PEER_WINDOW: u16 = 32_768;
const PEER_MSS: u16 = 1_200;

fn client_syn_numbers(payload: &[u8]) -> (u16, u32, u32) {
    let mut flow = client_flow(
        local_ipv4(),
        remote_ipv4(),
        REMOTE_PORT,
        Some(payload.to_vec()),
    );
    let mut context = PacketContext::new();
    let step = flow
        .state_mut(SYN_SENT)
        .expect("SynSent state exists")
        .run_entry(&mut context)
        .expect("SynSent entry succeeds")
        .expect("SynSent entry sends SYN");
    let syn = step.outgoing().expect("SynSent entry has outgoing SYN");
    let tcp = syn.layer::<crafter::Tcp>().expect("SYN has TCP layer");

    (
        tcp.source_port_value(),
        tcp.sequence_number_value(),
        context
            .get_tcp_snd_nxt()
            .expect("SynSent entry stores client snd_nxt"),
    )
}

fn syn_ack_from_peer(local_port: u16, peer_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(remote_ipv4())
            .dst(local_ipv4())
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(REMOTE_PORT)
                .dport(local_port)
                .seq(peer_seq)
                .ack(ack)
                .window(PEER_WINDOW)
                .syn_ack_segment()
                .tcp_option(crafter::TcpOption::maximum_segment_size(PEER_MSS))
                .expect("fixed peer TCP MSS option encodes"),
    )
}

fn ack_from_peer(local_port: u16, peer_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(remote_ipv4())
            .dst(local_ipv4())
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(REMOTE_PORT)
                .dport(local_port)
                .seq(peer_seq)
                .ack(ack)
                .window(PEER_WINDOW)
                .ack_segment(),
    )
}

fn data_from_peer(
    local_port: u16,
    peer_seq: u32,
    ack: u32,
    payload: impl AsRef<[u8]>,
) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(remote_ipv4())
            .dst(local_ipv4())
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(REMOTE_PORT)
                .dport(local_port)
                .seq(peer_seq)
                .ack(ack)
                .window(PEER_WINDOW)
                .ack_segment()
                .psh()
            / crafter::Raw::from_bytes(payload),
    )
}

fn fin_ack_from_peer(local_port: u16, peer_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(remote_ipv4())
            .dst(local_ipv4())
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(REMOTE_PORT)
                .dport(local_port)
                .seq(peer_seq)
                .ack(ack)
                .window(PEER_WINDOW)
                .fin_ack_segment(),
    )
}

fn rst_ack_from_peer(local_port: u16, peer_seq: u32, ack: u32) -> crafter::Packet {
    decode_ipv4(
        crafter::Ipv4::new()
            .src(remote_ipv4())
            .dst(local_ipv4())
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(REMOTE_PORT)
                .dport(local_port)
                .seq(peer_seq)
                .ack(ack)
                .window(PEER_WINDOW)
                .rst_ack_segment(),
    )
}

fn sent_packet(report: &crafter::net::SendReport) -> crafter::Packet {
    assert!(report.is_dry_run());
    crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, report.plan().bytes())
        .expect("dry-run send plan decodes as IPv4")
}

fn decode_ipv4(packet: crafter::Packet) -> crafter::Packet {
    let compiled = packet.compile().expect("TCP packet compiles");

    crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, compiled.as_bytes())
        .expect("TCP packet decodes as IPv4")
}

fn tcp(packet: &crafter::Packet) -> &crafter::Tcp {
    packet.layer::<crafter::Tcp>().expect("packet has TCP")
}

fn run_client_exchange(
    peer_iss: u32,
    client_payload: &[u8],
    peer_payload: &[u8],
) -> (u32, u32, Vec<crafter::Packet>) {
    let (local_port, client_iss, client_snd_nxt) = client_syn_numbers(client_payload);
    let client_data_end = client_snd_nxt.wrapping_add(client_payload.len() as u32);
    let peer_data_seq = peer_iss.wrapping_add(1);
    let peer_data_end = peer_data_seq.wrapping_add(peer_payload.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);
    let source = MemoryCaptureSource::new(vec![
        syn_ack_from_peer(local_port, peer_iss, client_snd_nxt),
        data_from_peer(local_port, peer_data_seq, client_data_end, peer_payload),
        ack_from_peer(local_port, peer_data_end, client_fin_end),
        fin_ack_from_peer(local_port, peer_data_end, client_fin_end),
    ]);
    let mut flow = client_flow(
        local_ipv4(),
        remote_ipv4(),
        REMOTE_PORT,
        Some(client_payload.to_vec()),
    );
    let mut runner = Runner::with_source(RunOptions::default(), source)
        .expect("offline runner opens with scripted TCP peer");

    let report = runner.run(&mut flow).expect("TCP client flow runs");

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(report.final_state(), Some(CLOSED));
    assert_eq!(report.received_payload(), peer_payload);

    let sent = runner
        .send_reports()
        .iter()
        .map(sent_packet)
        .collect::<Vec<_>>();
    assert_eq!(sent.len(), 6);

    (client_iss, client_snd_nxt, sent)
}

fn local_ipv4() -> Ipv4Addr {
    docaddr::CLIENT_IPV4
}

fn remote_ipv4() -> Ipv4Addr {
    docaddr::SERVER_IPV4
}

#[test]
fn tcp_client_flow_completes_offline_with_peer_data_and_graceful_close() {
    let client_payload = b"client payload".to_vec();
    let peer_payload = b"server reply".to_vec();
    let (local_port, client_iss, client_snd_nxt) = client_syn_numbers(&client_payload);
    let client_data_end = client_snd_nxt.wrapping_add(client_payload.len() as u32);
    let peer_data_seq = PEER_ISS.wrapping_add(1);
    let peer_data_end = peer_data_seq.wrapping_add(peer_payload.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);
    let source = MemoryCaptureSource::new(vec![
        syn_ack_from_peer(local_port, PEER_ISS, client_snd_nxt),
        ack_from_peer(local_port, peer_data_seq, client_data_end),
        data_from_peer(local_port, peer_data_seq, client_data_end, &peer_payload),
        ack_from_peer(local_port, peer_data_end, client_fin_end),
        fin_ack_from_peer(local_port, peer_data_end, client_fin_end),
    ]);
    let mut flow = client_flow(
        local_ipv4(),
        remote_ipv4(),
        REMOTE_PORT,
        Some(client_payload.clone()),
    );
    let mut runner = Runner::with_source(RunOptions::default(), source)
        .expect("offline runner opens with scripted TCP peer");

    let report = runner.run(&mut flow).expect("TCP client flow runs");

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(report.final_state(), Some(CLOSED));
    assert_eq!(
        report.visited_states(),
        &[
            SYN_SENT.to_string(),
            ESTABLISHED.to_string(),
            FIN_WAIT_1.to_string(),
            FIN_WAIT_2.to_string(),
            CLOSED.to_string(),
        ]
    );
    assert_eq!(report.received_payload(), peer_payload.as_slice());
    assert_eq!(report.bytes_received(), peer_payload.len());
    assert_eq!(report.bytes_sent(), client_payload.len());

    let sent = runner
        .send_reports()
        .iter()
        .map(sent_packet)
        .collect::<Vec<_>>();
    assert_eq!(sent.len(), 6);

    let syn = tcp(&sent[0]);
    assert_eq!(syn.source_port_value(), local_port);
    assert_eq!(syn.destination_port_value(), REMOTE_PORT);
    assert_eq!(syn.sequence_number_value(), client_iss);
    assert_eq!(syn.acknowledgment_number_value(), 0);
    assert_eq!(syn.flags_value(), crafter::TCP_FLAG_SYN);

    let handshake_ack = tcp(&sent[1]);
    assert_eq!(handshake_ack.sequence_number_value(), client_snd_nxt);
    assert_eq!(
        handshake_ack.acknowledgment_number_value(),
        PEER_ISS.wrapping_add(1)
    );
    assert_eq!(handshake_ack.flags_value(), crafter::TCP_FLAG_ACK);

    let data = tcp(&sent[2]);
    let raw = sent[2]
        .layer::<crafter::Raw>()
        .expect("client data has Raw");
    assert_eq!(data.sequence_number_value(), client_snd_nxt);
    assert_eq!(data.acknowledgment_number_value(), PEER_ISS.wrapping_add(1));
    assert_eq!(
        data.flags_value(),
        crafter::TCP_FLAG_PSH | crafter::TCP_FLAG_ACK
    );
    assert_eq!(raw.as_bytes(), client_payload.as_slice());

    let data_ack = tcp(&sent[3]);
    assert_eq!(data_ack.sequence_number_value(), client_data_end);
    assert_eq!(data_ack.acknowledgment_number_value(), peer_data_end);
    assert_eq!(data_ack.flags_value(), crafter::TCP_FLAG_ACK);

    let fin = tcp(&sent[4]);
    assert_eq!(fin.sequence_number_value(), client_data_end);
    assert_eq!(fin.acknowledgment_number_value(), peer_data_end);
    assert_eq!(
        fin.flags_value(),
        crafter::TCP_FLAG_FIN | crafter::TCP_FLAG_ACK
    );

    let final_ack = tcp(&sent[5]);
    assert_eq!(final_ack.sequence_number_value(), client_fin_end);
    assert_eq!(
        final_ack.acknowledgment_number_value(),
        peer_data_end.wrapping_add(1)
    );
    assert_eq!(final_ack.flags_value(), crafter::TCP_FLAG_ACK);
}

#[test]
fn tcp_client_ignores_stray_segment_for_different_port() {
    let client_payload = b"client payload".to_vec();
    let peer_payload = b"server reply".to_vec();
    let (local_port, _client_iss, client_snd_nxt) = client_syn_numbers(&client_payload);
    let client_data_end = client_snd_nxt.wrapping_add(client_payload.len() as u32);
    let peer_data_seq = PEER_ISS.wrapping_add(1);
    let peer_data_end = peer_data_seq.wrapping_add(peer_payload.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);
    let source = MemoryCaptureSource::new(vec![
        data_from_peer(
            local_port.wrapping_add(1),
            peer_data_seq,
            client_data_end,
            b"stray data",
        ),
        syn_ack_from_peer(local_port, PEER_ISS, client_snd_nxt),
        data_from_peer(local_port, peer_data_seq, client_data_end, &peer_payload),
        ack_from_peer(local_port, peer_data_end, client_fin_end),
        fin_ack_from_peer(local_port, peer_data_end, client_fin_end),
    ]);
    let mut flow = client_flow(
        local_ipv4(),
        remote_ipv4(),
        REMOTE_PORT,
        Some(client_payload),
    );
    let mut runner = Runner::with_source(RunOptions::default(), source)
        .expect("offline runner opens with scripted TCP peer");

    let report = runner.run(&mut flow).expect("TCP client flow runs");

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(report.final_state(), Some(CLOSED));
    assert_eq!(report.received_count(), 5);
    assert_eq!(
        report.visited_states(),
        &[
            SYN_SENT.to_string(),
            ESTABLISHED.to_string(),
            FIN_WAIT_1.to_string(),
            FIN_WAIT_2.to_string(),
            CLOSED.to_string(),
        ]
    );

    let sent = runner
        .send_reports()
        .iter()
        .map(sent_packet)
        .collect::<Vec<_>>();
    assert_eq!(sent.len(), 6);
    assert_eq!(
        tcp(&sent[1]).acknowledgment_number_value(),
        PEER_ISS.wrapping_add(1)
    );
}

#[test]
fn tcp_client_rst_after_handshake_closes_cleanly() {
    let client_payload = b"client payload before reset".to_vec();
    let (local_port, _client_iss, client_snd_nxt) = client_syn_numbers(&client_payload);
    let client_data_end = client_snd_nxt.wrapping_add(client_payload.len() as u32);
    let source = MemoryCaptureSource::new(vec![
        syn_ack_from_peer(local_port, PEER_ISS, client_snd_nxt),
        rst_ack_from_peer(local_port, PEER_ISS.wrapping_add(1), client_data_end),
    ]);
    let mut flow = client_flow(
        local_ipv4(),
        remote_ipv4(),
        REMOTE_PORT,
        Some(client_payload),
    );
    let mut runner = Runner::with_source(RunOptions::default(), source)
        .expect("offline runner opens with scripted TCP peer");

    let report = runner.run(&mut flow).expect("TCP client flow runs");

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(report.final_state(), Some(CLOSED));
    assert_eq!(report.received_count(), 2);
    assert_eq!(
        report.visited_states(),
        &[
            SYN_SENT.to_string(),
            ESTABLISHED.to_string(),
            CLOSED.to_string(),
        ]
    );
    assert_eq!(report.received_payload(), b"");
    assert_eq!(runner.send_reports().len(), 3);
}

#[test]
fn tcp_client_ignores_wrong_ack_syn_ack_until_correct_one_arrives() {
    let client_payload = b"client payload".to_vec();
    let peer_payload = b"server reply".to_vec();
    let wrong_peer_iss = 0x1112_1314;
    let (local_port, _client_iss, client_snd_nxt) = client_syn_numbers(&client_payload);
    let client_data_end = client_snd_nxt.wrapping_add(client_payload.len() as u32);
    let peer_data_seq = PEER_ISS.wrapping_add(1);
    let peer_data_end = peer_data_seq.wrapping_add(peer_payload.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);
    let source = MemoryCaptureSource::new(vec![
        syn_ack_from_peer(local_port, wrong_peer_iss, client_snd_nxt.wrapping_add(1)),
        syn_ack_from_peer(local_port, PEER_ISS, client_snd_nxt),
        data_from_peer(local_port, peer_data_seq, client_data_end, &peer_payload),
        ack_from_peer(local_port, peer_data_end, client_fin_end),
        fin_ack_from_peer(local_port, peer_data_end, client_fin_end),
    ]);
    let mut flow = client_flow(
        local_ipv4(),
        remote_ipv4(),
        REMOTE_PORT,
        Some(client_payload),
    );
    let mut runner = Runner::with_source(RunOptions::default(), source)
        .expect("offline runner opens with scripted TCP peer");

    let report = runner.run(&mut flow).expect("TCP client flow runs");

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(report.final_state(), Some(CLOSED));
    assert_eq!(report.received_count(), 5);

    let sent = runner
        .send_reports()
        .iter()
        .map(sent_packet)
        .collect::<Vec<_>>();
    assert_eq!(
        tcp(&sent[1]).acknowledgment_number_value(),
        PEER_ISS.wrapping_add(1)
    );
    assert_ne!(
        tcp(&sent[1]).acknowledgment_number_value(),
        wrong_peer_iss.wrapping_add(1)
    );
}

#[test]
fn tcp_client_seq_ack_tracks_arbitrary_peer_iss() {
    let client_payload = b"client bytes proving carry-forward";
    let peer_payload = b"reply-from-large-peer-iss";
    let peer_iss = 0x9F00_0000;
    let alternate_peer_iss = 0xA500_1234;
    let (client_iss, client_snd_nxt, sent) =
        run_client_exchange(peer_iss, client_payload, peer_payload);
    let (_, _, alternate_sent) =
        run_client_exchange(alternate_peer_iss, client_payload, peer_payload);
    let expected_peer_ack = peer_iss.wrapping_add(1);
    let expected_peer_data_end = expected_peer_ack.wrapping_add(peer_payload.len() as u32);
    let expected_client_data_end = client_iss
        .wrapping_add(1)
        .wrapping_add(client_payload.len() as u32);

    let handshake_ack = tcp(&sent[1]);
    assert_eq!(
        handshake_ack.sequence_number_value(),
        client_iss.wrapping_add(1)
    );
    assert_eq!(
        handshake_ack.acknowledgment_number_value(),
        expected_peer_ack
    );

    let data = tcp(&sent[2]);
    assert_eq!(data.sequence_number_value(), client_iss.wrapping_add(1));
    assert_eq!(data.sequence_number_value(), client_snd_nxt);
    assert_eq!(data.acknowledgment_number_value(), expected_peer_ack);

    let data_ack = tcp(&sent[3]);
    assert_eq!(data_ack.sequence_number_value(), expected_client_data_end);
    assert_eq!(
        data_ack.acknowledgment_number_value(),
        expected_peer_data_end
    );

    let fin = tcp(&sent[4]);
    assert_eq!(fin.sequence_number_value(), expected_client_data_end);
    assert_eq!(fin.acknowledgment_number_value(), expected_peer_data_end);

    let alternate_handshake_ack = tcp(&alternate_sent[1]).acknowledgment_number_value();
    let alternate_data_ack = tcp(&alternate_sent[3]).acknowledgment_number_value();
    assert_ne!(
        handshake_ack.acknowledgment_number_value(),
        alternate_handshake_ack
    );
    assert_ne!(data_ack.acknowledgment_number_value(), alternate_data_ack);
    assert_eq!(alternate_handshake_ack, alternate_peer_iss.wrapping_add(1));
    assert_eq!(
        alternate_data_ack,
        alternate_peer_iss
            .wrapping_add(1)
            .wrapping_add(peer_payload.len() as u32)
    );
}
