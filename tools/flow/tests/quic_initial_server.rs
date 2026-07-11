use crafter::protocols::quic::header::{
    classify_quic_header, QuicHeaderClassification, QuicLongPacketKind,
};
use crafter::{
    derive_quic_initial_secrets, quic_decode_initial_protected_payload_with_keys,
    quic_protect_complete_initial_packet, Ipv4, Quic, QuicFrame, QuicLongHeaderPacket,
    QuicPacketNumber, QuicVarInt, Udp, QUIC_VERSION_1,
};
use crafter_flow::flows::quic::{
    quic_initial_server_flow, QuicInitialClientConfig, QuicInitialRetryPolicy,
    QuicInitialServerConfig, INITIAL_OBSERVED, LISTEN,
};
use crafter_flow::{FlowOutcome, MemoryCaptureSource, RunOptions, Runner};

fn wrap(config: &QuicInitialServerConfig, payload: Quic) -> crafter::Packet {
    Ipv4::new().src(*config.peer.ip()).dst(*config.local.ip())
        / Udp::new()
            .source_port(config.peer.port())
            .destination_port(config.local.port())
        / payload
}

fn protected_client_initial(
    config: &QuicInitialServerConfig,
    frames: impl IntoIterator<Item = QuicFrame>,
) -> crafter::Packet {
    let client = QuicInitialClientConfig::default();
    let packet_number = QuicPacketNumber::new(0).with_encoded_len(2);
    let mut frames = frames.into_iter().collect::<Vec<_>>();
    frames.push(QuicFrame::padding(1200));
    let plaintext = QuicLongHeaderPacket::initial_builder()
        .version(QUIC_VERSION_1)
        .destination_connection_id(
            client
                .identifiers
                .original_destination_connection_id()
                .clone(),
        )
        .source_connection_id(client.identifiers.local_source_connection_id().clone())
        .packet_number(packet_number)
        .protected_payload(QuicFrame::encode_sequence(frames))
        .build()
        .unwrap();
    let keys = derive_quic_initial_secrets(
        QUIC_VERSION_1,
        client
            .identifiers
            .original_destination_connection_id()
            .as_bytes(),
    )
    .unwrap()
    .client_packet_keys()
    .unwrap();
    let protected = quic_protect_complete_initial_packet(&plaintext, 0, &keys, 2).unwrap();
    wrap(config, Quic::from_packets([protected]))
}

fn standard_client_initial(config: &QuicInitialServerConfig) -> crafter::Packet {
    protected_client_initial(
        config,
        [
            QuicFrame::crypto(QuicVarInt::new(0).unwrap(), b"deterministic client Initial")
                .unwrap(),
        ],
    )
}

fn run(
    config: QuicInitialServerConfig,
    packets: Vec<crafter::Packet>,
) -> (crafter_flow::FlowReport, Runner) {
    let mut flow = quic_initial_server_flow(config).expect("server flow builds");
    let mut runner = Runner::with_source(RunOptions::default(), MemoryCaptureSource::new(packets))
        .expect("offline runner opens");
    let report = runner.run(&mut flow).expect("Initial-only server runs");
    for send in runner.send_reports() {
        let emitted =
            crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, send.plan().bytes())
                .expect("dry-run response decodes through the packet abstraction");
        assert_typed_compilable(&emitted);
    }
    (report, runner)
}

fn assert_typed_compilable(packet: &crafter::Packet) {
    assert!(packet.layer::<Ipv4>().is_some());
    assert!(packet.layer::<Udp>().is_some());
    assert!(packet.layer::<Quic>().is_some());
    assert!(!packet.compile().unwrap().as_bytes().is_empty());
}

fn assert_initial_only(report: &crafter_flow::FlowReport) {
    assert!(!report.to_json().contains("Established"));
    assert!(!report.context_snapshot().contains("Established"));
}

#[test]
fn valid_initial_is_inspected_and_gets_a_typed_protected_response() {
    let config = QuicInitialServerConfig::default();
    let client = QuicInitialClientConfig::default();
    let request = standard_client_initial(&config);
    let (report, runner) = run(config.clone(), vec![request]);

    assert_eq!(report.outcome(), &FlowOutcome::TimedOut);
    assert_eq!(report.visited_states(), &[LISTEN, INITIAL_OBSERVED]);
    assert_eq!((report.sent_count(), report.received_count()), (1, 1));
    assert_eq!(runner.live_sender_open_count(), 0);
    assert_eq!(runner.send_reports().len(), 1);
    assert!(report
        .context_snapshot()
        .contains("quic::initial_crypto_bytes"));
    assert!(report
        .context_snapshot()
        .contains("quic::initial_ack_ranges"));
    assert!(
        report
            .context_snapshot()
            .contains("quic::initial_response_within_amplification_limit"),
        "{}",
        report.context_snapshot()
    );
    assert_initial_only(&report);

    let response = crafter::Packet::decode_from_l3(
        crafter::NetworkLayer::Ipv4,
        runner.send_reports()[0].plan().bytes(),
    )
    .unwrap();
    assert_typed_compilable(&response);
    let ipv4 = response.layer::<Ipv4>().unwrap();
    let udp = response.layer::<Udp>().unwrap();
    assert_eq!(
        (ipv4.source(), ipv4.destination()),
        (*config.local.ip(), *config.peer.ip())
    );
    assert_eq!(
        (udp.source_port_value(), udp.destination_port_value()),
        (config.local.port(), config.peer.port())
    );
    let protected = &response.layer::<Quic>().unwrap().packets()[0];
    match classify_quic_header(protected.as_bytes()).unwrap() {
        QuicHeaderClassification::LongHeader {
            destination_connection_id,
            source_connection_id,
            packet_kind: QuicLongPacketKind::Initial,
            ..
        } => {
            assert_eq!(
                destination_connection_id,
                *client.identifiers.local_source_connection_id()
            );
            assert_eq!(
                source_connection_id,
                *config.identifiers.local_source_connection_id()
            );
        }
        other => panic!("unexpected response header: {other:?}"),
    }
    let keys = derive_quic_initial_secrets(
        QUIC_VERSION_1,
        client
            .identifiers
            .original_destination_connection_id()
            .as_bytes(),
    )
    .unwrap()
    .server_packet_keys()
    .unwrap();
    let decoded =
        quic_decode_initial_protected_payload_with_keys(protected.as_bytes(), &keys).unwrap();
    assert!(decoded
        .frames()
        .iter()
        .any(|frame| frame.ack_frame().unwrap().is_some()));
    assert!(decoded
        .frames()
        .iter()
        .any(|frame| frame.crypto_frame().unwrap().is_some()));
}

#[test]
fn retry_and_version_negotiation_are_bounded_typed_offline_responses() {
    let mut retry_config = QuicInitialServerConfig::default();
    retry_config.retry_policy = QuicInitialRetryPolicy::Require;
    let token = retry_config.identifiers.retry_token().to_vec();
    let request = standard_client_initial(&retry_config);
    let (retry, retry_runner) = run(retry_config, vec![request]);
    assert_eq!(retry.visited_states(), &[LISTEN, "RetrySent"]);
    assert_eq!((retry.sent_count(), retry.received_count()), (1, 1));
    assert!(retry.to_json().contains("initial-only-retry-sent"));
    let token = String::from_utf8_lossy(&token);
    assert!(!retry.to_json().contains(token.as_ref()));
    assert!(!retry.context_snapshot().contains(token.as_ref()));
    assert_eq!(retry_runner.live_sender_open_count(), 0);
    assert_initial_only(&retry);

    let config = QuicInitialServerConfig::default();
    let mut unsupported = standard_client_initial(&config)
        .layer::<Quic>()
        .unwrap()
        .packets()[0]
        .as_bytes()
        .to_vec();
    unsupported[1..5].copy_from_slice(&0xface_feedu32.to_be_bytes());
    let (negotiated, runner) = run(
        config,
        vec![wrap(
            &QuicInitialServerConfig::default(),
            Quic::from_bytes(unsupported),
        )],
    );
    assert_eq!(
        negotiated.visited_states(),
        &[LISTEN, "VersionNegotiationSent"]
    );
    assert_eq!(
        (negotiated.sent_count(), negotiated.received_count()),
        (1, 1)
    );
    assert!(negotiated
        .to_json()
        .contains("initial-only-version-negotiation-sent"));
    assert_eq!(runner.send_reports().len(), 1);
    assert_initial_only(&negotiated);
}

#[test]
fn invalid_inputs_close_or_time_out_without_learning_or_sending() {
    let config = QuicInitialServerConfig::default();

    let valid = standard_client_initial(&config);
    let wrong_tuple = Ipv4::new().src(*config.peer.ip()).dst(*config.local.ip())
        / Udp::new()
            .source_port(config.peer.port() + 1)
            .destination_port(config.local.port())
        / valid.layer::<Quic>().unwrap().clone();
    let (wrong, wrong_runner) = run(config.clone(), vec![wrong_tuple]);
    assert_eq!(wrong.visited_states(), &[LISTEN]);
    assert_eq!(wrong.sent_count(), 0);
    assert!(wrong.to_json().contains("initial-only-timeout"));
    assert!(!wrong.context_snapshot().contains("quic::peer_tuple"));
    assert!(wrong_runner.send_reports().is_empty());

    let mut wrong_kind = standard_client_initial(&config)
        .layer::<Quic>()
        .unwrap()
        .packets()[0]
        .as_bytes()
        .to_vec();
    wrong_kind[0] = (wrong_kind[0] & !0x30) | 0x20;
    let (kind, _) = run(
        config.clone(),
        vec![wrap(&config, Quic::from_bytes(wrong_kind))],
    );
    assert_eq!(kind.visited_states(), &[LISTEN]);
    assert_eq!(kind.sent_count(), 0);
    assert!(kind.to_json().contains("initial-only-timeout"));

    let mut tampered = standard_client_initial(&config)
        .layer::<Quic>()
        .unwrap()
        .packets()[0]
        .as_bytes()
        .to_vec();
    *tampered.last_mut().unwrap() ^= 0x80;
    let (auth, _) = run(
        config.clone(),
        vec![wrap(&config, Quic::from_bytes(tampered))],
    );
    assert_eq!(auth.visited_states(), &[LISTEN]);
    assert_eq!((auth.sent_count(), auth.received_count()), (0, 1));
    assert!(auth.to_json().contains("initial-protection-failure"));

    let stream = QuicFrame::stream(QuicVarInt::new(0).unwrap(), b"not Initial data").unwrap();
    let (frames, _) = run(
        config.clone(),
        vec![protected_client_initial(&config, [stream])],
    );
    assert_eq!(frames.visited_states(), &[LISTEN]);
    assert_eq!((frames.sent_count(), frames.received_count()), (0, 1));
    assert!(frames.to_json().contains("initial-unexpected-frame"));
    assert_initial_only(&frames);
}

#[test]
fn client_close_and_empty_listen_timeout_are_bounded() {
    let config = QuicInitialServerConfig::default();
    let close = QuicFrame::connection_close_transport(
        QuicVarInt::new(0x0a).unwrap(),
        QuicVarInt::new(0x06).unwrap(),
        b"bounded client close",
    )
    .unwrap();
    let (closed, runner) = run(
        config.clone(),
        vec![protected_client_initial(&config, [close])],
    );
    assert_eq!(closed.visited_states(), &[LISTEN]);
    assert_eq!((closed.sent_count(), closed.received_count()), (0, 1));
    assert!(closed.to_json().contains("initial-only-peer-close"));
    assert!(
        closed
            .context_snapshot()
            .contains("quic::initial_close_origin"),
        "{}",
        closed.context_snapshot()
    );
    assert!(runner.send_reports().is_empty());
    assert_initial_only(&closed);

    let (timeout, timeout_runner) = run(config, vec![]);
    assert_eq!(timeout.outcome(), &FlowOutcome::Completed);
    assert_eq!(timeout.visited_states(), &[LISTEN]);
    assert_eq!((timeout.sent_count(), timeout.received_count()), (0, 0));
    assert!(timeout.to_json().contains("initial-only-timeout"));
    assert!(timeout
        .to_json()
        .contains("\"protocol_lifecycle\":\"Closed\""));
    assert_eq!(timeout_runner.live_sender_open_count(), 0);
    assert_initial_only(&timeout);
}
