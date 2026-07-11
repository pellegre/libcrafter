use crafter::{
    derive_quic_initial_secrets, quic_decode_initial_protected_payload_with_keys,
    quic_protect_complete_initial_packet, Ipv4, Quic, QuicFrame, QuicLongHeaderPacket, QuicPacket,
    QuicPacketNumber, QuicRetryPacket, QuicVarInt, QuicVersionNegotiationPacket, Udp,
    QUIC_VERSION_1, QUIC_VERSION_2,
};
use crafter_flow::flows::quic::{
    quic_initial_client_flow, QuicInitialClientConfig, QuicInitialVersionPolicy, INITIAL_SENT,
};
use crafter_flow::{FlowOutcome, MemoryCaptureSource, PacketContext, RunOptions, Runner};

fn wrap(config: &QuicInitialClientConfig, payload: Quic) -> crafter::Packet {
    Ipv4::new().src(*config.peer.ip()).dst(*config.local.ip())
        / Udp::new()
            .source_port(config.peer.port())
            .destination_port(config.local.port())
        / payload
}

fn protected_server_initial(
    config: &QuicInitialClientConfig,
    frames: impl IntoIterator<Item = QuicFrame>,
) -> crafter::Result<crafter::Packet> {
    let packet_number = QuicPacketNumber::new(0).with_encoded_len(2);
    let plaintext = QuicLongHeaderPacket::initial_builder()
        .version(QUIC_VERSION_1)
        .destination_connection_id(config.identifiers.local_source_connection_id().clone())
        .source_connection_id(config.identifiers.peer_source_connection_id().clone())
        .packet_number(packet_number)
        .protected_payload(QuicFrame::encode_sequence(frames))
        .build()?;
    let keys = derive_quic_initial_secrets(
        QUIC_VERSION_1,
        config
            .identifiers
            .original_destination_connection_id()
            .as_bytes(),
    )?
    .server_packet_keys()?;
    let protected = quic_protect_complete_initial_packet(&plaintext, 0, &keys, 2)?;
    Ok(wrap(config, Quic::from_packets([protected])))
}

fn successful_server_initial(config: &QuicInitialClientConfig) -> crafter::Packet {
    protected_server_initial(
        config,
        [
            QuicFrame::ack(
                QuicVarInt::new(0).unwrap(),
                QuicVarInt::new(0).unwrap(),
                QuicVarInt::new(0).unwrap(),
                [],
            )
            .unwrap(),
            QuicFrame::crypto(QuicVarInt::new(0).unwrap(), b"server fixture crypto").unwrap(),
        ],
    )
    .unwrap()
}

fn run(
    config: QuicInitialClientConfig,
    packets: Vec<crafter::Packet>,
) -> (crafter_flow::FlowReport, Runner) {
    let mut flow = quic_initial_client_flow(config).expect("client flow builds");
    let mut runner = Runner::with_source(RunOptions::default(), MemoryCaptureSource::new(packets))
        .expect("offline runner opens");
    let report = runner.run(&mut flow).expect("Initial-only client runs");
    for send in runner.send_reports() {
        let emitted =
            crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, send.plan().bytes())
                .expect("dry-run Initial plan decodes through the packet abstraction");
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

#[test]
fn first_initial_is_typed_protected_minimum_and_default_run_is_offline() {
    let config = QuicInitialClientConfig::default();
    let expected_crypto = config.crypto.clone();
    let odcid = config
        .identifiers
        .original_destination_connection_id()
        .clone();
    let mut flow = quic_initial_client_flow(config.clone()).unwrap();
    let mut context = PacketContext::new();
    let step = flow
        .state_mut(INITIAL_SENT)
        .unwrap()
        .run_entry(&mut context)
        .unwrap()
        .unwrap();

    assert_eq!(step.outputs().len(), 1);
    assert!(step.outputs()[0].requires_regeneration());
    assert!(step.expects_reply());
    let packet = step.outputs()[0].packet();
    assert_typed_compilable(packet);
    let ipv4 = packet.layer::<Ipv4>().unwrap();
    let udp = packet.layer::<Udp>().unwrap();
    let quic = packet.layer::<Quic>().unwrap();
    assert_eq!(
        (ipv4.source(), ipv4.destination()),
        (*config.local.ip(), *config.peer.ip())
    );
    assert_eq!(
        (udp.source_port_value(), udp.destination_port_value()),
        (config.local.port(), config.peer.port())
    );
    assert_eq!(quic.packets().len(), 1);
    assert!(quic.packets()[0].as_bytes().len() >= 1200);
    let keys = derive_quic_initial_secrets(QUIC_VERSION_1, odcid.as_bytes())
        .unwrap()
        .client_packet_keys()
        .unwrap();
    let decoded =
        quic_decode_initial_protected_payload_with_keys(quic.packets()[0].as_bytes(), &keys)
            .unwrap();
    assert_eq!(decoded.packet_number().value(), 0);
    assert_eq!(
        decoded
            .frames()
            .iter()
            .find_map(|frame| frame.crypto_frame().unwrap())
            .unwrap()
            .data(),
        expected_crypto
    );

    let (report, runner) = run(config, vec![]);
    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(report.visited_states(), &[INITIAL_SENT]);
    assert_eq!((report.sent_count(), report.received_count()), (1, 0));
    assert!(report.is_dry_run());
    assert_eq!(runner.live_sender_open_count(), 0);
    assert_eq!(runner.send_reports().len(), 1);
    assert!(runner.send_reports().iter().all(|send| send.is_dry_run()));
    assert_typed_compilable(packet);
    let json = report.to_json();
    assert!(json.contains("\"protocol_outcome\":\"initial-only-timeout\""));
    assert!(!json.contains("Established"));
}

#[test]
fn valid_initial_records_crypto_ack_counts_and_non_secret_snapshot() {
    let config = QuicInitialClientConfig::default();
    let response = successful_server_initial(&config);
    assert_typed_compilable(&response);
    let (report, runner) = run(config, vec![response]);

    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert_eq!(report.visited_states(), &[INITIAL_SENT]);
    assert_eq!((report.sent_count(), report.received_count()), (1, 1));
    assert_eq!(runner.live_sender_open_count(), 0);
    let json = report.to_json();
    assert!(json.contains("\"protocol_outcome\":\"initial-only-server-initial-observed\""));
    assert!(json.contains("\"protocol_lifecycle\":\"InitialObserved\""));
    assert!(report
        .context_snapshot()
        .contains("quic::initial_ack_ranges"));
    assert!(report
        .context_snapshot()
        .contains("quic::initial_crypto_bytes"));
    assert!(!json.contains("server fixture crypto"));
    assert!(!json.contains("Established"));
    for send in runner.send_reports() {
        let emitted =
            crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, send.plan().bytes())
                .unwrap();
        assert_typed_compilable(&emitted);
    }
}

#[test]
fn version_negotiation_restarts_once_and_rejects_unsupported_versions() {
    let mut config = QuicInitialClientConfig::default();
    config.version = QUIC_VERSION_2;
    config.version_policy = QuicInitialVersionPolicy::SelectVersion1;
    let valid = QuicVersionNegotiationPacket::new(
        config.identifiers.local_source_connection_id().clone(),
        config
            .identifiers
            .current_destination_connection_id()
            .clone(),
        [QUIC_VERSION_1],
    )
    .unwrap();
    let (selected, runner) = run(
        config.clone(),
        vec![wrap(
            &config,
            Quic::from_packets([QuicPacket::from_version_negotiation(valid)]),
        )],
    );
    assert_eq!(selected.visited_states(), &[INITIAL_SENT]);
    assert_eq!((selected.sent_count(), selected.received_count()), (2, 1));
    assert!(selected.to_json().contains("initial-only-timeout"));
    assert!(selected
        .context_snapshot()
        .contains("quic::version_negotiation_count"));
    assert_eq!(runner.send_reports().len(), 2);
    for send in runner.send_reports() {
        let packet =
            crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, send.plan().bytes())
                .unwrap();
        assert_typed_compilable(&packet);
    }

    let unsupported = QuicVersionNegotiationPacket::new(
        config.identifiers.local_source_connection_id().clone(),
        config
            .identifiers
            .current_destination_connection_id()
            .clone(),
        [0x0a0a_0a0a],
    )
    .unwrap();
    let packet = wrap(
        &config,
        Quic::from_packets([QuicPacket::from_version_negotiation(unsupported)]),
    );
    let (rejected, _) = run(config, vec![packet]);
    assert_eq!(rejected.visited_states(), &[INITIAL_SENT]);
    assert_eq!((rejected.sent_count(), rejected.received_count()), (1, 1));
    assert!(rejected
        .to_json()
        .contains("initial-only-version-negotiation-unsupported"));
    assert!(!rejected.to_json().contains("Established"));
}

#[test]
fn valid_and_invalid_retry_are_bounded_and_do_not_expose_token_bytes() {
    let config = QuicInitialClientConfig::default();
    let token = b"public deterministic retry token";
    let retry = QuicRetryPacket::builder()
        .version(QUIC_VERSION_1)
        .destination_connection_id(config.identifiers.local_source_connection_id().clone())
        .source_connection_id(config.identifiers.peer_source_connection_id().clone())
        .token(token)
        .compute_integrity_tag(
            config
                .identifiers
                .original_destination_connection_id()
                .as_bytes(),
        )
        .build()
        .unwrap();
    let (accepted, runner) = run(
        config.clone(),
        vec![wrap(
            &config,
            Quic::from_packets([QuicPacket::from_retry(retry.clone())]),
        )],
    );
    assert_eq!((accepted.sent_count(), accepted.received_count()), (2, 1));
    assert!(
        accepted.context_snapshot().contains("quic::retry_count"),
        "{} / {}",
        accepted.summary(),
        accepted.context_snapshot()
    );
    assert!(!accepted
        .context_snapshot()
        .contains("public deterministic retry token"));
    assert_eq!(runner.send_reports().len(), 2);
    assert_ne!(
        runner.send_reports()[0].plan().bytes(),
        runner.send_reports()[1].plan().bytes()
    );

    let mut tampered = retry.as_bytes().to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    let packet = wrap(&config, Quic::from_bytes(tampered));
    let (rejected, _) = run(config, vec![packet]);
    assert_eq!(rejected.visited_states(), &[INITIAL_SENT]);
    assert_eq!((rejected.sent_count(), rejected.received_count()), (1, 1));
    assert!(rejected
        .to_json()
        .contains("initial-only-retry-invalid-integrity"));
    assert!(!rejected.to_json().contains("Established"));
}

#[test]
fn peer_close_malformed_protection_and_wrong_tuple_have_inspectable_outcomes() {
    let config = QuicInitialClientConfig::default();
    let close = protected_server_initial(
        &config,
        [QuicFrame::connection_close_transport(
            QuicVarInt::new(0x0a).unwrap(),
            QuicVarInt::new(0x06).unwrap(),
            b"bounded close",
        )
        .unwrap()],
    )
    .unwrap();
    let (closed, _) = run(config.clone(), vec![close]);
    assert_eq!(closed.visited_states(), &[INITIAL_SENT]);
    assert_eq!((closed.sent_count(), closed.received_count()), (1, 1));
    assert!(closed.to_json().contains("initial-only-peer-close"));

    let valid = successful_server_initial(&config);
    let mut bytes = valid.layer::<Quic>().unwrap().packets()[0]
        .as_bytes()
        .to_vec();
    *bytes.last_mut().unwrap() ^= 0x80;
    let (malformed, _) = run(config.clone(), vec![wrap(&config, Quic::from_bytes(bytes))]);
    assert_eq!(malformed.visited_states(), &[INITIAL_SENT]);
    assert_eq!((malformed.sent_count(), malformed.received_count()), (1, 1));
    assert!(malformed.to_json().contains("initial-protection-failure"));

    let retry = QuicRetryPacket::builder()
        .version(QUIC_VERSION_1)
        .destination_connection_id(config.identifiers.local_source_connection_id().clone())
        .source_connection_id(config.identifiers.peer_source_connection_id().clone())
        .token(b"wrong tuple retry")
        .compute_integrity_tag(
            config
                .identifiers
                .original_destination_connection_id()
                .as_bytes(),
        )
        .build()
        .unwrap();
    let wrong_tuple = Ipv4::new().src(*config.peer.ip()).dst(*config.local.ip())
        / Udp::new()
            .source_port(config.peer.port() + 1)
            .destination_port(config.local.port())
        / Quic::from_packets([QuicPacket::from_retry(retry)]);
    let (wrong, _) = run(config, vec![wrong_tuple]);
    assert_eq!(wrong.visited_states(), &[INITIAL_SENT]);
    assert_eq!((wrong.sent_count(), wrong.received_count()), (1, 1));
    assert!(wrong
        .to_json()
        .contains("initial-only-retry-tuple-mismatch"));
    assert!(!wrong.to_json().contains("Established"));
}
