#![cfg(feature = "quic-endpoint")]

mod support;

use std::{net::SocketAddr, time::Duration};

use crafter::{Ipv4, Quic, Udp};
use crafter_flow::prelude::*;
use crafter_flow::{
    docaddr, QuicEndpointAddresses, QuicPeerConfig, QuicSyntheticIdentity, QuicTransportLimits,
};
use support::duplex::{DuplexConfig, DuplexHarness, Side, StopReason, TraceEventKind};

const PRIVATE_KEY_HEX: &str = concat!(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420",
    "faf4403a722d1287f76bda510073cf01bbd0a7f8f56497fc6173be9652ed51fda144",
    "0342000497f07570c53ac9740ca949533c9816ea6ed80ef368b4ff24250336c89fe4634e",
    "f2b64ecea26dea2f1f64bacb1126151ad209fc82e6c41617b40c77d5ac382d35",
);

const CERTIFICATE_HEX: &str = concat!(
    "308201c030820166a00302010202141a41e48f1d1641a1f9d33e76d142cb0728eb2d31",
    "300a06082a8648ce3d04030230173115301306035504030c0c717569632e6578616d706c",
    "65301e170d3236303731313133323132355a170d3336303730383133323132355a301731",
    "15301306035504030c0c717569632e6578616d706c653059301306072a8648ce3d020106",
    "082a8648ce3d0301070342000497f07570c53ac9740ca949533c9816ea6ed80ef368b4ff",
    "24250336c89fe4634ef2b64ecea26dea2f1f64bacb1126151ad209fc82e6c41617b40c7",
    "7d5ac382d35a3818f30818c301d0603551d0e04160414b07bf9242538693a5e4513b33f",
    "08e9144cb41b4a301f0603551d23041830168014b07bf9242538693a5e4513b33f08e914",
    "4cb41b4a30170603551d110410300e820c717569632e6578616d706c65300c0603551d13",
    "0101ff04023000300e0603551d0f0101ff04040302078030130603551d25040c300a0608",
    "2b06010505070301300a06082a8648ce3d0403020348003045022100eeaf706d28853535",
    "16566947544204ba8818cf87e4104c15c950bfcff956255c02200cd6a1e8d4cb0ea465",
    "1c9abd23b605557607a54a21a535febcd2b96d4bb95fea",
);

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn certificate() -> Vec<u8> {
    decode_hex(CERTIFICATE_HEX)
}

fn addresses() -> (QuicEndpointAddresses, QuicEndpointAddresses) {
    let client = QuicEndpointAddresses::new(
        SocketAddr::from((docaddr::CLIENT_IPV4, 44_300)),
        SocketAddr::from((docaddr::SERVER_IPV4, 443)),
    );
    (
        client,
        QuicEndpointAddresses::new(client.peer, client.local),
    )
}

fn client_config(request: Vec<u8>) -> QuicClientFlowConfig {
    QuicClientFlowConfig::new(
        addresses().0,
        QuicPeerConfig::new("quic.example", [b"crafter-flow".to_vec()]),
        QuicSyntheticIdentity::new(Vec::new(), Vec::new(), vec![certificate()]),
        request,
    )
}

fn server_config(response: Vec<u8>) -> QuicServerFlowConfig {
    QuicServerFlowConfig::new(
        addresses().1,
        QuicSyntheticIdentity::new(vec![certificate()], decode_hex(PRIVATE_KEY_HEX), Vec::new()),
        response,
    )
}

fn assert_server_output_is_typed(step: &Step) {
    assert!(!step.outputs().is_empty());
    for output in step.outputs() {
        assert!(output.requires_regeneration());
        let packet = output.packet();
        let ipv4 = packet.layer::<Ipv4>().expect("typed IPv4 output");
        let udp = packet.layer::<Udp>().expect("typed UDP output");
        assert!(packet.layer::<Quic>().is_some(), "typed QUIC output");
        assert_eq!(ipv4.source(), docaddr::SERVER_IPV4);
        assert_eq!(ipv4.destination(), docaddr::CLIENT_IPV4);
        assert_eq!(udp.source_port_value(), 443);
        assert_eq!(udp.destination_port_value(), 44_300);
        packet.compile().expect("typed server output compiles");
    }
}

#[test]
fn full_server_authenticates_reads_fragmented_request_responds_and_closes_offline() {
    let request = b"fragmented opaque request".to_vec();
    let response = b"fragmented opaque response".to_vec();

    let runner = Runner::bind(Binding::default()).expect("default binding is offline");
    assert!(runner.is_dry_run());
    assert_eq!(runner.live_sender_open_count(), 0);

    // Inspect the first passive response independently of the duplex driver so
    // the integration target proves provider output remains a typed stack.
    let mut client = quic_client_flow(client_config(request.clone())).unwrap();
    let mut server = quic_server_flow(server_config(response.clone())).unwrap();
    let mut client_context = PacketContext::new();
    let mut server_context = PacketContext::new();
    let initial = client
        .state_mut("InitialSent")
        .unwrap()
        .run_entry(&mut client_context)
        .unwrap()
        .unwrap();
    server
        .state_mut("Listen")
        .unwrap()
        .run_entry(&mut server_context)
        .unwrap();
    let transition = server
        .state_mut("Listen")
        .unwrap()
        .find_transition(initial.outputs()[0].packet(), &server_context)
        .expect("client Initial matches the passive tuple");
    let retry = transition
        .fire(initial.outputs()[0].packet(), &mut server_context)
        .expect("server accepts a valid client Initial");
    assert_server_output_is_typed(&retry);

    let report = DuplexHarness::new(
        quic_client_flow(client_config(request.clone())).unwrap(),
        quic_server_flow(server_config(response.clone())).unwrap(),
        DuplexConfig {
            step_limit: 2_048,
            time_limit: Duration::from_secs(60),
            ..DuplexConfig::default()
        },
    )
    .unwrap()
    .run()
    .expect("protected server exchange completes in memory");

    assert_eq!(
        report.stop_reason,
        StopReason::BothCompleted,
        "{:#?}",
        report.trace
    );
    let transitions: Vec<_> = report
        .trace
        .iter()
        .filter_map(|event| match (&event.side, &event.kind) {
            (Side::Right, TraceEventKind::Transition { from, to }) => {
                Some((from.as_str(), to.as_str()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        transitions,
        [
            ("Listen", "Handshaking"),
            ("Handshaking", "Established"),
            ("Established", "Closing"),
            ("Closing", "Closed"),
        ]
    );
    for state in [
        "Listen",
        "Handshaking",
        "Established",
        "Closing",
        "Draining",
        "Closed",
    ] {
        assert!(
            Flow::state(&server, state).is_some(),
            "server graph contains {state}"
        );
    }

    let context = &report.right_context;
    let snapshot = context
        .protocol_snapshot()
        .expect("server lifecycle snapshot");
    assert_eq!(
        (snapshot.protocol.as_str(), snapshot.lifecycle.as_str()),
        ("quic", "closed")
    );
    assert_eq!(snapshot.outcome.as_deref(), Some("closed"));
    assert!(snapshot
        .local_connection_id
        .as_ref()
        .is_some_and(|id| id.len() <= 20));
    assert!(snapshot
        .peer_connection_id
        .as_ref()
        .is_some_and(|id| id.len() <= 20));
    assert_eq!(
        context
            .get_namespaced_bytes("quic", "application.request")
            .unwrap(),
        Some(request.as_slice())
    );
    assert_eq!(
        context
            .get_namespaced_u64("quic", "application.request_bytes_received")
            .unwrap(),
        Some(request.len() as u64)
    );
    assert_eq!(
        context
            .get_namespaced_u64("quic", "application.response_bytes_sent")
            .unwrap(),
        Some(response.len() as u64)
    );
    assert_eq!(
        context
            .get_namespaced_bool("quic", "application.complete")
            .unwrap(),
        Some(true)
    );
    assert_eq!(context.recovery_metrics().exact_replay_transmits(), 0);
    for space in ["initial", "handshake", "application"] {
        assert!(context
            .get_namespaced_u64("quic", &format!("packet_spaces.{space}.sent"))
            .unwrap()
            .is_some());
    }
    let rendered = format!("{context:?}");
    assert!(!rendered.contains(PRIVATE_KEY_HEX));
    assert!(!rendered.contains(CERTIFICATE_HEX));
    assert!(!rendered.to_ascii_lowercase().contains("traffic secret"));
    assert!(!rendered.to_ascii_lowercase().contains("retry token"));
}

#[test]
fn full_server_rejects_malformed_identity_extra_stream_policy_and_oversized_payloads() {
    let malformed_identity = QuicServerFlowConfig::new(
        addresses().1,
        QuicSyntheticIdentity::new(vec![vec![1, 2, 3]], vec![4, 5, 6], Vec::new()),
        b"response".to_vec(),
    );
    let error = match quic_server_flow(malformed_identity) {
        Ok(_) => panic!("invalid server identity must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, FlowError::QuicEndpoint { .. }));
    assert!(!error.to_string().contains(PRIVATE_KEY_HEX));

    let extra_streams = QuicTransportLimits {
        max_bidirectional_streams: 2,
        ..QuicTransportLimits::default()
    };
    assert!(
        quic_server_flow(server_config(b"response".to_vec()).with_limits(extra_streams)).is_err()
    );

    let limits = QuicTransportLimits {
        max_stream_bytes: 32,
        max_connection_bytes: 64,
        ..QuicTransportLimits::default()
    };
    let oversized_response = vec![0u8; 33];
    let oversized_response_run = DuplexHarness::new(
        quic_client_flow(client_config(b"request".to_vec()).with_limits(limits)).unwrap(),
        quic_server_flow(server_config(oversized_response).with_limits(limits)).unwrap(),
        DuplexConfig {
            step_limit: 512,
            ..DuplexConfig::default()
        },
    )
    .unwrap()
    .run();
    assert!(oversized_response_run.is_err());

    let oversized_request = vec![0x7a; 65];
    let run = DuplexHarness::new(
        quic_client_flow(client_config(oversized_request).with_limits(limits)).unwrap(),
        quic_server_flow(server_config(b"ok".to_vec()).with_limits(limits)).unwrap(),
        DuplexConfig {
            step_limit: 512,
            ..DuplexConfig::default()
        },
    )
    .unwrap()
    .run();
    assert!(
        run.is_err(),
        "oversized request must be rejected before completion"
    );
}

#[test]
fn full_server_bounds_invalid_initial_repeated_attempt_reset_peer_close_and_idle_timeout() {
    let (client_addresses, _) = addresses();
    let malformed = Ipv4::new()
        .src(docaddr::CLIENT_IPV4)
        .dst(docaddr::SERVER_IPV4)
        / Udp::new().source_port(44_300).destination_port(443)
        / Quic::from_bytes([0xc0, 0, 0, 0, 1, 8, 1]);
    let mut server = quic_server_flow(server_config(b"response".to_vec())).unwrap();
    let mut context = PacketContext::new();
    server
        .state_mut("Listen")
        .unwrap()
        .run_entry(&mut context)
        .unwrap();
    let transition = server
        .state_mut("Listen")
        .unwrap()
        .find_transition(&malformed, &context)
        .expect("malformed Initial still matches the configured UDP tuple");
    let malformed_step = transition
        .fire(&malformed, &mut context)
        .expect("invalid Initial is classified without panicking");
    assert!(malformed_step.outputs().len() <= 1);
    assert!(matches!(
        malformed_step.target(),
        Some("Listen" | "Closing" | "Closed")
    ));
    assert_eq!(client_addresses.local, addresses().0.local);

    // Losing every client datagram covers a repeated/no-progress attempt and
    // provider-owned idle timeout without opening any sender. The terminal
    // snapshot classifies peer disappearance rather than transport recovery.
    let report = DuplexHarness::new(
        quic_client_flow(client_config(b"request".to_vec())).unwrap(),
        quic_server_flow(server_config(b"response".to_vec())).unwrap(),
        (0..64).fold(
            DuplexConfig {
                step_limit: 1_024,
                time_limit: Duration::from_secs(30),
                ..DuplexConfig::default()
            },
            |config, ordinal| config.drop_datagram(ordinal),
        ),
    )
    .unwrap()
    .run()
    .expect("loss and provider timeouts stay bounded");
    assert!(matches!(
        report.stop_reason,
        StopReason::BothCompleted | StopReason::Quiescent | StopReason::TimeLimit
    ));
    assert!(report.steps < 1_024);
    assert!(report
        .trace
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::Dropped { .. })));
    assert!(matches!(
        report.stop_reason,
        StopReason::Quiescent | StopReason::TimeLimit | StopReason::BothCompleted
    ));
    let rendered = format!("{:?}", report.right_context);
    assert!(!rendered.contains(PRIVATE_KEY_HEX));
    assert!(!rendered.to_ascii_lowercase().contains("traffic secret"));
}
