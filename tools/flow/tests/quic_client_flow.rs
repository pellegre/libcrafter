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
    let server = QuicEndpointAddresses::new(client.peer, client.local);
    (client, server)
}

fn client_config(
    peer_name: &str,
    alpns: impl IntoIterator<Item = Vec<u8>>,
) -> QuicClientFlowConfig {
    let (addresses, _) = addresses();
    QuicClientFlowConfig::new(
        addresses,
        QuicPeerConfig::new(peer_name, alpns),
        QuicSyntheticIdentity::new(Vec::new(), Vec::new(), vec![certificate()]),
        b"opaque request".to_vec(),
    )
}

fn server_config() -> QuicServerFlowConfig {
    let (_, addresses) = addresses();
    QuicServerFlowConfig::new(
        addresses,
        QuicSyntheticIdentity::new(vec![certificate()], decode_hex(PRIVATE_KEY_HEX), Vec::new()),
        b"fragmented opaque response".to_vec(),
    )
}

fn assert_typed_documentation_output(step: &Step) {
    assert!(!step.outputs().is_empty());
    for output in step.outputs() {
        assert!(output.requires_regeneration());
        let packet = output.packet();
        let ipv4 = packet.layer::<Ipv4>().expect("typed IPv4 output");
        let udp = packet.layer::<Udp>().expect("typed UDP output");
        assert!(packet.layer::<Quic>().is_some(), "typed QUIC output");
        assert_eq!(ipv4.source(), docaddr::CLIENT_IPV4);
        assert_eq!(ipv4.destination(), docaddr::SERVER_IPV4);
        assert_eq!(udp.source_port_value(), 44_300);
        assert_eq!(udp.destination_port_value(), 443);
        packet.compile().expect("typed output compiles");
    }
}

#[test]
fn full_client_authenticates_exchanges_one_stream_and_closes_offline() {
    let mut client = quic_client_flow(client_config("quic.example", [b"crafter-flow".to_vec()]))
        .expect("client graph builds");

    let mut entry_context = PacketContext::new();
    let initial_state = Flow::initial(&client).to_string();
    let initial = client
        .state_mut(&initial_state)
        .unwrap()
        .run_entry(&mut entry_context)
        .expect("client starts without a socket")
        .expect("client emits an Initial");
    assert_typed_documentation_output(&initial);
    let runner = Runner::bind(Binding::default()).expect("default binding is offline");
    assert!(runner.is_dry_run());
    assert_eq!(runner.live_sender_open_count(), 0);

    let report = DuplexHarness::new(
        quic_client_flow(client_config("quic.example", [b"crafter-flow".to_vec()])).unwrap(),
        quic_server_flow(server_config()).unwrap(),
        DuplexConfig {
            step_limit: 1_024,
            time_limit: Duration::from_secs(60),
            ..DuplexConfig::default()
        },
    )
    .unwrap()
    .run()
    .expect("protected datagrams exchange in memory");

    assert_eq!(
        report.stop_reason,
        StopReason::BothCompleted,
        "left={:#?}\nright={:#?}\ntrace={:#?}",
        report.left_context,
        report.right_context,
        report.trace
    );
    assert!(report.steps < 1_024);
    assert!(report.trace.iter().any(|event| {
        event.side == Side::Left
            && matches!(
                &event.kind,
                TraceEventKind::Transition { to, .. } if to == "Established"
            )
    }));
    assert!(report.trace.iter().any(|event| {
        event.side == Side::Left
            && matches!(
                &event.kind,
                TraceEventKind::Transition { to, .. } if to == "Closing" || to == "Draining"
            )
    }));

    let context = &report.left_context;
    let snapshot = context
        .protocol_snapshot()
        .expect("client lifecycle is inspectable");
    assert_eq!(snapshot.protocol, "quic");
    assert_eq!(snapshot.lifecycle, "closed");
    assert_eq!(snapshot.outcome.as_deref(), Some("closed"));
    assert_eq!(
        context
            .get_namespaced_bool("quic", "application.complete")
            .unwrap(),
        Some(true)
    );
    assert_eq!(
        context
            .get_namespaced_u64("quic", "application.bytes_sent")
            .unwrap(),
        Some(b"opaque request".len() as u64)
    );
    assert_eq!(
        context
            .get_namespaced_u64("quic", "application.bytes_received")
            .unwrap(),
        Some(b"fragmented opaque response".len() as u64)
    );
    for space in ["initial", "handshake", "application"] {
        assert!(context
            .get_namespaced_u64("quic", &format!("packet_spaces.{space}.sent"))
            .unwrap()
            .is_some());
    }
    assert_eq!(context.recovery_metrics().exact_replay_transmits(), 0);
    let rendered = format!("{context:?}");
    assert!(!rendered.contains(PRIVATE_KEY_HEX));
    assert!(!rendered.contains("3082019c"));
}

#[test]
fn full_client_rejects_unsafe_or_invalid_configuration_without_live_io() {
    let no_trust = QuicClientFlowConfig::new(
        addresses().0,
        QuicPeerConfig::new("quic.example", [b"crafter-flow".to_vec()]),
        QuicSyntheticIdentity::new(Vec::new(), Vec::new(), Vec::new()),
        b"request".to_vec(),
    );
    let error = match quic_client_flow(no_trust) {
        Ok(_) => panic!("a trust anchor is mandatory"),
        Err(error) => error,
    };
    assert!(matches!(error, FlowError::QuicEndpoint { .. }));
    assert!(!error.to_string().contains("certificate"));

    let disabled_auth = QuicClientFlowConfig::new(
        addresses().0,
        QuicPeerConfig::new("quic.example", [b"crafter-flow".to_vec()])
            .with_peer_verification(false),
        QuicSyntheticIdentity::new(Vec::new(), Vec::new(), vec![certificate()]),
        b"request".to_vec(),
    );
    assert!(quic_client_flow(disabled_auth).is_err());

    let invalid_limits = QuicTransportLimits {
        max_idle_timeout: Duration::ZERO,
        max_udp_payload_size: 1_199,
        max_bidirectional_streams: 2,
        max_stream_bytes: 0,
        max_connection_bytes: 0,
    };
    assert!(quic_client_flow(
        client_config("quic.example", [b"crafter-flow".to_vec()]).with_limits(invalid_limits)
    )
    .is_err());

    assert!(quic_client_flow(client_config("quic.example", [b"h3".to_vec()])).is_err());

    let report = DuplexHarness::new(
        quic_client_flow(client_config("wrong.example", [b"crafter-flow".to_vec()])).unwrap(),
        quic_server_flow(server_config()).unwrap(),
        DuplexConfig {
            step_limit: 128,
            time_limit: Duration::from_secs(20),
            ..DuplexConfig::default()
        },
    )
    .unwrap()
    .run();
    assert!(report.is_err() || report.unwrap().left_context.protocol_snapshot().is_some());
}
