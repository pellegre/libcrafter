#![cfg(feature = "quic-endpoint")]

mod support;

use std::{net::SocketAddr, time::Duration};

use crafter_flow::prelude::*;
use crafter_flow::{docaddr, QuicEndpointAddresses, QuicPeerConfig, QuicSyntheticIdentity};
use support::duplex::{
    DeliveryOrder, DuplexConfig, DuplexHarness, DuplexReport, Side, StopReason, TraceEventKind,
};

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

const REQUEST: &[u8] = b"opaque symmetry request";
const RESPONSE: &[u8] = b"opaque symmetry response";

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

fn flow_pair() -> (Flow, Flow) {
    let client_addresses = QuicEndpointAddresses::new(
        SocketAddr::from((docaddr::CLIENT_IPV4, 44_300)),
        SocketAddr::from((docaddr::SERVER_IPV4, 443)),
    );
    let server_addresses =
        QuicEndpointAddresses::new(client_addresses.peer, client_addresses.local);
    assert_eq!(client_addresses.local, server_addresses.peer);
    assert_eq!(client_addresses.peer, server_addresses.local);

    let client = quic_client_flow(QuicClientFlowConfig::new(
        client_addresses,
        QuicPeerConfig::new("quic.example", [b"crafter-flow".to_vec()]),
        QuicSyntheticIdentity::new(Vec::new(), Vec::new(), vec![certificate()]),
        REQUEST.to_vec(),
    ))
    .expect("offline client flow builds");
    let server = quic_server_flow(QuicServerFlowConfig::new(
        server_addresses,
        QuicSyntheticIdentity::new(vec![certificate()], decode_hex(PRIVATE_KEY_HEX), Vec::new()),
        RESPONSE.to_vec(),
    ))
    .expect("offline server flow builds");
    (client, server)
}

fn run_exchange(delivery_order: DeliveryOrder) -> DuplexReport {
    let (client, server) = flow_pair();
    DuplexHarness::new(
        client,
        server,
        DuplexConfig {
            delivery_order,
            step_limit: 2_048,
            time_limit: Duration::from_secs(60),
            ..DuplexConfig::default()
        },
    )
    .expect("bounded duplex harness builds")
    .run()
    .expect("provider-generated protected datagrams exchange in memory")
}

fn assert_transition(report: &DuplexReport, side: Side, target: &str) {
    assert!(
        report.trace.iter().any(|event| {
            event.side == side
                && matches!(
                    &event.kind,
                    TraceEventKind::Transition { to, .. } if to == target
                )
        }),
        "{side:?} never reached {target}; trace={:#?}",
        report.trace
    );
}

fn assert_completed_exchange(report: &DuplexReport) {
    assert_eq!(report.stop_reason, StopReason::BothCompleted);
    assert!(report.steps < 2_048);
    assert!(report.simulated_time <= Duration::from_secs(60));
    assert!(
        report
            .trace
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::Emitted { .. }))
            .count()
            < 2_048
    );

    for side in [Side::Left, Side::Right] {
        assert_transition(report, side, "Established");
        assert_transition(report, side, "Closing");
    }
    assert_transition(report, Side::Left, "Closed");
    assert_transition(report, Side::Right, "Closed");

    let client = &report.left_context;
    let server = &report.right_context;
    assert_eq!(
        client
            .get_namespaced_u64("quic", "application.bytes_sent")
            .unwrap(),
        Some(REQUEST.len() as u64)
    );
    assert_eq!(
        client
            .get_namespaced_u64("quic", "application.bytes_received")
            .unwrap(),
        Some(RESPONSE.len() as u64)
    );
    assert_eq!(
        server
            .get_namespaced_bytes("quic", "application.request")
            .unwrap(),
        Some(REQUEST)
    );
    assert_eq!(
        server
            .get_namespaced_u64("quic", "application.response_bytes_sent")
            .unwrap(),
        Some(RESPONSE.len() as u64)
    );
    for context in [client, server] {
        assert_eq!(
            context
                .get_namespaced_bool("quic", "application.complete")
                .unwrap(),
            Some(true)
        );
        assert_eq!(
            context
                .protocol_snapshot()
                .expect("final QUIC snapshot")
                .lifecycle,
            "closed"
        );
        for space in ["initial", "handshake", "application"] {
            assert!(
                context
                    .get_namespaced_u64("quic", &format!("packet_spaces.{space}.sent"))
                    .unwrap()
                    .is_some(),
                "missing {space} sent counter"
            );
            assert!(
                context
                    .get_namespaced_u64("quic", &format!("packet_spaces.{space}.received"))
                    .unwrap()
                    .is_some(),
                "missing {space} received counter"
            );
        }
        assert_eq!(context.recovery_metrics().exact_replay_transmits(), 0);
    }

    let rendered = format!("{:#?}{:#?}{:#?}", report.trace, client, server);
    assert!(!rendered.contains(PRIVATE_KEY_HEX));
    assert!(!rendered.to_ascii_lowercase().contains("traffic secret"));
    assert!(!rendered.to_ascii_lowercase().contains("retry token"));
}

#[test]
fn full_client_and_server_exchange_one_stream_offline() {
    let direct = run_exchange(DeliveryOrder::LeftFirst);
    assert_completed_exchange(&direct);

    // The bounded production server requires one provider Retry before it
    // accepts the token-bearing Initial. Exercise that path independently so
    // the Retry observations cannot be hidden by the happy-path assertions.
    let retried = run_exchange(DeliveryOrder::Alternate);
    assert_completed_exchange(&retried);
    assert_eq!(
        retried
            .left_context
            .get_namespaced_u64("quic", "retry.count")
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        retried
            .right_context
            .get_namespaced_u64("quic", "retry.count")
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        retried
            .left_context
            .get_namespaced_string("quic", "retry.lifecycle")
            .unwrap(),
        Some("retry-received")
    );
    assert_eq!(
        retried
            .right_context
            .get_namespaced_string("quic", "retry.lifecycle")
            .unwrap(),
        Some("retry-sent")
    );
}
