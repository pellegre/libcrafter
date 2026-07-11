#![cfg(feature = "quic-endpoint")]

mod support;

use std::{net::SocketAddr, time::Duration};

use crafter_flow::prelude::*;
use crafter_flow::{docaddr, QuicEndpointAddresses, QuicPeerConfig, QuicSyntheticIdentity};
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

const REQUEST: &[u8] = b"opaque recovery request";
const RESPONSE: &[u8] = b"opaque recovery response";

fn decode_hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn flow_pair() -> (Flow, Flow) {
    let client_addresses = QuicEndpointAddresses::new(
        SocketAddr::from((docaddr::CLIENT_IPV4, 44_300)),
        SocketAddr::from((docaddr::SERVER_IPV4, 443)),
    );
    let server_addresses =
        QuicEndpointAddresses::new(client_addresses.peer, client_addresses.local);
    let certificate = decode_hex(CERTIFICATE_HEX);
    let client = quic_client_flow(QuicClientFlowConfig::new(
        client_addresses,
        QuicPeerConfig::new("quic.example", [b"crafter-flow".to_vec()]),
        QuicSyntheticIdentity::new(Vec::new(), Vec::new(), vec![certificate.clone()]),
        REQUEST.to_vec(),
    ))
    .unwrap();
    let server = quic_server_flow(QuicServerFlowConfig::new(
        server_addresses,
        QuicSyntheticIdentity::new(vec![certificate], decode_hex(PRIVATE_KEY_HEX), Vec::new()),
        RESPONSE.to_vec(),
    ))
    .unwrap();
    (client, server)
}

#[test]
fn pto_regenerates_lost_information_and_completes() {
    // Datagram 3 is the server's first protected handshake flight after the
    // bounded Retry exchange. Dropping it deterministically forces provider
    // recovery instead of merely losing an ACK-only or closing datagram.
    const DROPPED_DATAGRAM: usize = 3;
    let (client, server) = flow_pair();
    let report = DuplexHarness::new(
        client,
        server,
        DuplexConfig {
            step_limit: 2_048,
            time_limit: Duration::from_secs(60),
            ..DuplexConfig::default().drop_datagram(DROPPED_DATAGRAM)
        },
    )
    .unwrap()
    .run()
    .expect("one protected loss remains recoverable");

    assert_eq!(report.stop_reason, StopReason::BothCompleted);
    assert!(report.simulated_time > Duration::ZERO);
    let dropped_at = report
        .trace
        .iter()
        .position(|event| {
            event.side == Side::Right
                && matches!(
                    event.kind,
                    TraceEventKind::Dropped {
                        datagram: DROPPED_DATAGRAM
                    }
                )
        })
        .expect("selected protected datagram was dropped");
    let recovery_timeout = report
        .trace
        .iter()
        .enumerate()
        .skip(dropped_at + 1)
        .find(|(_, event)| {
            event.side == Side::Right
                && event.at > Duration::ZERO
                && matches!(event.kind, TraceEventKind::Timeout { .. })
        })
        .map(|(index, event)| (index, event.at))
        .expect("manual time advanced to the server provider deadline");
    let recovered_datagrams = report
        .trace
        .iter()
        .skip(recovery_timeout.0 + 1)
        .take_while(|event| event.at == recovery_timeout.1)
        .filter_map(|event| match event.kind {
            TraceEventKind::Emitted { datagram, .. } if event.side == Side::Right => Some(datagram),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!recovered_datagrams.is_empty(), "PTO emitted fresh output");

    let dropped_payload = report
        .protected_payloads
        .get(&DROPPED_DATAGRAM)
        .expect("dropped protected payload was recorded");
    assert!(!dropped_payload.is_empty());
    for ordinal in recovered_datagrams {
        let recovered = report
            .protected_payloads
            .get(&ordinal)
            .expect("recovery output retained protected bytes");
        assert_ne!(
            recovered, dropped_payload,
            "protected bytes were not replayed"
        );
    }

    for context in [&report.left_context, &report.right_context] {
        assert_eq!(
            context
                .get_namespaced_bool("quic", "application.complete")
                .unwrap(),
            Some(true)
        );
        assert_eq!(
            context
                .protocol_snapshot()
                .expect("closed lifecycle snapshot")
                .lifecycle,
            "closed"
        );
        assert_eq!(context.recovery_metrics().exact_replay_transmits(), 0);
    }
    let pto_or_loss = report.left_context.recovery_metrics().pto_firings()
        + report.right_context.recovery_metrics().pto_firings()
        + report
            .left_context
            .recovery_metrics()
            .packets_declared_lost()
        + report
            .right_context
            .recovery_metrics()
            .packets_declared_lost();
    assert!(pto_or_loss > 0, "provider recovery must be inspectable");
    assert!(
        report
            .left_context
            .recovery_metrics()
            .regenerated_transmits()
            + report
                .right_context
                .recovery_metrics()
                .regenerated_transmits()
            > 0,
        "fresh recovery transmits must be reported"
    );
}
