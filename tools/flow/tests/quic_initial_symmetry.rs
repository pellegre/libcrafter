mod support;

use std::time::Duration;

use crafter::{QUIC_VERSION_1, QUIC_VERSION_2};
use crafter_flow::flows::quic::{
    quic_initial_client_flow, quic_initial_server_flow, QuicInitialClientConfig,
    QuicInitialRetryPolicy, QuicInitialServerConfig, QuicInitialVersionPolicy, INITIAL_OBSERVED,
};

use support::duplex::{DuplexConfig, DuplexHarness, DuplexReport, StopReason, TraceEventKind};

const STEP_LIMIT: usize = 16;
const TIME_LIMIT: Duration = Duration::from_secs(2);

fn run_pair(client: QuicInitialClientConfig, server: QuicInitialServerConfig) -> DuplexReport {
    let client = quic_initial_client_flow(client).expect("client flow builds");
    let server = quic_initial_server_flow(server).expect("server flow builds");
    DuplexHarness::new(
        client,
        server,
        DuplexConfig {
            step_limit: STEP_LIMIT,
            time_limit: TIME_LIMIT,
            ..DuplexConfig::default()
        },
    )
    .expect("offline duplex harness opens")
    .run()
    .expect("offline Initial exchange runs")
}

fn assert_bounded_offline(report: &DuplexReport) {
    assert_ne!(report.stop_reason, StopReason::StepLimit);
    assert_ne!(report.stop_reason, StopReason::TimeLimit);
    assert!(report.steps < STEP_LIMIT, "trace: {:#?}", report.trace);
    assert!(report.simulated_time <= TIME_LIMIT);

    // The duplex harness exchanges owned Packet values directly. Its trace has
    // no sender or capture backend, so every emitted datagram remains in memory.
    assert!(report
        .trace
        .iter()
        .any(|event| { matches!(event.kind, TraceEventKind::Emitted { .. }) }));
}

fn assert_initial_only(report: &DuplexReport) {
    for context in [&report.left_context, &report.right_context] {
        let snapshot = context
            .protocol_snapshot()
            .expect("each role records an Initial-only lifecycle");
        assert_ne!(snapshot.lifecycle, "Established");
        assert_ne!(snapshot.lifecycle, "Handshaking");
        assert!(
            snapshot.lifecycle == INITIAL_OBSERVED
                || snapshot.lifecycle == "Closed"
                || snapshot.lifecycle == "RetrySent"
                || snapshot.lifecycle == "VersionNegotiationSent",
            "unexpected Initial-only lifecycle: {}",
            snapshot.lifecycle
        );
        if let Some(outcome) = &snapshot.outcome {
            assert!(outcome.starts_with("initial-only-"), "{outcome}");
        }
    }
}

#[test]
fn direct_initial_exchange_is_symmetric_and_inspectable() {
    let client = QuicInitialClientConfig::default();
    let server = QuicInitialServerConfig::default();
    let odcid = client
        .identifiers
        .original_destination_connection_id()
        .as_bytes()
        .to_vec();
    let client_crypto = client.crypto.clone();
    let server_crypto = server.crypto.clone();

    let report = run_pair(client, server);

    assert_bounded_offline(&report);
    assert_initial_only(&report);
    assert_eq!(report.stop_reason, StopReason::Quiescent);
    assert_eq!(
        report
            .right_context
            .get_namespaced_bytes("quic", "original_destination_connection_id")
            .unwrap(),
        Some(odcid.as_slice())
    );
    assert_eq!(
        report
            .right_context
            .get_namespaced_u64("quic", "initial_packet_number_received")
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        report
            .left_context
            .get_namespaced_u64("quic", "initial_packet_number_received")
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        report
            .right_context
            .get_namespaced_bytes("quic", "initial_crypto_bytes")
            .unwrap(),
        Some(client_crypto.as_slice())
    );
    assert_eq!(
        report
            .left_context
            .get_namespaced_bytes("quic", "initial_crypto_bytes")
            .unwrap(),
        Some(server_crypto.as_slice())
    );
    assert_eq!(
        report.left_context.protocol_snapshot().unwrap().lifecycle,
        INITIAL_OBSERVED
    );
    assert_eq!(
        report.right_context.protocol_snapshot().unwrap().lifecycle,
        INITIAL_OBSERVED
    );
    assert_eq!(
        report.left_completion.as_ref().unwrap().outcome.as_deref(),
        Some("initial-only-server-initial-observed")
    );
    assert!(report.right_completion.is_none());
    assert_eq!(
        report
            .trace
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::Delivered { .. }))
            .count(),
        2
    );
}

#[test]
fn retry_path_exchanges_retry_and_fresh_followup_initial() {
    let client = QuicInitialClientConfig::default();
    let mut server = QuicInitialServerConfig::default();
    server.retry_policy = QuicInitialRetryPolicy::Require;
    let report = run_pair(client, server);

    assert_bounded_offline(&report);
    assert_initial_only(&report);
    assert_eq!(report.stop_reason, StopReason::Quiescent);
    assert_eq!(
        report
            .left_context
            .get_namespaced_u64("quic", "retry_count")
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        report
            .right_context
            .get_namespaced_u64("quic", "retry_count")
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        report.right_context.protocol_snapshot().unwrap().lifecycle,
        "RetrySent"
    );
    assert_eq!(
        report
            .trace
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::Emitted { .. }))
            .count(),
        3
    );
}

#[test]
fn supported_version_negotiation_restarts_with_version_one() {
    let mut client = QuicInitialClientConfig::default();
    client.version = QUIC_VERSION_2;
    client.version_policy = QuicInitialVersionPolicy::SelectVersion1;
    let server = QuicInitialServerConfig::default();

    let report = run_pair(client, server);

    assert_bounded_offline(&report);
    assert_initial_only(&report);
    assert_eq!(report.stop_reason, StopReason::Quiescent);
    assert_eq!(
        report
            .left_context
            .get_namespaced_u64("quic", "version_negotiation_count")
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        report
            .left_context
            .get_namespaced_u64("quic", "version_negotiation_selected_version")
            .unwrap(),
        Some(QUIC_VERSION_1 as u64)
    );
    assert_eq!(
        report.right_context.protocol_snapshot().unwrap().lifecycle,
        "VersionNegotiationSent"
    );
    assert_eq!(
        report
            .trace
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::Emitted { .. }))
            .count(),
        3
    );
}
