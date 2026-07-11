mod support;

use std::time::Duration;

use crafter_flow::prelude::*;
use support::duplex::{
    DeliveryOrder, DuplexConfig, DuplexHarness, Side, StopReason, TraceEventKind,
};

fn raw(value: u8) -> crafter::Packet {
    crafter::Packet::decode_raw([value]).expect("synthetic packet decodes")
}

fn client_flow() -> Flow {
    let initial = FlowState::new("Initial")
        .on_entry(|_| Ok(Step::emit_batch([raw(1), raw(2)]).goto("Waiting")))
        .entry_targets(["Waiting"]);
    let waiting = FlowState::new("Waiting")
        .on_entry(|_| Ok(Step::stay().wake_after(Duration::from_millis(5))))
        .on_timeout(|ctx| {
            ctx.insert_u64("timeouts", ctx.get_u64("timeouts").unwrap_or(0) + 1);
            Ok(Step::emit(raw(3)))
        })
        .on(Transition::on(
            PredicateMatcher::new("pong", |_packet, _ctx| true),
            |_packet, _ctx| Ok(Step::done_with("pong received")),
        )
        .terminal());
    Flow::new("synthetic-client")
        .state(initial)
        .state(waiting)
        .initial("Initial")
}

fn server_flow() -> Flow {
    let listening = FlowState::new("Listening").on(Transition::on(
        PredicateMatcher::new("ping", |_packet, _ctx| true),
        |_packet, ctx| {
            ctx.insert_u64("requests", ctx.get_u64("requests").unwrap_or(0) + 1);
            Ok(Step::emit(raw(4)).goto("Done"))
        },
    )
    .targets(["Done"]));
    let done = FlowState::new("Done")
        .on_entry(|_| Ok(Step::done_with("pong sent")))
        .entry_terminal();
    Flow::new("synthetic-server")
        .role(Role::Responder)
        .state(listening)
        .state(done)
        .initial("Listening")
}

#[test]
fn duplex_harness_batches_drops_advances_time_and_terminates() {
    let config = DuplexConfig {
        step_limit: 32,
        time_limit: Duration::from_millis(20),
        ..DuplexConfig::default()
    }
    .drop_datagram(0)
    .drop_datagram(1);

    let report = DuplexHarness::new(client_flow(), server_flow(), config)
        .expect("valid synthetic flows")
        .run()
        .expect("duplex run succeeds");

    assert_eq!(report.stop_reason, StopReason::BothCompleted);
    assert_eq!(report.simulated_time, Duration::from_millis(5));
    assert!(report.steps <= 32);
    assert_eq!(report.left_context.get_u64("timeouts"), Some(1));
    assert_eq!(report.right_context.get_u64("requests"), Some(1));
    assert_eq!(
        report.left_completion.as_ref().unwrap().outcome.as_deref(),
        Some("pong received")
    );
    assert_eq!(
        report.right_completion.as_ref().unwrap().outcome.as_deref(),
        Some("pong sent")
    );

    let emitted = report
        .trace
        .iter()
        .filter_map(|event| match event.kind {
            TraceEventKind::Emitted {
                datagram,
                batch_index,
            } if event.side == Side::Left => Some((datagram, batch_index)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(emitted, vec![(0, 0), (1, 1), (2, 0)]);
    assert!(report
        .trace
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::Dropped { datagram: 0 })));
    assert!(report.trace.iter().any(|event| {
        event.side == Side::Left
            && event.at == Duration::from_millis(5)
            && matches!(event.kind, TraceEventKind::Timeout { .. })
    }));
}

#[test]
fn duplex_harness_reports_explicit_bounds() {
    let report = DuplexHarness::new(
        client_flow(),
        server_flow(),
        DuplexConfig {
            delivery_order: DeliveryOrder::RightFirst,
            step_limit: 3,
            ..DuplexConfig::default()
        },
    )
    .unwrap()
    .run()
    .unwrap();

    assert_eq!(report.stop_reason, StopReason::StepLimit);
    assert_eq!(report.steps, 3);
}

#[test]
fn duplex_harness_stops_at_the_simulated_time_bound() {
    let report = DuplexHarness::new(
        client_flow(),
        server_flow(),
        DuplexConfig {
            delivery_order: DeliveryOrder::LeftFirst,
            drop_datagrams: [0, 1].into_iter().collect(),
            step_limit: 32,
            time_limit: Duration::from_millis(4),
        },
    )
    .unwrap()
    .run()
    .unwrap();

    assert_eq!(report.stop_reason, StopReason::TimeLimit);
    assert_eq!(report.simulated_time, Duration::from_millis(4));
    assert!(report.left_completion.is_none());
    assert!(report.right_completion.is_none());
}
