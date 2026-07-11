#[path = "support/quic_full.rs"]
mod quic_full;

use quic_full::{Side, StopReason};

fn main() -> crafter_flow::Result<()> {
    println!("Offline authenticated QUIC v1 client example (one bounded bidirectional stream).");
    quic_full::print_safe_configuration(Side::Left);
    let (client, _) = quic_full::flow_pair()?;
    println!("flow shape:\n{}", client.show());

    let report = quic_full::run_exchange()?;
    if report.stop_reason != StopReason::BothCompleted {
        return Err(crafter_flow::FlowError::Build(format!(
            "offline exchange stopped early: {:?}",
            report.stop_reason
        )));
    }
    quic_full::print_send_plans(&report, Side::Left)?;
    quic_full::print_state_trace(&report, Side::Left);
    quic_full::print_counts(&report, Side::Left)?;
    println!("live use requires explicit provider-backed authorization and separate tooling");
    Ok(())
}
