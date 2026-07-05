//! Inspectable outcome of one flow runner execution.

use std::fmt::Write as _;
use std::time::Duration;

use crate::Role;

/// Terminal status recorded in a [`FlowReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowOutcome {
    /// The flow reached a terminal step.
    Completed,
    /// The current state did not receive a matching packet before the timeout.
    TimedOut,
    /// The configured bound did not allow another iteration.
    BoundExhausted,
    /// The runner stopped on an error that could still be represented as a report.
    Error(String),
}

/// Inspectable execution report returned by [`crate::Runner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowReport {
    flow_name: String,
    role: Role,
    dry_run: bool,
    visited_states: Vec<String>,
    sent_count: usize,
    received_count: usize,
    transitions_taken: Vec<String>,
    iterations: u64,
    elapsed: Duration,
    outcome: FlowOutcome,
    context_snapshot: String,
}

impl FlowReport {
    /// Create a flow report from collected runner state.
    pub fn new(
        flow_name: impl Into<String>,
        role: Role,
        dry_run: bool,
        visited_states: Vec<String>,
        sent_count: usize,
        received_count: usize,
        transitions_taken: Vec<String>,
        iterations: u64,
        elapsed: Duration,
        outcome: FlowOutcome,
        context_snapshot: impl Into<String>,
    ) -> Self {
        Self {
            flow_name: flow_name.into(),
            role,
            dry_run,
            visited_states,
            sent_count,
            received_count,
            transitions_taken,
            iterations,
            elapsed,
            outcome,
            context_snapshot: context_snapshot.into(),
        }
    }

    /// Return the executed flow name.
    pub fn flow_name(&self) -> &str {
        &self.flow_name
    }

    /// Return the executed flow role.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Return true when this run used an offline dry-run binding.
    pub const fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Return state names in the order the runner entered them.
    pub fn visited_states(&self) -> &[String] {
        &self.visited_states
    }

    /// Return the number of packets sent or planned.
    pub const fn sent_count(&self) -> usize {
        self.sent_count
    }

    /// Return the number of packets received from the capture source.
    pub const fn received_count(&self) -> usize {
        self.received_count
    }

    /// Return transition descriptions in the order they fired.
    pub fn transitions_taken(&self) -> &[String] {
        &self.transitions_taken
    }

    /// Return the number of completed flow iterations.
    pub const fn iterations(&self) -> u64 {
        self.iterations
    }

    /// Return elapsed run time.
    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Return the terminal run outcome.
    pub const fn outcome(&self) -> &FlowOutcome {
        &self.outcome
    }

    /// Return the final packet-context summary captured by the runner.
    pub fn context_snapshot(&self) -> &str {
        &self.context_snapshot
    }

    /// Return a compact one-line description of this run.
    pub fn summary(&self) -> String {
        format!(
            "FlowReport '{}' ({:?}, dry_run={}): {:?}, states={}, sent={}, received={}, transitions={}, iterations={}, elapsed={:?}",
            self.flow_name,
            self.role,
            self.dry_run,
            self.outcome,
            self.visited_states.len(),
            self.sent_count,
            self.received_count,
            self.transitions_taken.len(),
            self.iterations,
            self.elapsed,
        )
    }

    /// Return a multi-line inspectable view of this run.
    pub fn show(&self) -> String {
        let mut output = String::new();

        let _ = writeln!(output, "FlowReport '{}'", self.flow_name);
        let _ = writeln!(output, "  role: {:?}", self.role);
        let _ = writeln!(output, "  dry-run: {}", self.dry_run);
        let _ = writeln!(output, "  outcome: {:?}", self.outcome);
        let _ = writeln!(output, "  iterations: {}", self.iterations);
        let _ = writeln!(output, "  elapsed: {:?}", self.elapsed);
        let _ = writeln!(
            output,
            "  packets: sent={}, received={}",
            self.sent_count, self.received_count
        );
        let _ = writeln!(output, "  visited states:");
        if self.visited_states.is_empty() {
            let _ = writeln!(output, "    none");
        } else {
            for state in &self.visited_states {
                let _ = writeln!(output, "    - {state}");
            }
        }
        let _ = writeln!(output, "  transitions taken:");
        if self.transitions_taken.is_empty() {
            let _ = writeln!(output, "    none");
        } else {
            for transition in &self.transitions_taken {
                let _ = writeln!(output, "    - {transition}");
            }
        }
        let _ = writeln!(output, "  context: {}", self.context_snapshot);

        output
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{FlowOutcome, FlowReport, Role};

    #[test]
    fn report_summary_and_show_include_core_fields() {
        let report = FlowReport::new(
            "example-flow",
            Role::Initiator,
            true,
            vec!["Start".to_string(), "Done".to_string()],
            1,
            2,
            vec!["reply packet".to_string()],
            1,
            Duration::from_millis(7),
            FlowOutcome::Completed,
            "PacketContext keys=[transaction_id]",
        );

        assert_eq!(report.flow_name(), "example-flow");
        assert_eq!(report.role(), Role::Initiator);
        assert!(report.is_dry_run());
        assert_eq!(
            report.visited_states(),
            &["Start".to_string(), "Done".to_string()]
        );
        assert_eq!(report.sent_count(), 1);
        assert_eq!(report.received_count(), 2);
        assert_eq!(report.transitions_taken(), &["reply packet".to_string()]);
        assert_eq!(report.iterations(), 1);
        assert_eq!(report.elapsed(), Duration::from_millis(7));
        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(
            report.context_snapshot(),
            "PacketContext keys=[transaction_id]"
        );
        assert!(report.summary().contains("example-flow"));
        assert!(report.summary().contains("dry_run=true"));
        assert!(report.show().contains("dry-run: true"));
        assert!(report.show().contains("reply packet"));
    }
}
