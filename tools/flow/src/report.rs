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
    bytes_sent: usize,
    bytes_received: usize,
    received_payload: Vec<u8>,
    transitions_taken: Vec<String>,
    iterations: u64,
    elapsed: Duration,
    outcome: FlowOutcome,
    context_snapshot: String,
}

impl FlowReport {
    /// Create a flow report from collected runner state.
    #[allow(clippy::too_many_arguments)]
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
            bytes_sent: 0,
            bytes_received: 0,
            received_payload: Vec::new(),
            transitions_taken,
            iterations,
            elapsed,
            outcome,
            context_snapshot: context_snapshot.into(),
        }
    }

    /// Return a report with TCP payload byte counters attached.
    pub fn with_tcp_payload(
        mut self,
        bytes_sent: usize,
        received_payload: impl Into<Vec<u8>>,
    ) -> Self {
        let received_payload = received_payload.into();
        self.bytes_sent = bytes_sent;
        self.bytes_received = received_payload.len();
        self.received_payload = received_payload;
        self
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

    /// Return TCP payload bytes sent by this run.
    pub const fn bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    /// Return TCP payload bytes received by this run.
    pub const fn bytes_received(&self) -> usize {
        self.bytes_received
    }

    /// Return received TCP payload accumulated by this run.
    pub fn received_payload(&self) -> &[u8] {
        &self.received_payload
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
            "FlowReport '{}' ({:?}, dry_run={}): {:?}, states={}, sent={}, received={}, bytes_sent={}, bytes_received={}, transitions={}, iterations={}, elapsed={:?}",
            self.flow_name,
            self.role,
            self.dry_run,
            self.outcome,
            self.visited_states.len(),
            self.sent_count,
            self.received_count,
            self.bytes_sent,
            self.bytes_received,
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
        let _ = writeln!(
            output,
            "  payload bytes: sent={}, received={}",
            self.bytes_sent, self.bytes_received
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

    /// Return a compact JSON artifact for this run.
    ///
    /// Field names are stable for artifact consumers:
    /// `flow_name`, `role`, `dry_run`, `visited_states`, `sent_count`,
    /// `received_count`, `transitions_taken`, `iterations`, `elapsed_nanos`,
    /// `outcome`, optional `error`, and `context_snapshot`.
    pub fn to_json(&self) -> String {
        let mut output = String::new();

        output.push('{');
        write_json_field(&mut output, "flow_name", &self.flow_name);
        output.push(',');
        write_json_field(&mut output, "role", &format!("{:?}", self.role));
        let _ = write!(output, ",\"dry_run\":{}", self.dry_run);
        output.push_str(",\"visited_states\":");
        write_json_string_array(&mut output, &self.visited_states);
        let _ = write!(
            output,
            ",\"sent_count\":{},\"received_count\":{}",
            self.sent_count, self.received_count
        );
        output.push_str(",\"transitions_taken\":");
        write_json_string_array(&mut output, &self.transitions_taken);
        let _ = write!(
            output,
            ",\"iterations\":{},\"elapsed_nanos\":{}",
            self.iterations,
            self.elapsed.as_nanos()
        );
        output.push(',');
        write_json_field(&mut output, "outcome", flow_outcome_name(&self.outcome));
        if let FlowOutcome::Error(error) = &self.outcome {
            output.push(',');
            write_json_field(&mut output, "error", error);
        }
        output.push(',');
        write_json_field(&mut output, "context_snapshot", &self.context_snapshot);
        output.push('}');

        output
    }
}

fn flow_outcome_name(outcome: &FlowOutcome) -> &'static str {
    match outcome {
        FlowOutcome::Completed => "Completed",
        FlowOutcome::TimedOut => "TimedOut",
        FlowOutcome::BoundExhausted => "BoundExhausted",
        FlowOutcome::Error(_) => "Error",
    }
}

fn write_json_field(output: &mut String, name: &str, value: &str) {
    write_json_string(output, name);
    output.push(':');
    write_json_string(output, value);
}

fn write_json_string_array(output: &mut String, values: &[String]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write_json_string(output, value);
    }
    output.push(']');
}

fn write_json_string(output: &mut String, value: &str) {
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(output, "\\u{:04x}", ch as u32);
            }
            ch => output.push(ch),
        }
    }
    output.push('"');
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
        assert_eq!(report.bytes_sent(), 0);
        assert_eq!(report.bytes_received(), 0);
        assert_eq!(report.received_payload(), b"");
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
        assert!(report.summary().contains("bytes_sent=0"));
        assert!(report.show().contains("dry-run: true"));
        assert!(report.show().contains("payload bytes: sent=0, received=0"));
        assert!(report.show().contains("reply packet"));
    }

    #[test]
    fn report_reflects_tcp_payload_byte_counts() {
        let report = FlowReport::new(
            "payload-flow",
            Role::Initiator,
            true,
            vec!["Established".to_string()],
            1,
            1,
            vec!["tcp data".to_string()],
            1,
            Duration::from_millis(3),
            FlowOutcome::Completed,
            "PacketContext keys=[tcp_received_payload]",
        )
        .with_tcp_payload(12, b"peer-bytes".to_vec());

        assert_eq!(report.bytes_sent(), 12);
        assert_eq!(report.bytes_received(), 10);
        assert_eq!(report.received_payload(), b"peer-bytes");
        assert!(report.summary().contains("bytes_sent=12"));
        assert!(report.summary().contains("bytes_received=10"));
        assert!(report
            .show()
            .contains("payload bytes: sent=12, received=10"));
    }

    #[test]
    fn report_json_contains_stable_core_fields() {
        let report = FlowReport::new(
            "json-flow",
            Role::Responder,
            true,
            vec!["Wait".to_string(), "Done".to_string()],
            2,
            3,
            vec!["matched packet".to_string()],
            1,
            Duration::from_micros(2),
            FlowOutcome::Completed,
            "PacketContext keys=[client_mac]",
        );

        let json = report.to_json();

        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"flow_name\":\"json-flow\""));
        assert!(json.contains("\"role\":\"Responder\""));
        assert!(json.contains("\"outcome\":\"Completed\""));
        assert!(json.contains("\"visited_states\":[\"Wait\",\"Done\"]"));
        assert!(json.contains("\"elapsed_nanos\":2000"));
        assert!(json.contains("\"context_snapshot\":\"PacketContext keys=[client_mac]\""));
    }

    #[test]
    fn report_json_escapes_strings() {
        let report = FlowReport::new(
            "quoted \"flow\"",
            Role::Injector,
            false,
            vec!["Line\nOne".to_string()],
            0,
            0,
            vec!["slash\\match".to_string()],
            0,
            Duration::ZERO,
            FlowOutcome::Error("bad\tpacket".to_string()),
            "PacketContext keys=[]",
        );

        let json = report.to_json();

        assert!(json.contains("\"flow_name\":\"quoted \\\"flow\\\"\""));
        assert!(json.contains("\"visited_states\":[\"Line\\nOne\"]"));
        assert!(json.contains("\"transitions_taken\":[\"slash\\\\match\"]"));
        assert!(json.contains("\"outcome\":\"Error\""));
        assert!(json.contains("\"error\":\"bad\\tpacket\""));
    }
}
