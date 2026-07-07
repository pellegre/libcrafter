//! Small helpers for generated flow-tool binaries.

use crafter::net::SendReport;

use crate::{CaptureSource, Flow, FlowReport, Identity, Mutator, Result, RunOptions, Runner};

/// Completed run plus the send reports produced by its runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRunReport {
    report: FlowReport,
    send_reports: Vec<SendReport>,
}

impl ToolRunReport {
    /// Return the flow report produced by the runner.
    pub const fn report(&self) -> &FlowReport {
        &self.report
    }

    /// Return dry-run plans or live send reports in emission order.
    pub fn send_reports(&self) -> &[SendReport] {
        &self.send_reports
    }
}

/// Declarative runner configuration for a generated tool.
pub struct ToolRun {
    options: RunOptions,
    source: Option<Box<dyn CaptureSource>>,
    mutator: Box<dyn Mutator>,
}

impl ToolRun {
    /// Create a tool run from explicit runner options.
    ///
    /// The default mutator is identity, and the runner selects the binding's
    /// default capture source so dry-run stays offline while live bindings open
    /// live capture.
    pub fn new(options: RunOptions) -> Self {
        Self {
            options,
            source: None,
            mutator: Box::new(Identity),
        }
    }

    /// Replace the capture source used by the run.
    pub fn source<S>(mut self, source: S) -> Self
    where
        S: CaptureSource + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    /// Set the live capture BPF filter used when the runner opens its default source.
    pub fn capture_filter(mut self, capture_filter: impl Into<String>) -> Self {
        self.options = self.options.capture_filter(capture_filter);
        self
    }

    /// Replace the outgoing packet mutator used by the run.
    pub fn mutator<M>(mut self, mutator: M) -> Self
    where
        M: Mutator + 'static,
    {
        self.mutator = Box::new(mutator);
        self
    }

    /// Run the flow and collect its report and send reports.
    pub fn run(self, flow: &mut Flow) -> Result<ToolRunReport> {
        let runner = match self.source {
            Some(source) => Runner::with_source(self.options, source)?,
            None => Runner::with_options(self.options)?,
        };
        let mut runner = runner.mutator(self.mutator);
        let report = runner.run(flow)?;
        let send_reports = runner.send_reports().to_vec();

        Ok(ToolRunReport {
            report,
            send_reports,
        })
    }
}

impl Default for ToolRun {
    fn default() -> Self {
        Self::new(RunOptions::default())
    }
}

/// Run a generated tool flow through the shared tool-run helper.
pub fn run_tool(flow: &mut Flow, run: ToolRun) -> Result<ToolRunReport> {
    run.run(flow)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::{
        run_tool, Binding, Bound, Flow, FlowBuilderExt, FlowOutcome, FlowState,
        MemoryCaptureSource, Role, RunOptions, Step, ToolRun,
    };

    fn packet() -> crafter::Packet {
        crafter::Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / crafter::Udp::new().sport(53000).dport(53)
            / crafter::Raw::from_bytes([0xde, 0xad])
    }

    #[test]
    fn tool_run_helper_executes_offline_dry_run() {
        let mut flow = Flow::new("tool-helper")
            .role(Role::Injector)
            .state(
                FlowState::new("Emit")
                    .on_entry(|_ctx| Ok(Step::emit(packet())))
                    .entry_description("emit documentation packet"),
            )
            .initial("Emit");
        let options = crate::RunOptions::default()
            .bound(Bound::Count(1))
            .step_timeout(Duration::from_millis(1));

        let result = run_tool(&mut flow, ToolRun::new(options)).expect("tool helper runs");

        assert_eq!(result.report().outcome(), &FlowOutcome::TimedOut);
        assert!(result.report().is_dry_run());
        assert_eq!(result.report().sent_count(), 1);
        assert_eq!(result.send_reports().len(), 1);
        assert!(result.send_reports()[0].is_dry_run());
    }

    #[test]
    fn tool_run_helper_live_binding_reaches_runner_capture_open() {
        let mut flow = Flow::new("tool-live-binding")
            .role(Role::Injector)
            .state(
                FlowState::new("Done")
                    .on_entry(|_ctx| Ok(Step::done()))
                    .entry_terminal(),
            )
            .initial("Done");
        let options = RunOptions::default().binding(
            Binding::interface("nonexistent-iface-zzz")
                .network_layer()
                .live(),
        );

        let error = run_tool(&mut flow, ToolRun::new(options))
            .expect_err("missing live interface should fail during capture open");

        match error {
            crate::FlowError::Capture(message) => {
                assert!(message.contains("nonexistent-iface-zzz"));
                assert!(message.contains("pcap capture"));
            }
            other => panic!("expected capture error, got {other:?}"),
        }
    }

    #[test]
    fn tool_run_helper_keeps_runner_injected_source_for_offline_flow() {
        let observed = crafter::Packet::decode_raw([0x41]).expect("raw packet decodes");
        let expected = observed
            .compile()
            .expect("packet compiles")
            .as_ref()
            .to_vec();
        let mut flow = Flow::new("tool-injected-source")
            .state(FlowState::new("Waiting").on(crate::Transition::on(
                crate::PredicateMatcher::new("observed packet", move |packet, _ctx| {
                    packet
                        .compile()
                        .map(|bytes| bytes.as_ref() == expected.as_slice())
                        .unwrap_or(false)
                }),
                |_packet, _ctx| Ok(Step::goto("Done")),
            )))
            .state(
                FlowState::new("Done")
                    .on_entry(|_ctx| Ok(Step::done()))
                    .entry_terminal(),
            )
            .initial("Waiting");

        let result = run_tool(
            &mut flow,
            ToolRun::new(RunOptions::default()).source(MemoryCaptureSource::new(vec![observed])),
        )
        .expect("tool helper runs with injected source");

        assert_eq!(result.report().outcome(), &FlowOutcome::Completed);
        assert_eq!(result.report().received_count(), 1);
        assert_eq!(
            result.report().transitions_taken(),
            &["observed packet".to_string()]
        );
    }
}
