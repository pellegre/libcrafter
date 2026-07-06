//! Small helpers for generated flow-tool binaries.

use crafter::net::SendReport;

use crate::{
    CaptureSource, Flow, FlowReport, Identity, MemoryCaptureSource, Mutator, Result, RunOptions,
    Runner,
};

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
    source: Box<dyn CaptureSource>,
    mutator: Box<dyn Mutator>,
}

impl ToolRun {
    /// Create a tool run from explicit runner options.
    ///
    /// The default source is empty memory capture and the default mutator is
    /// identity, so the safe dry-run path is available without extra setup.
    pub fn new(options: RunOptions) -> Self {
        Self {
            options,
            source: Box::<MemoryCaptureSource>::default(),
            mutator: Box::new(Identity),
        }
    }

    /// Replace the capture source used by the run.
    pub fn source<S>(mut self, source: S) -> Self
    where
        S: CaptureSource + 'static,
    {
        self.source = Box::new(source);
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
        let mut runner = Runner::with_source(self.options, self.source)?.mutator(self.mutator);
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

    use crate::{run_tool, Bound, Flow, FlowBuilderExt, FlowOutcome, FlowState, Role, Step, ToolRun};

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
}
