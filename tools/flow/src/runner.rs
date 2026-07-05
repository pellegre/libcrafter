//! Flow runner core loop.

use crafter::net::SendReport;

use crate::{
    Binding, CaptureSource, Conversation, Flow, FlowError, FlowState, MemoryCaptureSource,
    Matcher, PacketContext, Result, RunOptions, Step,
};

/// Minimal execution result returned by the runner.
///
/// A fuller report type is introduced by a later flow-engine step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerOutcome {
    /// The flow reached a terminal step.
    Completed {
        /// State where the flow completed.
        state: String,
        /// Optional terminal outcome label.
        outcome: Option<String>,
    },
}

impl RunnerOutcome {
    /// Return true when the run reached a terminal step.
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    /// Return the completion state name.
    pub fn state(&self) -> &str {
        match self {
            Self::Completed { state, .. } => state,
        }
    }

    /// Return the optional terminal outcome label.
    pub fn outcome(&self) -> Option<&str> {
        match self {
            Self::Completed { outcome, .. } => outcome.as_deref(),
        }
    }
}

enum StepAction {
    Settled,
    Enter(String),
    Completed(RunnerOutcome),
}

struct StateTransitionsMatcher<'a> {
    state: &'a FlowState,
}

impl Matcher for StateTransitionsMatcher<'_> {
    fn matches(&self, packet: &crafter::Packet, ctx: &PacketContext) -> bool {
        self.state
            .transitions()
            .iter()
            .any(|transition| transition.matches(packet, ctx))
    }

    fn describe(&self) -> String {
        format!("any transition in state '{}'", self.state.name())
    }
}

/// Owns the run options and single conversation for one flow run.
pub struct Runner {
    options: RunOptions,
    conversation: Conversation,
    send_reports: Vec<SendReport>,
}

impl Runner {
    /// Create a runner from a binding and default run options.
    pub fn bind(binding: Binding) -> Result<Self> {
        Self::with_options(RunOptions::default().binding(binding))
    }

    /// Create a runner using an empty offline capture source.
    pub fn with_options(options: RunOptions) -> Result<Self> {
        Self::with_source(options, MemoryCaptureSource::default())
    }

    /// Create a runner with an injected capture source.
    pub fn with_source<S>(options: RunOptions, source: S) -> Result<Self>
    where
        S: CaptureSource + 'static,
    {
        let conversation = Conversation::open_with_source(&options.binding, source)?;

        Ok(Self {
            options,
            conversation,
            send_reports: Vec::new(),
        })
    }

    /// Borrow the options used to construct this runner.
    pub const fn options(&self) -> &RunOptions {
        &self.options
    }

    /// Returns true when this runner was opened for offline dry-run operation.
    pub fn is_dry_run(&self) -> bool {
        self.conversation.is_dry_run()
    }

    /// Reports for packets sent or planned by this runner.
    pub fn send_reports(&self) -> &[SendReport] {
        &self.send_reports
    }

    /// Run a flow until it reaches a terminal step.
    pub fn run(&mut self, flow: &mut Flow) -> Result<RunnerOutcome> {
        flow.validate()?;

        let mut ctx = PacketContext::new();
        let mut current_state = flow.initial().to_string();

        if let Some(outcome) = self.settle_entry(flow, &mut current_state, &mut ctx)? {
            return Ok(outcome);
        }

        loop {
            let packet = {
                let state = Self::state(flow, &current_state)?;
                let matcher = StateTransitionsMatcher { state };
                self.conversation
                    .recv_matching(&matcher, &ctx, self.options.step_timeout)?
                    .ok_or(FlowError::Timeout)?
            };

            let step = {
                let state = Self::state_mut(flow, &current_state)?;
                let Some(transition) = state.find_transition(&packet, &ctx) else {
                    continue;
                };

                transition.fire(&packet, &mut ctx)?
            };

            match self.apply_step(flow, &current_state, step)? {
                StepAction::Settled => {}
                StepAction::Enter(target) => {
                    current_state = target;
                    if let Some(outcome) = self.settle_entry(flow, &mut current_state, &mut ctx)? {
                        return Ok(outcome);
                    }
                }
                StepAction::Completed(outcome) => return Ok(outcome),
            }
        }
    }

    fn settle_entry(
        &mut self,
        flow: &mut Flow,
        current_state: &mut String,
        ctx: &mut PacketContext,
    ) -> Result<Option<RunnerOutcome>> {
        loop {
            let Some(step) = Self::state_mut(flow, current_state)?.run_entry(ctx)? else {
                return Ok(None);
            };

            match self.apply_step(flow, current_state, step)? {
                StepAction::Settled => return Ok(None),
                StepAction::Enter(target) => *current_state = target,
                StepAction::Completed(outcome) => return Ok(Some(outcome)),
            }
        }
    }

    fn apply_step(&mut self, flow: &Flow, current_state: &str, step: Step) -> Result<StepAction> {
        if let Some(packet) = step.outgoing() {
            let report = self.conversation.send(packet)?;
            self.send_reports.push(report);
        }

        let target = step.target().map(str::to_string);
        if let Some(target) = target.as_deref() {
            Self::ensure_state(flow, target)?;
        }

        if step.is_terminal() {
            let state = target.unwrap_or_else(|| current_state.to_string());
            return Ok(StepAction::Completed(RunnerOutcome::Completed {
                state,
                outcome: step.outcome().map(str::to_string),
            }));
        }

        match target {
            Some(target) => Ok(StepAction::Enter(target)),
            None => Ok(StepAction::Settled),
        }
    }

    fn state_mut<'a>(flow: &'a mut Flow, state: &str) -> Result<&'a mut FlowState> {
        Self::ensure_state(flow, state)?;
        Ok(flow
            .state_mut(state)
            .expect("state was checked before mutable lookup"))
    }

    fn state<'a>(flow: &'a Flow, state: &str) -> Result<&'a FlowState> {
        Self::ensure_state(flow, state)?;
        Ok(flow
            .state(state)
            .expect("state was checked before immutable lookup"))
    }

    fn ensure_state(flow: &Flow, state: &str) -> Result<()> {
        if flow.state(state).is_some() {
            return Ok(());
        }

        Err(FlowError::Build(format!(
            "flow '{}' references missing state '{}'",
            flow.name(),
            state
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::Runner;
    use crate::{
        Binding, Flow, FlowBuilderExt, FlowState, MemoryCaptureSource, PredicateMatcher,
        RunOptions, Step, StepGotoExt, Transition,
    };
    use std::net::Ipv4Addr;

    fn raw_packet(bytes: impl AsRef<[u8]>) -> crafter::Packet {
        crafter::Packet::decode_raw(bytes).expect("raw packet decodes")
    }

    fn compiled_bytes(packet: &crafter::Packet) -> Vec<u8> {
        packet.compile().expect("packet compiles").as_ref().to_vec()
    }

    fn request_packet() -> crafter::Packet {
        crafter::Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 53))
            / crafter::Udp::new().sport(53000).dport(53)
            / crafter::Dns::a_query("example.com").id(0x1234)
    }

    #[test]
    fn runner_bind_default_succeeds_and_reports_dry_run() {
        let runner = Runner::bind(Binding::default()).expect("runner binds default dry-run");

        assert!(runner.is_dry_run());
        assert_eq!(runner.options().binding, Binding::default());
    }

    #[test]
    fn runner_with_source_accepts_injected_capture_source() {
        let packet = crafter::Packet::decode_raw([0xde, 0xad]).expect("raw packet decodes");
        let options = RunOptions::default();
        let runner = Runner::with_source(options.clone(), MemoryCaptureSource::new(vec![packet]))
            .expect("runner opens with injected source");

        assert!(runner.is_dry_run());
        assert_eq!(runner.options(), &options);
    }

    #[test]
    fn runner_runs_entry_send_transition_and_terminal_entry() {
        let request = request_packet();
        let reply = raw_packet([0xde, 0xad, 0xbe, 0xef]);
        let expected_reply = compiled_bytes(&reply);
        let matcher = PredicateMatcher::new("expected reply", move |packet, _ctx| {
            packet
                .compile()
                .map(|bytes| bytes.as_ref() == expected_reply.as_slice())
                .unwrap_or(false)
        });
        let transition =
            Transition::on(matcher, |_packet, _ctx| Ok(Step::goto("Done"))).targets(["Done"]);
        let selecting = FlowState::new("Selecting")
            .on_entry(move |_ctx| Ok(Step::send(request.clone()).goto("Waiting")))
            .entry_targets(["Waiting"]);
        let waiting = FlowState::new("Waiting").on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-core-loop")
            .state(selecting)
            .state(waiting)
            .state(done)
            .initial("Selecting");
        let mut runner =
            Runner::with_source(RunOptions::default(), MemoryCaptureSource::new(vec![reply]))
                .expect("runner opens with injected source");

        let outcome = runner.run(&mut flow).expect("runner completes flow");

        assert!(outcome.is_completed());
        assert_eq!(outcome.state(), "Done");
        assert_eq!(outcome.outcome(), None);
        assert!(runner.conversation.sent_count() >= 1);
    }

    #[test]
    fn runner_preserves_packet_for_later_state_transition() {
        let request = request_packet();
        let packet_for_next_state = raw_packet([0xa2, 0x02]);
        let packet_for_waiting_state = raw_packet([0xb1, 0x01]);
        let next_state_bytes = compiled_bytes(&packet_for_next_state);
        let waiting_state_bytes = compiled_bytes(&packet_for_waiting_state);
        let waiting_match = waiting_state_bytes.clone();
        let next_match = next_state_bytes.clone();
        let waiting_transition = Transition::on(
            PredicateMatcher::new("waiting-state packet", move |packet, _ctx| {
                packet
                    .compile()
                    .map(|bytes| bytes.as_ref() == waiting_match.as_slice())
                    .unwrap_or(false)
            }),
            |_packet, _ctx| Ok(Step::goto("Next")),
        )
        .targets(["Next"]);
        let next_transition = Transition::on(
            PredicateMatcher::new("next-state packet", move |packet, _ctx| {
                packet
                    .compile()
                    .map(|bytes| bytes.as_ref() == next_match.as_slice())
                    .unwrap_or(false)
            }),
            |_packet, _ctx| Ok(Step::goto("Done")),
        )
        .targets(["Done"]);
        let selecting = FlowState::new("Selecting")
            .on_entry(move |_ctx| Ok(Step::send(request.clone()).goto("Waiting")))
            .entry_targets(["Waiting"]);
        let waiting = FlowState::new("Waiting").on(waiting_transition);
        let next = FlowState::new("Next").on(next_transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-pending-packets")
            .state(selecting)
            .state(waiting)
            .state(next)
            .state(done)
            .initial("Selecting");
        let mut runner = Runner::with_source(
            RunOptions::default(),
            MemoryCaptureSource::new(vec![packet_for_next_state, packet_for_waiting_state]),
        )
        .expect("runner opens with injected source");

        let outcome = runner.run(&mut flow).expect("runner completes flow");

        assert!(outcome.is_completed());
        assert_eq!(outcome.state(), "Done");
    }

    #[test]
    fn runner_threads_context_from_transition_to_later_entry_send() {
        let offered = Ipv4Addr::new(192, 0, 2, 44);
        let offer = raw_packet([0x32, 0x01]);
        let offer_bytes = compiled_bytes(&offer);
        let offer_match = offer_bytes.clone();
        let selecting_transition = Transition::on(
            PredicateMatcher::new("offer packet", move |packet, _ctx| {
                packet
                    .compile()
                    .map(|bytes| bytes.as_ref() == offer_match.as_slice())
                    .unwrap_or(false)
            }),
            move |_packet, ctx| {
                ctx.set_offered_ipv4(offered);
                Ok(Step::goto("Requesting"))
            },
        )
        .targets(["Requesting"]);
        let selecting = FlowState::new("Selecting").on(selecting_transition);
        let requesting = FlowState::new("Requesting")
            .on_entry(|ctx| {
                let destination = ctx
                    .get_offered_ipv4()
                    .expect("offered address should be carried into Requesting");
                let packet = crafter::Ipv4::new()
                    .src(Ipv4Addr::new(192, 0, 2, 10))
                    .dst(destination)
                    / crafter::Udp::new().sport(68).dport(67)
                    / crafter::Raw::from("request");

                Ok(Step::send(packet).goto("Done"))
            })
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-context-threading")
            .state(selecting)
            .state(requesting)
            .state(done)
            .initial("Selecting");
        let mut runner =
            Runner::with_source(RunOptions::default(), MemoryCaptureSource::new(vec![offer]))
                .expect("runner opens with injected source");

        let outcome = runner.run(&mut flow).expect("runner completes flow");
        let sent = runner
            .send_reports()
            .last()
            .expect("request packet should be sent");
        let decoded = crafter::Packet::decode_from_l3(
            crafter::NetworkLayer::Ipv4,
            sent.plan().bytes(),
        )
        .expect("dry-run send plan decodes as IPv4");
        let ipv4 = decoded
            .layer::<crafter::Ipv4>()
            .expect("sent packet has IPv4 layer");

        assert!(outcome.is_completed());
        assert_eq!(outcome.state(), "Done");
        assert_eq!(ipv4.destination(), offered);
    }
}
