//! Flow runner core loop.

use std::thread;
use std::time::{Duration, Instant};

use crafter::net::SendReport;

use crate::{
    Binding, CaptureSource, Conversation, Flow, FlowError, FlowOutcome, FlowReport, FlowState,
    Identity, Matcher, Mutator, PacketContext, Result, Role, RunOptions, Step,
};

struct TerminalStep {
    state: String,
    entered_state: bool,
}

enum IterationResult {
    Terminal,
    TimedOut,
    BoundExhausted,
}

enum ReceiveCompletion {
    Packet(crafter::Packet),
    TimedOut(DeadlineKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeadlineKind {
    Run,
    Protocol,
    Step,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectiveDeadline {
    duration: Duration,
    kind: DeadlineKind,
}

enum StepAction {
    Settled,
    Enter(String),
    Terminal(TerminalStep),
}

#[derive(Clone, Copy)]
enum StepMode {
    Active,
    Recovery,
    PassiveSetup,
}

#[derive(Default)]
struct RunTrace {
    visited_states: Vec<String>,
    transitions_taken: Vec<String>,
}

impl RunTrace {
    fn enter(&mut self, state: &str) {
        self.visited_states.push(state.to_string());
    }

    fn take_transition(&mut self, description: String) {
        self.transitions_taken.push(description);
    }
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

struct OutstandingSegment {
    awaiting_state: String,
    packets: Vec<crafter::Packet>,
}

struct ScheduledWakeup {
    state: String,
    deadline: Instant,
    immediate: bool,
}

/// Owns the run options and single conversation for one flow run.
pub struct Runner {
    options: RunOptions,
    conversation: Conversation,
    mutator: Box<dyn Mutator>,
    send_reports: Vec<SendReport>,
    tcp_payload_bytes_sent: usize,
    outstanding_segment: Option<OutstandingSegment>,
    scheduled_wakeup: Option<ScheduledWakeup>,
    immediate_wakeup_dispatched: bool,
    #[cfg(test)]
    fail_send_at: Option<usize>,
    #[cfg(test)]
    send_attempts: usize,
}

impl Runner {
    /// Create a runner from a binding and default run options.
    ///
    /// ```
    /// use crafter_flow::prelude::*;
    ///
    /// let packet = crafter::Ipv4::new()
    ///     .src(docaddr::CLIENT_IPV4)
    ///     .dst(docaddr::DNS_IPV4)
    ///     / crafter::Udp::new().sport(53000).dport(53)
    ///     / crafter::Dns::a_query("example.com").id(0x4321);
    ///
    /// let start = FlowState::new("Start")
    ///     .on_entry(move |_ctx| Ok(Step::emit(packet.clone()).goto("Done")))
    ///     .entry_targets(["Done"]);
    /// let done = FlowState::new("Done")
    ///     .on_entry(|_ctx| Ok(Step::done()))
    ///     .entry_terminal();
    /// let mut flow = Flow::new("runner-bind-example")
    ///     .role(Role::Injector)
    ///     .state(start)
    ///     .state(done)
    ///     .initial("Start");
    ///
    /// let mut runner = Runner::bind(Binding::default())?;
    /// let report = runner.run(&mut flow)?;
    ///
    /// println!("{}", report.summary());
    /// assert!(runner.is_dry_run());
    /// assert_eq!(runner.live_sender_open_count(), 0);
    /// assert_eq!(report.outcome(), &FlowOutcome::Completed);
    /// # Ok::<(), FlowError>(())
    /// ```
    pub fn bind(binding: Binding) -> Result<Self> {
        Self::with_options(RunOptions::default().binding(binding))
    }

    /// Create a runner using an empty offline capture source.
    pub fn with_options(options: RunOptions) -> Result<Self> {
        let conversation = Conversation::open_with_capture_filter(
            &options.binding,
            options.capture_filter.as_deref(),
        )?;
        Self::from_conversation(options, conversation)
    }

    /// Create a runner with an injected capture source.
    pub fn with_source<S>(options: RunOptions, source: S) -> Result<Self>
    where
        S: CaptureSource + 'static,
    {
        let conversation = Conversation::open_with_source_and_capture_filter(
            &options.binding,
            source,
            options.capture_filter.as_deref(),
        )?;
        Self::from_conversation(options, conversation)
    }

    fn from_conversation(options: RunOptions, conversation: Conversation) -> Result<Self> {
        Ok(Self {
            options,
            conversation,
            mutator: Box::new(Identity),
            send_reports: Vec::new(),
            tcp_payload_bytes_sent: 0,
            outstanding_segment: None,
            scheduled_wakeup: None,
            immediate_wakeup_dispatched: false,
            #[cfg(test)]
            fail_send_at: None,
            #[cfg(test)]
            send_attempts: 0,
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

    /// Number of live sender handles opened by this runner.
    pub fn live_sender_open_count(&self) -> usize {
        self.conversation.live_sender_open_count()
    }

    /// Reports for packets sent or planned by this runner.
    pub fn send_reports(&self) -> &[SendReport] {
        &self.send_reports
    }

    /// Set the outgoing packet mutator used immediately before each send.
    pub fn mutator<M>(mut self, mutator: M) -> Self
    where
        M: Mutator + 'static,
    {
        self.mutator = Box::new(mutator);
        self
    }

    /// Run a flow and return an inspectable execution report.
    pub fn run(&mut self, flow: &mut Flow) -> Result<FlowReport> {
        flow.validate()?;

        let started = Instant::now();
        let mut iterations = 0;
        let mut ctx = PacketContext::new();
        let mut trace = RunTrace::default();

        loop {
            let elapsed = started.elapsed();
            if self.run_timeout_elapsed(elapsed) {
                return Ok(self.build_report(
                    flow,
                    trace,
                    iterations,
                    elapsed,
                    FlowOutcome::TimedOut,
                    &ctx,
                ));
            }

            if !self.options.bound.should_continue(iterations, elapsed) {
                return Ok(self.build_report(
                    flow,
                    trace,
                    iterations,
                    elapsed,
                    FlowOutcome::BoundExhausted,
                    &ctx,
                ));
            }

            let mut current_state = flow.initial().to_string();
            trace.enter(&current_state);
            let iteration_result = self.run_iteration(
                flow,
                &mut current_state,
                &mut ctx,
                &mut trace,
                iterations,
                started,
            );
            let iteration_result = match iteration_result {
                Ok(result) => result,
                Err(error @ FlowError::BatchSend { .. }) => {
                    return Ok(self.build_report(
                        flow,
                        trace,
                        iterations,
                        started.elapsed(),
                        FlowOutcome::Error(error.to_string()),
                        &ctx,
                    ));
                }
                Err(error) => return Err(error),
            };
            match iteration_result {
                IterationResult::Terminal => {
                    iterations += 1;
                    let elapsed = started.elapsed();
                    if self.options.bound.should_continue(iterations, elapsed) {
                        continue;
                    }

                    return Ok(self.build_report(
                        flow,
                        trace,
                        iterations,
                        elapsed,
                        FlowOutcome::Completed,
                        &ctx,
                    ));
                }
                IterationResult::TimedOut => {
                    return Ok(self.build_report(
                        flow,
                        trace,
                        iterations,
                        started.elapsed(),
                        FlowOutcome::TimedOut,
                        &ctx,
                    ));
                }
                IterationResult::BoundExhausted => {
                    return Ok(self.build_report(
                        flow,
                        trace,
                        iterations,
                        started.elapsed(),
                        FlowOutcome::BoundExhausted,
                        &ctx,
                    ));
                }
            }
        }
    }

    fn run_iteration(
        &mut self,
        flow: &mut Flow,
        current_state: &mut String,
        ctx: &mut PacketContext,
        trace: &mut RunTrace,
        iteration: u64,
        run_started: Instant,
    ) -> Result<IterationResult> {
        self.clear_scheduled_wakeup();
        match flow.role() {
            Role::Initiator | Role::Injector => {
                if self
                    .settle_entry(flow, current_state, ctx, trace, iteration)?
                    .is_some()
                {
                    return Ok(IterationResult::Terminal);
                }
            }
            Role::Responder => {
                self.run_passive_entry_setup(flow, current_state, ctx)?;
            }
        }

        loop {
            let receive = if self.take_due_wakeup(current_state) {
                // The request is consumed before dispatch, so a zero-duration
                // timeout action cannot spin by repeatedly requesting it.
                ReceiveCompletion::TimedOut(DeadlineKind::Protocol)
            } else {
                let state = Self::state(flow, current_state.as_str())?;
                let matcher = StateTransitionsMatcher { state };
                let Some(deadline) = self.effective_step_timeout(run_started, current_state) else {
                    return Ok(IterationResult::TimedOut);
                };
                if deadline.duration.is_zero() {
                    ReceiveCompletion::TimedOut(deadline.kind)
                } else {
                    match self.recv_matching_with_retransmit(
                        &matcher,
                        current_state,
                        ctx,
                        deadline.duration,
                    )? {
                        ReceiveCompletion::Packet(packet) => ReceiveCompletion::Packet(packet),
                        ReceiveCompletion::TimedOut(_) => {
                            ReceiveCompletion::TimedOut(deadline.kind)
                        }
                    }
                }
            };

            let packet = match receive {
                ReceiveCompletion::Packet(packet) => {
                    self.immediate_wakeup_dispatched = false;
                    packet
                }
                ReceiveCompletion::TimedOut(deadline_kind) => {
                    let elapsed = run_started.elapsed();
                    if deadline_kind == DeadlineKind::Run || self.run_timeout_elapsed(elapsed) {
                        return Ok(IterationResult::TimedOut);
                    }
                    if !self.options.bound.should_continue(iteration, elapsed) {
                        return Ok(IterationResult::BoundExhausted);
                    }
                    if !Self::state(flow, current_state.as_str())?.has_timeout() {
                        return Ok(IterationResult::TimedOut);
                    }

                    if deadline_kind == DeadlineKind::Protocol {
                        self.scheduled_wakeup = None;
                    }

                    ctx.add_timeout_events(1);
                    let step = Self::state_mut(flow, current_state.as_str())?
                        .run_timeout(ctx)?
                        .expect("timeout handler presence was checked before dispatch");
                    match self.apply_step(
                        flow,
                        current_state.as_str(),
                        step,
                        StepMode::Recovery,
                        iteration,
                        ctx,
                    )? {
                        StepAction::Settled => continue,
                        StepAction::Enter(target) => {
                            *current_state = target;
                            trace.enter(current_state);
                            if self
                                .settle_entry(flow, current_state, ctx, trace, iteration)?
                                .is_some()
                            {
                                return Ok(IterationResult::Terminal);
                            }
                            continue;
                        }
                        StepAction::Terminal(terminal) => {
                            if terminal.entered_state {
                                trace.enter(&terminal.state);
                            }
                            return Ok(IterationResult::Terminal);
                        }
                    }
                }
            };

            let (description, step) = {
                let state = Self::state_mut(flow, current_state.as_str())?;
                let Some(transition) = state.find_transition(&packet, ctx) else {
                    continue;
                };

                let description = transition.describe();
                let step = transition.fire(&packet, ctx)?;
                (description, step)
            };
            trace.take_transition(description);

            match self.apply_step(
                flow,
                current_state.as_str(),
                step,
                StepMode::Active,
                iteration,
                ctx,
            )? {
                StepAction::Settled => {}
                StepAction::Enter(target) => {
                    *current_state = target;
                    trace.enter(current_state);
                    if self
                        .settle_entry(flow, current_state, ctx, trace, iteration)?
                        .is_some()
                    {
                        return Ok(IterationResult::Terminal);
                    }
                }
                StepAction::Terminal(terminal) => {
                    if terminal.entered_state {
                        trace.enter(&terminal.state);
                    }
                    return Ok(IterationResult::Terminal);
                }
            }
        }
    }

    fn settle_entry(
        &mut self,
        flow: &mut Flow,
        current_state: &mut String,
        ctx: &mut PacketContext,
        trace: &mut RunTrace,
        iteration: u64,
    ) -> Result<Option<TerminalStep>> {
        loop {
            let Some(step) = Self::state_mut(flow, current_state)?.run_entry(ctx)? else {
                return Ok(None);
            };

            match self.apply_step(flow, current_state, step, StepMode::Active, iteration, ctx)? {
                StepAction::Settled => return Ok(None),
                StepAction::Enter(target) => {
                    *current_state = target;
                    trace.enter(current_state);
                }
                StepAction::Terminal(terminal) => {
                    if terminal.entered_state {
                        trace.enter(&terminal.state);
                    }
                    return Ok(Some(terminal));
                }
            }
        }
    }

    fn run_passive_entry_setup(
        &mut self,
        flow: &mut Flow,
        current_state: &str,
        ctx: &mut PacketContext,
    ) -> Result<()> {
        let Some(step) = Self::state_mut(flow, current_state)?.run_entry(ctx)? else {
            return Ok(());
        };

        let _ = self.apply_step(flow, current_state, step, StepMode::PassiveSetup, 0, ctx)?;
        Ok(())
    }

    fn apply_step(
        &mut self,
        flow: &Flow,
        current_state: &str,
        step: Step,
        mode: StepMode,
        iteration: u64,
        ctx: &mut PacketContext,
    ) -> Result<StepAction> {
        let action_completed_at = Instant::now();
        let target = step.target().map(str::to_string);
        let entered_state = target.is_some();
        let awaiting_state = target.clone().unwrap_or_else(|| current_state.to_string());
        let expects_reply = step.expects_reply();
        let is_terminal = step.is_terminal();
        let wake_after = step.wakeup();
        let outputs = step.outputs().to_vec();

        if matches!(mode, StepMode::Active | StepMode::Recovery) {
            if !outputs.is_empty() {
                let mutated_outputs = outputs
                    .into_iter()
                    .map(|output| {
                        let allows_exact_replay = output.allows_exact_replay();
                        let requires_regeneration = output.requires_regeneration();
                        self.mutator
                            .mutate(output.into_packet(), iteration, ctx)
                            .map(|packet| (packet, allows_exact_replay, requires_regeneration))
                    })
                    .collect::<Result<Vec<_>>>()?;
                // Repeat the complete batch in stored order: A, B, C, A, B, C.
                // Protected QUIC output uses regeneration-only recovery and must
                // not be configured with `send_repeat`, which replays generated
                // output rather than asking the protocol driver for fresh bytes.
                let reports_before_batch = self.send_reports.len();
                for repeat in 0..self.options.send_repeat.count() {
                    if repeat > 0 {
                        let interval = self.options.send_repeat.interval();
                        if !interval.is_zero() {
                            thread::sleep(interval);
                        }
                    }

                    for (output_index, (packet, _, requires_regeneration)) in
                        mutated_outputs.iter().enumerate()
                    {
                        if let Err(error) = self.send_packet(packet) {
                            return Err(FlowError::BatchSend {
                                output_index,
                                sent_count: self.send_reports.len() - reports_before_batch,
                                error: error.to_string(),
                            });
                        }
                        if matches!(mode, StepMode::Recovery) && *requires_regeneration {
                            ctx.add_regenerated_transmits(1);
                        }
                    }
                }

                self.outstanding_segment = if expects_reply {
                    let packets = mutated_outputs
                        .into_iter()
                        .filter_map(|(packet, allows_exact_replay, _)| {
                            allows_exact_replay.then_some(packet)
                        })
                        .collect::<Vec<_>>();
                    if packets.is_empty() {
                        None
                    } else {
                        Some(OutstandingSegment {
                            awaiting_state,
                            packets,
                        })
                    }
                } else {
                    None
                };
            } else if target.is_some() || is_terminal {
                self.outstanding_segment = None;
            }
        }

        if matches!(mode, StepMode::PassiveSetup) {
            if let Some(delay) = wake_after {
                self.schedule_wakeup(current_state, delay, action_completed_at);
            }
            return Ok(StepAction::Settled);
        }

        if let Some(target) = target.as_deref() {
            Self::ensure_state(flow, target)?;
        }

        if target.is_some() || is_terminal {
            self.clear_scheduled_wakeup();
        } else if let Some(delay) = wake_after {
            self.schedule_wakeup(current_state, delay, action_completed_at);
        }

        if is_terminal {
            let state = target.unwrap_or_else(|| current_state.to_string());
            return Ok(StepAction::Terminal(TerminalStep {
                state,
                entered_state,
            }));
        }

        match target {
            Some(target) => Ok(StepAction::Enter(target)),
            None => Ok(StepAction::Settled),
        }
    }

    fn recv_matching_with_retransmit(
        &mut self,
        matcher: &dyn Matcher,
        current_state: &str,
        ctx: &mut PacketContext,
        timeout: Duration,
    ) -> Result<ReceiveCompletion> {
        let mut retransmits = 0;

        loop {
            if let Some(packet) = self.conversation.recv_matching(matcher, ctx, timeout)? {
                return Ok(ReceiveCompletion::Packet(packet));
            }

            if !self.retransmit_outstanding(current_state, retransmits, ctx)? {
                return Ok(ReceiveCompletion::TimedOut(DeadlineKind::Step));
            }

            retransmits += 1;
        }
    }

    fn retransmit_outstanding(
        &mut self,
        current_state: &str,
        retransmits: u32,
        ctx: &mut PacketContext,
    ) -> Result<bool> {
        let Some(policy) = self.options.retransmit else {
            return Ok(false);
        };

        if retransmits >= policy.count() {
            return Ok(false);
        }

        let Some(outstanding) = self.outstanding_segment.as_ref() else {
            return Ok(false);
        };

        if outstanding.awaiting_state != current_state {
            return Ok(false);
        }

        let interval = policy.interval();
        if !interval.is_zero() {
            thread::sleep(interval);
        }

        let packets = outstanding.packets.clone();
        for packet in packets {
            self.send_packet(&packet)?;
            ctx.add_exact_replay_transmits(1);
        }
        Ok(true)
    }

    fn send_packet(&mut self, packet: &crafter::Packet) -> Result<()> {
        #[cfg(test)]
        {
            let attempt = self.send_attempts;
            self.send_attempts += 1;
            if self.fail_send_at == Some(attempt) {
                return Err(FlowError::Send("injected test send failure".to_string()));
            }
        }

        let tcp_payload_bytes = tcp_payload_len(packet);
        let report = self.conversation.send(packet)?;
        self.tcp_payload_bytes_sent += tcp_payload_bytes;
        self.send_reports.push(report);
        Ok(())
    }

    #[cfg(test)]
    fn fail_send_at_for_test(&mut self, attempt: usize) {
        self.fail_send_at = Some(attempt);
    }

    fn build_report(
        &self,
        flow: &Flow,
        trace: RunTrace,
        iterations: u64,
        elapsed: std::time::Duration,
        outcome: FlowOutcome,
        ctx: &PacketContext,
    ) -> FlowReport {
        FlowReport::new(
            flow.name(),
            flow.role(),
            self.is_dry_run(),
            trace.visited_states,
            self.conversation.sent_count(),
            self.conversation.received_count(),
            trace.transitions_taken,
            iterations,
            elapsed,
            outcome,
            ctx.summary(),
        )
        .with_tcp_payload(
            self.tcp_payload_bytes_sent,
            ctx.tcp_received_payload().to_vec(),
        )
        .with_recovery_metrics(ctx.recovery_metrics())
        .with_tcp_state(ctx.get_tcp_snd_nxt(), ctx.get_tcp_rcv_nxt())
        .with_protocol_snapshot(ctx.protocol_snapshot().cloned())
    }

    fn run_timeout_elapsed(&self, elapsed: Duration) -> bool {
        self.options
            .run_timeout
            .is_some_and(|timeout| elapsed >= timeout)
    }

    fn effective_step_timeout(
        &self,
        run_started: Instant,
        current_state: &str,
    ) -> Option<EffectiveDeadline> {
        let elapsed = run_started.elapsed();
        let run_remaining = self
            .options
            .run_timeout
            .map(|run_timeout| run_timeout.saturating_sub(elapsed));
        if run_remaining.is_some_and(|remaining| remaining.is_zero()) {
            return None;
        }

        let wakeup_remaining = self
            .scheduled_wakeup
            .as_ref()
            .filter(|wakeup| wakeup.state == current_state)
            .map(|wakeup| wakeup.deadline.saturating_duration_since(Instant::now()));

        Some(Self::select_deadline(
            self.options.step_timeout,
            run_remaining,
            wakeup_remaining,
        ))
    }

    fn select_deadline(
        step: Duration,
        run: Option<Duration>,
        protocol: Option<Duration>,
    ) -> EffectiveDeadline {
        // Equal deadlines use run > protocol > step precedence. This keeps the
        // whole-run bound authoritative and treats a coincident protocol
        // wakeup as recoverable rather than a generic step expiry.
        let mut selected = EffectiveDeadline {
            duration: step,
            kind: DeadlineKind::Step,
        };
        if let Some(protocol) = protocol {
            if protocol <= selected.duration {
                selected = EffectiveDeadline {
                    duration: protocol,
                    kind: DeadlineKind::Protocol,
                };
            }
        }
        if let Some(run) = run {
            if run <= selected.duration {
                selected = EffectiveDeadline {
                    duration: run,
                    kind: DeadlineKind::Run,
                };
            }
        }
        selected
    }

    fn schedule_wakeup(&mut self, state: &str, delay: Duration, scheduled_at: Instant) {
        if delay.is_zero() && self.immediate_wakeup_dispatched {
            self.scheduled_wakeup = None;
            return;
        }

        self.scheduled_wakeup = Some(ScheduledWakeup {
            state: state.to_string(),
            deadline: scheduled_at.checked_add(delay).unwrap_or(scheduled_at),
            immediate: delay.is_zero(),
        });
    }

    fn take_due_wakeup(&mut self, current_state: &str) -> bool {
        let Some(wakeup) = self.scheduled_wakeup.as_ref() else {
            return false;
        };
        if wakeup.state != current_state {
            self.clear_scheduled_wakeup();
            return false;
        }
        if wakeup.deadline > Instant::now() {
            return false;
        }

        let wakeup = self.scheduled_wakeup.take().expect("wakeup was present");
        self.immediate_wakeup_dispatched = wakeup.immediate;
        true
    }

    fn clear_scheduled_wakeup(&mut self) {
        self.scheduled_wakeup = None;
        self.immediate_wakeup_dispatched = false;
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

fn tcp_payload_len(packet: &crafter::Packet) -> usize {
    if packet.layer::<crafter::Tcp>().is_none() {
        return 0;
    }

    packet
        .layers::<crafter::Raw>()
        .map(crafter::Raw::as_bytes)
        .map(<[u8]>::len)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::{DeadlineKind, EffectiveDeadline, Runner};
    use crate::step::SendIntent;
    use crate::{
        Binding, Bound, CaptureSource, Flow, FlowBuilderExt, FlowError, FlowOutcome, FlowState,
        FnMutator, Identity, MemoryCaptureSource, PredicateMatcher, Role, RunOptions, Step,
        StepGotoExt, Transition,
    };
    use std::cell::{Cell, RefCell};
    use std::net::Ipv4Addr;
    use std::rc::Rc;
    use std::time::Duration;

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

    fn tcp_payload_packet(payload: impl AsRef<[u8]>) -> crafter::Packet {
        crafter::Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            .protocol(crafter::IPPROTO_TCP)
            / crafter::Tcp::new()
                .sport(49_152)
                .dport(443)
                .seq(0x1000)
                .ack(0x2000)
                .ack_segment()
                .psh()
            / crafter::Raw::from_bytes(payload)
    }

    fn arp_frame() -> crafter::Packet {
        let sender_mac = crafter::MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x31]);

        crafter::Ethernet::new()
            .src(sender_mac)
            .dst(crafter::MacAddr::BROADCAST)
            / crafter::Arp::who_has(
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(192, 0, 2, 1),
                sender_mac,
            )
    }

    fn emit_once_flow(name: &str, packet: crafter::Packet) -> Flow {
        let emit = FlowState::new("Emit")
            .on_entry(move |_ctx| Ok(Step::emit(packet.clone()).goto("Done")))
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();

        Flow::new(name)
            .role(Role::Injector)
            .state(emit)
            .state(done)
            .initial("Emit")
    }

    fn waiting_reply_flow(name: &str, packet: crafter::Packet) -> Flow {
        let transition = Transition::on(
            PredicateMatcher::new("never matches", |_packet, _ctx| false),
            |_packet, _ctx| Ok(Step::goto("Done")),
        )
        .targets(["Done"]);
        let waiting = FlowState::new("Waiting")
            .on_entry(move |_ctx| Ok(Step::send(packet.clone())))
            .on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();

        Flow::new(name)
            .state(waiting)
            .state(done)
            .initial("Waiting")
    }

    struct RecordingTimeoutSource {
        seen_timeout: Rc<Cell<Option<Duration>>>,
    }

    impl CaptureSource for RecordingTimeoutSource {
        fn next_packet(&mut self, timeout: Duration) -> crate::Result<Option<crafter::Packet>> {
            self.seen_timeout.set(Some(timeout));
            std::thread::sleep(timeout);
            Ok(None)
        }

        fn describe(&self) -> String {
            "recording timeout source".to_string()
        }
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
    fn runner_with_source_threads_capture_filter_to_conversation() {
        let options = RunOptions::default().capture_filter(" udp and port 53 ");
        let runner = Runner::with_source(options, MemoryCaptureSource::default())
            .expect("runner opens with injected source");

        assert_eq!(
            runner.options().capture_filter.as_deref(),
            Some("udp and port 53")
        );
        assert_eq!(
            runner.conversation.capture_filter(),
            Some("udp and port 53")
        );
        assert!(runner
            .conversation
            .describe()
            .contains("memory capture source"));
    }

    #[test]
    fn runner_default_run_reports_dry_run_and_opens_no_live_sender() {
        let packet = request_packet();
        let start = FlowState::new("Start")
            .on_entry(move |_ctx| Ok(Step::emit(packet.clone()).goto("Done")))
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-safe-default")
            .role(Role::Injector)
            .state(start)
            .state(done)
            .initial("Start");
        let mut runner = Runner::bind(Binding::default()).expect("default runner binds");

        let report = runner
            .run(&mut flow)
            .expect("default runner completes flow");

        assert!(runner.is_dry_run());
        assert!(report.is_dry_run());
        assert_eq!(runner.live_sender_open_count(), 0);
        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.sent_count(), 1);
        assert!(runner
            .send_reports()
            .iter()
            .all(crafter::net::SendReport::is_dry_run));
    }

    #[test]
    fn runner_live_binding_attempts_capture_open_on_configured_interface() {
        let result = Runner::bind(
            Binding::interface("nonexistent-iface-zzz")
                .network_layer()
                .live(),
        );

        let error = match result {
            Ok(_) => panic!("missing live interface should fail during capture open"),
            Err(error) => error,
        };
        match error {
            FlowError::Capture(message) => {
                assert!(message.contains("nonexistent-iface-zzz"));
                assert!(message.contains("pcap capture"));
            }
            other => panic!("expected capture error, got {other:?}"),
        }
    }

    #[test]
    fn runner_dry_run_respects_explicit_link_and_network_bindings() {
        let mut link_flow = emit_once_flow("runner-link-binding", arp_frame());
        let link_options =
            RunOptions::default().binding(Binding::interface("flow-lab0").link_layer());
        let mut link_runner = Runner::with_options(link_options).expect("link runner opens");

        let link_report = link_runner.run(&mut link_flow).expect("link flow runs");
        let link_plan = link_runner.send_reports()[0].plan();
        let decoded_link =
            crafter::Packet::decode_from_link(crafter::LinkType::Ethernet, link_plan.bytes())
                .expect("link-layer dry-run plan decodes as Ethernet");

        assert_eq!(link_report.outcome(), &FlowOutcome::Completed);
        assert_eq!(link_plan.interface(), "flow-lab0");
        assert_eq!(
            link_plan.requested_mode(),
            crafter::net::SendMode::LinkLayer
        );
        assert!(link_plan.target().is_link_layer());
        assert!(decoded_link.layer::<crafter::Ethernet>().is_some());
        assert!(decoded_link.layer::<crafter::Arp>().is_some());

        let mut network_flow = emit_once_flow("runner-network-binding", request_packet());
        let network_options =
            RunOptions::default().binding(Binding::interface("flow-lab0").network_layer());
        let mut network_runner =
            Runner::with_options(network_options).expect("network runner opens");

        let network_report = network_runner
            .run(&mut network_flow)
            .expect("network flow runs");
        let network_plan = network_runner.send_reports()[0].plan();
        let decoded_network =
            crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, network_plan.bytes())
                .expect("network-layer dry-run plan decodes as IPv4");

        assert_eq!(network_report.outcome(), &FlowOutcome::Completed);
        assert_eq!(network_plan.interface(), "flow-lab0");
        assert_eq!(
            network_plan.requested_mode(),
            crafter::net::SendMode::NetworkLayer
        );
        assert!(network_plan.target().is_network_layer());
        assert!(decoded_network.layer::<crafter::Ipv4>().is_some());
        assert!(decoded_network.layer::<crafter::Udp>().is_some());
    }

    #[test]
    fn runner_identity_mutator_sends_packet_unchanged() {
        let request = request_packet();
        let expected = compiled_bytes(&request);
        let start = FlowState::new("Start")
            .on_entry(move |_ctx| Ok(Step::emit(request.clone()).goto("Done")))
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-identity-mutator")
            .role(Role::Injector)
            .state(start)
            .state(done)
            .initial("Start");
        let mut runner = Runner::with_options(RunOptions::default())
            .expect("runner opens")
            .mutator(Identity);

        let report = runner.run(&mut flow).expect("runner completes flow");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.sent_count(), 1);
        assert_eq!(runner.send_reports()[0].plan().bytes(), expected.as_slice());
    }

    #[test]
    fn runner_default_send_repeat_emits_once() {
        let request = request_packet();
        let start = FlowState::new("Start")
            .on_entry(move |_ctx| Ok(Step::emit(request.clone()).goto("Done")))
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-default-repeat")
            .role(Role::Injector)
            .state(start)
            .state(done)
            .initial("Start");
        let mut runner = Runner::with_options(RunOptions::default()).expect("runner opens");

        let report = runner.run(&mut flow).expect("runner completes");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.sent_count(), 1);
        assert_eq!(runner.send_reports().len(), 1);
    }

    #[test]
    fn runner_sends_step_batches_in_order() {
        let packets = [1_u8, 2, 3].map(|marker| {
            crafter::Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 10))
                .dst(Ipv4Addr::new(198, 51, 100, 53))
                / crafter::Udp::new()
                    .sport(49_152 + u16::from(marker))
                    .dport(9)
                / crafter::Raw::from_bytes([marker])
        });
        let expected = packets.iter().map(compiled_bytes).collect::<Vec<_>>();
        let start = FlowState::new("Start")
            .on_entry(move |_ctx| Ok(Step::emit_batch(packets.clone()).goto("Done")))
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-step-batch-order")
            .role(Role::Injector)
            .state(start)
            .state(done)
            .initial("Start");
        let mut runner = Runner::with_source(RunOptions::default(), MemoryCaptureSource::default())
            .expect("runner opens with memory source");

        let report = runner.run(&mut flow).expect("runner completes");
        let actual = runner
            .send_reports()
            .iter()
            .map(|report| report.plan().bytes().to_vec())
            .collect::<Vec<_>>();

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.sent_count(), 3);
        assert_eq!(runner.send_reports().len(), 3);
        assert_eq!(actual, expected);
    }

    #[test]
    fn runner_reports_partial_batch_failure_without_state_advance() {
        let packets = [1_u8, 2, 3].map(|marker| {
            crafter::Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 10))
                .dst(Ipv4Addr::new(198, 51, 100, 53))
                / crafter::Udp::new()
                    .sport(49_152 + u16::from(marker))
                    .dport(9)
                / crafter::Raw::from_bytes([marker])
        });
        let start = FlowState::new("Start")
            .on_entry(move |_ctx| Ok(Step::send_batch(packets.clone()).goto("Done")))
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-partial-batch-failure")
            .role(Role::Initiator)
            .state(start)
            .state(done)
            .initial("Start");
        let mut runner = Runner::with_options(RunOptions::default()).expect("runner opens");
        runner.fail_send_at_for_test(1);

        let report = runner.run(&mut flow).expect("send failure is reportable");

        assert_eq!(report.final_state(), Some("Start"));
        assert_eq!(report.visited_states(), &["Start".to_string()]);
        assert_eq!(report.sent_count(), 1);
        assert_eq!(runner.send_reports().len(), 1);
        assert!(runner.outstanding_segment.is_none());
        let error = report.error().expect("report records the batch failure");
        assert!(error.contains("output 1"));
        assert!(error.contains("after 1 successful sends"));
        assert!(error.contains("injected test send failure"));
    }

    #[test]
    fn runner_mutates_each_new_batch_packet_once() {
        let packets = [1_u8, 2, 3].map(|marker| {
            crafter::Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 10))
                .dst(Ipv4Addr::new(198, 51, 100, 53))
                / crafter::Udp::new()
                    .sport(49_152 + u16::from(marker))
                    .dport(9)
                / crafter::Raw::from_bytes([marker])
        });
        let start = FlowState::new("Start")
            .on_entry(move |_ctx| Ok(Step::emit_batch(packets.clone()).goto("Done")))
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-mutate-step-batch")
            .role(Role::Injector)
            .state(start)
            .state(done)
            .initial("Start");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let calls_for_mutator = Rc::clone(&calls);
        let options = RunOptions::default().send_repeat(2, Duration::ZERO);
        let mut runner = Runner::with_options(options)
            .expect("runner opens")
            .mutator(FnMutator::new(
                "record-batch-entry",
                move |packet, iteration, ctx| {
                    let marker = *packet
                        .compile()?
                        .as_ref()
                        .last()
                        .expect("batch packet has a marker");
                    calls_for_mutator.borrow_mut().push((
                        marker,
                        iteration,
                        ctx.get_transaction_id(),
                    ));
                    ctx.set_transaction_id(u32::from(marker));

                    Ok(crafter::Ipv4::new()
                        .src(Ipv4Addr::new(192, 0, 2, 10))
                        .dst(Ipv4Addr::new(198, 51, 100, 53))
                        / crafter::Udp::new()
                            .sport(49_152 + u16::from(marker))
                            .dport(9)
                        / crafter::Raw::from_bytes([marker, marker + 10]))
                },
            ));

        let report = runner.run(&mut flow).expect("runner completes");
        let sent_markers = runner
            .send_reports()
            .iter()
            .map(|report| report.plan().bytes()[report.plan().bytes().len() - 2..].to_vec())
            .collect::<Vec<_>>();

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.sent_count(), 6);
        assert_eq!(
            calls.borrow().as_slice(),
            &[(1, 0, None), (2, 0, Some(1)), (3, 0, Some(2))]
        );
        assert_eq!(
            sent_markers,
            vec![
                vec![1, 11],
                vec![2, 12],
                vec![3, 13],
                vec![1, 11],
                vec![2, 12],
                vec![3, 13],
            ]
        );
    }

    #[test]
    fn runner_send_repeat_policy_emits_bounded_copies() {
        let request = request_packet();
        let start = FlowState::new("Start")
            .on_entry(move |_ctx| Ok(Step::emit(request.clone()).goto("Done")))
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-repeat-policy")
            .role(Role::Injector)
            .state(start)
            .state(done)
            .initial("Start");
        let options = RunOptions::default().send_repeat(3, Duration::ZERO);
        let mut runner = Runner::with_options(options).expect("runner opens");

        let report = runner.run(&mut flow).expect("runner completes");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.sent_count(), 3);
        assert_eq!(runner.send_reports().len(), 3);
        assert!(runner
            .send_reports()
            .iter()
            .all(crafter::net::SendReport::is_dry_run));
    }

    #[test]
    fn runner_mutator_stamps_iteration_into_each_looped_send() {
        let base = raw_packet([0xff]);
        let start = FlowState::new("Start")
            .on_entry(move |_ctx| Ok(Step::emit(base.clone()).goto("Done")))
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-iteration-mutator")
            .role(Role::Injector)
            .state(start)
            .state(done)
            .initial("Start");
        let options = RunOptions::default().bound(Bound::Count(3));
        let mut runner = Runner::with_options(options)
            .expect("runner opens")
            .mutator(FnMutator::new(
                "stamp-iteration",
                |_packet, iteration, _ctx| {
                    Ok(crafter::Ipv4::new()
                        .src(Ipv4Addr::new(192, 0, 2, 10))
                        .dst(Ipv4Addr::new(198, 51, 100, 53))
                        / crafter::Udp::new().sport(49152).dport(9)
                        / crafter::Raw::from_bytes([iteration as u8]))
                },
            ));

        let report = runner.run(&mut flow).expect("runner completes flow");
        let sent = runner
            .send_reports()
            .iter()
            .map(|report| {
                *report
                    .plan()
                    .bytes()
                    .last()
                    .expect("mutated packet has a payload byte")
            })
            .collect::<Vec<_>>();

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.iterations(), 3);
        assert_eq!(sent, vec![0, 1, 2]);
    }

    #[test]
    fn runner_mutator_stamps_iteration_into_each_transition_send() {
        let observed = raw_packet([0x47, 0x01]);
        let observed_bytes = compiled_bytes(&observed);
        let transition = Transition::on(
            PredicateMatcher::new("observed trigger", move |packet, _ctx| {
                packet
                    .compile()
                    .map(|bytes| bytes.as_ref() == observed_bytes.as_slice())
                    .unwrap_or(false)
            }),
            |_packet, _ctx| Ok(Step::emit(raw_packet([0xff])).goto("Done")),
        )
        .targets(["Done"]);
        let watch = FlowState::new("Watch").on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-transition-iteration-mutator")
            .role(Role::Injector)
            .state(watch)
            .state(done)
            .initial("Watch");
        let options = RunOptions::default().bound(Bound::Count(3));
        let mut runner = Runner::with_source(
            options,
            MemoryCaptureSource::new(vec![observed.clone(), observed.clone(), observed]),
        )
        .expect("runner opens")
        .mutator(FnMutator::new(
            "stamp-transition-iteration",
            |_packet, iteration, _ctx| {
                Ok(crafter::Ipv4::new()
                    .src(Ipv4Addr::new(192, 0, 2, 10))
                    .dst(Ipv4Addr::new(198, 51, 100, 53))
                    / crafter::Udp::new().sport(49152).dport(9)
                    / crafter::Raw::from_bytes([iteration as u8]))
            },
        ));

        let report = runner.run(&mut flow).expect("runner completes flow");
        let sent = runner
            .send_reports()
            .iter()
            .map(|report| {
                *report
                    .plan()
                    .bytes()
                    .last()
                    .expect("mutated packet has a payload byte")
            })
            .collect::<Vec<_>>();

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.iterations(), 3);
        assert_eq!(report.received_count(), 3);
        assert_eq!(sent, vec![0, 1, 2]);
        assert_eq!(
            report.transitions_taken(),
            &vec!["observed trigger".to_string(); 3]
        );
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

        let report = runner.run(&mut flow).expect("runner completes flow");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.flow_name(), "runner-core-loop");
        assert_eq!(
            report.visited_states(),
            &[
                "Selecting".to_string(),
                "Waiting".to_string(),
                "Done".to_string()
            ]
        );
        assert_eq!(report.transitions_taken(), &["expected reply".to_string()]);
        assert!(report.sent_count() >= 1);
        assert_eq!(report.received_count(), 1);
    }

    #[test]
    fn runner_initiator_sends_entry_packet_before_receiving_reply() {
        let entry_ran = Rc::new(Cell::new(false));
        let entry_seen_by_transition = Rc::clone(&entry_ran);
        let request = request_packet();
        let reply = raw_packet([0x1a, 0x35]);
        let expected_reply = compiled_bytes(&reply);
        let transition = Transition::on(
            PredicateMatcher::new("initiator reply", move |packet, _ctx| {
                packet
                    .compile()
                    .map(|bytes| bytes.as_ref() == expected_reply.as_slice())
                    .unwrap_or(false)
            }),
            move |_packet, _ctx| {
                assert!(entry_seen_by_transition.get());
                Ok(Step::goto("Done"))
            },
        )
        .targets(["Done"]);
        let selecting = FlowState::new("Selecting")
            .on_entry(move |_ctx| {
                entry_ran.set(true);
                Ok(Step::send(request.clone()).goto("Waiting"))
            })
            .entry_targets(["Waiting"]);
        let waiting = FlowState::new("Waiting").on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-initiator")
            .role(Role::Initiator)
            .state(selecting)
            .state(waiting)
            .state(done)
            .initial("Selecting");
        let mut runner =
            Runner::with_source(RunOptions::default(), MemoryCaptureSource::new(vec![reply]))
                .expect("runner opens with injected source");

        let report = runner.run(&mut flow).expect("runner completes flow");

        assert_eq!(report.role(), Role::Initiator);
        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert!(report.sent_count() >= 1);
        assert_eq!(report.received_count(), 1);
    }

    #[test]
    fn runner_responder_receives_before_sending_first_packet() {
        let passive_entry_ran = Rc::new(Cell::new(false));
        let passive_entry_seen_by_transition = Rc::clone(&passive_entry_ran);
        let blocked_initial_send = request_packet();
        let request = raw_packet([0x36, 0x01]);
        let expected_request = compiled_bytes(&request);
        let reply = request_packet();
        let transition = Transition::on(
            PredicateMatcher::new("responder request", move |packet, _ctx| {
                packet
                    .compile()
                    .map(|bytes| bytes.as_ref() == expected_request.as_slice())
                    .unwrap_or(false)
            }),
            move |_packet, ctx| {
                assert!(passive_entry_seen_by_transition.get());
                assert_eq!(ctx.get_transaction_id(), Some(0x3600_0001));
                Ok(Step::send(reply.clone()).goto("Done"))
            },
        )
        .targets(["Done"]);
        let listening = FlowState::new("Listening")
            .on_entry(move |ctx| {
                passive_entry_ran.set(true);
                ctx.set_transaction_id(0x3600_0001);
                Ok(Step::send(blocked_initial_send.clone()).goto("Unreachable"))
            })
            .on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-responder")
            .role(Role::Responder)
            .state(listening)
            .state(done)
            .initial("Listening");
        let mut runner = Runner::with_source(
            RunOptions::default(),
            MemoryCaptureSource::new(vec![request]),
        )
        .expect("runner opens with injected source");

        let report = runner.run(&mut flow).expect("runner completes flow");

        assert_eq!(report.role(), Role::Responder);
        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(
            report.visited_states(),
            &["Listening".to_string(), "Done".to_string()]
        );
        assert_eq!(report.sent_count(), 1);
        assert_eq!(runner.send_reports().len(), 1);
        assert_eq!(report.received_count(), 1);
        assert_eq!(
            report.context_snapshot(),
            "PacketContext keys=[transaction_id]"
        );
    }

    #[test]
    fn runner_injector_reemits_entry_packet_for_bounded_iterations() {
        let emit_count = Rc::new(Cell::new(0));
        let emit_counter = Rc::clone(&emit_count);
        let announcement = request_packet();
        let announce = FlowState::new("Announce")
            .on_entry(move |_ctx| {
                emit_counter.set(emit_counter.get() + 1);
                Ok(Step::emit(announcement.clone()).goto("Done"))
            })
            .entry_targets(["Done"]);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-injector-entry")
            .role(Role::Injector)
            .state(announce)
            .state(done)
            .initial("Announce");
        let options = RunOptions::default().bound(Bound::Count(3));
        let mut runner = Runner::with_options(options).expect("runner opens");

        let report = runner.run(&mut flow).expect("runner completes flow");

        assert_eq!(report.role(), Role::Injector);
        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.iterations(), 3);
        assert_eq!(report.sent_count(), 3);
        assert_eq!(runner.send_reports().len(), 3);
        assert_eq!(report.received_count(), 0);
        assert_eq!(emit_count.get(), 3);
    }

    #[test]
    fn runner_injector_reacts_to_observed_packet_with_emit() {
        let observed = raw_packet([0x37, 0x01]);
        let expected_observed = compiled_bytes(&observed);
        let forged = request_packet();
        let transition = Transition::on(
            PredicateMatcher::new("observed request", move |packet, _ctx| {
                packet
                    .compile()
                    .map(|bytes| bytes.as_ref() == expected_observed.as_slice())
                    .unwrap_or(false)
            }),
            move |_packet, _ctx| Ok(Step::emit(forged.clone()).goto("Done")),
        )
        .targets(["Done"]);
        let watch = FlowState::new("Watch").on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-injector-reactive")
            .role(Role::Injector)
            .state(watch)
            .state(done)
            .initial("Watch");
        let mut runner = Runner::with_source(
            RunOptions::default(),
            MemoryCaptureSource::new(vec![observed]),
        )
        .expect("runner opens with injected source");

        let report = runner.run(&mut flow).expect("runner completes flow");

        assert_eq!(report.role(), Role::Injector);
        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(
            report.transitions_taken(),
            &["observed request".to_string()]
        );
        assert_eq!(report.sent_count(), 1);
        assert_eq!(report.received_count(), 1);
    }

    #[test]
    fn runner_report_completed_two_state_flow_lists_states_and_counts_sent_packets() {
        let request = tcp_payload_packet(b"client");
        let reply = tcp_payload_packet(b"peer");
        let expected_reply = compiled_bytes(&reply);
        let transition = Transition::on(
            PredicateMatcher::new("coffee reply", move |packet, _ctx| {
                packet
                    .compile()
                    .map(|bytes| bytes.as_ref() == expected_reply.as_slice())
                    .unwrap_or(false)
            }),
            |packet, ctx| {
                for raw in packet.layers::<crafter::Raw>() {
                    ctx.append_tcp_payload(raw.as_bytes());
                }
                Ok(Step::done().goto("Done"))
            },
        )
        .targets(["Done"])
        .terminal();
        let start = FlowState::new("Start")
            .on_entry(move |_ctx| Ok(Step::send(request.clone())))
            .on(transition);
        let done = FlowState::new("Done");
        let mut flow = Flow::new("runner-report-two-state")
            .state(start)
            .state(done)
            .initial("Start");
        let mut runner =
            Runner::with_source(RunOptions::default(), MemoryCaptureSource::new(vec![reply]))
                .expect("runner opens with injected source");

        let report = runner.run(&mut flow).expect("runner returns report");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(
            report.visited_states(),
            &["Start".to_string(), "Done".to_string()]
        );
        assert_eq!(report.final_state(), Some("Done"));
        assert!(report.sent_count() >= 1);
        assert_eq!(report.bytes_sent(), 6);
        assert_eq!(report.bytes_received(), 4);
        assert_eq!(report.received_payload(), b"peer");
        assert!(report.summary().contains("state_trace=Start -> Done"));
        assert!(report.show().contains("state trace: Start -> Done"));
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

        let report = runner.run(&mut flow).expect("runner completes flow");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(
            report.visited_states(),
            &[
                "Selecting".to_string(),
                "Waiting".to_string(),
                "Next".to_string(),
                "Done".to_string()
            ]
        );
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

        let report = runner.run(&mut flow).expect("runner completes flow");
        let sent = runner
            .send_reports()
            .last()
            .expect("request packet should be sent");
        let decoded =
            crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, sent.plan().bytes())
                .expect("dry-run send plan decodes as IPv4");
        let ipv4 = decoded
            .layer::<crafter::Ipv4>()
            .expect("sent packet has IPv4 layer");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(
            report.context_snapshot(),
            "PacketContext keys=[offered_ipv4]"
        );
        assert_eq!(ipv4.destination(), offered);
    }

    #[test]
    fn runner_without_timeout_action_still_times_out() {
        let transition = Transition::on(
            PredicateMatcher::new("any packet", |_packet, _ctx| true),
            |_packet, _ctx| Ok(Step::goto("Done")),
        )
        .targets(["Done"]);
        let waiting = FlowState::new("Waiting").on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-timeout")
            .state(waiting)
            .state(done)
            .initial("Waiting");
        let options = RunOptions::default().step_timeout(Duration::from_millis(1));
        let mut runner = Runner::with_source(options, MemoryCaptureSource::default())
            .expect("runner opens with empty source");

        let report = runner
            .run(&mut flow)
            .expect("runner returns timeout report");

        assert_eq!(report.outcome(), &FlowOutcome::TimedOut);
        assert_eq!(report.visited_states(), &["Waiting".to_string()]);
        assert_eq!(report.iterations(), 0);
        assert_eq!(report.recovery_metrics().timeout_events(), 0);
    }

    #[test]
    fn runner_dispatches_state_timeout_action() {
        let initial = request_packet();
        let recovery_packets = [request_packet(), request_packet()];
        let waiting = FlowState::new("Waiting")
            .on_entry(move |_ctx| Ok(Step::send(initial.clone())))
            .on_timeout(
                move |_ctx| Ok(Step::send_batch(recovery_packets.clone()).goto("Recovered")),
            )
            .timeout_targets(["Recovered"]);
        let recovered = FlowState::new("Recovered")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-state-timeout-action")
            .state(waiting)
            .state(recovered)
            .initial("Waiting");
        let options = RunOptions::default().step_timeout(Duration::from_millis(1));
        let mut runner = Runner::with_source(options, MemoryCaptureSource::default())
            .expect("runner opens with empty source");

        let report = runner
            .run(&mut flow)
            .expect("runner dispatches the timeout action");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(
            report.visited_states(),
            &["Waiting".to_string(), "Recovered".to_string()]
        );
        assert_eq!(report.sent_count(), 3);
        assert_eq!(runner.send_reports().len(), 3);
        assert_eq!(report.recovery_metrics().timeout_events(), 1);
        assert!(runner.outstanding_segment.is_none());
    }

    #[test]
    fn runner_honors_dynamic_wakeup_before_step_timeout() {
        let seen_timeout = Rc::new(Cell::new(None));
        let source = RecordingTimeoutSource {
            seen_timeout: Rc::clone(&seen_timeout),
        };
        let waiting = FlowState::new("Waiting")
            .on_entry(|_ctx| Ok(Step::stay().wake_after(Duration::from_millis(5))))
            .on_timeout(|_ctx| Ok(Step::goto("Recovered")))
            .timeout_targets(["Recovered"]);
        let recovered = FlowState::new("Recovered")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-dynamic-wakeup")
            .state(waiting)
            .state(recovered)
            .initial("Waiting");
        let options = RunOptions::default()
            .step_timeout(Duration::from_secs(1))
            .run_timeout(Duration::from_millis(100));
        let mut runner = Runner::with_source(options, source).expect("runner opens");

        let report = runner
            .run(&mut flow)
            .expect("runner dispatches the dynamic wakeup");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(
            report.visited_states(),
            &["Waiting".to_string(), "Recovered".to_string()]
        );
        assert_eq!(report.recovery_metrics().timeout_events(), 1);
        assert!(
            seen_timeout.get().expect("source saw a timeout") < Duration::from_secs(1),
            "dynamic wakeup should cap the configured step timeout"
        );
    }

    #[test]
    fn runner_uses_earliest_deadline() {
        let millis = Duration::from_millis;

        assert_eq!(
            Runner::select_deadline(millis(10), Some(millis(20)), Some(millis(30))),
            EffectiveDeadline {
                duration: millis(10),
                kind: DeadlineKind::Step,
            }
        );
        assert_eq!(
            Runner::select_deadline(millis(20), Some(millis(30)), Some(millis(10))),
            EffectiveDeadline {
                duration: millis(10),
                kind: DeadlineKind::Protocol,
            }
        );
        assert_eq!(
            Runner::select_deadline(millis(30), Some(millis(10)), Some(millis(20))),
            EffectiveDeadline {
                duration: millis(10),
                kind: DeadlineKind::Run,
            }
        );
        assert_eq!(
            Runner::select_deadline(millis(10), None, Some(millis(10))).kind,
            DeadlineKind::Protocol
        );
        assert_eq!(
            Runner::select_deadline(millis(20), Some(millis(10)), Some(millis(10))).kind,
            DeadlineKind::Run
        );
        assert_eq!(
            Runner::select_deadline(millis(10), Some(millis(10)), Some(millis(10))).kind,
            DeadlineKind::Run
        );
    }

    #[test]
    fn run_deadline_remains_authoritative() {
        let seen_timeout = Rc::new(Cell::new(None));
        let source = RecordingTimeoutSource {
            seen_timeout: Rc::clone(&seen_timeout),
        };
        let waiting = FlowState::new("Waiting")
            .on_timeout(|_ctx| Ok(Step::goto("Recovered")))
            .timeout_targets(["Recovered"]);
        let recovered = FlowState::new("Recovered")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("authoritative-run-deadline")
            .state(waiting)
            .state(recovered)
            .initial("Waiting");
        let options = RunOptions::default()
            .step_timeout(Duration::from_secs(1))
            .run_timeout(Duration::from_millis(5));
        let mut runner = Runner::with_source(options, source).expect("runner opens");

        let report = runner.run(&mut flow).expect("runner returns timeout");

        assert_eq!(report.outcome(), &FlowOutcome::TimedOut);
        assert_eq!(report.visited_states(), &["Waiting".to_string()]);
        assert_eq!(report.recovery_metrics().timeout_events(), 0);
        let timeout = seen_timeout.get().expect("source saw a timeout");
        assert!(!timeout.is_zero());
        assert!(timeout <= Duration::from_millis(5));
    }

    #[test]
    fn runner_without_retransmit_sends_outstanding_segment_once_before_timeout() {
        let mut flow = waiting_reply_flow("runner-no-retransmit", request_packet());
        let options = RunOptions::default().step_timeout(Duration::from_millis(1));
        let mut runner = Runner::with_source(options, MemoryCaptureSource::default())
            .expect("runner opens with empty source");

        let report = runner
            .run(&mut flow)
            .expect("runner returns timeout report");

        assert_eq!(report.outcome(), &FlowOutcome::TimedOut);
        assert_eq!(report.sent_count(), 1);
        assert_eq!(runner.send_reports().len(), 1);
    }

    #[test]
    fn runner_retransmits_outstanding_segment() {
        let request = request_packet();
        let legacy_step = Step::send(request.clone());
        assert_eq!(legacy_step.outputs().len(), 1);
        assert_eq!(
            legacy_step.outputs()[0].intent(),
            SendIntent::ReplyExpectedReplaySafe
        );

        let mut flow = waiting_reply_flow("runner-retransmit", request);
        let retransmit_interval = Duration::from_millis(2);
        let options = RunOptions::default()
            .step_timeout(Duration::from_millis(1))
            .retransmit(2, retransmit_interval);
        let mut runner = Runner::with_source(options, MemoryCaptureSource::default())
            .expect("runner opens with empty source");

        let policy = runner
            .options()
            .retransmit
            .expect("legacy retransmit policy is configured");
        assert_eq!(policy.count(), 2);
        assert_eq!(policy.interval(), retransmit_interval);

        let report = runner
            .run(&mut flow)
            .expect("runner returns timeout report");

        assert_eq!(report.outcome(), &FlowOutcome::TimedOut);
        assert!(report.elapsed() >= retransmit_interval * 2);
        assert_eq!(report.sent_count(), 3);
        assert_eq!(runner.send_reports().len(), 3);
        assert_eq!(report.recovery_metrics().exact_replay_transmits(), 2);
        assert_eq!(report.recovery_metrics().regenerated_transmits(), 0);
        assert!(runner
            .send_reports()
            .iter()
            .all(crafter::net::SendReport::is_dry_run));

        let transition = Transition::on(
            PredicateMatcher::new("any packet", |_packet, _ctx| true),
            |_packet, _ctx| Ok(Step::goto("Done")),
        )
        .targets(["Done"]);
        let request = request_packet();
        let waiting = FlowState::new("Waiting")
            .on_entry(move |_ctx| Ok(Step::send(request.clone())))
            .on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut matched_flow = Flow::new("runner-clears-outstanding")
            .state(waiting)
            .state(done)
            .initial("Waiting");
        let mut matched_runner = Runner::with_source(
            RunOptions::default().retransmit(2, retransmit_interval),
            MemoryCaptureSource::new(vec![request_packet()]),
        )
        .expect("runner opens with matching reply");

        let matched_report = matched_runner
            .run(&mut matched_flow)
            .expect("runner completes after matching reply");

        assert_eq!(matched_report.outcome(), &FlowOutcome::Completed);
        assert_eq!(matched_report.sent_count(), 1);
        assert_eq!(matched_runner.send_reports().len(), 1);
        assert_eq!(
            matched_report.recovery_metrics().exact_replay_transmits(),
            0
        );
        assert!(matched_runner.outstanding_segment.is_none());
    }

    #[test]
    fn runner_never_replays_regeneration_only_output() {
        let protected_looking = crafter::Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 53))
            / crafter::Udp::new().sport(49_152).dport(443)
            / crafter::Raw::from_bytes([0xc3, 0x00, 0x00, 0x00, 0x01, 0xa5, 0x7e, 0x91]);
        let transition = Transition::on(
            PredicateMatcher::new("never matches", |_packet, _ctx| false),
            |_packet, _ctx| Ok(Step::goto("Done")),
        )
        .targets(["Done"]);
        let waiting = FlowState::new("Waiting")
            .on_entry(move |_ctx| Ok(Step::send_regeneration_only(protected_looking.clone())))
            .on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-regeneration-only")
            .state(waiting)
            .state(done)
            .initial("Waiting");
        let options = RunOptions::default()
            .step_timeout(Duration::from_millis(1))
            .retransmit(2, Duration::ZERO);
        let mut runner = Runner::with_source(options, MemoryCaptureSource::default())
            .expect("runner opens with empty source");

        let report = runner
            .run(&mut flow)
            .expect("runner returns timeout without replaying protected output");

        assert_eq!(report.outcome(), &FlowOutcome::TimedOut);
        assert_eq!(report.sent_count(), 1);
        assert_eq!(runner.send_reports().len(), 1);
        assert!(runner.outstanding_segment.is_none());
        assert_eq!(report.recovery_metrics().exact_replay_transmits(), 0);
        assert_eq!(report.recovery_metrics().regenerated_transmits(), 0);
    }

    #[test]
    fn runner_counts_timeout_regeneration_separately_from_exact_replay() {
        let initial = request_packet();
        let regenerated = request_packet();
        let waiting = FlowState::new("Waiting")
            .on_entry(move |_ctx| Ok(Step::send_regeneration_only(initial.clone())))
            .on_timeout(move |_ctx| {
                Ok(Step::send_regeneration_only(regenerated.clone()).goto("Recovered"))
            })
            .timeout_targets(["Recovered"]);
        let recovered = FlowState::new("Recovered")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-timeout-regeneration-metrics")
            .state(waiting)
            .state(recovered)
            .initial("Waiting");
        let options = RunOptions::default()
            .step_timeout(Duration::from_millis(1))
            .retransmit(2, Duration::ZERO);
        let mut runner = Runner::with_source(options, MemoryCaptureSource::default())
            .expect("runner opens with empty source");

        let report = runner
            .run(&mut flow)
            .expect("runner regenerates output from timeout action");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.sent_count(), 2);
        assert_eq!(report.recovery_metrics().regenerated_transmits(), 1);
        assert_eq!(report.recovery_metrics().exact_replay_transmits(), 0);
    }

    #[test]
    fn runner_run_timeout_caps_step_receive_timeout() {
        let seen_timeout = Rc::new(Cell::new(None));
        let source = RecordingTimeoutSource {
            seen_timeout: Rc::clone(&seen_timeout),
        };
        let transition = Transition::on(
            PredicateMatcher::new("any packet", |_packet, _ctx| true),
            |_packet, _ctx| Ok(Step::goto("Done")),
        )
        .targets(["Done"]);
        let waiting = FlowState::new("Waiting").on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-run-timeout")
            .state(waiting)
            .state(done)
            .initial("Waiting");
        let options = RunOptions::default()
            .step_timeout(Duration::from_secs(1))
            .run_timeout(Duration::from_millis(5));
        let mut runner = Runner::with_source(options, source).expect("runner opens");

        let report = runner.run(&mut flow).expect("runner returns timeout");

        assert_eq!(report.outcome(), &FlowOutcome::TimedOut);
        assert_eq!(report.visited_states(), &["Waiting".to_string()]);
        assert!(seen_timeout.get().expect("source saw a timeout") <= Duration::from_millis(5));
    }

    #[test]
    fn runner_handles_non_matching_burst_before_match() {
        let expected = raw_packet([0xaa, 0xbb, 0xcc]);
        let expected_bytes = compiled_bytes(&expected);
        let transition = Transition::on(
            PredicateMatcher::new("expected packet", move |packet, _ctx| {
                packet
                    .compile()
                    .map(|bytes| bytes.as_ref() == expected_bytes.as_slice())
                    .unwrap_or(false)
            }),
            |_packet, _ctx| Ok(Step::goto("Done")),
        )
        .targets(["Done"]);
        let waiting = FlowState::new("Waiting").on(transition);
        let done = FlowState::new("Done")
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal();
        let mut flow = Flow::new("runner-burst-before-match")
            .state(waiting)
            .state(done)
            .initial("Waiting");
        let packets = vec![
            raw_packet([0x01]),
            raw_packet([0x02]),
            raw_packet([0x03]),
            expected,
        ];
        let options = RunOptions::default().step_timeout(Duration::from_millis(50));
        let mut runner =
            Runner::with_source(options, MemoryCaptureSource::new(packets)).expect("runner opens");

        let report = runner.run(&mut flow).expect("runner completes");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.received_count(), 4);
        assert_eq!(report.transitions_taken(), &["expected packet".to_string()]);
        assert_eq!(
            report.visited_states(),
            &["Waiting".to_string(), "Done".to_string()]
        );
    }

    #[test]
    fn runner_count_bound_restarts_terminal_path_exactly_three_times() {
        let terminal_count = Rc::new(Cell::new(0));
        let count_for_entry = Rc::clone(&terminal_count);
        let done = FlowState::new("Done")
            .on_entry(move |_ctx| {
                count_for_entry.set(count_for_entry.get() + 1);
                Ok(Step::done())
            })
            .entry_terminal();
        let mut flow = Flow::new("runner-count-bound").state(done).initial("Done");
        let options = RunOptions::default().bound(Bound::Count(3));
        let mut runner = Runner::with_options(options).expect("runner opens");

        let report = runner
            .run(&mut flow)
            .expect("runner completes bounded flow");

        assert_eq!(report.outcome(), &FlowOutcome::Completed);
        assert_eq!(report.iterations(), 3);
        assert_eq!(
            report.visited_states(),
            &["Done".to_string(), "Done".to_string(), "Done".to_string()]
        );
        assert_eq!(terminal_count.get(), 3);
    }
}
