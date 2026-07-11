use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use crafter_flow::{Flow, FlowError, PacketContext, Result, Step};

/// One participant in a duplex run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

impl Side {
    fn peer(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

/// Deterministic preference used when both participants have queued output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOrder {
    Alternate,
    LeftFirst,
    RightFirst,
}

/// Bounds and delivery controls for one duplex run.
#[derive(Debug, Clone)]
pub struct DuplexConfig {
    pub delivery_order: DeliveryOrder,
    pub drop_datagrams: BTreeSet<usize>,
    pub step_limit: usize,
    pub time_limit: Duration,
}

impl Default for DuplexConfig {
    fn default() -> Self {
        Self {
            delivery_order: DeliveryOrder::Alternate,
            drop_datagrams: BTreeSet::new(),
            step_limit: 1_000,
            time_limit: Duration::from_secs(30),
        }
    }
}

impl DuplexConfig {
    pub fn drop_datagram(mut self, ordinal: usize) -> Self {
        self.drop_datagrams.insert(ordinal);
        self
    }
}

/// Why the deterministic driver stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    BothCompleted,
    StepLimit,
    TimeLimit,
    Quiescent,
}

/// Terminal observation retained for one participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    pub outcome: Option<String>,
    pub at: Duration,
}

/// One inspectable action in the duplex execution trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    pub at: Duration,
    pub side: Side,
    pub kind: TraceEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEventKind {
    Entry { state: String },
    Emitted { datagram: usize, batch_index: usize },
    Delivered { datagram: usize, to_state: String },
    Dropped { datagram: usize },
    Ignored { datagram: usize, state: String },
    Timeout { state: String },
    Transition { from: String, to: String },
    Completed { outcome: Option<String> },
}

/// Final state and trace of an entirely in-memory two-party run.
#[derive(Debug)]
pub struct DuplexReport {
    pub stop_reason: StopReason,
    pub simulated_time: Duration,
    pub steps: usize,
    pub left_context: PacketContext,
    pub right_context: PacketContext,
    pub left_completion: Option<Completion>,
    pub right_completion: Option<Completion>,
    pub trace: Vec<TraceEvent>,
    /// Protected QUIC UDP payload bytes keyed by deterministic datagram ordinal.
    pub protected_payloads: BTreeMap<usize, Vec<u8>>,
}

struct PendingDatagram {
    ordinal: usize,
    packet: crafter::Packet,
}

struct Party {
    flow: Flow,
    context: PacketContext,
    state: String,
    pending: VecDeque<PendingDatagram>,
    wakeup: Option<Duration>,
    completion: Option<Completion>,
}

impl Party {
    fn new(flow: Flow) -> Result<Self> {
        flow.validate()?;
        let state = flow.initial().to_string();
        Ok(Self {
            flow,
            context: PacketContext::new(),
            state,
            pending: VecDeque::new(),
            wakeup: None,
            completion: None,
        })
    }
}

/// Deterministic in-memory driver for two public flow graphs.
pub struct DuplexHarness {
    left: Party,
    right: Party,
    config: DuplexConfig,
    now: Duration,
    steps: usize,
    next_datagram: usize,
    alternate_next: Side,
    trace: Vec<TraceEvent>,
    protected_payloads: BTreeMap<usize, Vec<u8>>,
}

impl DuplexHarness {
    pub fn new(left: Flow, right: Flow, config: DuplexConfig) -> Result<Self> {
        Ok(Self {
            left: Party::new(left)?,
            right: Party::new(right)?,
            config,
            now: Duration::ZERO,
            steps: 0,
            next_datagram: 0,
            alternate_next: Side::Left,
            trace: Vec::new(),
            protected_payloads: BTreeMap::new(),
        })
    }

    pub fn run(mut self) -> Result<DuplexReport> {
        self.run_entry(Side::Left)?;
        self.run_entry(Side::Right)?;

        let stop_reason = loop {
            if self.both_completed() {
                break StopReason::BothCompleted;
            }
            if self.steps >= self.config.step_limit {
                break StopReason::StepLimit;
            }
            if let Some(side) = self.next_delivery_side() {
                self.deliver_one(side)?;
                continue;
            }

            let Some((side, deadline)) = self.next_wakeup() else {
                break StopReason::Quiescent;
            };
            if deadline > self.config.time_limit {
                self.now = self.config.time_limit;
                break StopReason::TimeLimit;
            }
            self.now = deadline;
            self.run_timeout(side)?;
        };

        Ok(DuplexReport {
            stop_reason,
            simulated_time: self.now,
            steps: self.steps,
            left_context: self.left.context,
            right_context: self.right.context,
            left_completion: self.left.completion,
            right_completion: self.right.completion,
            trace: self.trace,
            protected_payloads: self.protected_payloads,
        })
    }

    fn party(&self, side: Side) -> &Party {
        match side {
            Side::Left => &self.left,
            Side::Right => &self.right,
        }
    }

    fn party_mut(&mut self, side: Side) -> &mut Party {
        match side {
            Side::Left => &mut self.left,
            Side::Right => &mut self.right,
        }
    }

    fn both_completed(&self) -> bool {
        self.left.completion.is_some() && self.right.completion.is_some()
    }

    fn run_entry(&mut self, side: Side) -> Result<()> {
        if self.party(side).completion.is_some() || self.steps >= self.config.step_limit {
            return Ok(());
        }
        let state_name = self.party(side).state.clone();
        self.trace.push(TraceEvent {
            at: self.now,
            side,
            kind: TraceEventKind::Entry {
                state: state_name.clone(),
            },
        });
        self.steps += 1;
        let step = {
            let party = self.party_mut(side);
            let state = party.flow.state_mut(&state_name).ok_or_else(|| {
                FlowError::Build(format!("duplex state '{state_name}' does not exist"))
            })?;
            state.run_entry(&mut party.context)?
        };
        if let Some(step) = step {
            self.apply_step(side, step, false)?;
        }
        Ok(())
    }

    fn run_timeout(&mut self, side: Side) -> Result<()> {
        if self.party(side).completion.is_some() || self.steps >= self.config.step_limit {
            return Ok(());
        }
        let state_name = self.party(side).state.clone();
        self.party_mut(side).wakeup = None;
        self.trace.push(TraceEvent {
            at: self.now,
            side,
            kind: TraceEventKind::Timeout {
                state: state_name.clone(),
            },
        });
        self.steps += 1;
        self.party_mut(side).context.add_timeout_events(1);
        let step = {
            let party = self.party_mut(side);
            let state = party.flow.state_mut(&state_name).ok_or_else(|| {
                FlowError::Build(format!("duplex state '{state_name}' does not exist"))
            })?;
            state.run_timeout(&mut party.context)?
        };
        if let Some(step) = step {
            self.apply_step(side, step, true)?;
        }
        Ok(())
    }

    fn deliver_one(&mut self, side: Side) -> Result<()> {
        let pending = self
            .party_mut(side)
            .pending
            .pop_front()
            .expect("delivery side has queued output");
        self.steps += 1;

        if self.config.drop_datagrams.contains(&pending.ordinal) {
            self.trace.push(TraceEvent {
                at: self.now,
                side,
                kind: TraceEventKind::Dropped {
                    datagram: pending.ordinal,
                },
            });
            return Ok(());
        }

        let peer = side.peer();
        if self.party(peer).completion.is_some() {
            self.trace.push(TraceEvent {
                at: self.now,
                side,
                kind: TraceEventKind::Ignored {
                    datagram: pending.ordinal,
                    state: self.party(peer).state.clone(),
                },
            });
            return Ok(());
        }

        let peer_state = self.party(peer).state.clone();
        let step = {
            let party = self.party_mut(peer);
            let state = party.flow.state_mut(&peer_state).ok_or_else(|| {
                FlowError::Build(format!("duplex state '{peer_state}' does not exist"))
            })?;
            match state.find_transition(&pending.packet, &party.context) {
                Some(transition) => Some(transition.fire(&pending.packet, &mut party.context)?),
                None => None,
            }
        };

        let kind = if step.is_some() {
            TraceEventKind::Delivered {
                datagram: pending.ordinal,
                to_state: peer_state,
            }
        } else {
            TraceEventKind::Ignored {
                datagram: pending.ordinal,
                state: peer_state,
            }
        };
        self.trace.push(TraceEvent {
            at: self.now,
            side,
            kind,
        });
        if let Some(step) = step {
            self.apply_step(peer, step, false)?;
        }
        Ok(())
    }

    fn apply_step(&mut self, side: Side, step: Step, recovery: bool) -> Result<()> {
        let regenerated = step
            .outputs()
            .iter()
            .filter(|output| recovery && output.requires_regeneration())
            .count() as u64;
        for (batch_index, output) in step.outputs().iter().enumerate() {
            let ordinal = self.next_datagram;
            self.next_datagram += 1;
            if let Some(quic) = output.packet().layer::<crafter::Quic>() {
                self.protected_payloads
                    .insert(ordinal, quic.payload_bytes().to_vec());
            }
            self.party_mut(side).pending.push_back(PendingDatagram {
                ordinal,
                packet: output.packet().clone(),
            });
            self.trace.push(TraceEvent {
                at: self.now,
                side,
                kind: TraceEventKind::Emitted {
                    datagram: ordinal,
                    batch_index,
                },
            });
        }
        if regenerated > 0 {
            self.party_mut(side)
                .context
                .add_regenerated_transmits(regenerated);
        }

        if step.is_terminal() {
            let outcome = step.outcome().map(str::to_string);
            self.party_mut(side).wakeup = None;
            self.party_mut(side).completion = Some(Completion {
                outcome: outcome.clone(),
                at: self.now,
            });
            self.trace.push(TraceEvent {
                at: self.now,
                side,
                kind: TraceEventKind::Completed { outcome },
            });
            return Ok(());
        }

        let old_state = self.party(side).state.clone();
        let changed_state = match step.target() {
            Some(target) if target != old_state => {
                self.party_mut(side).state = target.to_string();
                self.party_mut(side).wakeup = None;
                self.trace.push(TraceEvent {
                    at: self.now,
                    side,
                    kind: TraceEventKind::Transition {
                        from: old_state,
                        to: target.to_string(),
                    },
                });
                true
            }
            _ => false,
        };

        if !changed_state {
            if let Some(delay) = step.wakeup() {
                self.party_mut(side).wakeup = Some(self.now.saturating_add(delay));
            }
        }
        if changed_state {
            self.run_entry(side)?;
        }
        Ok(())
    }

    fn next_delivery_side(&mut self) -> Option<Side> {
        let left = !self.left.pending.is_empty();
        let right = !self.right.pending.is_empty();
        let side = match (left, right) {
            (false, false) => return None,
            (true, false) => Side::Left,
            (false, true) => Side::Right,
            (true, true) => match self.config.delivery_order {
                DeliveryOrder::LeftFirst => Side::Left,
                DeliveryOrder::RightFirst => Side::Right,
                DeliveryOrder::Alternate => self.alternate_next,
            },
        };
        if self.config.delivery_order == DeliveryOrder::Alternate {
            self.alternate_next = side.peer();
        }
        Some(side)
    }

    fn next_wakeup(&self) -> Option<(Side, Duration)> {
        [
            (Side::Left, self.left.wakeup),
            (Side::Right, self.right.wakeup),
        ]
        .into_iter()
        .filter_map(|(side, deadline)| deadline.map(|deadline| (side, deadline)))
        .min_by_key(|(side, deadline)| (*deadline, matches!(side, Side::Right)))
    }
}
