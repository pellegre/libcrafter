//! Transition outcomes for protocol flows.

use std::time::Duration;

/// Delivery behavior attached to one packet output.
///
/// The three values make reply expectation and exact-replay safety a single,
/// non-contradictory choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendIntent {
    /// Send the packet without waiting for a direct reply.
    FireAndForget,
    /// Wait for a reply and permit retransmission of the exact packet bytes.
    ReplyExpectedReplaySafe,
    /// Wait for a reply, but regenerate fresh packet bytes after loss.
    ReplyExpectedRegenerationOnly,
}

impl SendIntent {
    /// Return true when this output expects a direct reply.
    pub const fn expects_reply(self) -> bool {
        !matches!(self, Self::FireAndForget)
    }

    /// Return true when retransmission may replay the exact packet bytes.
    pub const fn allows_exact_replay(self) -> bool {
        matches!(self, Self::ReplyExpectedReplaySafe)
    }

    /// Return true when recovery must produce newly generated packet bytes.
    pub const fn requires_regeneration(self) -> bool {
        matches!(self, Self::ReplyExpectedRegenerationOnly)
    }
}

/// One ordered packet output produced by a flow step.
#[derive(Debug, Clone)]
pub struct StepOutput {
    packet: crafter::Packet,
    intent: SendIntent,
}

impl StepOutput {
    /// Create a legacy reply-expected output whose exact bytes may be replayed.
    pub const fn new(packet: crafter::Packet) -> Self {
        Self::replay_safe(packet)
    }

    /// Create an output that does not expect a direct reply.
    pub const fn fire_and_forget(packet: crafter::Packet) -> Self {
        Self {
            packet,
            intent: SendIntent::FireAndForget,
        }
    }

    /// Create a reply-expected output whose exact bytes may be replayed.
    pub const fn replay_safe(packet: crafter::Packet) -> Self {
        Self {
            packet,
            intent: SendIntent::ReplyExpectedReplaySafe,
        }
    }

    /// Create a reply-expected output that must be regenerated after loss.
    pub const fn regeneration_only(packet: crafter::Packet) -> Self {
        Self {
            packet,
            intent: SendIntent::ReplyExpectedRegenerationOnly,
        }
    }

    /// Borrow the packet carried by this output.
    pub const fn packet(&self) -> &crafter::Packet {
        &self.packet
    }

    /// Consume this output and return its packet.
    pub fn into_packet(self) -> crafter::Packet {
        self.packet
    }

    /// Return this output's delivery intent.
    pub const fn intent(&self) -> SendIntent {
        self.intent
    }

    /// Return true when this output expects a direct reply.
    pub const fn expects_reply(&self) -> bool {
        self.intent.expects_reply()
    }

    /// Return true when retransmission may replay the exact packet bytes.
    pub const fn allows_exact_replay(&self) -> bool {
        self.intent.allows_exact_replay()
    }

    /// Return true when recovery must produce newly generated packet bytes.
    pub const fn requires_regeneration(&self) -> bool {
        self.intent.requires_regeneration()
    }
}

/// Instruction returned by a transition after it fires.
#[derive(Debug, Clone)]
pub struct Step {
    /// Packets to send or emit, in insertion order, before applying the state change.
    outputs: Vec<StepOutput>,
    /// Target state. `None` means stay in the current state.
    pub target: Option<String>,
    /// Whether this step ends the flow successfully.
    pub terminal: bool,
    /// Optional terminal outcome label.
    pub outcome: Option<String>,
    /// Whether the runner should expect a reply after sending the packet.
    pub expects_reply: bool,
    /// Optional relative delay before the current state's timeout action should run.
    wake_after: Option<Duration>,
}

impl Step {
    /// Send a packet and stay in the current state unless a target is added.
    pub fn send(packet: crafter::Packet) -> Self {
        Self::send_batch([packet])
    }

    /// Send an ordered batch of packets and stay in the current state unless a target is added.
    pub fn send_batch(packets: impl IntoIterator<Item = crafter::Packet>) -> Self {
        Self {
            outputs: packets.into_iter().map(StepOutput::replay_safe).collect(),
            target: None,
            terminal: false,
            outcome: None,
            expects_reply: true,
            wake_after: None,
        }
    }

    /// Emit a packet without expecting a direct reply.
    pub fn emit(packet: crafter::Packet) -> Self {
        Self::emit_batch([packet])
    }

    /// Emit an ordered batch of packets without expecting a direct reply.
    pub fn emit_batch(packets: impl IntoIterator<Item = crafter::Packet>) -> Self {
        Self {
            outputs: packets
                .into_iter()
                .map(StepOutput::fire_and_forget)
                .collect(),
            target: None,
            terminal: false,
            outcome: None,
            expects_reply: false,
            wake_after: None,
        }
    }

    /// Send a packet that must be regenerated rather than replayed after loss.
    pub fn send_regeneration_only(packet: crafter::Packet) -> Self {
        Self::send_regeneration_only_batch([packet])
    }

    /// Send an ordered batch whose packets must be regenerated after loss.
    pub fn send_regeneration_only_batch(
        packets: impl IntoIterator<Item = crafter::Packet>,
    ) -> Self {
        Self {
            outputs: packets
                .into_iter()
                .map(StepOutput::regeneration_only)
                .collect(),
            target: None,
            terminal: false,
            outcome: None,
            expects_reply: true,
            wake_after: None,
        }
    }

    /// Move to another state without sending a packet.
    pub fn goto(state: impl Into<String>) -> Self {
        Self {
            outputs: Vec::new(),
            target: Some(state.into()),
            terminal: false,
            outcome: None,
            expects_reply: false,
            wake_after: None,
        }
    }

    /// Stay in the current state without sending a packet.
    pub fn stay() -> Self {
        Self {
            outputs: Vec::new(),
            target: None,
            terminal: false,
            outcome: None,
            expects_reply: false,
            wake_after: None,
        }
    }

    /// Finish the flow successfully without a label.
    pub fn done() -> Self {
        Self {
            outputs: Vec::new(),
            target: None,
            terminal: true,
            outcome: None,
            expects_reply: false,
            wake_after: None,
        }
    }

    /// Finish the flow successfully with an outcome label.
    pub fn done_with(label: impl Into<String>) -> Self {
        Self {
            outcome: Some(label.into()),
            ..Self::done()
        }
    }

    /// Return the first outgoing packet, if any.
    ///
    /// Single-packet steps return their sole packet. Batch steps return their
    /// first packet for compatibility; use [`Self::outputs`] to inspect the
    /// complete ordered batch.
    pub const fn outgoing(&self) -> Option<&crafter::Packet> {
        match self.outputs.as_slice().first() {
            Some(output) => Some(output.packet()),
            None => None,
        }
    }

    /// Borrow every output in deterministic insertion order.
    pub fn outputs(&self) -> &[StepOutput] {
        &self.outputs
    }

    /// Return the target state name, if any.
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Return true if this step ends the flow.
    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Return the terminal outcome label, if any.
    pub fn outcome(&self) -> Option<&str> {
        self.outcome.as_deref()
    }

    /// Return true if this step expects a direct reply after sending.
    pub const fn expects_reply(&self) -> bool {
        self.expects_reply
    }

    /// Request that the current state's timeout action run after `delay`.
    pub fn wake_after(mut self, delay: Duration) -> Self {
        self.wake_after = Some(delay);
        self
    }

    /// Return the requested relative wakeup delay, if any.
    pub const fn wakeup(&self) -> Option<Duration> {
        self.wake_after
    }
}

/// Adds a target state to a step built by another constructor.
pub trait StepGotoExt {
    /// Set the target state for this step.
    fn goto(self, state: impl Into<String>) -> Step;
}

impl StepGotoExt for Step {
    fn goto(mut self, state: impl Into<String>) -> Step {
        self.target = Some(state.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{SendIntent, Step, StepGotoExt};
    use std::time::Duration;

    #[test]
    fn step_send_then_goto_carries_packet_and_target() {
        let packet =
            crafter::Packet::decode_raw([0xde, 0xad, 0xbe, 0xef]).expect("raw packet decodes");

        let step = Step::send(packet).goto("s");

        assert!(step.outgoing().is_some());
        assert_eq!(step.target(), Some("s"));
        assert!(!step.is_terminal());
        assert!(step.expects_reply());
    }

    #[test]
    fn step_records_relative_wakeup_request() {
        let step = Step::stay().wake_after(Duration::from_millis(25));

        assert_eq!(step.wakeup(), Some(Duration::from_millis(25)));
    }

    #[test]
    fn step_batch_preserves_packet_order() {
        let first = crafter::Packet::decode_raw([0x01]).expect("first raw packet decodes");
        let second = crafter::Packet::decode_raw([0x02]).expect("second raw packet decodes");
        let third = crafter::Packet::decode_raw([0x03]).expect("third raw packet decodes");

        let step = Step::send_batch([first, second, third]).goto("next");
        let bytes = step
            .outputs()
            .iter()
            .map(|output| {
                output
                    .packet()
                    .layer::<crafter::Raw>()
                    .expect("output has raw layer")
                    .as_bytes()[0]
            })
            .collect::<Vec<_>>();

        assert_eq!(bytes, [0x01, 0x02, 0x03]);
        assert_eq!(
            step.outgoing()
                .and_then(|packet| packet.layer::<crafter::Raw>())
                .expect("compatibility accessor returns first output")
                .as_bytes(),
            [0x01]
        );
        assert_eq!(step.target(), Some("next"));
        assert!(step.expects_reply());
    }

    #[test]
    fn step_output_intents_distinguish_replay_safety() {
        let replay_safe =
            Step::send(crafter::Packet::decode_raw([0x01]).expect("replay-safe packet decodes"));
        let fire_and_forget = Step::emit(
            crafter::Packet::decode_raw([0x02]).expect("fire-and-forget packet decodes"),
        );
        let regeneration_only = Step::send_regeneration_only_batch([
            crafter::Packet::decode_raw([0x03]).expect("first regeneration packet decodes"),
            crafter::Packet::decode_raw([0x04]).expect("second regeneration packet decodes"),
        ]);

        let replay_safe = &replay_safe.outputs()[0];
        assert_eq!(replay_safe.intent(), SendIntent::ReplyExpectedReplaySafe);
        assert!(replay_safe.expects_reply());
        assert!(replay_safe.allows_exact_replay());
        assert!(!replay_safe.requires_regeneration());

        let fire_and_forget = &fire_and_forget.outputs()[0];
        assert_eq!(fire_and_forget.intent(), SendIntent::FireAndForget);
        assert!(!fire_and_forget.expects_reply());
        assert!(!fire_and_forget.allows_exact_replay());
        assert!(!fire_and_forget.requires_regeneration());

        assert!(regeneration_only.expects_reply());
        assert_eq!(regeneration_only.outputs().len(), 2);
        for output in regeneration_only.outputs() {
            assert_eq!(output.intent(), SendIntent::ReplyExpectedRegenerationOnly);
            assert!(output.expects_reply());
            assert!(!output.allows_exact_replay());
            assert!(output.requires_regeneration());
        }

        let regeneration_single = Step::send_regeneration_only(
            crafter::Packet::decode_raw([0x05]).expect("single regeneration packet decodes"),
        );
        assert_eq!(
            regeneration_single.outputs()[0].intent(),
            SendIntent::ReplyExpectedRegenerationOnly
        );
    }

    #[test]
    fn step_done_is_terminal() {
        let step = Step::done();

        assert!(step.is_terminal());
        assert_eq!(step.outcome(), None);
    }

    #[test]
    fn step_stay_has_no_target_and_is_non_terminal() {
        let step = Step::stay();

        assert_eq!(step.target(), None);
        assert!(!step.is_terminal());
    }
}
