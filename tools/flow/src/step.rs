//! Transition outcomes for protocol flows.

/// One ordered packet output produced by a flow step.
#[derive(Debug, Clone)]
pub struct StepOutput {
    packet: crafter::Packet,
}

impl StepOutput {
    /// Create an output from a packet.
    pub const fn new(packet: crafter::Packet) -> Self {
        Self { packet }
    }

    /// Borrow the packet carried by this output.
    pub const fn packet(&self) -> &crafter::Packet {
        &self.packet
    }

    /// Consume this output and return its packet.
    pub fn into_packet(self) -> crafter::Packet {
        self.packet
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
}

impl Step {
    /// Send a packet and stay in the current state unless a target is added.
    pub fn send(packet: crafter::Packet) -> Self {
        Self::send_batch([packet])
    }

    /// Send an ordered batch of packets and stay in the current state unless a target is added.
    pub fn send_batch(packets: impl IntoIterator<Item = crafter::Packet>) -> Self {
        Self {
            outputs: packets.into_iter().map(StepOutput::new).collect(),
            target: None,
            terminal: false,
            outcome: None,
            expects_reply: true,
        }
    }

    /// Emit a packet without expecting a direct reply.
    pub fn emit(packet: crafter::Packet) -> Self {
        Self::emit_batch([packet])
    }

    /// Emit an ordered batch of packets without expecting a direct reply.
    pub fn emit_batch(packets: impl IntoIterator<Item = crafter::Packet>) -> Self {
        Self {
            outputs: packets.into_iter().map(StepOutput::new).collect(),
            target: None,
            terminal: false,
            outcome: None,
            expects_reply: false,
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
    use super::{Step, StepGotoExt};

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
