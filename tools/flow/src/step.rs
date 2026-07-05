//! Transition outcomes for protocol flows.

/// Instruction returned by a transition after it fires.
#[derive(Debug, Clone)]
pub struct Step {
    /// Packet to send or emit before applying the state change.
    pub outgoing: Option<crafter::Packet>,
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
        Self {
            outgoing: Some(packet),
            target: None,
            terminal: false,
            outcome: None,
            expects_reply: true,
        }
    }

    /// Emit a packet without expecting a direct reply.
    pub fn emit(packet: crafter::Packet) -> Self {
        Self {
            outgoing: Some(packet),
            target: None,
            terminal: false,
            outcome: None,
            expects_reply: false,
        }
    }

    /// Move to another state without sending a packet.
    pub fn goto(state: impl Into<String>) -> Self {
        Self {
            outgoing: None,
            target: Some(state.into()),
            terminal: false,
            outcome: None,
            expects_reply: false,
        }
    }

    /// Stay in the current state without sending a packet.
    pub fn stay() -> Self {
        Self {
            outgoing: None,
            target: None,
            terminal: false,
            outcome: None,
            expects_reply: false,
        }
    }

    /// Finish the flow successfully without a label.
    pub fn done() -> Self {
        Self {
            outgoing: None,
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

    /// Return the outgoing packet, if any.
    pub const fn outgoing(&self) -> Option<&crafter::Packet> {
        self.outgoing.as_ref()
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
