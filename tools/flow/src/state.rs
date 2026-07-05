//! Named states for protocol flow graphs.

use crate::{PacketContext, Result, Step, Transition};

type EntryHandler = dyn FnMut(&mut PacketContext) -> Result<Step>;

/// A named flow state with optional entry behavior and ordered transitions.
pub struct FlowState {
    name: String,
    on_entry: Option<Box<EntryHandler>>,
    entry_target_hints: Option<Vec<String>>,
    entry_terminal_path: bool,
    transitions: Vec<Transition>,
}

impl FlowState {
    /// Create a state with no on-entry action and no transitions.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            on_entry: None,
            entry_target_hints: None,
            entry_terminal_path: false,
            transitions: Vec::new(),
        }
    }

    /// Return this state's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the state's ordered transitions.
    pub fn transitions(&self) -> &[Transition] {
        &self.transitions
    }

    /// Return the state's ordered transitions mutably.
    pub fn transitions_mut(&mut self) -> &mut [Transition] {
        &mut self.transitions
    }

    /// Set the action run when entering this state.
    pub fn on_entry<H>(mut self, handler: H) -> Self
    where
        H: FnMut(&mut PacketContext) -> Result<Step> + 'static,
    {
        self.on_entry = Some(Box::new(handler));
        self
    }

    /// Declare the state names this state's entry handler may target.
    pub fn entry_targets<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.entry_target_hints = Some(names.into_iter().map(Into::into).collect());
        self
    }

    /// Declare that this state's entry handler may end the flow with `Step::done`.
    pub fn entry_terminal(mut self) -> Self {
        self.entry_terminal_path = true;
        self
    }

    /// Add a transition to this state.
    pub fn on(mut self, transition: Transition) -> Self {
        self.transitions.push(transition);
        self
    }

    /// Add a transition to this state.
    pub fn transition(self, transition: Transition) -> Self {
        self.on(transition)
    }

    /// Return declared entry target state names for static graph validation.
    pub fn declared_entry_targets(&self) -> &[String] {
        self.entry_target_hints.as_deref().unwrap_or(&[])
    }

    /// Return true when this state has explicit entry target hints.
    pub fn has_entry_target_hints(&self) -> bool {
        self.entry_target_hints.is_some()
    }

    /// Return true when this state's entry handler declares a terminal path.
    pub fn declares_entry_terminal_path(&self) -> bool {
        self.entry_terminal_path
    }

    /// Return true when this state has an entry handler.
    pub fn has_entry(&self) -> bool {
        self.on_entry.is_some()
    }

    /// Run the on-entry action, if this state has one.
    pub fn run_entry(&mut self, ctx: &mut PacketContext) -> Result<Option<Step>> {
        match self.on_entry.as_mut() {
            Some(handler) => handler(ctx).map(Some),
            None => Ok(None),
        }
    }

    /// Return the first transition whose matcher accepts `packet`.
    pub fn find_transition(
        &mut self,
        packet: &crafter::Packet,
        ctx: &PacketContext,
    ) -> Option<&mut Transition> {
        self.transitions
            .iter_mut()
            .find(|transition| transition.matches(packet, ctx))
    }
}

#[cfg(test)]
mod tests {
    use crate::{FlowState, PacketContext, PredicateMatcher, Step, Transition};

    #[test]
    fn state_entry_action_returns_step() {
        let mut state = FlowState::new("Selecting").on_entry(|ctx| {
            ctx.set_transaction_id(0x1234_5678);
            Ok(Step::goto("Waiting"))
        });
        let mut context = PacketContext::new();

        let step = state
            .run_entry(&mut context)
            .expect("entry action should run")
            .expect("entry action should return a step");

        assert_eq!(state.name(), "Selecting");
        assert_eq!(context.get_transaction_id(), Some(0x1234_5678));
        assert_eq!(step.target(), Some("Waiting"));
    }

    #[test]
    fn state_returns_first_matching_transition() {
        let first = Transition::on(
            PredicateMatcher::new("first match", |_packet, _ctx| true),
            |_packet, _ctx| Ok(Step::goto("first")),
        );
        let second = Transition::on(
            PredicateMatcher::new("second match", |_packet, _ctx| true),
            |_packet, _ctx| Ok(Step::goto("second")),
        );
        let mut state = FlowState::new("Waiting").on(first).transition(second);
        let packet = crafter::Packet::decode_raw([0xde, 0xad, 0xbe, 0xef])
            .expect("raw packet should decode");
        let mut context = PacketContext::new();

        let transition = state
            .find_transition(&packet, &context)
            .expect("a transition should match");
        let step = transition
            .fire(&packet, &mut context)
            .expect("transition should fire");

        assert_eq!(state.transitions().len(), 2);
        assert_eq!(step.target(), Some("first"));
    }
}
