//! Top-level protocol flow graph definitions.

use std::collections::BTreeMap;

use crate::{FlowState, Role};

/// A named state graph that a runner can execute for one participant role.
pub struct Flow {
    name: String,
    role: Role,
    initial: String,
    states: BTreeMap<String, FlowState>,
}

impl Flow {
    /// Create an initiator flow with no states and no initial state.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            role: Role::Initiator,
            initial: String::new(),
            states: BTreeMap::new(),
        }
    }

    /// Return this flow's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return this flow's role.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Return the initial state name.
    pub fn initial(&self) -> &str {
        &self.initial
    }

    /// Return the named state, if present.
    pub fn state(&self, name: &str) -> Option<&FlowState> {
        self.states.get(name)
    }

    /// Return the named state mutably, if present.
    pub fn state_mut(&mut self, name: &str) -> Option<&mut FlowState> {
        self.states.get_mut(name)
    }

    /// Return state names in deterministic order.
    pub fn state_names(&self) -> impl Iterator<Item = &str> {
        self.states.keys().map(String::as_str)
    }
}

/// Fluent builder methods for [`Flow`].
///
/// This is an extension trait because the builder method names intentionally
/// match read-only accessor names.
pub trait FlowBuilderExt {
    /// Set the participant role for this flow.
    fn role(self, role: Role) -> Flow;

    /// Insert a state, keyed by its name.
    fn state(self, state: FlowState) -> Flow;

    /// Set the initial state name.
    fn initial(self, name: impl Into<String>) -> Flow;
}

impl FlowBuilderExt for Flow {
    fn role(mut self, role: Role) -> Flow {
        self.role = role;
        self
    }

    fn state(mut self, state: FlowState) -> Flow {
        self.states.insert(state.name().to_string(), state);
        self
    }

    fn initial(mut self, name: impl Into<String>) -> Flow {
        self.initial = name.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::{Flow, FlowBuilderExt, FlowState, Role};

    #[test]
    fn flow_builder_tracks_role_initial_and_states() {
        let flow = Flow::new("dhcpv4-client")
            .role(Role::Initiator)
            .state(FlowState::new("Selecting"))
            .state(FlowState::new("Bound"))
            .initial("Selecting");

        assert_eq!(flow.name(), "dhcpv4-client");
        assert_eq!(Flow::role(&flow), Role::Initiator);
        assert_eq!(Flow::initial(&flow), "Selecting");
        assert!(Flow::state(&flow, "Selecting").is_some());
        assert!(Flow::state(&flow, "Bound").is_some());
    }
}
