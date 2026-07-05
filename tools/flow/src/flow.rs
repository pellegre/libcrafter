//! Top-level protocol flow graph definitions.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::{FlowError, FlowState, Result, Role};

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

    /// Return a compact one-line description of this flow graph.
    pub fn summary(&self) -> String {
        format!(
            "Flow '{}' ({:?}, {} states, initial '{}')",
            self.name,
            self.role,
            self.states.len(),
            self.initial
        )
    }

    /// Return a multi-line inspectable view of states and transitions.
    pub fn show(&self) -> String {
        let mut output = String::new();

        let _ = writeln!(output, "Flow '{}'", self.name);
        let _ = writeln!(output, "  role: {:?}", self.role);
        let _ = writeln!(output, "  initial: {}", self.initial);
        let _ = writeln!(output, "  states:");

        for state in self.states.values() {
            let mut markers = Vec::new();
            if state.name() == self.initial {
                markers.push("initial");
            }
            if state.declares_entry_terminal_path() {
                markers.push("terminal");
            }

            if markers.is_empty() {
                let _ = writeln!(output, "    - {}", state.name());
            } else {
                let _ = writeln!(output, "    - {} [{}]", state.name(), markers.join(", "));
            }

            let entry = if state.has_entry() { "present" } else { "none" };
            let entry_description = state
                .entry_description_text()
                .map(|description| format!(" ({description})"))
                .unwrap_or_default();
            let _ = writeln!(
                output,
                "      entry: {}{}{}{}",
                entry,
                entry_description,
                self.format_declared_targets(state.declared_entry_targets()),
                if state.declares_entry_terminal_path() {
                    " [terminal]"
                } else {
                    ""
                }
            );

            if state.transitions().is_empty() {
                let _ = writeln!(output, "      transitions: none");
            } else {
                let _ = writeln!(output, "      transitions:");
                for transition in state.transitions() {
                    let _ = write!(
                        output,
                        "        - {}{}",
                        transition.describe(),
                        self.format_declared_targets(transition.declared_targets())
                    );
                    if transition.declares_terminal_path() {
                        output.push_str(" [terminal]");
                    }
                    output.push('\n');
                }
            }
        }

        output
    }

    /// Validate the statically knowable shape of this flow graph.
    ///
    /// Handler closures reach terminality at run time by returning
    /// [`Step::done`](crate::Step::done). Validation checks explicit terminal
    /// hints and validates any declared target state names without executing
    /// those handlers.
    pub fn validate(&self) -> Result<()> {
        if self.states.is_empty() {
            return Err(FlowError::Build(format!(
                "flow '{}' has no states",
                self.name
            )));
        }

        if self.initial.is_empty() {
            return Err(FlowError::Build(format!(
                "flow '{}' has no initial state",
                self.name
            )));
        }

        if !self.states.contains_key(&self.initial) {
            return Err(FlowError::Build(format!(
                "flow '{}' initial state '{}' does not exist",
                self.name, self.initial
            )));
        }

        self.validate_declared_targets()?;

        if !self.has_terminal_path_declaration() && !self.has_dynamic_terminal_candidate() {
            return Err(FlowError::Build(format!(
                "flow '{}' declares no terminal path; mark handlers that can return Step::done with terminal hints",
                self.name
            )));
        }

        Ok(())
    }

    fn validate_declared_targets(&self) -> Result<()> {
        for state in self.states.values() {
            for target in state.declared_entry_targets() {
                self.validate_target(target, format!("state '{}' entry handler", state.name()))?;
            }

            for transition in state.transitions() {
                for target in transition.declared_targets() {
                    self.validate_target(
                        target,
                        format!(
                            "state '{}' transition '{}'",
                            state.name(),
                            transition.describe()
                        ),
                    )?;
                }
            }
        }

        Ok(())
    }

    fn validate_target(&self, target: &str, origin: String) -> Result<()> {
        if self.states.contains_key(target) {
            return Ok(());
        }

        Err(FlowError::Build(format!(
            "flow '{}' {} declares missing target state '{}'",
            self.name, origin, target
        )))
    }

    fn has_terminal_path_declaration(&self) -> bool {
        self.states.values().any(|state| {
            state.declares_entry_terminal_path()
                || state
                    .transitions()
                    .iter()
                    .any(|transition| transition.declares_terminal_path())
        })
    }

    fn has_dynamic_terminal_candidate(&self) -> bool {
        self.states.values().any(|state| {
            (state.has_entry()
                && !state.has_entry_target_hints()
                && !state.declares_entry_terminal_path())
                || state.transitions().iter().any(|transition| {
                    !transition.has_target_hints() && !transition.declares_terminal_path()
                })
        })
    }

    fn format_declared_targets(&self, targets: &[String]) -> String {
        if targets.is_empty() {
            return String::new();
        }

        let rendered = targets
            .iter()
            .map(|target| {
                if self
                    .states
                    .get(target)
                    .map_or(false, FlowState::declares_entry_terminal_path)
                {
                    format!("{target} [terminal]")
                } else {
                    target.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");

        format!(" -> {rendered}")
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
    use crate::{
        Flow, FlowBuilderExt, FlowError, FlowState, PredicateMatcher, Role, Step, Transition,
    };

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

    #[test]
    fn validate_rejects_missing_initial_state() {
        let flow = Flow::new("bad-initial")
            .state(terminal_state("Ready"))
            .initial("Missing");

        let error = flow
            .validate()
            .expect_err("missing initial state should fail validation");

        assert_build_error_contains(error, "initial state 'Missing' does not exist");
    }

    #[test]
    fn validate_rejects_missing_transition_target_hint() {
        let transition = Transition::on(
            PredicateMatcher::new("any packet", |_packet, _ctx| true),
            |_packet, _ctx| Ok(Step::goto("Missing")),
        )
        .targets(["Missing"])
        .terminal();
        let flow = Flow::new("bad-target")
            .state(FlowState::new("Waiting").on(transition))
            .initial("Waiting");

        let error = flow
            .validate()
            .expect_err("missing transition target should fail validation");

        assert_build_error_contains(error, "declares missing target state 'Missing'");
    }

    #[test]
    fn validate_accepts_well_formed_flow() {
        let transition = Transition::on(
            PredicateMatcher::new("any packet", |_packet, _ctx| true),
            |_packet, _ctx| Ok(Step::goto("Done")),
        )
        .targets(["Done"]);
        let flow = Flow::new("well-formed")
            .state(FlowState::new("Waiting").on(transition))
            .state(terminal_state("Done"))
            .initial("Waiting");

        flow.validate()
            .expect("well-formed flow should pass validation");
    }

    #[test]
    fn summary_includes_name_role_state_count_and_initial() {
        let flow = two_state_flow();
        let summary = flow.summary();

        assert!(summary.contains("two-state"));
        assert!(summary.contains("Responder"));
        assert!(summary.contains("2 states"));
        assert!(summary.contains("Waiting"));
    }

    #[test]
    fn summary_show_lists_states_and_transition_description() {
        let flow = two_state_flow();
        let show = flow.show();

        assert!(show.contains("Waiting"));
        assert!(show.contains("Done"));
        assert!(show.contains("any packet"));
    }

    fn two_state_flow() -> Flow {
        let transition = Transition::on(
            PredicateMatcher::new("any packet", |_packet, _ctx| true),
            |_packet, _ctx| Ok(Step::goto("Done")),
        )
        .targets(["Done"]);

        Flow::new("two-state")
            .role(Role::Responder)
            .state(FlowState::new("Waiting").on(transition))
            .state(terminal_state("Done"))
            .initial("Waiting")
    }

    fn terminal_state(name: &str) -> FlowState {
        FlowState::new(name)
            .on_entry(|_ctx| Ok(Step::done()))
            .entry_terminal()
    }

    fn assert_build_error_contains(error: FlowError, expected: &str) {
        match error {
            FlowError::Build(message) => assert!(
                message.contains(expected),
                "expected build error containing '{expected}', got '{message}'"
            ),
            other => panic!("expected build error containing '{expected}', got {other:?}"),
        }
    }
}
