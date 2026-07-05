//! Participant role for a protocol flow.

/// Selects which side of a conversation the engine drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Acts first, such as a client starting a conversation.
    Initiator,
    /// Waits for another party to start, such as a server or rogue responder.
    Responder,
    /// Observes traffic and injects packets off-path; it may also act first via a timer.
    Injector,
}

impl Role {
    /// Returns whether the role waits for observed traffic before acting by default.
    ///
    /// `Injector` returns true for reactive use, though an injector flow may also
    /// act first through a timer-driven transition.
    pub const fn waits_first(self) -> bool {
        match self {
            Self::Initiator => false,
            Self::Responder | Self::Injector => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Role;

    #[test]
    fn role_variants_are_distinct_and_waits_first_matches_semantics() {
        assert_ne!(Role::Initiator, Role::Responder);
        assert_ne!(Role::Initiator, Role::Injector);
        assert_ne!(Role::Responder, Role::Injector);

        assert!(!Role::Initiator.waits_first());
        assert!(Role::Responder.waits_first());
        assert!(Role::Injector.waits_first());
    }
}
