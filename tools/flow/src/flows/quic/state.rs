//! Initial-only QUIC lifecycle labels.

/// Client state after an Initial has been emitted.
pub const INITIAL_SENT: &str = "InitialSent";
/// Server state waiting for an Initial datagram.
pub const LISTEN: &str = "Listen";
/// Client state after a valid Retry has been observed.
pub const RETRY_RECEIVED: &str = "RetryReceived";
/// State after a protected peer Initial has been inspected.
pub const INITIAL_OBSERVED: &str = "InitialObserved";
/// Terminal Initial-only state.
pub const CLOSED: &str = "Closed";

/// Inspectable lifecycle for an Initial-only QUIC exchange.
///
/// This lifecycle deliberately has no `Established` variant: observing and
/// protecting Initial packets does not complete an authenticated connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicInitialState {
    /// The client emitted an Initial packet.
    InitialSent,
    /// The server is waiting for an Initial packet.
    Listen,
    /// The client accepted a valid Retry packet.
    RetryReceived,
    /// A protected peer Initial was inspected.
    InitialObserved,
    /// The bounded Initial-only exchange ended.
    Closed,
}

impl QuicInitialState {
    /// Return the stable flow-state label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InitialSent => INITIAL_SENT,
            Self::Listen => LISTEN,
            Self::RetryReceived => RETRY_RECEIVED,
            Self::InitialObserved => INITIAL_OBSERVED,
            Self::Closed => CLOSED,
        }
    }
}

impl std::fmt::Display for QuicInitialState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}
