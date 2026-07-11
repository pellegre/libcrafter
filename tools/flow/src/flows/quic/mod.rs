//! Bounded QUIC flow templates.
//!
//! Initial-only configuration and lifecycle types live here without entering
//! the broad TCP-oriented prelude. Flow entrypoints are added under explicit
//! `quic_*` names once their state graphs exist.

mod initial;
mod state;

pub use initial::{
    QuicInitialBounds, QuicInitialClientConfig, QuicInitialRetryPolicy, QuicInitialServerConfig,
    QuicInitialVersionPolicy,
};
pub use state::{QuicInitialState, CLOSED, INITIAL_OBSERVED, INITIAL_SENT, LISTEN, RETRY_RECEIVED};
