//! Stateful protocol-flow engine built on `crafter`.

pub mod binding;
pub mod bound;
pub mod capture;
pub mod context;
pub mod conversation;
pub mod docaddr;
pub mod error;
pub mod flow;
pub mod flows;
pub mod matcher;
pub mod mutator;
pub mod netns;
pub mod options;
pub mod prelude;
mod quic_endpoint;
pub mod report;
pub mod role;
pub mod runner;
pub mod state;
pub mod step;
pub mod tool;
pub mod transition;

pub use binding::{BindMode, BindSendClass, BindTarget, Binding};
pub use bound::Bound;
pub use capture::{
    derive_capture_filter, derive_capture_filter_for_packets, CaptureSource, MemoryCaptureSource,
    PcapCaptureSource,
};
pub use context::PacketContext;
pub use conversation::Conversation;
pub use error::{FlowError, Result};
pub use flow::{Flow, FlowBuilderExt};
pub use matcher::{Matcher, PredicateMatcher};
pub use mutator::{FnMutator, Identity, Mutator};
pub use options::{RetransmitPolicy, RunOptions, SendRepeat};
pub use quic_endpoint::{
    QuicEndpointAddresses, QuicEndpointErrorCategory, QuicPeerConfig, QuicSyntheticIdentity,
    QuicTransportLimits,
};
pub use report::{FlowOutcome, FlowReport, RecoveryMetrics};
pub use role::Role;
pub use runner::Runner;
pub use state::FlowState;
pub use step::{Step, StepGotoExt};
pub use tool::{run_tool, ToolRun, ToolRunReport};
pub use transition::Transition;
