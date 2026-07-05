//! Stateful protocol-flow engine built on `crafter`.

pub mod bound;
pub mod binding;
pub mod capture;
pub mod context;
pub mod docaddr;
pub mod error;
pub mod flow;
pub mod matcher;
pub mod mutator;
pub mod options;
pub mod prelude;
pub mod role;
pub mod state;
pub mod step;
pub mod transition;

pub use bound::Bound;
pub use binding::{BindMode, BindSendClass, BindTarget, Binding};
pub use capture::{CaptureSource, MemoryCaptureSource};
pub use context::PacketContext;
pub use error::{FlowError, Result};
pub use flow::{Flow, FlowBuilderExt};
pub use matcher::{Matcher, PredicateMatcher};
pub use mutator::{FnMutator, Identity, Mutator};
pub use options::RunOptions;
pub use role::Role;
pub use state::FlowState;
pub use step::{Step, StepGotoExt};
pub use transition::Transition;
