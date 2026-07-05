//! Stateful protocol-flow engine built on `crafter`.

pub mod bound;
pub mod binding;
pub mod context;
pub mod docaddr;
pub mod error;
pub mod matcher;
pub mod options;
pub mod prelude;
pub mod role;
pub mod step;
pub mod transition;

pub use bound::Bound;
pub use binding::{BindMode, BindSendClass, BindTarget, Binding};
pub use context::PacketContext;
pub use error::{FlowError, Result};
pub use matcher::{Matcher, PredicateMatcher};
pub use options::RunOptions;
pub use role::Role;
pub use step::{Step, StepGotoExt};
pub use transition::Transition;
