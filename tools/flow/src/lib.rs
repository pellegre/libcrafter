//! Stateful protocol-flow engine built on `crafter`.

pub mod bound;
pub mod binding;
pub mod docaddr;
pub mod error;
pub mod options;
pub mod prelude;
pub mod role;

pub use bound::Bound;
pub use binding::{BindMode, BindSendClass, BindTarget, Binding};
pub use error::{FlowError, Result};
pub use options::RunOptions;
pub use role::Role;
