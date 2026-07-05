//! Stateful protocol-flow engine built on `crafter`.

pub mod docaddr;
pub mod error;
pub mod prelude;
pub mod role;

pub use error::{FlowError, Result};
pub use role::Role;
