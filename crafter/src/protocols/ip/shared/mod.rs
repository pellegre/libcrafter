//! Version-neutral IP concepts.

pub mod traffic_class;

pub use traffic_class::{Dscp, Ecn};
pub(crate) use traffic_class::{DSCP_SHIFT, ECN_MASK};
