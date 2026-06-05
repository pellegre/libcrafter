//! Compatibility re-exports for the IPv6 protocol implementation.
//!
//! The IPv6 implementation lives in [`crate::protocols::ip::v6`]. This module
//! preserves the original `crate::protocols::ipv6` import path for downstream
//! callers.

pub use crate::protocols::ip::v6::*;
