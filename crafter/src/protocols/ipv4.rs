//! Compatibility re-exports for the IPv4 protocol implementation.
//!
//! The canonical IPv4 module lives at [`crate::protocols::ip::v4`]. This
//! module keeps the original `crate::protocols::ipv4` public path working for
//! existing callers.

pub use crate::protocols::ip::v4::*;
