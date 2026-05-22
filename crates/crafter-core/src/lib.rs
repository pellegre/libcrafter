//! Core packet model, protocol encoding, protocol decoding, checksums, and formatting.

#![forbid(unsafe_code)]

pub mod checksum;
pub mod endian;
pub mod error;
pub mod field;
pub mod mac;
pub mod packet {}
pub mod protocols {}

pub use error::{CrafterError, Result};
pub use field::{Field, FieldState};
pub use mac::MacAddr;
