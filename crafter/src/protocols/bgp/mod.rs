//! Border Gateway Protocol version 4 (BGP-4, RFC 4271) support.
//!
//! This module provides packet-layer construction and decoding for BGP-4
//! messages. Types and constants are added in subsequent steps; for now this is
//! an empty-but-compiling scaffold that mirrors the DNS/DHCP module layout.

mod constants;

pub mod attribute;
pub mod capability;
pub mod decode;
pub mod message;

// `constants` is empty until later steps populate it; allow the glob re-export
// now so the scaffold compiles warning-free.
#[allow(unused_imports)]
pub use constants::*;
