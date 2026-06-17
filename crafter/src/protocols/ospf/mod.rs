//! OSPF (Open Shortest Path First) protocol support.
//!
//! This module hosts the OSPFv2 (RFC 2328) wire-level layer and, in later
//! blocks, its packet bodies, link-state advertisements, authentication, and a
//! base OSPFv3 layer. OSPF runs directly over IP (protocol 89).
//!
//! This is the bootstrap block: it lays down the module skeleton and the
//! codepoint constants. The typed layer, decode entrypoint, and curated
//! exports are wired in by subsequent steps.

#[allow(unused_imports)]
pub mod constants;

#[allow(unused_imports)]
pub use constants::*;
