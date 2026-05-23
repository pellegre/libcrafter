//! Helpers for disposable live packet test environments.
//!
//! The alpha keeps provider orchestration in repository tools, not in this
//! crate. This crate is reserved for shared types and helpers that live tests
//! can use without coupling the core packet model to any cloud provider.

#![forbid(unsafe_code)]

pub mod artifact {}
pub mod provider {}
pub mod validation {}
