//! TLS packet-layer module skeleton.
//!
//! This module intentionally only defines the TLS module boundary. Later
//! source-backed steps add typed record, handshake, extension, and decode
//! behavior while preserving unknown or encrypted bytes as raw payloads.

pub mod alert;
pub mod constants;
pub(crate) mod decode;
pub mod extension;
pub mod handshake;
pub mod record;
pub mod vectors;

#[cfg(test)]
mod tests;
