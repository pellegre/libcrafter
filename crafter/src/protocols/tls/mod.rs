//! TLS packet-layer module skeleton.
//!
//! This module intentionally only defines the TLS module boundary. Later
//! source-backed steps add typed record, handshake, extension, and decode
//! behavior while preserving unknown or encrypted bytes as raw payloads.

pub mod alert;
pub mod constants;
pub mod content_type;
pub(crate) mod decode;
pub mod extension;
pub mod handshake;
pub mod record;
pub mod vectors;
pub mod version;

pub use alert::{TlsAlert, TlsAlertDescription, TlsAlertLevel, TLS_ALERT_LEN};
pub use content_type::TlsContentType;
pub use version::{TlsVersion, TlsVersionField};

#[cfg(test)]
mod tests;
