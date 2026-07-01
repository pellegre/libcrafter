//! TLS packet-layer module.
//!
//! Source-backed steps add typed record, handshake, extension, and codepoint
//! behavior while preserving unknown or encrypted bytes as raw payloads.

pub mod alert;
pub mod cipher_suite;
pub mod constants;
pub mod content_type;
pub(crate) mod decode;
pub mod extension;
pub mod handshake;
pub mod named_group;
pub mod record;
pub mod signature_scheme;
pub mod vectors;
pub mod version;

pub use alert::{TlsAlert, TlsAlertDescription, TlsAlertLevel, TLS_ALERT_LEN};
pub use cipher_suite::{TlsCipherSuite, TlsCipherSuiteList};
pub use content_type::TlsContentType;
pub use extension::{
    TlsExtensionType, TlsRawExtension, TLS_EXTENSION_HEADER_LEN, TLS_EXTENSION_LENGTH_LEN,
    TLS_EXTENSION_TYPE_LEN,
};
pub use named_group::{TlsNamedGroup, TlsNamedGroupList};
pub use signature_scheme::{TlsSignatureScheme, TlsSignatureSchemeList};
pub use version::{TlsVersion, TlsVersionField};

#[cfg(test)]
mod tests;
