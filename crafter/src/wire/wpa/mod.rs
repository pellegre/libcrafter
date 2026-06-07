//! Passive WPA/WPA2-Personal packet-stream transform scaffolding.
//!
//! The WPA module is intentionally rooted in the wire transform pipeline. It is
//! designed to observe monitor-mode 802.11 packet records, keep handshake and
//! key state, and later emit decrypted packet-shaped records without adding a
//! second sniffer API.

mod ccmp;
mod config;
mod crypto;
mod metadata;
mod state;
mod transform;

pub use config::{WpaDecryptConfig, WpaNetwork};
pub use metadata::{
    WpaAkm, WpaCipher, WpaCredentialStatus, WpaDecryptReason, WpaHandshakeStatus, WpaKeyKind,
    WpaMetadata,
};
pub use transform::WpaDecrypt;
