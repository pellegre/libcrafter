//! Passive WPA/WPA2-Personal packet-stream transform.
//!
//! The WPA module is intentionally rooted in the wire transform pipeline. It is
//! designed to observe monitor-mode 802.11 packet records, keep handshake and
//! key state, and emit decrypted packet-shaped records without adding a second
//! sniffer API.
//!
//! The first complete decrypt path is WPA2-PSK CCMP-128. Unsupported ciphers,
//! unsupported AKMs, incomplete handshakes, MIC failures, replayed packet
//! numbers, and malformed protected frames remain inspectable through
//! [`WpaMetadata`] and [`WpaDecryptReason`].

mod ccmp;
mod config;
mod crypto;
mod metadata;
mod state;
mod transform;

pub use config::{WpaDecryptConfig, WpaNetwork};
pub use crypto::{derive_pmk, derive_ptk, PairwiseTransientKey, Pmk};
pub use metadata::{
    WpaAkm, WpaCipher, WpaCredentialStatus, WpaDecryptReason, WpaHandshakeStatus, WpaKeyKind,
    WpaMetadata,
};
pub use transform::WpaDecrypt;
