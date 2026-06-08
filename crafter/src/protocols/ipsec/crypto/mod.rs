//! IPSec cryptographic transforms.
//!
//! Integrity (HMAC-SHA family, AES-XCBC-MAC, AES-GMAC), block/stream ciphers
//! with separate integrity (AES-CBC, AES-CTR, NULL), and AEAD suites
//! (AES-GCM, AES-CCM, ChaCha20-Poly1305), each verified against an RFC
//! Known-Answer Test before use. Submodules are added by later steps.

pub mod cipher;
pub mod integrity;

pub use cipher::CipherTransform;
pub use integrity::IntegrityTransform;
