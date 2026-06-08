//! IPSec Security Association.
//!
//! A lightweight per-packet crypto context carrying the SPI, mode,
//! encryption/integrity algorithms, keys, salt, and ESN flag that drive
//! ESP/AH and IKEv2 SK crypto. It is not a policy database (SAD/SPD).
//! The `SecurityAssociation` value type and the seal/open crypto driver are
//! added by later steps; the algorithm-identifier enums live in `algorithms`.

mod algorithms;

pub use algorithms::{
    EncryptionAlgorithm, IntegrityAlgorithm, AUTH_AES_128_GMAC, AUTH_AES_XCBC_96,
    AUTH_HMAC_SHA1_96, AUTH_HMAC_SHA2_256_128, AUTH_HMAC_SHA2_384_192, AUTH_HMAC_SHA2_512_256,
    AUTH_NONE, ENCR_AES_CBC, ENCR_AES_CCM_8, ENCR_AES_CTR, ENCR_AES_GCM_16, ENCR_CHACHA20_POLY1305,
    ENCR_NULL,
};
