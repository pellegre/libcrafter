//! Encapsulating Security Payload (ESP, RFC 4303).
//!
//! The `Esp` layer models the SPI/sequence header and the encrypted trailer
//! (pad | pad length | next header) with the Integrity Check Value appended
//! after the ciphertext. A caller either attaches a [`SecurityAssociation`] to
//! encrypt the following layers, or carries pre-encrypted bytes opaquely when
//! no SA is supplied. ESP composes with `/` over IPv4 and IPv6 (IP protocol
//! 50). The `Layer` impl, builder, crypto compile, and decode paths are added
//! by later steps.

pub mod header;

use crate::field::Field;
use crate::protocols::ipsec::sa::SecurityAssociation;

/// Encapsulating Security Payload header, trailer, and crypto context.
///
/// The unencrypted header is the SPI and Sequence Number. When a
/// [`SecurityAssociation`] is attached, `compile()` encrypts the following
/// layers, builds the RFC 4303 §2.4 trailer, and appends the ICV; the `pad`,
/// `iv`, and `icv` overrides pin those values for deterministic or deliberately
/// malformed output. When no SA is present, `opaque` carries pre-encrypted
/// body bytes verbatim so decode/re-encode is byte-exact.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Esp {
    /// Security Parameters Index identifying the SA on the wire.
    spi: Field<u32>,
    /// Per-datagram Sequence Number (RFC 4303 §2.2).
    sequence: Field<u32>,
    /// ESP trailer Next Header (auto-filled from the inner layer).
    next_header: Field<u8>,
    /// Explicit pad override; otherwise RFC 4303 §2.4 padding is computed.
    pad: Field<Vec<u8>>,
    /// Explicit IV/nonce for deterministic ciphertext.
    iv: Field<Vec<u8>>,
    /// Explicit ICV override.
    icv: Field<Vec<u8>>,
    /// Crypto context driving seal/open; `None` keeps the body opaque.
    sa: Option<SecurityAssociation>,
    /// Pre-encrypted body when no SA is supplied (decode / no-crypto).
    opaque: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl Esp {
    /// Stored SPI value, when explicit or decoded.
    pub fn spi_value(&self) -> Option<u32> {
        self.spi.value().copied()
    }

    /// Stored Sequence Number value, when explicit or decoded.
    pub fn sequence_value(&self) -> Option<u32> {
        self.sequence.value().copied()
    }

    /// Stored ESP trailer Next Header value, when explicit or decoded.
    pub fn next_header_value(&self) -> Option<u8> {
        self.next_header.value().copied()
    }

    /// Explicit pad override bytes, when set.
    pub fn pad_value(&self) -> Option<&[u8]> {
        self.pad.value().map(Vec::as_slice)
    }

    /// Explicit IV/nonce override bytes, when set.
    pub fn iv_value(&self) -> Option<&[u8]> {
        self.iv.value().map(Vec::as_slice)
    }

    /// Explicit ICV override bytes, when set.
    pub fn icv_value(&self) -> Option<&[u8]> {
        self.icv.value().map(Vec::as_slice)
    }

    /// The attached Security Association, when present.
    pub fn security_association(&self) -> Option<&SecurityAssociation> {
        self.sa.as_ref()
    }

    /// The opaque pre-encrypted body bytes, when present.
    pub fn opaque_body(&self) -> Option<&[u8]> {
        self.opaque.as_deref()
    }
}
