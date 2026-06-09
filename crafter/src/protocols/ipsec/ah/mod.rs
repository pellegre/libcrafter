//! Authentication Header (AH, RFC 4302).
//!
//! The `Ah` layer models the fixed AH header — Next Header, Payload Len,
//! Reserved, SPI, Sequence Number — and the variable-length Integrity Check
//! Value. A caller either attaches a [`SecurityAssociation`] so `compile()`
//! authenticates the canonicalized immutable IP fields, the AH header (with the
//! ICV field zeroed), and the upper-layer data, or pins an explicit `icv` for
//! deterministic or deliberately malformed output. AH composes with `/` over
//! IPv4 and IPv6 (IP protocol 51).
//!
//! This step defines only the layer struct, its constants, and accessors. The
//! builder, the immutable-field canonicalization, the `compile()` crypto path,
//! the `Layer` impl, and the opaque/SA-driven verify decode path are added by
//! later steps.

pub mod header;

use crate::field::Field;
use crate::protocols::ipsec::sa::SecurityAssociation;

/// Default SPI assigned when the caller does not set one.
///
/// Mirrors the ESP builder default; the first SA in a manifest commonly uses a
/// low SPI, and a deterministic default keeps builder output reproducible.
const DEFAULT_AH_SPI: u32 = 0x0000_0001;

/// Default Sequence Number (RFC 4302 §2.5: the first packet sent on an SA uses
/// sequence number 1).
const DEFAULT_AH_SEQUENCE: u32 = 1;

/// Default Reserved field value (RFC 4302 §2.3: set to zero on transmission).
const DEFAULT_AH_RESERVED: u16 = 0;

/// Default high-order Extended Sequence Number word (RFC 4302 §2.5.1: the
/// 64-bit ESN counter starts at 1, so its high 32 bits are 0).
const DEFAULT_AH_HIGH_SEQUENCE: u32 = 0;

/// Authentication Header (RFC 4302) layer model.
///
/// The header is Next Header, Payload Len, Reserved, SPI, and Sequence Number,
/// followed by the variable-length Integrity Check Value. When a
/// [`SecurityAssociation`] is attached, `compile()` (a later step) computes the
/// ICV over the canonicalized immutable IP fields, the AH header with the ICV
/// field zeroed, and the upper-layer data (RFC 4302 §3.3). The `icv` and
/// `payload_len` / `reserved` overrides pin those values for deterministic or
/// deliberately malformed output. AH only authenticates — it never encrypts —
/// so the following layers are emitted in the clear.
#[derive(Debug, Clone)]
pub struct Ah {
    /// Next Header: the protocol of the data following the AH (RFC 4302 §2.1).
    /// Auto-filled from the following layer unless set.
    next_header: Field<u8>,
    /// Payload Len: AH length in 32-bit words minus 2 (RFC 4302 §2.2).
    /// Auto-filled from the ICV length unless overridden for malformed tests.
    payload_len: Field<u8>,
    /// Reserved: zero on transmission (RFC 4302 §2.3); overridable for
    /// deliberately malformed output.
    reserved: Field<u16>,
    /// Security Parameters Index identifying the SA on the wire (RFC 4302 §2.4).
    spi: Field<u32>,
    /// Per-datagram Sequence Number (RFC 4302 §2.5).
    sequence: Field<u32>,
    /// Explicit Integrity Check Value override (RFC 4302 §2.6); otherwise the
    /// ICV is computed by `compile()` from the attached SA.
    icv: Field<Vec<u8>>,
    /// Crypto context driving the ICV computation/verification; `None` keeps
    /// the ICV opaque (decode / no-crypto).
    sa: Option<SecurityAssociation>,
    /// High-order 32 bits of the 64-bit Extended Sequence Number (RFC 4302
    /// §2.5.1). When the SA enables ESN, this word participates in the ICV
    /// computation but is never transmitted; only the low 32-bit `sequence`
    /// appears on the wire. Defaults to 0.
    high_sequence: Field<u32>,
}

impl Ah {
    /// Create an AH layer with deterministic packet-builder defaults.
    ///
    /// The SPI is defaulted to `0x0000_0001` and the Sequence Number to `1`
    /// (RFC 4302 §2.5); the Reserved field defaults to 0 and the ESN high word
    /// to 0. Every other field is unset, no SA is attached, and there is no
    /// explicit ICV. `compile()` (a later step) fills the unset fields; any
    /// value the caller sets afterwards is preserved untouched.
    pub fn new() -> Self {
        Self {
            next_header: Field::unset(),
            payload_len: Field::unset(),
            reserved: Field::defaulted(DEFAULT_AH_RESERVED),
            spi: Field::defaulted(DEFAULT_AH_SPI),
            sequence: Field::defaulted(DEFAULT_AH_SEQUENCE),
            icv: Field::unset(),
            sa: None,
            high_sequence: Field::defaulted(DEFAULT_AH_HIGH_SEQUENCE),
        }
    }

    /// Create an AH layer with an attached [`SecurityAssociation`].
    ///
    /// Equivalent to `Ah::new()` with the SA attached: the SA is the integrity
    /// context the ICV computation (a later step) consumes.
    pub fn secured(sa: SecurityAssociation) -> Self {
        let mut ah = Self::new();
        ah.sa = Some(sa);
        ah
    }

    /// Stored Next Header value, when explicit or decoded.
    pub fn next_header_value(&self) -> Option<u8> {
        self.next_header.value().copied()
    }

    /// Stored Payload Len value, when explicit or decoded.
    pub fn payload_len_value(&self) -> Option<u8> {
        self.payload_len.value().copied()
    }

    /// Stored Reserved field value (defaults to 0).
    pub fn reserved_value(&self) -> Option<u16> {
        self.reserved.value().copied()
    }

    /// Stored SPI value, when explicit or decoded.
    pub fn spi_value(&self) -> Option<u32> {
        self.spi.value().copied()
    }

    /// Stored Sequence Number value, when explicit or decoded.
    pub fn sequence_value(&self) -> Option<u32> {
        self.sequence.value().copied()
    }

    /// Stored high-order Extended Sequence Number word (RFC 4302 §2.5.1).
    ///
    /// Defaults to 0; only participates in the ICV when the SA enables ESN.
    pub fn high_sequence_value(&self) -> Option<u32> {
        self.high_sequence.value().copied()
    }

    /// Explicit ICV override bytes, when set or decoded.
    pub fn icv_value(&self) -> Option<&[u8]> {
        self.icv.value().map(Vec::as_slice)
    }

    /// The attached Security Association, when present.
    pub fn attached_security_association(&self) -> Option<&SecurityAssociation> {
        self.sa.as_ref()
    }
}

impl Default for Ah {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldState;
    use crate::protocols::ipsec::sa::{EncryptionAlgorithm, SecurityAssociation};

    #[test]
    fn new_defaults_spi_sequence_reserved_and_high_sequence() {
        let ah = Ah::new();

        // SPI and Sequence are library defaults, not caller-set.
        assert_eq!(ah.spi.state(), FieldState::Defaulted);
        assert_eq!(ah.spi_value(), Some(DEFAULT_AH_SPI));
        assert_eq!(ah.sequence.state(), FieldState::Defaulted);
        assert_eq!(ah.sequence_value(), Some(DEFAULT_AH_SEQUENCE));

        // Reserved defaults to 0 (RFC 4302 §2.3); ESN high word to 0 (§2.5.1).
        assert_eq!(ah.reserved.state(), FieldState::Defaulted);
        assert_eq!(ah.reserved_value(), Some(DEFAULT_AH_RESERVED));
        assert_eq!(ah.high_sequence.state(), FieldState::Defaulted);
        assert_eq!(ah.high_sequence_value(), Some(DEFAULT_AH_HIGH_SEQUENCE));

        // Next Header, Payload Len, and ICV are unset; no SA attached.
        assert_eq!(ah.next_header.state(), FieldState::Unset);
        assert_eq!(ah.payload_len.state(), FieldState::Unset);
        assert_eq!(ah.icv.state(), FieldState::Unset);
        assert!(ah.next_header_value().is_none());
        assert!(ah.payload_len_value().is_none());
        assert!(ah.icv_value().is_none());
        assert!(ah.attached_security_association().is_none());
    }

    #[test]
    fn default_matches_new() {
        let ah = Ah::default();
        assert_eq!(ah.spi_value(), Some(DEFAULT_AH_SPI));
        assert_eq!(ah.sequence_value(), Some(DEFAULT_AH_SEQUENCE));
        assert!(ah.attached_security_association().is_none());
    }

    #[test]
    fn secured_attaches_the_sa() {
        let sa = SecurityAssociation::new(0x0000_2000).integrity(
            crate::protocols::ipsec::sa::IntegrityAlgorithm::HmacSha2_256_128,
            vec![0x33u8; 32],
        );
        let ah = Ah::secured(sa.clone());

        assert_eq!(ah.attached_security_association(), Some(&sa));
        // secured() leaves the SPI/Sequence defaults in place.
        assert_eq!(ah.spi.state(), FieldState::Defaulted);
        assert_eq!(ah.sequence.state(), FieldState::Defaulted);
    }

    #[test]
    fn fixed_header_length_constant_is_twelve() {
        // Next Header(1) + Payload Len(1) + Reserved(2) + SPI(4) + Seq(4) = 12.
        assert_eq!(header::AH_FIXED_LEN, 12);
        assert_eq!(
            header::AH_NEXT_HEADER_LEN
                + header::AH_PAYLOAD_LEN_FIELD_LEN
                + header::AH_RESERVED_LEN
                + header::AH_SPI_LEN
                + header::AH_SEQUENCE_LEN,
            header::AH_FIXED_LEN
        );

        // Reference the AesGcm16 algorithm only to keep the crypto import live
        // and confirm the SA surface is reachable from this module.
        let _ = EncryptionAlgorithm::AesGcm16;
    }
}
