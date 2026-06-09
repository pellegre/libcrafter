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

/// Default SPI assigned by [`Esp::new`] when the caller does not set one.
const DEFAULT_ESP_SPI: u32 = 0x0000_0001;

/// Default Sequence Number assigned by [`Esp::new`] (RFC 4303 §3.3.3: the
/// first packet sent on an SA uses sequence number 1).
const DEFAULT_ESP_SEQUENCE: u32 = 1;

#[allow(dead_code)]
impl Esp {
    /// Create an ESP layer with deterministic packet-builder defaults.
    ///
    /// The SPI is defaulted to `0x0000_0001` and the Sequence Number to `1`
    /// (RFC 4303 §3.3.3); every other field is unset, no SA is attached, and
    /// there is no opaque body. `compile()` (Step 12+) fills the unset fields;
    /// any value the caller sets afterwards is preserved untouched.
    pub fn new() -> Self {
        Self {
            spi: Field::defaulted(DEFAULT_ESP_SPI),
            sequence: Field::defaulted(DEFAULT_ESP_SEQUENCE),
            next_header: Field::unset(),
            pad: Field::unset(),
            iv: Field::unset(),
            icv: Field::unset(),
            sa: None,
            opaque: None,
        }
    }

    /// Create an ESP layer with an attached [`SecurityAssociation`].
    ///
    /// Equivalent to `Esp::new().security_association(sa)`: the SA is the
    /// crypto context the seal/open driver (Step 12+) consumes.
    pub fn secured(sa: SecurityAssociation) -> Self {
        Self::new().security_association(sa)
    }

    /// Set the Security Parameters Index explicitly.
    pub fn spi(mut self, spi: u32) -> Self {
        self.spi.set_user(spi);
        self
    }

    /// Set the Sequence Number explicitly.
    pub fn sequence(mut self, sequence: u32) -> Self {
        self.sequence.set_user(sequence);
        self
    }

    /// Compatibility alias for [`Esp::sequence`].
    pub fn seq(self, sequence: u32) -> Self {
        self.sequence(sequence)
    }

    /// Attach a [`SecurityAssociation`] crypto context.
    pub fn security_association(mut self, sa: SecurityAssociation) -> Self {
        self.sa = Some(sa);
        self
    }

    /// Set the ESP trailer Next Header explicitly.
    ///
    /// `compile()` otherwise derives this from the inner layer; setting it
    /// pins the value, including a deliberately wrong one for malformed tests.
    pub fn next_header(mut self, next_header: u8) -> Self {
        self.next_header.set_user(next_header);
        self
    }

    /// Set explicit ESP trailer padding bytes.
    ///
    /// Overrides the RFC 4303 §2.4 computed padding for deterministic or
    /// deliberately malformed output.
    pub fn pad(mut self, pad: impl Into<Vec<u8>>) -> Self {
        self.pad.set_user(pad.into());
        self
    }

    /// Set an explicit IV/nonce for deterministic ciphertext.
    pub fn iv(mut self, iv: impl Into<Vec<u8>>) -> Self {
        self.iv.set_user(iv.into());
        self
    }

    /// Set explicit Integrity Check Value bytes.
    pub fn icv(mut self, icv: impl Into<Vec<u8>>) -> Self {
        self.icv.set_user(icv.into());
        self
    }

    /// Carry a pre-encrypted body verbatim (no-SA / decode path).
    pub fn opaque(mut self, opaque: impl Into<Vec<u8>>) -> Self {
        self.opaque = Some(opaque.into());
        self
    }

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
    pub fn attached_security_association(&self) -> Option<&SecurityAssociation> {
        self.sa.as_ref()
    }

    /// The opaque pre-encrypted body bytes, when present.
    pub fn opaque_body(&self) -> Option<&[u8]> {
        self.opaque.as_deref()
    }
}

impl Default for Esp {
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
    fn new_defaults_spi_and_sequence() {
        let esp = Esp::new();

        // SPI and sequence are library defaults, not caller-set.
        assert_eq!(esp.spi.state(), FieldState::Defaulted);
        assert_eq!(esp.spi.value().copied(), Some(DEFAULT_ESP_SPI));
        assert_eq!(esp.sequence.state(), FieldState::Defaulted);
        assert_eq!(esp.sequence.value().copied(), Some(DEFAULT_ESP_SEQUENCE));

        // Everything else is unset, no SA, no opaque body.
        assert_eq!(esp.next_header.state(), FieldState::Unset);
        assert_eq!(esp.pad.state(), FieldState::Unset);
        assert_eq!(esp.iv.state(), FieldState::Unset);
        assert_eq!(esp.icv.state(), FieldState::Unset);
        assert!(esp.sa.is_none());
        assert!(esp.opaque.is_none());
    }

    #[test]
    fn default_matches_new() {
        let from_default = Esp::default();
        assert_eq!(from_default.spi.state(), FieldState::Defaulted);
        assert_eq!(from_default.spi_value(), Some(DEFAULT_ESP_SPI));
        assert_eq!(from_default.sequence_value(), Some(DEFAULT_ESP_SEQUENCE));
        assert!(from_default.attached_security_association().is_none());
    }

    #[test]
    fn setters_mark_fields_as_user() {
        let esp = Esp::new()
            .spi(0x0000_2000)
            .sequence(42)
            .next_header(6)
            .pad(vec![0x01, 0x02])
            .iv(vec![0xAAu8; 8])
            .icv(vec![0xBBu8; 16]);

        assert_eq!(esp.spi.state(), FieldState::User);
        assert_eq!(esp.spi_value(), Some(0x0000_2000));
        assert_eq!(esp.sequence.state(), FieldState::User);
        assert_eq!(esp.sequence_value(), Some(42));
        assert_eq!(esp.next_header.state(), FieldState::User);
        assert_eq!(esp.next_header_value(), Some(6));
        assert_eq!(esp.pad.state(), FieldState::User);
        assert_eq!(esp.pad_value(), Some(&[0x01, 0x02][..]));
        assert_eq!(esp.iv.state(), FieldState::User);
        assert_eq!(esp.iv_value(), Some(&[0xAAu8; 8][..]));
        assert_eq!(esp.icv.state(), FieldState::User);
        assert_eq!(esp.icv_value(), Some(&[0xBBu8; 16][..]));
    }

    #[test]
    fn seq_alias_matches_sequence() {
        let esp = Esp::new().seq(7);
        assert_eq!(esp.sequence.state(), FieldState::User);
        assert_eq!(esp.sequence_value(), Some(7));
    }

    #[test]
    fn secured_attaches_the_sa() {
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesGcm16, vec![0u8; 16])
            .salt(vec![0u8; 4]);

        let esp = Esp::secured(sa.clone());

        let attached = esp.attached_security_association().expect("SA attached");
        assert_eq!(attached, &sa);
        // secured() leaves the SPI/sequence defaults in place.
        assert_eq!(esp.spi.state(), FieldState::Defaulted);
        assert_eq!(esp.sequence.state(), FieldState::Defaulted);
    }

    #[test]
    fn security_association_setter_attaches_the_sa() {
        let sa = SecurityAssociation::new(0x10);
        let esp = Esp::new().security_association(sa.clone());
        assert_eq!(esp.attached_security_association(), Some(&sa));
    }

    #[test]
    fn opaque_carries_body_bytes() {
        let esp = Esp::new().opaque(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(esp.opaque_body(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }
}
