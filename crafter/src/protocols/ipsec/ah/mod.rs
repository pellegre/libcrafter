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

    /// Set the Security Parameters Index explicitly (RFC 4302 §2.4).
    pub fn spi(mut self, spi: u32) -> Self {
        self.spi.set_user(spi);
        self
    }

    /// Set the Sequence Number explicitly (RFC 4302 §2.5).
    pub fn sequence(mut self, sequence: u32) -> Self {
        self.sequence.set_user(sequence);
        self
    }

    /// Compatibility alias for [`Ah::sequence`].
    pub fn seq(self, sequence: u32) -> Self {
        self.sequence(sequence)
    }

    /// Set the Next Header explicitly (RFC 4302 §2.1).
    ///
    /// `compile()` (a later step) otherwise derives this from the following
    /// layer; setting it pins the value, including a deliberately wrong one for
    /// malformed tests.
    pub fn next_header(mut self, next_header: u8) -> Self {
        self.next_header.set_user(next_header);
        self
    }

    /// Set the Payload Len field explicitly (RFC 4302 §2.2).
    ///
    /// `compile()` (a later step) otherwise derives this from the ICV length
    /// ([`Ah::effective_payload_len`]); setting it pins the value verbatim,
    /// including a deliberately wrong one for malformed tests.
    pub fn payload_len(mut self, payload_len: u8) -> Self {
        self.payload_len.set_user(payload_len);
        self
    }

    /// Set the Reserved field explicitly (RFC 4302 §2.3).
    ///
    /// The Reserved field is zero on transmission; an override emits the value
    /// verbatim for deliberately malformed output.
    pub fn reserved(mut self, reserved: u16) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Set explicit Integrity Check Value bytes (RFC 4302 §2.6).
    ///
    /// Overrides the SA-driven ICV computation for deterministic or
    /// deliberately malformed output.
    pub fn icv(mut self, icv: impl Into<Vec<u8>>) -> Self {
        self.icv.set_user(icv.into());
        self
    }

    /// Attach a [`SecurityAssociation`] integrity context.
    pub fn security_association(mut self, sa: SecurityAssociation) -> Self {
        self.sa = Some(sa);
        self
    }

    /// Set the high-order 32 bits of the Extended Sequence Number (RFC 4302
    /// §2.5.1).
    ///
    /// This word is only meaningful when the attached [`SecurityAssociation`]
    /// has ESN enabled. It is folded into the ICV computation (a later step) but
    /// never appears on the wire — only the low 32-bit [`Ah::sequence`] is
    /// transmitted. With ESN disabled the high word is ignored.
    pub fn high_sequence(mut self, high_sequence: u32) -> Self {
        self.high_sequence.set_user(high_sequence);
        self
    }

    /// Resolve the on-wire ICV length in octets for the given IP version.
    ///
    /// The unpadded ICV length comes from the caller's explicit `icv` override
    /// (its byte length), else the attached SA — the AEAD tag length for an AEAD
    /// encryption suite (RFC 4543 GMAC-style integrity), otherwise the separate
    /// integrity algorithm's output length. With no SA and no override the
    /// length is 0.
    ///
    /// RFC 4302 §2.6 requires the ICV to be padded so the whole AH header is a
    /// multiple of 32 bits for IPv4 and 64 bits for IPv6. Because the fixed AH
    /// header is already 12 octets (a multiple of 4), only the ICV needs to be
    /// padded to the alignment boundary; this returns that padded length.
    ///
    /// A caller `payload_len` override does **not** influence this helper — it
    /// describes the ICV bytes themselves; the override interacts with
    /// [`Ah::effective_payload_len`].
    #[allow(dead_code)]
    pub(crate) fn effective_icv_len(&self, ip_version: u8) -> usize {
        let unpadded = self.unpadded_icv_len();
        let alignment = icv_alignment(ip_version);
        let remainder = unpadded % alignment;
        if remainder == 0 {
            unpadded
        } else {
            unpadded + (alignment - remainder)
        }
    }

    /// Resolve the Payload Len field value for the given IP version.
    ///
    /// A caller-set `payload_len` (including a deliberately wrong one) is
    /// returned verbatim. Otherwise it is computed per RFC 4302 §2.2 as the AH
    /// header length in 32-bit words minus 2:
    /// `(AH_FIXED_LEN + padded_ICV) / 4 - 2`, where the padded ICV length comes
    /// from [`Ah::effective_icv_len`].
    #[allow(dead_code)]
    pub(crate) fn effective_payload_len(&self, ip_version: u8) -> u8 {
        if let Some(payload_len) = self.payload_len.value().copied() {
            return payload_len;
        }
        let total = header::AH_FIXED_LEN + self.effective_icv_len(ip_version);
        // AH_FIXED_LEN (12) and a boundary-padded ICV are both multiples of 4,
        // so the division is exact. Saturating-subtract keeps a pathologically
        // tiny header (no honest AH reaches it) from underflowing.
        let words = (total / header::AH_LENGTH_UNIT) as u8;
        words.saturating_sub(header::AH_PAYLOAD_LEN_OFFSET)
    }

    /// Unpadded ICV length in octets, before boundary padding.
    ///
    /// The caller's explicit `icv` override wins (its byte length); otherwise the
    /// attached SA resolves it — the AEAD tag length for an AEAD encryption suite
    /// (RFC 4543 GMAC), else the separate integrity algorithm's length. No SA and
    /// no override means no ICV (length 0).
    #[allow(dead_code)]
    fn unpadded_icv_len(&self) -> usize {
        if let Some(icv) = self.icv.value() {
            return icv.len();
        }
        let Some(sa) = self.sa.as_ref() else {
            return 0;
        };
        let resolved = if sa.enc.is_aead() {
            sa.enc.icv_len()
        } else {
            sa.integ.icv_len()
        };
        resolved.unwrap_or(0)
    }
}

/// ICV alignment boundary in octets for the given IP version (RFC 4302 §2.6).
///
/// IPv4 requires the AH header to be a multiple of 32 bits (4 octets); IPv6
/// requires a multiple of 64 bits (8 octets). Any non-IPv6 version defaults to
/// the 4-octet boundary.
const fn icv_alignment(ip_version: u8) -> usize {
    if ip_version == 6 {
        8
    } else {
        4
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

    use crate::protocols::ipsec::sa::IntegrityAlgorithm;

    #[test]
    fn setters_mark_fields_as_user() {
        let ah = Ah::new()
            .spi(0x0000_2000)
            .sequence(42)
            .high_sequence(0x0000_0001)
            .next_header(6)
            .payload_len(7)
            .reserved(0xFFFF)
            .icv(vec![0xAAu8; 12]);

        assert_eq!(ah.spi.state(), FieldState::User);
        assert_eq!(ah.spi_value(), Some(0x0000_2000));
        assert_eq!(ah.sequence.state(), FieldState::User);
        assert_eq!(ah.sequence_value(), Some(42));
        assert_eq!(ah.high_sequence.state(), FieldState::User);
        assert_eq!(ah.high_sequence_value(), Some(0x0000_0001));
        assert_eq!(ah.next_header.state(), FieldState::User);
        assert_eq!(ah.next_header_value(), Some(6));
        assert_eq!(ah.payload_len.state(), FieldState::User);
        assert_eq!(ah.payload_len_value(), Some(7));
        assert_eq!(ah.reserved.state(), FieldState::User);
        assert_eq!(ah.reserved_value(), Some(0xFFFF));
        assert_eq!(ah.icv.state(), FieldState::User);
        assert_eq!(ah.icv_value(), Some(&[0xAAu8; 12][..]));
    }

    #[test]
    fn seq_alias_matches_sequence() {
        let ah = Ah::new().seq(9);
        assert_eq!(ah.sequence.state(), FieldState::User);
        assert_eq!(ah.sequence_value(), Some(9));
    }

    #[test]
    fn security_association_setter_attaches_the_sa() {
        let sa = SecurityAssociation::new(0x10)
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x33u8; 32]);
        let ah = Ah::new().security_association(sa.clone());
        assert_eq!(ah.attached_security_association(), Some(&sa));
    }

    #[test]
    fn payload_len_for_twelve_byte_icv_over_ipv4_is_rfc_value() {
        // A 12-octet ICV (e.g. HMAC-SHA1-96 / AES-XCBC-96) is already a multiple
        // of 32 bits, so no IPv4 padding is needed. RFC 4302 §2.2: Payload Len =
        // (AH length in 32-bit words) − 2 = (AH_FIXED_LEN(12) + ICV(12)) / 4 − 2
        // = 24/4 − 2 = 4.
        let sa = SecurityAssociation::new(0x0000_2000)
            .integrity(IntegrityAlgorithm::HmacSha1_96, vec![0x44u8; 20]);
        let ah = Ah::secured(sa);

        assert_eq!(ah.effective_icv_len(4), 12);
        assert_eq!(ah.effective_payload_len(4), 4);
    }

    #[test]
    fn payload_len_override_is_kept_verbatim() {
        // A caller-set Payload Len wins over the RFC computation, even when it
        // disagrees with the ICV length (deliberately malformed output).
        let sa = SecurityAssociation::new(0x0000_2000)
            .integrity(IntegrityAlgorithm::HmacSha1_96, vec![0x44u8; 20]);
        let ah = Ah::secured(sa).payload_len(0x7F);

        // The RFC value would be 4, but the override stands.
        assert_eq!(ah.effective_payload_len(4), 0x7F);
    }

    #[test]
    fn sixteen_byte_icv_pads_to_sixty_four_bits_on_ipv6() {
        // HMAC-SHA-256-128 emits a 16-octet ICV (RFC 4868). On IPv4 (32-bit
        // boundary) 16 is already aligned: (12+16)/4 − 2 = 5. On IPv6 (64-bit
        // boundary) 16 is also aligned, so the value matches.
        let sa = SecurityAssociation::new(0x0000_2000)
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x33u8; 32]);
        let ah = Ah::secured(sa);

        assert_eq!(ah.effective_icv_len(4), 16);
        assert_eq!(ah.effective_payload_len(4), 5);
        assert_eq!(ah.effective_icv_len(6), 16);
        assert_eq!(ah.effective_payload_len(6), 5);
    }

    #[test]
    fn icv_padded_to_sixty_four_bits_on_ipv6_when_unaligned() {
        // HMAC-SHA-384-192 emits a 24-octet ICV (RFC 4868). On IPv4 24 is a
        // multiple of 4: (12+24)/4 − 2 = 7. On IPv6 the ICV must reach a 64-bit
        // (8-octet) boundary; 24 already is, so it stays 24. A 12-octet ICV,
        // by contrast, pads from 12 to 16 on IPv6.
        let sha384 = SecurityAssociation::new(0x0000_2000)
            .integrity(IntegrityAlgorithm::HmacSha2_384_192, vec![0x55u8; 48]);
        let ah384 = Ah::secured(sha384);
        assert_eq!(ah384.effective_icv_len(4), 24);
        assert_eq!(ah384.effective_payload_len(4), 7);
        assert_eq!(ah384.effective_icv_len(6), 24);
        assert_eq!(ah384.effective_payload_len(6), 7);

        // 12-octet ICV: 32-bit aligned on IPv4 (stays 12), padded to 16 on IPv6.
        let sha1 = SecurityAssociation::new(0x0000_2000)
            .integrity(IntegrityAlgorithm::HmacSha1_96, vec![0x44u8; 20]);
        let ah1 = Ah::secured(sha1);
        assert_eq!(ah1.effective_icv_len(4), 12);
        assert_eq!(ah1.effective_icv_len(6), 16);
        // IPv6: (12 + 16)/4 − 2 = 5.
        assert_eq!(ah1.effective_payload_len(6), 5);
    }

    #[test]
    fn icv_override_drives_the_padded_length() {
        // An explicit ICV override sets the unpadded length by its byte count;
        // padding to the IP-version boundary still applies. A 10-octet override
        // pads to 12 on IPv4 and to 16 on IPv6.
        let ah = Ah::new().icv(vec![0xABu8; 10]);
        assert_eq!(ah.effective_icv_len(4), 12);
        assert_eq!(ah.effective_icv_len(6), 16);
        // IPv4: (12 + 12)/4 − 2 = 4.
        assert_eq!(ah.effective_payload_len(4), 4);
    }
}
