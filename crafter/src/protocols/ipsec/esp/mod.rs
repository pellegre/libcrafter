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
use crate::packet::{Layer, LayerContext};
use crate::protocols::icmp::{Icmpv4, Icmpv6};
use crate::protocols::ip::shared::protocol_numbers::{
    IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IPV6, IPPROTO_NO_NEXT, IPPROTO_TCP, IPPROTO_UDP,
};
use crate::protocols::ipsec::sa::{seal, IpsecMode, SecurityAssociation};
use crate::protocols::ipv4::Ipv4;
use crate::protocols::ipv6::Ipv6;
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object, payload_bytes_after};
use crate::protocols::{Tcp, Udp};
use crate::{CrafterError, Result};

use self::header::ESP_HEADER_LEN;

/// IP protocol number for IPv4-in-IPv4 encapsulation (tunnel-mode inner IPv4).
///
/// IANA assigns protocol number 4 to "IPv4 encapsulation"; the shared
/// `protocol_numbers` table does not define a constant for it, so ESP carries a
/// local one for the tunnel-mode ESP Next Header.
const IPPROTO_IPV4: u8 = 4;

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

/// Default per-packet IV/nonce used when the caller pins none.
///
/// `compile()` needs a deterministic IV so the emitted ESP bytes are
/// reproducible (and oracle byte-parity holds). When the caller does not set
/// [`Esp::iv`], the cipher's required IV is filled with all-zero octets of the
/// algorithm's [`crate::protocols::ipsec::sa::EncryptionAlgorithm::iv_len`].
/// This is a builder convenience only — a real send would pin a unique IV.
fn default_iv(len: usize) -> Vec<u8> {
    vec![0u8; len]
}

/// Map a following layer to the ESP Next Header value for the given mode.
///
/// - **Transport mode** (RFC 4303 §3.1.1): the Next Header is the protected
///   upper-layer protocol number — TCP (6), UDP (17), ICMPv4 (1), or ICMPv6
///   (58). An inner IP header in transport mode is unusual, so an `Ipv4`/`Ipv6`
///   inner layer is still mapped to its IP-in-IP protocol number.
/// - **Tunnel mode** (RFC 4303 §3.1.2): the protected data is an entire inner
///   IP datagram, so the Next Header is `IPv4`-in-`IPv4` (4) or `IPv6` (41).
///
/// A following layer ESP does not recognize yields `None`; the caller then
/// falls back to `IPPROTO_NO_NEXT` (59) rather than guessing.
fn layer_esp_next_header(layer: &dyn Layer, _mode: IpsecMode) -> Option<u8> {
    let any = layer.as_any();
    // IP-in-IP uses the same protocol number whether the inner IP datagram is
    // protected in tunnel mode or (unusually) nested in transport mode.
    if any.is::<Ipv4>() {
        return Some(IPPROTO_IPV4);
    }
    if any.is::<Ipv6>() {
        return Some(IPPROTO_IPV6);
    }
    if any.is::<Tcp>() {
        return Some(IPPROTO_TCP);
    }
    if any.is::<Udp>() {
        return Some(IPPROTO_UDP);
    }
    if any.is::<Icmpv4>() {
        return Some(IPPROTO_ICMP);
    }
    if any.is::<Icmpv6>() {
        return Some(IPPROTO_ICMPV6);
    }
    None
}

impl Esp {
    /// Resolve the ESP trailer Next Header for `compile()`.
    ///
    /// A caller-set value (including a deliberately wrong one) wins. Otherwise it
    /// is derived from the following layer via [`layer_esp_next_header`]; with no
    /// following layer the Next Header is `IPPROTO_NO_NEXT` (59).
    fn effective_next_header(&self, ctx: &LayerContext<'_>, mode: IpsecMode) -> u8 {
        if let Some(next_header) = self.next_header.value().copied() {
            return next_header;
        }
        ctx.next()
            .and_then(|layer| layer_esp_next_header(layer, mode))
            .unwrap_or(IPPROTO_NO_NEXT)
    }

    /// Compute the RFC 4303 §2.4 ESP padding for a plaintext of `payload_len`
    /// upper-layer octets under `block_size`.
    ///
    /// The padded plaintext is `payload || pad || pad-length || next-header`; its
    /// total length must be a multiple of the cipher block size **and** of 4
    /// octets (RFC 4303 §2.4). The pad bytes themselves are the monotonically
    /// increasing sequence `1, 2, 3, …` the RFC specifies. A caller-set [`pad`]
    /// override is returned verbatim, even when it breaks that alignment, so
    /// deliberately malformed packets remain buildable.
    ///
    /// [`pad`]: Esp::pad
    fn effective_pad(&self, payload_len: usize, block_size: usize) -> Vec<u8> {
        if let Some(pad) = self.pad.value() {
            return pad.clone();
        }
        // The trailer always contributes the Pad Length + Next Header octets, so
        // the alignment target covers `payload + pad + 2`.
        let alignment = block_size.max(4);
        let trailer_fixed = header::ESP_PAD_LENGTH_FIELD_LEN + header::ESP_NEXT_HEADER_FIELD_LEN;
        let unaligned = payload_len + trailer_fixed;
        let remainder = unaligned % alignment;
        let pad_len = if remainder == 0 {
            0
        } else {
            alignment - remainder
        };
        // RFC 4303 §2.4: padding octets are 1, 2, 3, … starting at 1.
        (1..=pad_len as u8).collect()
    }

    /// Build the ESP plaintext, AAD, explicit IV, and SPI/Seq for `compile()`.
    ///
    /// Both the cipher+integrity and the AEAD paths share the same RFC 4303 §2
    /// trailer assembly and integrity prefix:
    ///
    /// - **plaintext** = `upper-layer bytes || pad || pad-length || next-header`,
    ///   the padding computed to the cipher block / 4-octet boundary (RFC 4303
    ///   §2.4) unless the caller pinned an explicit `pad`.
    /// - **AAD** = `SPI || Seq` — for cipher+integrity this is the integrity
    ///   prefix, for AEAD this is the authenticated data (the ESN high-order bits
    ///   are folded in by Step 20).
    /// - **iv** = the caller `iv` override, else a deterministic all-zero IV of
    ///   the cipher's IV length.
    ///
    /// Returns `(spi, sequence, plaintext, aad, iv)`.
    fn esp_seal_inputs(
        &self,
        ctx: &LayerContext<'_>,
        sa: &SecurityAssociation,
    ) -> Result<(u32, u32, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let spi = self.spi.value().copied().unwrap_or(DEFAULT_ESP_SPI);
        let sequence = self
            .sequence
            .value()
            .copied()
            .unwrap_or(DEFAULT_ESP_SEQUENCE);

        // Upper-layer plaintext = every following layer's bytes.
        let payload = payload_bytes_after(*ctx)?;

        // Trailer: pad || pad-length || next-header (RFC 4303 §2.4–2.6).
        let block_size = sa.enc.block_size();
        let pad = self.effective_pad(payload.len(), block_size);
        let pad_len = u8::try_from(pad.len()).map_err(|_| {
            CrafterError::invalid_field_value("esp.pad", "ESP pad exceeds 255 octets")
        })?;
        let next_header = self.effective_next_header(ctx, sa.mode);

        let mut plaintext = Vec::with_capacity(
            payload.len()
                + pad.len()
                + header::ESP_PAD_LENGTH_FIELD_LEN
                + header::ESP_NEXT_HEADER_FIELD_LEN,
        );
        plaintext.extend_from_slice(&payload);
        plaintext.extend_from_slice(&pad);
        plaintext.push(pad_len);
        plaintext.push(next_header);

        // Integrity / AEAD prefix = SPI || Seq (ESN high bits added in Step 20).
        let mut aad = Vec::with_capacity(ESP_HEADER_LEN);
        aad.extend_from_slice(&spi.to_be_bytes());
        aad.extend_from_slice(&sequence.to_be_bytes());

        // Explicit IV: caller override, else a deterministic all-zero IV.
        let iv = match self.iv.value() {
            Some(iv) => iv.clone(),
            None => default_iv(sa.enc.iv_len()),
        };

        Ok((spi, sequence, plaintext, aad, iv))
    }

    /// Compile the cipher + separate-integrity (non-AEAD) ESP datagram.
    ///
    /// Implements the RFC 4303 §2 encrypt-then-MAC layout for AES-CBC / AES-CTR
    /// (and `NULL`) paired with a separate HMAC/XCBC/GMAC integrity algorithm:
    ///
    /// 1. Gather the upper-layer bytes (the following layers) as the plaintext.
    /// 2. Append `pad || pad-length || next-header` (RFC 4303 §2.4–2.6); the
    ///    padding is computed to the cipher block / 4-octet boundary unless the
    ///    caller pinned an explicit pad.
    /// 3. Encrypt the padded plaintext under the SA's cipher with the explicit
    ///    IV (caller override, else an all-zero IV of the cipher's IV length).
    /// 4. Compute the ICV over `SPI||Seq || IV || ciphertext` via the SA's
    ///    integrity algorithm (caller `icv` override wins).
    /// 5. Emit `SPI || Seq || IV || ciphertext || ICV`.
    ///
    /// This path rejects the `NULL`+`NONE` (no-integrity) case with a structured
    /// error — that branch is filled by Step 14.
    fn compile_with_cipher(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let sa = self.sa.as_ref().ok_or_else(|| {
            CrafterError::invalid_field_value(
                "esp.compile",
                "ESP compile without a SecurityAssociation is not supported in this build step",
            )
        })?;

        // The no-integrity NULL case (NULL+NONE) is handled by Step 14.
        if matches!(
            sa.integ,
            crate::protocols::ipsec::sa::IntegrityAlgorithm::None
        ) {
            return Err(CrafterError::invalid_field_value(
                "esp.compile",
                "NULL/opaque ESP compilation is unsupported in this build step",
            ));
        }

        let (_spi, _sequence, plaintext, aad, iv) = self.esp_seal_inputs(ctx, sa)?;

        // Seal: cipher encrypt, then ICV over SPI||Seq || IV || ciphertext.
        let sealed = seal(sa, &iv, &aad, &plaintext)?;
        let icv = match self.icv.value() {
            Some(icv) => icv.clone(),
            None => sealed.icv,
        };

        // Wire layout: SPI || Seq || IV || ciphertext || ICV.
        out.reserve(ESP_HEADER_LEN + iv.len() + sealed.ciphertext.len() + icv.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&sealed.ciphertext);
        out.extend_from_slice(&icv);
        Ok(())
    }

    /// Compile the AEAD ESP datagram (AES-GCM, AES-CCM, ChaCha20-Poly1305).
    ///
    /// Implements the RFC 4106 / 4309 / 7634 combined-mode layout: a single seal
    /// produces ciphertext and the authentication tag (the ICV). Block alignment
    /// is not required for these stream/AEAD suites, but RFC 4303 still pads to a
    /// 4-octet boundary (handled by `effective_pad`); a caller `pad` override is
    /// honored verbatim.
    ///
    /// 1. Gather the upper-layer bytes and append `pad || pad-length ||
    ///    next-header` to form the plaintext.
    /// 2. AAD = `SPI || Seq` (the ESN high-order bits are folded in by Step 20).
    /// 3. The nonce is `sa.salt || iv`, assembled inside [`seal`]; the IV is the
    ///    caller override or a deterministic 8-octet IV.
    /// 4. Emit `SPI || Seq || IV || ciphertext || tag(ICV)`; a caller `icv`
    ///    override replaces the AEAD tag verbatim for deliberately malformed
    ///    output.
    fn compile_with_aead(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let sa = self.sa.as_ref().ok_or_else(|| {
            CrafterError::invalid_field_value(
                "esp.compile",
                "ESP compile without a SecurityAssociation is not supported in this build step",
            )
        })?;

        let (_spi, _sequence, plaintext, aad, iv) = self.esp_seal_inputs(ctx, sa)?;

        // Seal: the AEAD authenticates `aad` and returns the tag as the ICV; the
        // nonce `sa.salt || iv` is assembled inside `seal`.
        let sealed = seal(sa, &iv, &aad, &plaintext)?;
        let icv = match self.icv.value() {
            Some(icv) => icv.clone(),
            None => sealed.icv,
        };

        // Wire layout: SPI || Seq || IV || ciphertext || tag(ICV).
        out.reserve(ESP_HEADER_LEN + iv.len() + sealed.ciphertext.len() + icv.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&sealed.ciphertext);
        out.extend_from_slice(&icv);
        Ok(())
    }
}

impl Layer for Esp {
    fn name(&self) -> &'static str {
        "Esp"
    }

    fn encoded_len(&self) -> usize {
        // A context-free capacity hint: the fixed SPI + Sequence header. The true
        // on-wire size depends on the encrypted trailer and ICV, finalized in a
        // later step.
        ESP_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Dispatch by the SA's encryption suite. AEAD suites (AES-GCM, AES-CCM,
        // ChaCha20-Poly1305) take the combined-mode path; AES-CBC/CTR + separate
        // integrity take the encrypt-then-MAC path. The NULL/opaque and no-SA
        // branches return a structured error and are filled by Step 14.
        match self.sa.as_ref() {
            Some(sa) if sa.enc.is_aead() => self.compile_with_aead(ctx, out),
            _ => self.compile_with_cipher(ctx, out),
        }
    }

    impl_layer_object!(Esp);
}

impl_layer_div!(Esp);

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

    // --- compile (CBC/CTR + HMAC) golden vectors --------------------------

    use crate::packet::Packet;
    use crate::packet::Raw;
    use crate::protocols::ipsec::sa::{seal, IntegrityAlgorithm};
    use crate::protocols::ipv4::Ipv4;

    /// A 16-octet AES-128 key (fixed, documentation-only).
    fn aes_key() -> Vec<u8> {
        vec![0x11u8; 16]
    }

    /// A 32-octet HMAC-SHA-256 integrity key (fixed, documentation-only).
    fn hmac_key() -> Vec<u8> {
        vec![0x33u8; 32]
    }

    /// A fixed upper-layer payload of 4 octets.
    fn payload() -> Vec<u8> {
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    }

    /// Build the expected ESP datagram bytes for a cipher+integrity SA using the
    /// already-RFC-KAT-proven [`seal`] primitive (Steps 04/05/09). This locks the
    /// step-12 wire assembly (`SPI || Seq || IV || ciphertext || ICV`, RFC 4303
    /// §2) against the proven crypto without re-deriving ciphertext by hand.
    fn expected_esp_bytes(
        sa: &SecurityAssociation,
        spi: u32,
        sequence: u32,
        iv: &[u8],
        next_header: u8,
        upper: &[u8],
    ) -> Vec<u8> {
        // Recompute the RFC 4303 §2.4 padding for this payload + block size.
        let block_size = sa.enc.block_size();
        let alignment = block_size.max(4);
        let unaligned =
            upper.len() + header::ESP_PAD_LENGTH_FIELD_LEN + header::ESP_NEXT_HEADER_FIELD_LEN;
        let remainder = unaligned % alignment;
        let pad_len = if remainder == 0 {
            0
        } else {
            alignment - remainder
        };
        let pad: Vec<u8> = (1..=pad_len as u8).collect();

        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(upper);
        plaintext.extend_from_slice(&pad);
        plaintext.push(pad_len as u8);
        plaintext.push(next_header);

        let mut aad = Vec::new();
        aad.extend_from_slice(&spi.to_be_bytes());
        aad.extend_from_slice(&sequence.to_be_bytes());
        let sealed = seal(sa, iv, &aad, &plaintext).unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(&aad);
        out.extend_from_slice(iv);
        out.extend_from_slice(&sealed.ciphertext);
        out.extend_from_slice(&sealed.icv);
        out
    }

    /// Build `Ipv4 / Esp / <inner...>` and compile only the ESP layer in
    /// isolation, returning its ESP datagram bytes plus the IPv4 protocol number.
    ///
    /// The ESP layer at index 1 is compiled through its own `LayerContext` so its
    /// encrypted body — which already embeds the following layers via
    /// `payload_bytes_after` — is not double-emitted by the trailing cleartext
    /// layers. (Whole-packet compilation that elides the consumed tail is the
    /// step-15 "Layer polish" concern.) The IPv4 protocol is pinned to ESP (50);
    /// auto-deriving 50 from an inner `Esp` is a later registry step.
    fn compile_esp_over_ipv4_inner(esp: Esp, inner: Packet) -> (Vec<u8>, u8) {
        let ipv4 = Ipv4::new()
            .protocol(crate::protocols::ipv4::IPPROTO_ESP)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap());
        let packet: Packet = (Packet::from_layer(ipv4) / esp).concat(inner);

        // Confirm the enclosing IPv4 datagram advertises ESP (protocol 50).
        let ip_bytes = {
            let mut out = Vec::new();
            let ctx = LayerContext::new(&packet, 0);
            packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
            out
        };
        let ip_protocol = ip_bytes[9];

        // Compile only the ESP layer (index 1) in isolation.
        let mut esp_bytes = Vec::new();
        let ctx = LayerContext::new(&packet, 1);
        packet
            .get(1)
            .unwrap()
            .compile(&ctx, &mut esp_bytes)
            .unwrap();
        (esp_bytes, ip_protocol)
    }

    /// Convenience wrapper for the common `Esp / Raw(upper)` case.
    fn compile_esp_over_ipv4(esp: Esp, upper: &[u8]) -> (Vec<u8>, u8) {
        compile_esp_over_ipv4_inner(esp, Packet::from_layer(Raw::from_bytes(upper)))
    }

    #[test]
    fn compile_aes_cbc_hmac_sha256_golden() {
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesCbc, aes_key())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key());
        assert!(sa.validate().is_ok());

        // Fixed 16-octet CBC IV.
        let iv: Vec<u8> = (0u8..16).collect();
        let esp = Esp::secured(sa.clone())
            .spi(0x0000_2000)
            .sequence(1)
            .next_header(IPPROTO_TCP)
            .iv(iv.clone());

        let (esp_bytes, ip_protocol) = compile_esp_over_ipv4(esp, &payload());

        // The enclosing IPv4 datagram advertises ESP (protocol 50).
        assert_eq!(ip_protocol, crate::protocols::ipv4::IPPROTO_ESP);

        let expected = expected_esp_bytes(&sa, 0x0000_2000, 1, &iv, IPPROTO_TCP, &payload());
        assert_eq!(esp_bytes, expected);

        // Structural locks: SPI || Seq prefix, then the 16-octet IV.
        assert_eq!(&esp_bytes[0..4], &0x0000_2000u32.to_be_bytes());
        assert_eq!(&esp_bytes[4..8], &1u32.to_be_bytes());
        assert_eq!(&esp_bytes[8..24], &iv[..]);
        // payload(4) + pad + padlen + nh padded to the 16-octet CBC block = 16;
        // ciphertext is 16 octets; HMAC-SHA-256-128 ICV is 16 octets.
        assert_eq!(esp_bytes.len(), ESP_HEADER_LEN + 16 + 16 + 16);
    }

    #[test]
    fn compile_aes_ctr_hmac_sha256_golden() {
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesCtr, aes_key())
            .salt(vec![0x00, 0x00, 0x00, 0x30]) // CTR salt is 4 octets (RFC 3686).
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key());
        assert!(sa.validate().is_ok());

        // Fixed 8-octet CTR IV.
        let iv: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let esp = Esp::secured(sa.clone())
            .spi(0x0000_2000)
            .sequence(1)
            .next_header(IPPROTO_TCP)
            .iv(iv.clone());

        let (esp_bytes, ip_protocol) = compile_esp_over_ipv4(esp, &payload());

        assert_eq!(ip_protocol, crate::protocols::ipv4::IPPROTO_ESP);

        let expected = expected_esp_bytes(&sa, 0x0000_2000, 1, &iv, IPPROTO_TCP, &payload());
        assert_eq!(esp_bytes, expected);

        // CTR has block size 1, so padding only satisfies the 4-octet alignment:
        // payload(4) + padlen(1) + nh(1) = 6 → pad 2 → 8 ciphertext octets.
        assert_eq!(&esp_bytes[0..4], &0x0000_2000u32.to_be_bytes());
        assert_eq!(&esp_bytes[4..8], &1u32.to_be_bytes());
        assert_eq!(&esp_bytes[8..16], &iv[..]);
        assert_eq!(esp_bytes.len(), ESP_HEADER_LEN + 8 + 8 + 16);
    }

    #[test]
    fn compile_round_trips_through_seal_open() {
        // Sealing then opening the produced ciphertext recovers the padded
        // plaintext, confirming the wire bytes are an openable ESP datagram.
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesCbc, aes_key())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key());
        let iv: Vec<u8> = (0u8..16).collect();
        let esp = Esp::secured(sa.clone())
            .spi(0x0000_2000)
            .sequence(1)
            .next_header(IPPROTO_TCP)
            .iv(iv.clone());
        let (esp_bytes, _) = compile_esp_over_ipv4(esp, &payload());

        let mut aad = Vec::new();
        aad.extend_from_slice(&0x0000_2000u32.to_be_bytes());
        aad.extend_from_slice(&1u32.to_be_bytes());
        let ct = &esp_bytes[ESP_HEADER_LEN + 16..esp_bytes.len() - 16];
        let icv = &esp_bytes[esp_bytes.len() - 16..];
        let opened = crate::protocols::ipsec::sa::open(&sa, &iv, &aad, ct, icv).unwrap();
        // Padded plaintext: payload | pad(1..=10) | pad_len(10) | next_header(6).
        assert_eq!(&opened[..4], &payload()[..]);
        assert_eq!(*opened.last().unwrap(), IPPROTO_TCP);
    }

    #[test]
    fn compile_pad_override_is_emitted_verbatim() {
        // A caller-set pad is honored even when it breaks block alignment; the
        // emitted plaintext uses exactly those pad octets (CTR keeps ciphertext
        // length equal to plaintext length, so this is directly observable).
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesCtr, aes_key())
            .salt(vec![0x00, 0x00, 0x00, 0x30])
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key());
        let iv: Vec<u8> = vec![0u8; 8];
        let esp = Esp::secured(sa.clone())
            .spi(0x10)
            .sequence(1)
            .next_header(IPPROTO_TCP)
            .iv(iv.clone())
            .pad(vec![0xAA, 0xBB, 0xCC]); // 3 octets, deliberately unaligned.
        let (esp_bytes, _) = compile_esp_over_ipv4(esp, &payload());

        // ESP_HEADER(8) + IV(8) + ciphertext + ICV(16).
        // ciphertext = payload(4) + pad(3) + padlen(1) + nh(1) = 9 octets.
        assert_eq!(esp_bytes.len(), ESP_HEADER_LEN + 8 + 9 + 16);

        // Open and confirm the override pad bytes survived untouched.
        let mut aad = Vec::new();
        aad.extend_from_slice(&0x10u32.to_be_bytes());
        aad.extend_from_slice(&1u32.to_be_bytes());
        let ct = &esp_bytes[ESP_HEADER_LEN + 8..esp_bytes.len() - 16];
        let icv = &esp_bytes[esp_bytes.len() - 16..];
        let opened = crate::protocols::ipsec::sa::open(&sa, &iv, &aad, ct, icv).unwrap();
        assert_eq!(
            opened,
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0xAA, 0xBB, 0xCC, 3, IPPROTO_TCP]
        );
    }

    #[test]
    fn compile_default_iv_is_zero_filled() {
        // With no IV override, compile fills the cipher's IV length with zeros.
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesCbc, aes_key())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key());
        let esp = Esp::secured(sa)
            .spi(0x10)
            .sequence(1)
            .next_header(IPPROTO_TCP);
        let (esp_bytes, _) = compile_esp_over_ipv4(esp, &payload());
        // The 16-octet CBC IV directly follows the 8-octet ESP header.
        assert_eq!(&esp_bytes[ESP_HEADER_LEN..ESP_HEADER_LEN + 16], &[0u8; 16]);
    }

    #[test]
    fn compile_derives_next_header_from_inner_udp() {
        // Without a next_header override the value comes from the following layer
        // (transport mode → the inner IP protocol number, UDP = 17).
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesCbc, aes_key())
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key());
        let iv: Vec<u8> = (0u8..16).collect();
        let esp = Esp::secured(sa.clone())
            .spi(0x10)
            .sequence(1)
            .iv(iv.clone());

        let inner: Packet =
            Packet::from_layer(crate::protocols::Udp::new()) / Raw::from_bytes([0u8; 0]);
        let (esp_bytes, _) = compile_esp_over_ipv4_inner(esp, inner);

        // Decrypt the trailer and confirm the next-header octet is UDP (17).
        let mut aad = Vec::new();
        aad.extend_from_slice(&0x10u32.to_be_bytes());
        aad.extend_from_slice(&1u32.to_be_bytes());
        let ct = &esp_bytes[ESP_HEADER_LEN + 16..esp_bytes.len() - 16];
        let icv = &esp_bytes[esp_bytes.len() - 16..];
        let opened = crate::protocols::ipsec::sa::open(&sa, &iv, &aad, ct, icv).unwrap();
        assert_eq!(*opened.last().unwrap(), IPPROTO_UDP);
    }

    // --- compile (AEAD) golden vectors ------------------------------------

    /// A 32-octet ChaCha20-Poly1305 key (fixed, documentation-only).
    fn chacha_key() -> Vec<u8> {
        vec![0x22u8; 32]
    }

    /// A fixed 8-octet AEAD explicit IV (the IV carried before the ciphertext).
    fn aead_iv() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    }

    #[test]
    fn compile_aes_gcm_16_golden() {
        // AES-GCM-16 (RFC 4106): AEAD, 16-octet ICV, 4-octet salt, 8-octet IV.
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(sa.validate().is_ok());

        let iv = aead_iv();
        let esp = Esp::secured(sa.clone())
            .spi(0x0000_2000)
            .sequence(1)
            .next_header(IPPROTO_TCP)
            .iv(iv.clone());

        let (esp_bytes, ip_protocol) = compile_esp_over_ipv4(esp, &payload());

        // The enclosing IPv4 datagram advertises ESP (protocol 50).
        assert_eq!(ip_protocol, crate::protocols::ipv4::IPPROTO_ESP);

        // Behavior-lock against the RFC-KAT-proven `seal` primitive (Steps 06/09).
        let expected = expected_esp_bytes(&sa, 0x0000_2000, 1, &iv, IPPROTO_TCP, &payload());
        assert_eq!(esp_bytes, expected);

        // Structural locks: SPI || Seq prefix, then the 8-octet IV.
        assert_eq!(&esp_bytes[0..4], &0x0000_2000u32.to_be_bytes());
        assert_eq!(&esp_bytes[4..8], &1u32.to_be_bytes());
        assert_eq!(&esp_bytes[ESP_HEADER_LEN..ESP_HEADER_LEN + 8], &iv[..]);
        // AEAD imposes no block alignment, only the 4-octet boundary:
        // payload(4) + padlen(1) + nh(1) = 6 → pad 2 → 8 ciphertext octets.
        // GCM ICV (tag) is 16 octets.
        assert_eq!(esp_bytes.len(), ESP_HEADER_LEN + 8 + 8 + 16);
    }

    #[test]
    fn compile_chacha20_poly1305_golden() {
        // ChaCha20-Poly1305 (RFC 7634): AEAD, 16-octet ICV, 32-octet key.
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::ChaCha20Poly1305, chacha_key())
            .salt(vec![0xA0, 0xA1, 0xA2, 0xA3]);
        assert!(sa.validate().is_ok());

        let iv = aead_iv();
        let esp = Esp::secured(sa.clone())
            .spi(0x0000_2000)
            .sequence(1)
            .next_header(IPPROTO_TCP)
            .iv(iv.clone());

        let (esp_bytes, ip_protocol) = compile_esp_over_ipv4(esp, &payload());

        assert_eq!(ip_protocol, crate::protocols::ipv4::IPPROTO_ESP);

        let expected = expected_esp_bytes(&sa, 0x0000_2000, 1, &iv, IPPROTO_TCP, &payload());
        assert_eq!(esp_bytes, expected);

        assert_eq!(&esp_bytes[0..4], &0x0000_2000u32.to_be_bytes());
        assert_eq!(&esp_bytes[4..8], &1u32.to_be_bytes());
        assert_eq!(&esp_bytes[ESP_HEADER_LEN..ESP_HEADER_LEN + 8], &iv[..]);
        // payload(4) → pad to 4-octet boundary → 8 ciphertext octets; 16 ICV.
        assert_eq!(esp_bytes.len(), ESP_HEADER_LEN + 8 + 8 + 16);
    }

    #[test]
    fn compile_aes_ccm_8_golden() {
        // AES-CCM-8 (RFC 4309): AEAD, 8-octet ICV, 3-octet salt, 8-octet IV.
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesCcm8, aes_key())
            .salt(vec![0xA0, 0xA1, 0xA2]);
        assert!(sa.validate().is_ok());

        let iv = aead_iv();
        let esp = Esp::secured(sa.clone())
            .spi(0x0000_2000)
            .sequence(1)
            .next_header(IPPROTO_TCP)
            .iv(iv.clone());

        let (esp_bytes, ip_protocol) = compile_esp_over_ipv4(esp, &payload());

        assert_eq!(ip_protocol, crate::protocols::ipv4::IPPROTO_ESP);

        let expected = expected_esp_bytes(&sa, 0x0000_2000, 1, &iv, IPPROTO_TCP, &payload());
        assert_eq!(esp_bytes, expected);

        assert_eq!(&esp_bytes[0..4], &0x0000_2000u32.to_be_bytes());
        assert_eq!(&esp_bytes[4..8], &1u32.to_be_bytes());
        assert_eq!(&esp_bytes[ESP_HEADER_LEN..ESP_HEADER_LEN + 8], &iv[..]);
        // payload(4) → pad to 4-octet boundary → 8 ciphertext octets; 8 ICV.
        assert_eq!(esp_bytes.len(), ESP_HEADER_LEN + 8 + 8 + 8);
    }

    #[test]
    fn compile_aead_round_trips_through_seal_open() {
        // The AEAD wire bytes are an openable ESP datagram: opening recovers the
        // padded plaintext and confirms the next-header octet.
        let sa = SecurityAssociation::new(0x0000_2000)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let iv = aead_iv();
        let esp = Esp::secured(sa.clone())
            .spi(0x0000_2000)
            .sequence(1)
            .next_header(IPPROTO_TCP)
            .iv(iv.clone());
        let (esp_bytes, _) = compile_esp_over_ipv4(esp, &payload());

        let mut aad = Vec::new();
        aad.extend_from_slice(&0x0000_2000u32.to_be_bytes());
        aad.extend_from_slice(&1u32.to_be_bytes());
        // GCM ICV is 16 octets; IV is 8 octets after the 8-octet ESP header.
        let ct = &esp_bytes[ESP_HEADER_LEN + 8..esp_bytes.len() - 16];
        let icv = &esp_bytes[esp_bytes.len() - 16..];
        let opened = crate::protocols::ipsec::sa::open(&sa, &iv, &aad, ct, icv).unwrap();
        assert_eq!(&opened[..4], &payload()[..]);
        assert_eq!(*opened.last().unwrap(), IPPROTO_TCP);
    }

    #[test]
    fn compile_aead_default_iv_is_zero_filled() {
        // With no IV override, AEAD compile fills the cipher's 8-octet IV length
        // with zeros (deterministic builder convenience).
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0u8; 4]);
        let esp = Esp::secured(sa)
            .spi(0x10)
            .sequence(1)
            .next_header(IPPROTO_TCP);
        let (esp_bytes, _) = compile_esp_over_ipv4(esp, &payload());
        // The 8-octet AEAD IV directly follows the 8-octet ESP header.
        assert_eq!(&esp_bytes[ESP_HEADER_LEN..ESP_HEADER_LEN + 8], &[0u8; 8]);
    }

    #[test]
    fn compile_aead_icv_override_is_emitted_verbatim() {
        // A caller-set ICV replaces the AEAD tag verbatim (malformed-by-design).
        let sa = SecurityAssociation::new(0x10)
            .encryption(EncryptionAlgorithm::AesGcm16, aes_key())
            .salt(vec![0u8; 4]);
        let bad_icv = vec![0xFFu8; 16];
        let esp = Esp::secured(sa)
            .spi(0x10)
            .sequence(1)
            .next_header(IPPROTO_TCP)
            .iv(aead_iv())
            .icv(bad_icv.clone());
        let (esp_bytes, _) = compile_esp_over_ipv4(esp, &payload());
        assert_eq!(&esp_bytes[esp_bytes.len() - 16..], &bad_icv[..]);
    }

    #[test]
    fn compile_rejects_null_and_no_sa_in_this_step() {
        // AEAD compile is now implemented (Step 13); NULL+NONE / no-SA stay
        // unsupported until Step 14.
        let no_sa = Esp::new().next_header(IPPROTO_TCP);
        let err = compile_err(no_sa);
        assert!(
            matches!(err, CrafterError::InvalidFieldValue { field, .. } if field == "esp.compile")
        );

        // NULL encryption with NONE integrity (no crypto at all) is the Step 14
        // opaque/passthrough case and still errors here.
        let null_none = Esp::secured(SecurityAssociation::new(0x10)).next_header(IPPROTO_TCP);
        let err = compile_err(null_none);
        assert!(
            matches!(err, CrafterError::InvalidFieldValue { field, .. } if field == "esp.compile")
        );
    }

    /// Compile `Ipv4 / Esp / Raw` and return the expected structured error.
    fn compile_err(esp: Esp) -> CrafterError {
        let ipv4 = Ipv4::new()
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap());
        let packet: Packet = Packet::from_layer(ipv4) / esp / Raw::from_bytes(payload());
        packet.compile().unwrap_err()
    }
}
