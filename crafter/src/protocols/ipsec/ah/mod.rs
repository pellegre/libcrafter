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
pub(crate) mod icv;

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::icmp::{Icmpv4, Icmpv6};
use crate::protocols::ip::shared::protocol_numbers::{
    IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IPV6, IPPROTO_NO_NEXT, IPPROTO_TCP, IPPROTO_UDP,
};
use crate::protocols::ipsec::sa::{IpsecMode, SecurityAssociation};
use crate::protocols::ipv4::Ipv4;
use crate::protocols::ipv6::Ipv6;
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object, payload_bytes_after};
use crate::protocols::{Tcp, Udp};
use crate::{CrafterError, Result};

use self::icv::{
    canonical_ipv4_for_ah, canonical_ipv6_for_ah, preceding_ipv4_header_bytes,
    preceding_ipv6_header_bytes,
};

/// IP protocol number for IPv4-in-IPv4 encapsulation (tunnel-mode inner IPv4).
///
/// IANA assigns protocol number 4 to "IPv4 encapsulation"; the shared
/// `protocol_numbers` table does not define a constant for it, so AH carries a
/// local one for the tunnel-mode Next Header (RFC 4302 §3.1.2).
const IPPROTO_IPV4: u8 = 4;

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

    /// IP version of the header immediately preceding AH in the packet stack.
    ///
    /// AH authenticates the enclosing IP header, whose immutable-field
    /// canonicalization differs by version (RFC 4302 §3.3.3.1.1 vs §3.3.3.1.2).
    /// Returns `4` for a preceding [`Ipv4`], `6` for a preceding [`Ipv6`], and a
    /// structured error otherwise — AH built without an enclosing IP header
    /// surfaces a typed error rather than guessing.
    fn preceding_ip_version(ctx: &LayerContext<'_>) -> Result<u8> {
        let previous = ctx.previous().ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ah.compile.previous",
                "AH requires a preceding IP header to authenticate",
            )
        })?;
        let any = previous.as_any();
        if any.is::<Ipv4>() {
            Ok(4)
        } else if any.is::<Ipv6>() {
            Ok(6)
        } else {
            Err(CrafterError::invalid_field_value(
                "ah.compile.previous",
                "preceding layer is not an IPv4 or IPv6 header",
            ))
        }
    }

    /// Resolve the AH Next Header for `compile()` (RFC 4302 §2.1).
    ///
    /// A caller-set value (including a deliberately wrong one) wins. Otherwise it
    /// is derived from the following layer via [`layer_ah_next_header`] under the
    /// SA's mode (tunnel → inner IP 4/41, transport → the upper-layer protocol
    /// number); with no following layer the Next Header is `IPPROTO_NO_NEXT` (59).
    fn effective_next_header(&self, ctx: &LayerContext<'_>, mode: IpsecMode) -> u8 {
        if let Some(next_header) = self.next_header.value().copied() {
            return next_header;
        }
        ctx.next()
            .and_then(|layer| layer_ah_next_header(layer, mode))
            .unwrap_or(IPPROTO_NO_NEXT)
    }

    /// Canonicalize the immutable bytes of the IP header preceding AH (RFC 4302
    /// §3.3.3.1): the IPv4 or IPv6 base header (and any IPv6 extension headers),
    /// with mutable fields zeroed, as the first part of the ICV input.
    fn canonical_preceding_ip(ctx: &LayerContext<'_>, ip_version: u8) -> Result<Vec<u8>> {
        if ip_version == 6 {
            let (base, ext) = preceding_ipv6_header_bytes(ctx)?;
            canonical_ipv6_for_ah(&base, &ext)
        } else {
            let header = preceding_ipv4_header_bytes(ctx)?;
            canonical_ipv4_for_ah(&header)
        }
    }

    /// Assemble the fixed AH header (Next Header | Payload Len | Reserved | SPI |
    /// Seq) followed by the ICV field, which is `zeroed` for the ICV-input form
    /// and the computed ICV bytes for the on-wire form.
    ///
    /// `payload_len`, `reserved`, `spi`, and `sequence` are the resolved field
    /// values; `icv` is the (already-padded) ICV bytes to place in the ICV field.
    fn assemble_header(
        next_header: u8,
        payload_len: u8,
        reserved: u16,
        spi: u32,
        sequence: u32,
        icv: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(header::AH_FIXED_LEN + icv.len());
        bytes.push(next_header);
        bytes.push(payload_len);
        bytes.extend_from_slice(&reserved.to_be_bytes());
        bytes.extend_from_slice(&spi.to_be_bytes());
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(icv);
        bytes
    }

    /// Compute the AH Integrity Check Value over the RFC 4302 §3.3.3 ICV input.
    ///
    /// The ICV input is `canonical immutable IP header || AH header with the ICV
    /// field zeroed || upper-layer data`, with the high-order 32-bit Extended
    /// Sequence Number word appended when the SA enables ESN (RFC 4302 §3.3.3.2).
    /// The ICV is computed via the SA's integrity algorithm and zero-padded to the
    /// boundary-aligned [`Ah::effective_icv_len`].
    ///
    /// Returns the padded ICV bytes. The HMAC and AES-XCBC-MAC integrity
    /// algorithms (the RFC 8221 MUST/SHOULD set) key directly from the SA's
    /// integrity key; the AES-GMAC salt/IV key folding (RFC 4543) is layered in a
    /// later step alongside the verify path.
    fn compute_icv(
        &self,
        ctx: &LayerContext<'_>,
        sa: &SecurityAssociation,
        ip_version: u8,
        next_header: u8,
        payload_len: u8,
        reserved: u16,
        spi: u32,
        sequence: u32,
    ) -> Result<Vec<u8>> {
        let padded_icv_len = self.effective_icv_len(ip_version);

        // RFC 4302 §3.3.3: ICV input = canonical IP header || AH header with the
        // ICV field zeroed || upper-layer data (|| ESN high word when enabled).
        let canonical_ip = Self::canonical_preceding_ip(ctx, ip_version)?;
        let zeroed = vec![0u8; padded_icv_len];
        let ah_zeroed =
            Self::assemble_header(next_header, payload_len, reserved, spi, sequence, &zeroed);
        let upper = payload_bytes_after(*ctx)?;

        let mut input = Vec::with_capacity(canonical_ip.len() + ah_zeroed.len() + upper.len() + 4);
        input.extend_from_slice(&canonical_ip);
        input.extend_from_slice(&ah_zeroed);
        input.extend_from_slice(&upper);
        if sa.esn {
            let high = self
                .high_sequence
                .value()
                .copied()
                .unwrap_or(DEFAULT_AH_HIGH_SEQUENCE);
            input.extend_from_slice(&high.to_be_bytes());
        }

        // Compute the ICV via the SA integrity algorithm, then zero-pad it to the
        // boundary-aligned length the AH header reserves (RFC 4302 §2.6).
        let transform = sa.integ.integrity_transform()?;
        let mut icv = transform.compute(&sa.integ_key, &input)?;
        if icv.len() < padded_icv_len {
            icv.resize(padded_icv_len, 0);
        }
        Ok(icv)
    }

    /// Compile the AH header and ICV into `out` (RFC 4302 §3.3).
    ///
    /// AH inserts its header and ICV between the preceding IP header and the
    /// upper-layer data; it does **not** consume the following layers (unlike
    /// ESP), so the protected payload is emitted in the clear by those layers
    /// afterwards (RFC 4302 §3.1). This method emits only the AH bytes.
    ///
    /// The Payload Len, Reserved, SPI, Sequence, and Next Header fields use the
    /// caller's override when set, else the RFC-derived value. The ICV is the
    /// caller `icv` override (zero-padded to the boundary) when set, else computed
    /// from the SA's integrity algorithm over the §3.3.3 ICV input. A bare AH with
    /// neither an SA nor an ICV override emits the header with an empty ICV.
    fn compile_ah(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let ip_version = Self::preceding_ip_version(ctx)?;

        let mode = self.sa.as_ref().map(|sa| sa.mode).unwrap_or_default();
        let next_header = self.effective_next_header(ctx, mode);
        let payload_len = self.effective_payload_len(ip_version);
        let reserved = self
            .reserved
            .value()
            .copied()
            .unwrap_or(DEFAULT_AH_RESERVED);
        let spi = self.spi.value().copied().unwrap_or(DEFAULT_AH_SPI);
        let sequence = self
            .sequence
            .value()
            .copied()
            .unwrap_or(DEFAULT_AH_SEQUENCE);

        // Resolve the ICV: a caller override (zero-padded to the AH boundary)
        // wins; otherwise compute it from the SA when one is attached; with
        // neither the ICV field is empty.
        let padded_icv_len = self.effective_icv_len(ip_version);
        let icv = if let Some(icv) = self.icv.value() {
            let mut icv = icv.clone();
            if icv.len() < padded_icv_len {
                icv.resize(padded_icv_len, 0);
            }
            icv
        } else if let Some(sa) = self.sa.as_ref() {
            self.compute_icv(
                ctx,
                sa,
                ip_version,
                next_header,
                payload_len,
                reserved,
                spi,
                sequence,
            )?
        } else {
            Vec::new()
        };

        let header = Self::assemble_header(next_header, payload_len, reserved, spi, sequence, &icv);
        out.extend_from_slice(&header);
        Ok(())
    }
}

/// Map a following layer to the AH Next Header value for the given mode
/// (RFC 4302 §2.1, §3.1).
///
/// - **Transport mode**: the Next Header is the protected upper-layer protocol
///   number — TCP (6), UDP (17), ICMPv4 (1), or ICMPv6 (58). An inner IP header
///   is still mapped to its IP-in-IP protocol number.
/// - **Tunnel mode**: the protected data is an entire inner IP datagram, so the
///   Next Header is `IPv4`-in-`IPv4` (4) or `IPv6` (41).
///
/// A following layer AH does not recognize yields `None`; the caller then falls
/// back to `IPPROTO_NO_NEXT` (59) rather than guessing.
fn layer_ah_next_header(layer: &dyn Layer, _mode: IpsecMode) -> Option<u8> {
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

impl Layer for Ah {
    fn name(&self) -> &'static str {
        "Ah"
    }

    fn encoded_len(&self) -> usize {
        // Context-free capacity hint: the fixed 12-octet header plus the unpadded
        // ICV length. The exact on-wire size (boundary-padded ICV) depends on the
        // enclosing IP version and is refined by `encoded_len_with_context`; the
        // full summary/inspection surface is finalized in a later step.
        header::AH_FIXED_LEN + self.unpadded_icv_len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.compile_ah(ctx, out)
    }

    impl_layer_object!(Ah);
}

impl_layer_div!(Ah);

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

    // --- compile (ICV computation) golden vector --------------------------

    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ah::icv::{canonical_ipv4_for_ah, preceding_ipv4_header_bytes};
    use crate::protocols::ipsec::crypto::IntegrityTransform;
    use crate::protocols::ipv4::{Ipv4, IPPROTO_AH};
    use crate::protocols::transport::common::payload_bytes_after;
    use crate::protocols::Tcp;

    /// A 32-octet HMAC-SHA-256 integrity key (fixed, documentation-only).
    fn hmac_key() -> Vec<u8> {
        vec![0x77u8; 32]
    }

    /// Build the expected AH datagram bytes — `Next Header | Payload Len |
    /// Reserved | SPI | Seq | ICV` — using the already-RFC-KAT-proven
    /// [`IntegrityTransform`] over the RFC 4302 §3.3.3 ICV input. This locks the
    /// step-26 wire assembly and ICV-input ordering against the proven crypto
    /// without re-deriving the MAC by hand.
    ///
    /// `ip_ctx` is the compile context of the AH layer (index 1), used to read the
    /// preceding IPv4 header bytes exactly as `compile()` does.
    fn expected_ah_bytes(
        ip_ctx: &LayerContext<'_>,
        integ_key: &[u8],
        spi: u32,
        sequence: u32,
        next_header: u8,
        payload_len: u8,
        reserved: u16,
        icv_len: usize,
    ) -> Vec<u8> {
        // Canonical immutable IPv4 header (mutable fields zeroed; protocol 51).
        let ip_header = preceding_ipv4_header_bytes(ip_ctx).unwrap();
        let canonical_ip = canonical_ipv4_for_ah(&ip_header).unwrap();

        // AH header with the ICV field zeroed at its padded length.
        let mut ah_zeroed = Vec::new();
        ah_zeroed.push(next_header);
        ah_zeroed.push(payload_len);
        ah_zeroed.extend_from_slice(&reserved.to_be_bytes());
        ah_zeroed.extend_from_slice(&spi.to_be_bytes());
        ah_zeroed.extend_from_slice(&sequence.to_be_bytes());
        ah_zeroed.extend_from_slice(&vec![0u8; icv_len]);

        // Upper-layer data (the following layers, in the clear).
        let upper = payload_bytes_after(*ip_ctx).unwrap();

        let mut input = Vec::new();
        input.extend_from_slice(&canonical_ip);
        input.extend_from_slice(&ah_zeroed);
        input.extend_from_slice(&upper);

        let mut icv = IntegrityTransform::HmacSha2_256_128
            .compute(integ_key, &input)
            .unwrap();
        icv.resize(icv_len, 0);

        // Wire bytes: Next Header | Payload Len | Reserved | SPI | Seq | ICV.
        let mut out = Vec::new();
        out.push(next_header);
        out.push(payload_len);
        out.extend_from_slice(&reserved.to_be_bytes());
        out.extend_from_slice(&spi.to_be_bytes());
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&icv);
        out
    }

    #[test]
    fn compile_ipv4_ah_hmac_sha256_golden() {
        // Ipv4 / Ah::secured(sa) / Tcp / Raw over HMAC-SHA-256-128 with a fixed
        // integrity key, asserting exact AH bytes. The enclosing IPv4 pins
        // protocol = AH (51) so the canonical header reflects the AH datagram.
        let sa = SecurityAssociation::new(0x0000_2000)
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key());
        assert!(sa.validate().is_ok());

        let ipv4 = Ipv4::new()
            .protocol(IPPROTO_AH)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap())
            .ttl(64);
        let ah = Ah::secured(sa.clone()).spi(0x0000_2000).sequence(1);

        // Ipv4 / Ah / Tcp / Raw. AH does not consume the following layers, so the
        // whole packet compiles the IPv4 header, the AH header+ICV, then the
        // cleartext Tcp / Raw tail.
        let packet: Packet = ipv4 / ah / Tcp::new() / Raw::from_bytes([0xDE, 0xAD, 0xBE, 0xEF]);

        // Compile the whole packet; the AH bytes sit between the IP header and the
        // Tcp payload.
        let whole = packet.compile().unwrap();

        // Compile just the AH layer (index 1) to assert its exact bytes.
        let ah_ctx = LayerContext::new(&packet, 1);
        let mut ah_bytes = Vec::new();
        packet
            .get(1)
            .unwrap()
            .compile(&ah_ctx, &mut ah_bytes)
            .unwrap();

        // HMAC-SHA-256-128 ICV is 16 octets (already 32-bit aligned on IPv4), so
        // Payload Len = (12 + 16)/4 − 2 = 5 and the AH header is 28 octets.
        let next_header = IPPROTO_TCP;
        let payload_len = 5u8;
        let reserved = 0u16;
        let icv_len = 16usize;
        let expected = expected_ah_bytes(
            &ah_ctx,
            &hmac_key(),
            0x0000_2000,
            1,
            next_header,
            payload_len,
            reserved,
            icv_len,
        );
        assert_eq!(ah_bytes, expected);

        // Structural locks on the AH header fields (RFC 4302 §2).
        assert_eq!(
            ah_bytes[0], IPPROTO_TCP,
            "Next Header is the inner protocol"
        );
        assert_eq!(ah_bytes[1], 5, "Payload Len = (12 + 16)/4 − 2");
        assert_eq!(&ah_bytes[2..4], &[0, 0], "Reserved is zero");
        assert_eq!(&ah_bytes[4..8], &0x0000_2000u32.to_be_bytes(), "SPI");
        assert_eq!(&ah_bytes[8..12], &1u32.to_be_bytes(), "Sequence");
        assert_eq!(ah_bytes.len(), header::AH_FIXED_LEN + icv_len);

        // AH does not consume the tail: the whole packet carries the cleartext
        // Tcp / Raw payload after the AH datagram, so the AH bytes appear verbatim
        // inside the compiled packet immediately after the IPv4 header.
        let ip_header = preceding_ipv4_header_bytes(&ah_ctx).unwrap();
        let ah_start = ip_header.len();
        assert_eq!(&whole[ah_start..ah_start + ah_bytes.len()], &ah_bytes[..]);
        // The 4-octet Raw payload survives in the clear at the end of the packet.
        assert_eq!(&whole[whole.len() - 4..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
