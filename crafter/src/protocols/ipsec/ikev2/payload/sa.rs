//! IKEv2 Security Association (SA) payload, type 33 (RFC 7296 §3.3).
//!
//! An SA payload offers one or more **Proposals**; each Proposal names a
//! protocol (IKE/ESP/AH) and lists the **Transforms** that make up a complete
//! cryptographic suite (encryption, PRF, integrity, key-exchange method, and
//! Extended Sequence Numbers). Each Transform may carry one or more **Transform
//! Attributes** (most commonly Key Length) in the AF-tagged TV/TLV form.
//!
//! The wire layout (RFC 7296 §3.3) nests three substructures inside the
//! payload body that follows the 4-octet generic payload header (emitted by
//! [`write_generic_payload_header`]):
//!
//! - **Proposal Substructure (§3.3.1):** Last Substruc (1) | RESERVED (1) |
//!   Proposal Length (2) | Proposal Num (1) | Protocol ID (1) | SPI Size (1) |
//!   Num Transforms (1) | SPI (SPI Size) | Transforms. `Last Substruc` is `0`
//!   on the final Proposal and `2` when more Proposals follow.
//! - **Transform Substructure (§3.3.2):** Last Substruc (1) | RESERVED (1) |
//!   Transform Length (2) | Transform Type (1) | RESERVED (1) | Transform ID
//!   (2) | Transform Attributes. `Last Substruc` is `0` on the final Transform
//!   and `3` when more Transforms follow.
//! - **Transform Attribute (§3.3.5):** AF (1 bit) + Attribute Type (15 bits)
//!   packed into 2 octets, then either a 2-octet Value (TV form, AF = 1) or a
//!   2-octet Length followed by Length octets of Value (TLV form, AF = 0).
//!
//! The Last Substruc flags and every Length are auto-filled by `compile()` per
//! §3.3, and any caller-pinned value is emitted verbatim so deliberately
//! malformed proposals can be constructed for testing.
//!
//! Transform IDs reuse the algorithm enums from Step 07 where applicable, but
//! the substructures store the raw `u8`/`u16` codepoints so that any value —
//! including key-exchange-method and ESN IDs this crate does not otherwise
//! model — round-trips byte-for-byte.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::CrafterError;
use crate::Result;

/// Layer name for the IKEv2 SA payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_SA_PAYLOAD_NAME: &str = "IkeSaPayload";

/// Length of the fixed Proposal Substructure header (RFC 7296 §3.3.1): Last
/// Substruc (1) + RESERVED (1) + Proposal Length (2) + Proposal Num (1) +
/// Protocol ID (1) + SPI Size (1) + Num Transforms (1) = 8 octets, excluding
/// the variable SPI and the Transforms that follow.
pub const PROPOSAL_FIXED_LEN: usize = 8;

/// Length of the fixed Transform Substructure header (RFC 7296 §3.3.2): Last
/// Substruc (1) + RESERVED (1) + Transform Length (2) + Transform Type (1) +
/// RESERVED (1) + Transform ID (2) = 8 octets, excluding the Transform
/// Attributes that follow.
pub const TRANSFORM_FIXED_LEN: usize = 8;

/// `Last Substruc` value `0`: this is the final substructure (RFC 7296 §3.3.1,
/// §3.3.2).
pub const SUBSTRUC_LAST: u8 = 0;

/// `Last Substruc` value `2`: more Proposal Substructures follow (RFC 7296
/// §3.3.1).
pub const SUBSTRUC_MORE_PROPOSAL: u8 = 2;

/// `Last Substruc` value `3`: more Transform Substructures follow (RFC 7296
/// §3.3.2).
pub const SUBSTRUC_MORE_TRANSFORM: u8 = 3;

// --- Protocol IDs (RFC 7296 §3.3.1; IANA "IKEv2 Security Protocol Identifiers")

/// Protocol ID `IKE` (RFC 7296 §3.3.1): the IKE SA itself.
pub const PROTOCOL_ID_IKE: u8 = 1;
/// Protocol ID `AH` (RFC 7296 §3.3.1).
pub const PROTOCOL_ID_AH: u8 = 2;
/// Protocol ID `ESP` (RFC 7296 §3.3.1).
pub const PROTOCOL_ID_ESP: u8 = 3;

// --- Transform Types (RFC 7296 §3.3.2; IANA "Transform Type Values") --------

/// Transform Type `ENCR` — Encryption Algorithm (RFC 7296 §3.3.2).
pub const TRANSFORM_TYPE_ENCR: u8 = 1;
/// Transform Type `PRF` — Pseudo-random Function (RFC 7296 §3.3.2).
pub const TRANSFORM_TYPE_PRF: u8 = 2;
/// Transform Type `INTEG` — Integrity Algorithm (RFC 7296 §3.3.2).
pub const TRANSFORM_TYPE_INTEG: u8 = 3;
/// Transform Type `D-H` — Key Exchange Method / Diffie-Hellman Group
/// (RFC 7296 §3.3.2).
pub const TRANSFORM_TYPE_DH: u8 = 4;
/// Transform Type `ESN` — Extended Sequence Numbers (RFC 7296 §3.3.2).
pub const TRANSFORM_TYPE_ESN: u8 = 5;

// --- Transform Attribute format (RFC 7296 §3.3.5) ---------------------------

/// Transform Attribute Format bit (RFC 7296 §3.3.5): the high bit of the
/// 2-octet Attribute Type field. Set (`1`) selects TV (Type/Value) form with a
/// 2-octet inline value; clear (`0`) selects TLV (Type/Length/Value) form.
pub const ATTRIBUTE_FORMAT_TV: u16 = 0x8000;

/// Attribute Type `Key Length` (RFC 7296 §3.3.5): the key length in bits for a
/// variable-key-length encryption transform, carried in TV form.
pub const ATTRIBUTE_TYPE_KEY_LENGTH: u16 = 14;

/// One IKEv2 Transform Attribute in AF-tagged TV/TLV form (RFC 7296 §3.3.5).
///
/// The on-wire 2-octet Attribute Type word packs the Format bit
/// ([`ATTRIBUTE_FORMAT_TV`]) in its high bit and the 15-bit attribute type in
/// the low bits. In **TV** form (Format = 1) the attribute is exactly 4 octets:
/// the type word followed by a 2-octet value. In **TLV** form (Format = 0) the
/// type word is followed by a 2-octet length and that many octets of value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformAttribute {
    /// The 15-bit attribute type (without the Format bit), e.g.
    /// [`ATTRIBUTE_TYPE_KEY_LENGTH`].
    attribute_type: u16,
    /// TV value (`Some` in Type/Value form) or TLV value (`None` here means the
    /// `tlv_value` field carries the bytes). Exactly one of `tv_value` /
    /// `tlv_value` is populated.
    tv_value: Option<u16>,
    /// TLV value bytes (populated only in Type/Length/Value form).
    tlv_value: Option<Vec<u8>>,
}

impl TransformAttribute {
    /// A TV (Type/Value) attribute (RFC 7296 §3.3.5): a 4-octet attribute whose
    /// value is the given 16-bit word. Use this for fixed-width attributes such
    /// as Key Length ([`TransformAttribute::key_length`]).
    pub fn tv(attribute_type: u16, value: u16) -> Self {
        Self {
            attribute_type: attribute_type & !ATTRIBUTE_FORMAT_TV,
            tv_value: Some(value),
            tlv_value: None,
        }
    }

    /// A TLV (Type/Length/Value) attribute (RFC 7296 §3.3.5) carrying arbitrary
    /// value bytes; `compile()` fills the on-wire Length from the byte count.
    pub fn tlv(attribute_type: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            attribute_type: attribute_type & !ATTRIBUTE_FORMAT_TV,
            tv_value: None,
            tlv_value: Some(value.into()),
        }
    }

    /// The Key Length attribute (type 14, TV form) in bits (RFC 7296 §3.3.5),
    /// used to select a non-default key size for a variable-length cipher
    /// (e.g. `256` for AES-256).
    pub fn key_length(bits: u16) -> Self {
        Self::tv(ATTRIBUTE_TYPE_KEY_LENGTH, bits)
    }

    /// The 15-bit attribute type (without the Format bit).
    pub fn attribute_type(&self) -> u16 {
        self.attribute_type
    }

    /// Whether this attribute is encoded in TV (Type/Value) form.
    pub fn is_tv(&self) -> bool {
        self.tv_value.is_some()
    }

    /// The TV value, when this attribute is in Type/Value form.
    pub fn tv_value(&self) -> Option<u16> {
        self.tv_value
    }

    /// The TLV value bytes, when this attribute is in Type/Length/Value form.
    pub fn tlv_value(&self) -> Option<&[u8]> {
        self.tlv_value.as_deref()
    }

    /// On-wire length of this attribute in octets (RFC 7296 §3.3.5): 4 for TV
    /// form, `4 + value.len()` for TLV form.
    pub fn encoded_len(&self) -> usize {
        match (&self.tv_value, &self.tlv_value) {
            (Some(_), _) => 4,
            (None, Some(value)) => 4 + value.len(),
            (None, None) => 4,
        }
    }

    /// Append this attribute to `out` in its AF-tagged TV/TLV form
    /// (RFC 7296 §3.3.5).
    fn write(&self, out: &mut Vec<u8>) {
        match (&self.tv_value, &self.tlv_value) {
            (Some(value), _) => {
                let type_word = ATTRIBUTE_FORMAT_TV | (self.attribute_type & !ATTRIBUTE_FORMAT_TV);
                out.extend_from_slice(&type_word.to_be_bytes());
                out.extend_from_slice(&value.to_be_bytes());
            }
            (None, Some(value)) => {
                let type_word = self.attribute_type & !ATTRIBUTE_FORMAT_TV;
                out.extend_from_slice(&type_word.to_be_bytes());
                out.extend_from_slice(&(value.len() as u16).to_be_bytes());
                out.extend_from_slice(value);
            }
            (None, None) => {
                // Defensive: an attribute with neither value behaves as an empty
                // TLV (4-octet header, zero-length value).
                let type_word = self.attribute_type & !ATTRIBUTE_FORMAT_TV;
                out.extend_from_slice(&type_word.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
            }
        }
    }
}

/// One IKEv2 Transform Substructure (RFC 7296 §3.3.2).
///
/// A Transform names a single component of a cryptographic suite by its
/// Transform Type (ENCR/PRF/INTEG/D-H/ESN) and a 16-bit Transform ID, and may
/// carry Transform Attributes (e.g. Key Length). The Last Substruc flag and the
/// Transform Length are auto-filled by the enclosing [`Proposal`]/payload
/// `compile()` unless the caller pins them.
#[derive(Debug, Clone)]
pub struct Transform {
    /// Transform Type (RFC 7296 §3.3.2; see `TRANSFORM_TYPE_*`).
    transform_type: u8,
    /// Transform ID (RFC 7296 §3.3.2): the algorithm/group/ESN codepoint.
    transform_id: u16,
    /// Transform Attributes appended after the fixed header (RFC 7296 §3.3.5).
    attributes: Vec<TransformAttribute>,
    /// Caller override for `Last Substruc`; unset lets the chain auto-fill it.
    last_substruc: Field<u8>,
    /// Caller override for Transform Length; unset lets `compile()` fill it.
    length: Field<u16>,
}

impl Transform {
    /// A Transform with the given Transform Type and ID and no attributes.
    pub fn new(transform_type: u8, transform_id: u16) -> Self {
        Self {
            transform_type,
            transform_id,
            attributes: Vec::new(),
            last_substruc: Field::unset(),
            length: Field::unset(),
        }
    }

    /// An Encryption (ENCR, type 1) Transform (RFC 7296 §3.3.2).
    pub fn encryption(transform_id: u16) -> Self {
        Self::new(TRANSFORM_TYPE_ENCR, transform_id)
    }

    /// A Pseudo-random Function (PRF, type 2) Transform (RFC 7296 §3.3.2).
    pub fn prf(transform_id: u16) -> Self {
        Self::new(TRANSFORM_TYPE_PRF, transform_id)
    }

    /// An Integrity (INTEG, type 3) Transform (RFC 7296 §3.3.2).
    pub fn integrity(transform_id: u16) -> Self {
        Self::new(TRANSFORM_TYPE_INTEG, transform_id)
    }

    /// A Key Exchange Method / Diffie-Hellman group (D-H, type 4) Transform
    /// (RFC 7296 §3.3.2).
    pub fn key_exchange(transform_id: u16) -> Self {
        Self::new(TRANSFORM_TYPE_DH, transform_id)
    }

    /// An Extended Sequence Numbers (ESN, type 5) Transform (RFC 7296 §3.3.2).
    pub fn extended_sequence_numbers(transform_id: u16) -> Self {
        Self::new(TRANSFORM_TYPE_ESN, transform_id)
    }

    /// Append a Transform Attribute (RFC 7296 §3.3.5), consuming-builder style.
    pub fn with_attribute(mut self, attribute: TransformAttribute) -> Self {
        self.attributes.push(attribute);
        self
    }

    /// Append a Transform Attribute (RFC 7296 §3.3.5) in place.
    pub fn push_attribute(&mut self, attribute: TransformAttribute) {
        self.attributes.push(attribute);
    }

    /// Pin the `Last Substruc` octet explicitly (RFC 7296 §3.3.2). An override
    /// is emitted verbatim, including a deliberately wrong value.
    pub fn last_substruc(mut self, last_substruc: u8) -> Self {
        self.last_substruc.set_user(last_substruc);
        self
    }

    /// Pin the Transform Length explicitly (RFC 7296 §3.3.2). An override is
    /// emitted verbatim, including a deliberately wrong value.
    pub fn length(mut self, length: u16) -> Self {
        self.length.set_user(length);
        self
    }

    /// Transform Type (RFC 7296 §3.3.2).
    pub fn transform_type(&self) -> u8 {
        self.transform_type
    }

    /// Transform ID (RFC 7296 §3.3.2).
    pub fn transform_id(&self) -> u16 {
        self.transform_id
    }

    /// The Transform Attributes carried by this Transform (RFC 7296 §3.3.5).
    pub fn attributes(&self) -> &[TransformAttribute] {
        &self.attributes
    }

    /// On-wire length of this Transform in octets: the 8-octet fixed header plus
    /// every attribute (RFC 7296 §3.3.2).
    pub fn encoded_len(&self) -> usize {
        let attrs: usize = self.attributes.iter().map(|a| a.encoded_len()).sum();
        TRANSFORM_FIXED_LEN + attrs
    }

    /// Append this Transform to `out` (RFC 7296 §3.3.2).
    ///
    /// `is_last` drives the auto-filled `Last Substruc` (`0` for the final
    /// Transform in a Proposal, `3` otherwise); a caller-pinned override wins.
    fn write(&self, out: &mut Vec<u8>, is_last: bool) {
        let last_substruc = self.last_substruc.value().copied().unwrap_or(if is_last {
            SUBSTRUC_LAST
        } else {
            SUBSTRUC_MORE_TRANSFORM
        });
        let length = self
            .length
            .value()
            .copied()
            .unwrap_or(self.encoded_len() as u16);

        out.push(last_substruc);
        out.push(0); // RESERVED.
        out.extend_from_slice(&length.to_be_bytes());
        out.push(self.transform_type);
        out.push(0); // RESERVED.
        out.extend_from_slice(&self.transform_id.to_be_bytes());
        for attribute in &self.attributes {
            attribute.write(out);
        }
    }
}

/// One IKEv2 Proposal Substructure (RFC 7296 §3.3.1).
///
/// A Proposal names a security protocol (IKE/ESP/AH) by its Protocol ID, an
/// optional SPI, and a Proposal Num, and lists the Transforms that make up a
/// complete suite. The Last Substruc flag, Proposal Length, SPI Size, and Num
/// Transforms are auto-filled by `compile()` unless the caller pins them.
#[derive(Debug, Clone)]
pub struct Proposal {
    /// Proposal Num (RFC 7296 §3.3.1): proposals in one SA payload are numbered
    /// sequentially from 1.
    num: u8,
    /// Protocol ID (RFC 7296 §3.3.1; see `PROTOCOL_ID_*`).
    protocol_id: u8,
    /// SPI bytes (RFC 7296 §3.3.1): empty for an initial IKE proposal, 4 octets
    /// for ESP/AH. The SPI Size on the wire is derived from this length.
    spi: Vec<u8>,
    /// The Transforms making up the proposed suite (RFC 7296 §3.3.2).
    transforms: Vec<Transform>,
    /// Caller override for `Last Substruc`; unset lets the chain auto-fill it.
    last_substruc: Field<u8>,
    /// Caller override for Proposal Length; unset lets `compile()` fill it.
    length: Field<u16>,
    /// Caller override for SPI Size; unset derives it from `spi.len()`.
    spi_size: Field<u8>,
    /// Caller override for Num Transforms; unset derives it from
    /// `transforms.len()`.
    num_transforms: Field<u8>,
}

impl Proposal {
    /// A Proposal with the given Proposal Num and Protocol ID, an empty SPI, and
    /// no Transforms (RFC 7296 §3.3.1).
    pub fn new(num: u8, protocol_id: u8) -> Self {
        Self {
            num,
            protocol_id,
            spi: Vec::new(),
            transforms: Vec::new(),
            last_substruc: Field::unset(),
            length: Field::unset(),
            spi_size: Field::unset(),
            num_transforms: Field::unset(),
        }
    }

    /// Set the SPI bytes (RFC 7296 §3.3.1); the wire SPI Size derives from the
    /// byte length unless [`Proposal::spi_size`] overrides it.
    pub fn spi(mut self, spi: impl Into<Vec<u8>>) -> Self {
        self.spi = spi.into();
        self
    }

    /// Append a Transform (RFC 7296 §3.3.2), consuming-builder style.
    pub fn with_transform(mut self, transform: Transform) -> Self {
        self.transforms.push(transform);
        self
    }

    /// Append a Transform (RFC 7296 §3.3.2) in place.
    pub fn push_transform(&mut self, transform: Transform) {
        self.transforms.push(transform);
    }

    /// Pin the `Last Substruc` octet explicitly (RFC 7296 §3.3.1). An override
    /// is emitted verbatim, including a deliberately wrong value.
    pub fn last_substruc(mut self, last_substruc: u8) -> Self {
        self.last_substruc.set_user(last_substruc);
        self
    }

    /// Pin the Proposal Length explicitly (RFC 7296 §3.3.1).
    pub fn length(mut self, length: u16) -> Self {
        self.length.set_user(length);
        self
    }

    /// Pin the SPI Size explicitly (RFC 7296 §3.3.1), independent of the SPI
    /// byte length, for malformed-input testing.
    pub fn spi_size(mut self, spi_size: u8) -> Self {
        self.spi_size.set_user(spi_size);
        self
    }

    /// Pin the Num Transforms count explicitly (RFC 7296 §3.3.1), independent of
    /// the actual transform count, for malformed-input testing.
    pub fn num_transforms(mut self, num_transforms: u8) -> Self {
        self.num_transforms.set_user(num_transforms);
        self
    }

    /// Proposal Num (RFC 7296 §3.3.1).
    pub fn proposal_num(&self) -> u8 {
        self.num
    }

    /// Protocol ID (RFC 7296 §3.3.1).
    pub fn protocol_id(&self) -> u8 {
        self.protocol_id
    }

    /// SPI bytes (RFC 7296 §3.3.1).
    pub fn spi_bytes(&self) -> &[u8] {
        &self.spi
    }

    /// The Transforms in this Proposal (RFC 7296 §3.3.2).
    pub fn transforms(&self) -> &[Transform] {
        &self.transforms
    }

    /// On-wire length of this Proposal in octets: the 8-octet fixed header, the
    /// SPI, and every Transform (RFC 7296 §3.3.1).
    pub fn encoded_len(&self) -> usize {
        let transforms: usize = self.transforms.iter().map(|t| t.encoded_len()).sum();
        PROPOSAL_FIXED_LEN + self.spi.len() + transforms
    }

    /// Append this Proposal to `out` (RFC 7296 §3.3.1).
    ///
    /// `is_last` drives the auto-filled `Last Substruc` (`0` for the final
    /// Proposal, `2` otherwise); caller-pinned overrides win for Last Substruc,
    /// Length, SPI Size, and Num Transforms.
    fn write(&self, out: &mut Vec<u8>, is_last: bool) {
        let last_substruc = self.last_substruc.value().copied().unwrap_or(if is_last {
            SUBSTRUC_LAST
        } else {
            SUBSTRUC_MORE_PROPOSAL
        });
        let length = self
            .length
            .value()
            .copied()
            .unwrap_or(self.encoded_len() as u16);
        let spi_size = self
            .spi_size
            .value()
            .copied()
            .unwrap_or(self.spi.len() as u8);
        let num_transforms = self
            .num_transforms
            .value()
            .copied()
            .unwrap_or(self.transforms.len() as u8);

        out.push(last_substruc);
        out.push(0); // RESERVED.
        out.extend_from_slice(&length.to_be_bytes());
        out.push(self.num);
        out.push(self.protocol_id);
        out.push(spi_size);
        out.push(num_transforms);
        out.extend_from_slice(&self.spi);

        let last_index = self.transforms.len().saturating_sub(1);
        for (index, transform) in self.transforms.iter().enumerate() {
            transform.write(out, index == last_index);
        }
    }
}

/// IKEv2 Security Association (SA) payload, type 33 (RFC 7296 §3.3).
///
/// Holds the ordered list of [`Proposal`]s the payload offers. As a [`Layer`]
/// it emits the 4-octet generic payload header (via
/// [`write_generic_payload_header`]) followed by the proposal substructures.
/// The generic-header Next Payload, Critical flag, and Payload Length are the
/// shared overridable fields carried in [`PayloadHeaderFields`].
#[derive(Debug, Clone)]
pub struct IkeSaPayload {
    /// The Proposals offered by this SA payload (RFC 7296 §3.3.1).
    proposals: Vec<Proposal>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeSaPayload {
    /// An empty SA payload with no proposals (RFC 7296 §3.3).
    pub fn new() -> Self {
        Self {
            proposals: Vec::new(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// Append a Proposal (RFC 7296 §3.3.1), consuming-builder style.
    pub fn with_proposal(mut self, proposal: Proposal) -> Self {
        self.proposals.push(proposal);
        self
    }

    /// Append a Proposal (RFC 7296 §3.3.1) in place.
    pub fn push_proposal(&mut self, proposal: Proposal) {
        self.proposals.push(proposal);
    }

    /// The Proposals offered by this payload (RFC 7296 §3.3.1).
    pub fn proposals(&self) -> &[Proposal] {
        &self.proposals
    }

    /// Pin the generic-header Next Payload explicitly (RFC 7296 §3.2).
    pub fn next_payload(mut self, next_payload: u8) -> Self {
        self.header.set_next_payload(next_payload);
        self
    }

    /// Pin the generic-header Payload Length explicitly (RFC 7296 §3.2).
    pub fn payload_length(mut self, length: u16) -> Self {
        self.header.set_length(length);
        self
    }

    /// Set the Critical (C) flag for this payload explicitly (RFC 7296 §3.2).
    pub fn critical(mut self, critical: bool) -> Self {
        self.header.set_critical(critical);
        self
    }

    /// The proposal substructures (everything after the generic header), per
    /// RFC 7296 §3.3.1: each Proposal in order with auto-filled Last Substruc.
    fn proposals_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let last_index = self.proposals.len().saturating_sub(1);
        for (index, proposal) in self.proposals.iter().enumerate() {
            proposal.write(&mut out, index == last_index);
        }
        out
    }
}

impl Default for IkeSaPayload {
    fn default() -> Self {
        Self::new()
    }
}

impl IkePayload for IkeSaPayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::SecurityAssociation
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.proposals_bytes())
    }

    fn next_payload_override(&self) -> Option<u8> {
        self.header.next_payload_override()
    }

    fn payload_length_override(&self) -> Option<u16> {
        self.header.payload_length_override()
    }

    fn critical(&self) -> bool {
        self.header.critical()
    }
}

impl Layer for IkeSaPayload {
    fn name(&self) -> &'static str {
        IKE_SA_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        let transforms: usize = self.proposals.iter().map(|p| p.transforms.len()).sum();
        format!(
            "IkeSaPayload(proposals={}, transforms={})",
            self.proposals.len(),
            transforms
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![("proposals", self.proposals.len().to_string())];
        for proposal in &self.proposals {
            let transforms = proposal
                .transforms
                .iter()
                .map(|t| format!("{}:{}", t.transform_type, t.transform_id))
                .collect::<Vec<_>>()
                .join(",");
            fields.push((
                "proposal",
                format!(
                    "num={} protocol={} spi_len={} transforms=[{}]",
                    proposal.num,
                    proposal.protocol_id,
                    proposal.spi.len(),
                    transforms
                ),
            ));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        let body: usize = self.proposals.iter().map(|p| p.encoded_len()).sum();
        super::GENERIC_PAYLOAD_HEADER_LEN + body
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // proposal substructures.
        let body = self.payload_body(ctx)?;
        write_generic_payload_header(
            out,
            ctx,
            self.next_payload_override(),
            self.critical(),
            self.payload_length_override(),
            body.len(),
        )?;
        out.extend_from_slice(&body);
        Ok(())
    }

    impl_layer_object!(IkeSaPayload);
}

impl_layer_div!(IkeSaPayload);

// --- Local parse helpers (Step 45 closes the full registry decode) ----------

/// A parsed Transform Attribute and the number of octets it consumed
/// (RFC 7296 §3.3.5). Local to this step; the full payload-chain decode is
/// added by Step 45.
pub(crate) fn parse_transform_attribute(bytes: &[u8]) -> Result<(TransformAttribute, usize)> {
    if bytes.len() < 4 {
        return Err(CrafterError::buffer_too_short(
            "ikev2.sa.attribute",
            4,
            bytes.len(),
        ));
    }
    let type_word = u16::from_be_bytes([bytes[0], bytes[1]]);
    let attribute_type = type_word & !ATTRIBUTE_FORMAT_TV;
    if type_word & ATTRIBUTE_FORMAT_TV != 0 {
        let value = u16::from_be_bytes([bytes[2], bytes[3]]);
        Ok((TransformAttribute::tv(attribute_type, value), 4))
    } else {
        let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let end = 4 + len;
        if bytes.len() < end {
            return Err(CrafterError::buffer_too_short(
                "ikev2.sa.attribute.value",
                end,
                bytes.len(),
            ));
        }
        Ok((
            TransformAttribute::tlv(attribute_type, bytes[4..end].to_vec()),
            end,
        ))
    }
}

/// A parsed Transform and the number of octets it consumed (RFC 7296 §3.3.2).
pub(crate) fn parse_transform(bytes: &[u8]) -> Result<(Transform, usize)> {
    if bytes.len() < TRANSFORM_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.sa.transform",
            TRANSFORM_FIXED_LEN,
            bytes.len(),
        ));
    }
    let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if length < TRANSFORM_FIXED_LEN || bytes.len() < length {
        return Err(CrafterError::buffer_too_short(
            "ikev2.sa.transform.length",
            length.max(TRANSFORM_FIXED_LEN),
            bytes.len(),
        ));
    }
    let transform_type = bytes[4];
    let transform_id = u16::from_be_bytes([bytes[6], bytes[7]]);
    let mut transform = Transform::new(transform_type, transform_id);

    let mut offset = TRANSFORM_FIXED_LEN;
    while offset < length {
        let (attribute, consumed) = parse_transform_attribute(&bytes[offset..length])?;
        transform.push_attribute(attribute);
        offset += consumed;
    }
    Ok((transform, length))
}

/// A parsed Proposal and the number of octets it consumed (RFC 7296 §3.3.1).
pub(crate) fn parse_proposal(bytes: &[u8]) -> Result<(Proposal, usize)> {
    if bytes.len() < PROPOSAL_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.sa.proposal",
            PROPOSAL_FIXED_LEN,
            bytes.len(),
        ));
    }
    let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let num = bytes[4];
    let protocol_id = bytes[5];
    let spi_size = bytes[6] as usize;
    let num_transforms = bytes[7] as usize;
    if length < PROPOSAL_FIXED_LEN || bytes.len() < length {
        return Err(CrafterError::buffer_too_short(
            "ikev2.sa.proposal.length",
            length.max(PROPOSAL_FIXED_LEN),
            bytes.len(),
        ));
    }

    let spi_end = PROPOSAL_FIXED_LEN + spi_size;
    if length < spi_end {
        return Err(CrafterError::buffer_too_short(
            "ikev2.sa.proposal.spi",
            spi_end,
            length,
        ));
    }
    let spi = bytes[PROPOSAL_FIXED_LEN..spi_end].to_vec();
    let mut proposal = Proposal::new(num, protocol_id).spi(spi);

    let mut offset = spi_end;
    for _ in 0..num_transforms {
        let (transform, consumed) = parse_transform(&bytes[offset..length])?;
        proposal.push_transform(transform);
        offset += consumed;
    }
    Ok((proposal, length))
}

/// Parse the proposal substructures of an SA payload **body** (the bytes after
/// the 4-octet generic header), per RFC 7296 §3.3. Local to this step; the
/// registry-driven chain decode lands in Step 45.
pub(crate) fn parse_sa_payload_body(bytes: &[u8]) -> Result<IkeSaPayload> {
    let mut payload = IkeSaPayload::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let (proposal, consumed) = parse_proposal(&bytes[offset..])?;
        payload.push_proposal(proposal);
        offset += consumed;
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::sa::{AUTH_HMAC_SHA2_256_128, ENCR_AES_GCM_16};

    /// Compile a standalone SA payload and return its full bytes (generic header
    /// + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeSaPayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative full proposal: AES-GCM-16 (with a 256-bit key length
    /// attribute) + HMAC-SHA-256-128 + a D-H group (MODP-2048, group 14) + ESN.
    fn sample_proposal() -> Proposal {
        Proposal::new(1, PROTOCOL_ID_ESP)
            .spi(vec![0x11, 0x22, 0x33, 0x44])
            .with_transform(
                Transform::encryption(ENCR_AES_GCM_16)
                    .with_attribute(TransformAttribute::key_length(256)),
            )
            .with_transform(Transform::integrity(AUTH_HMAC_SHA2_256_128))
            .with_transform(Transform::key_exchange(14))
            .with_transform(Transform::extended_sequence_numbers(1))
    }

    #[test]
    fn substructure_constants_match_rfc() {
        // RFC 7296 §3.3.1/§3.3.2: Last Substruc is 0 (last), 2 (more proposals),
        // 3 (more transforms); fixed substructure headers are 8 octets each.
        assert_eq!(SUBSTRUC_LAST, 0);
        assert_eq!(SUBSTRUC_MORE_PROPOSAL, 2);
        assert_eq!(SUBSTRUC_MORE_TRANSFORM, 3);
        assert_eq!(PROPOSAL_FIXED_LEN, 8);
        assert_eq!(TRANSFORM_FIXED_LEN, 8);
        // Transform Types (RFC 7296 §3.3.2).
        assert_eq!(TRANSFORM_TYPE_ENCR, 1);
        assert_eq!(TRANSFORM_TYPE_PRF, 2);
        assert_eq!(TRANSFORM_TYPE_INTEG, 3);
        assert_eq!(TRANSFORM_TYPE_DH, 4);
        assert_eq!(TRANSFORM_TYPE_ESN, 5);
        // Key Length attribute is TV form, type 14 (RFC 7296 §3.3.5).
        assert_eq!(ATTRIBUTE_TYPE_KEY_LENGTH, 14);
        assert_eq!(ATTRIBUTE_FORMAT_TV, 0x8000);
    }

    #[test]
    fn payload_type_is_security_association() {
        assert_eq!(
            IkeSaPayload::new().payload_type(),
            PayloadType::SecurityAssociation
        );
        // The layer name is registered for the chain next-payload derivation.
        assert_eq!(IkeSaPayload::new().name(), IKE_SA_PAYLOAD_NAME);
    }

    #[test]
    fn key_length_attribute_is_tv_four_octets() {
        // RFC 7296 §3.3.5: Key Length is a TV attribute, exactly 4 octets:
        // 0x800E (AF=1, type 14) then the 16-bit key length in bits.
        let attribute = TransformAttribute::key_length(128);
        assert!(attribute.is_tv());
        assert_eq!(attribute.encoded_len(), 4);
        let mut out = Vec::new();
        attribute.write(&mut out);
        assert_eq!(out, vec![0x80, 0x0E, 0x00, 0x80]);
    }

    #[test]
    fn tlv_attribute_carries_length_and_value() {
        // RFC 7296 §3.3.5: a TLV attribute is the type word (AF=0), a 16-bit
        // length, and that many value octets.
        let attribute = TransformAttribute::tlv(7, vec![0xDE, 0xAD, 0xBE]);
        assert!(!attribute.is_tv());
        assert_eq!(attribute.encoded_len(), 7);
        let mut out = Vec::new();
        attribute.write(&mut out);
        assert_eq!(out, vec![0x00, 0x07, 0x00, 0x03, 0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn single_transform_auto_fills_last_and_length() {
        // The sole transform in a proposal is the last one (Last Substruc = 0)
        // and its length is 8 + attribute bytes (RFC 7296 §3.3.2).
        let transform = Transform::encryption(ENCR_AES_GCM_16)
            .with_attribute(TransformAttribute::key_length(256));
        let mut out = Vec::new();
        transform.write(&mut out, true);

        assert_eq!(out[0], SUBSTRUC_LAST);
        assert_eq!(out[1], 0); // RESERVED.
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 12); // 8 + 4-octet attr.
        assert_eq!(out[4], TRANSFORM_TYPE_ENCR);
        assert_eq!(out[5], 0); // RESERVED.
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), ENCR_AES_GCM_16);
        assert_eq!(out.len(), 12);
    }

    #[test]
    fn non_last_transform_uses_more_flag() {
        let mut out = Vec::new();
        Transform::integrity(AUTH_HMAC_SHA2_256_128).write(&mut out, false);
        assert_eq!(out[0], SUBSTRUC_MORE_TRANSFORM);
    }

    #[test]
    fn proposal_auto_fills_counts_and_length() {
        // RFC 7296 §3.3.1: SPI Size and Num Transforms derive from the data, and
        // the Proposal Length is the fixed header + SPI + transforms.
        let proposal = sample_proposal();
        let mut out = Vec::new();
        proposal.write(&mut out, true);

        assert_eq!(out[0], SUBSTRUC_LAST);
        assert_eq!(out[4], 1); // Proposal Num.
        assert_eq!(out[5], PROTOCOL_ID_ESP);
        assert_eq!(out[6], 4); // SPI Size derived from 4-octet SPI.
        assert_eq!(out[7], 4); // Num Transforms.
        let length = u16::from_be_bytes([out[2], out[3]]) as usize;
        assert_eq!(length, proposal.encoded_len());
        assert_eq!(length, out.len());
        // SPI bytes follow the fixed header.
        assert_eq!(&out[8..12], &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the proposal body.
        let payload = IkeSaPayload::new().with_proposal(sample_proposal());
        let bytes = compile_payload(payload.clone());

        // Generic header: Next Payload terminator, Critical clear.
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[1], 0);
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive.
        let payload = IkeSaPayload::new()
            .with_proposal(sample_proposal())
            .next_payload(40)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 40);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn payload_chain_next_payload_points_at_sa() {
        // An SA payload following another layer derives the preceding header's
        // Next Payload through payload_type_for_layer_name (registered this
        // step) as the SA codepoint (33).
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_SA,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_SA_PAYLOAD_NAME),
            Some(PayloadType::SecurityAssociation)
        );
        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / IkeSaPayload::new();
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_SA);
    }

    #[test]
    fn round_trip_preserves_transform_ids_and_attributes() {
        // Build the full sample proposal, compile to wire, parse the body back,
        // and confirm every transform type/ID and the key-length attribute
        // round-trip (Step 45 closes the registry decode; this is the local
        // parse helper for the step).
        let payload = IkeSaPayload::new().with_proposal(sample_proposal());
        let bytes = compile_payload(payload);

        // Skip the 4-octet generic header to reach the proposal body.
        let parsed = parse_sa_payload_body(&bytes[4..]).unwrap();
        assert_eq!(parsed.proposals().len(), 1);
        let proposal = &parsed.proposals()[0];
        assert_eq!(proposal.proposal_num(), 1);
        assert_eq!(proposal.protocol_id(), PROTOCOL_ID_ESP);
        assert_eq!(proposal.spi_bytes(), &[0x11, 0x22, 0x33, 0x44]);

        let transforms = proposal.transforms();
        assert_eq!(transforms.len(), 4);

        // Transform 0: ENCR AES-GCM-16 with a 256-bit key-length attribute.
        assert_eq!(transforms[0].transform_type(), TRANSFORM_TYPE_ENCR);
        assert_eq!(transforms[0].transform_id(), ENCR_AES_GCM_16);
        assert_eq!(transforms[0].attributes().len(), 1);
        let key_length = &transforms[0].attributes()[0];
        assert!(key_length.is_tv());
        assert_eq!(key_length.attribute_type(), ATTRIBUTE_TYPE_KEY_LENGTH);
        assert_eq!(key_length.tv_value(), Some(256));

        // Transform 1: INTEG HMAC-SHA-256-128, no attributes.
        assert_eq!(transforms[1].transform_type(), TRANSFORM_TYPE_INTEG);
        assert_eq!(transforms[1].transform_id(), AUTH_HMAC_SHA2_256_128);
        assert!(transforms[1].attributes().is_empty());

        // Transform 2: D-H group 14.
        assert_eq!(transforms[2].transform_type(), TRANSFORM_TYPE_DH);
        assert_eq!(transforms[2].transform_id(), 14);

        // Transform 3: ESN enabled (ID 1).
        assert_eq!(transforms[3].transform_type(), TRANSFORM_TYPE_ESN);
        assert_eq!(transforms[3].transform_id(), 1);
    }

    #[test]
    fn round_trip_preserves_tlv_attribute() {
        // A TLV attribute (arbitrary bytes) survives the compile/parse round-trip.
        let payload = IkeSaPayload::new().with_proposal(
            Proposal::new(1, PROTOCOL_ID_ESP).with_transform(
                Transform::encryption(ENCR_AES_GCM_16)
                    .with_attribute(TransformAttribute::tlv(99, vec![0x01, 0x02, 0x03])),
            ),
        );
        let bytes = compile_payload(payload);
        let parsed = parse_sa_payload_body(&bytes[4..]).unwrap();
        let attribute = &parsed.proposals()[0].transforms()[0].attributes()[0];
        assert!(!attribute.is_tv());
        assert_eq!(attribute.attribute_type(), 99);
        assert_eq!(attribute.tlv_value(), Some(&[0x01, 0x02, 0x03][..]));
    }

    #[test]
    fn multiple_proposals_use_more_then_last_flags() {
        // RFC 7296 §3.3.1: every proposal but the last carries Last Substruc 2.
        let payload = IkeSaPayload::new()
            .with_proposal(
                Proposal::new(1, PROTOCOL_ID_ESP)
                    .with_transform(Transform::encryption(ENCR_AES_GCM_16)),
            )
            .with_proposal(
                Proposal::new(2, PROTOCOL_ID_ESP)
                    .with_transform(Transform::encryption(ENCR_AES_CBC_FOR_TEST)),
            );
        let bytes = compile_payload(payload);
        let body = &bytes[4..];
        // First proposal: Last Substruc = 2 (more follow).
        assert_eq!(body[0], SUBSTRUC_MORE_PROPOSAL);
        let first_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        // Second proposal: Last Substruc = 0 (last).
        assert_eq!(body[first_len], SUBSTRUC_LAST);
    }

    /// ENCR_AES_CBC transform ID (12), used by the multi-proposal test.
    const ENCR_AES_CBC_FOR_TEST: u16 = 12;

    #[test]
    fn parse_rejects_truncated_proposal() {
        // A buffer shorter than the fixed proposal header is a structured error.
        let err = parse_sa_payload_body(&[0u8, 0, 0]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
