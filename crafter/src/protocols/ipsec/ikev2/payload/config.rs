//! IKEv2 Configuration (CP) payload, type 47 (RFC 7296 §3.15).
//!
//! The Configuration payload carries configuration information (most commonly an
//! internal IP address handed to a remote access client) between IKE peers. The
//! body that follows the 4-octet generic payload header (emitted by
//! [`write_generic_payload_header`]) is:
//!
//! ```text
//!  CFG Type (1) | RESERVED (3) | Configuration Attributes (variable)
//! ```
//!
//! (RFC 7296 §3.15). The CFG Type names the message kind — a request, a reply, a
//! push of configuration (set), or an acknowledgement — and the three RESERVED
//! octets are sent as zero. The Configuration Attributes are a sequence of
//! Type/Length/Value entries (RFC 7296 §3.15.1):
//!
//! ```text
//!  Reserved (1 bit) | Attribute Type (15 bits) | Length (2) | Value (Length)
//! ```
//!
//! This crate models the **wire form only** — the attribute values are opaque
//! bytes carried verbatim and no attribute semantics are interpreted. The
//! generic-header Payload Length and each attribute Length are auto-filled by
//! `compile()`, while any caller-pinned value (Next Payload, Payload Length,
//! Critical) is emitted verbatim so deliberately malformed Configuration payloads
//! can be constructed for testing.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
#[cfg(test)]
use crate::CrafterError;
use crate::Result;

/// Layer name for the IKEv2 Configuration payload, registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_CONFIG_PAYLOAD_NAME: &str = "IkeConfigPayload";

/// Length of the fixed Configuration payload body header (RFC 7296 §3.15): CFG
/// Type (1) + RESERVED (3) = 4 octets, excluding the Configuration Attributes
/// that follow.
pub const CONFIG_FIXED_LEN: usize = 4;

/// Length of a Configuration Attribute fixed header (RFC 7296 §3.15.1):
/// Reserved + Attribute Type (2) + Length (2) = 4 octets, excluding the Value.
pub const CONFIG_ATTRIBUTE_FIXED_LEN: usize = 4;

// --- CFG Type (RFC 7296 §3.15; IANA "IKEv2 Configuration Payload CFG Types") --

/// CFG Type `1` — CFG_REQUEST: a request for configuration (RFC 7296 §3.15).
pub const CFG_REQUEST: u8 = 1;
/// CFG Type `2` — CFG_REPLY: a reply carrying configuration (RFC 7296 §3.15).
pub const CFG_REPLY: u8 = 2;
/// CFG Type `3` — CFG_SET: a push of configuration to the peer (RFC 7296 §3.15).
pub const CFG_SET: u8 = 3;
/// CFG Type `4` — CFG_ACK: an acknowledgement of a CFG_SET (RFC 7296 §3.15).
pub const CFG_ACK: u8 = 4;

/// An IKEv2 Configuration payload CFG Type (RFC 7296 §3.15; IANA "IKEv2
/// Configuration Payload CFG Types" registry).
///
/// Names the kind of Configuration message. Only the four standard types are
/// given named variants; any other codepoint is preserved as [`CfgType::Unknown`]
/// so a decoded value round-trips byte-for-byte and the crate never rejects an
/// unrecognized type (the IANA registry remains the authority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CfgType {
    /// `1` — CFG_REQUEST.
    Request,
    /// `2` — CFG_REPLY.
    Reply,
    /// `3` — CFG_SET.
    Set,
    /// `4` — CFG_ACK.
    Ack,
    /// Any CFG Type not named above, preserved verbatim.
    Unknown(u8),
}

impl CfgType {
    /// The 8-bit CFG Type codepoint for this type (RFC 7296 §3.15).
    /// [`CfgType::Unknown`] returns its preserved value.
    pub fn codepoint(self) -> u8 {
        match self {
            Self::Request => CFG_REQUEST,
            Self::Reply => CFG_REPLY,
            Self::Set => CFG_SET,
            Self::Ack => CFG_ACK,
            Self::Unknown(value) => value,
        }
    }
}

impl From<u8> for CfgType {
    /// Map a CFG Type codepoint to a [`CfgType`], preserving an unrecognized
    /// value as [`CfgType::Unknown`] (never erroring).
    fn from(value: u8) -> Self {
        match value {
            CFG_REQUEST => Self::Request,
            CFG_REPLY => Self::Reply,
            CFG_SET => Self::Set,
            CFG_ACK => Self::Ack,
            other => Self::Unknown(other),
        }
    }
}

// `TryFrom<u8>` is provided automatically by the blanket
// `impl<T, U: Into<T>> TryFrom<U> for T` (`Error = Infallible`): unknown
// codepoints are preserved as `Unknown` rather than rejected, so the conversion
// never fails. This mirrors `PayloadType` and the SA algorithm enums.

impl From<CfgType> for u8 {
    fn from(cfg_type: CfgType) -> Self {
        cfg_type.codepoint()
    }
}

/// One IKEv2 Configuration Attribute in Type/Length/Value form (RFC 7296
/// §3.15.1).
///
/// The on-wire 2-octet Attribute Type word carries a Reserved high bit and a
/// 15-bit attribute type; the 2-octet Length gives the Value length, and the
/// Value follows. The crate carries the Value as opaque bytes and auto-fills the
/// Length from the byte count on compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigAttribute {
    /// The 15-bit attribute type (without the reserved high bit), e.g. type 1 for
    /// INTERNAL_IP4_ADDRESS (RFC 7296 §3.15.1; IANA registry).
    attribute_type: u16,
    /// The attribute Value, carried verbatim (RFC 7296 §3.15.1). An empty Value
    /// is valid (e.g. an attribute requested with no preferred value).
    value: Vec<u8>,
}

impl ConfigAttribute {
    /// A Configuration Attribute of the given attribute type carrying the given
    /// Value bytes verbatim (RFC 7296 §3.15.1). The reserved high bit of the
    /// type word is masked off and always sent as zero.
    pub fn new(attribute_type: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            attribute_type: attribute_type & 0x7FFF,
            value: value.into(),
        }
    }

    /// The 15-bit attribute type (RFC 7296 §3.15.1).
    pub fn attribute_type(&self) -> u16 {
        self.attribute_type
    }

    /// The attribute Value bytes (RFC 7296 §3.15.1).
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// On-wire length of this attribute in octets (RFC 7296 §3.15.1): the 4-octet
    /// fixed header plus the Value length.
    pub fn encoded_len(&self) -> usize {
        CONFIG_ATTRIBUTE_FIXED_LEN + self.value.len()
    }

    /// Append this attribute to `out` per RFC 7296 §3.15.1: Reserved + Attribute
    /// Type (2) | Length (2) | Value. The reserved high bit is sent as zero and
    /// the Length is filled from the Value byte count.
    fn write(&self, out: &mut Vec<u8>) {
        // The high bit is Reserved (sent as zero); the low 15 bits are the type.
        out.extend_from_slice(&(self.attribute_type & 0x7FFF).to_be_bytes());
        out.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.value);
    }
}

/// IKEv2 Configuration (CP) payload, type 47 (RFC 7296 §3.15).
///
/// Carries the CFG Type and a sequence of [`ConfigAttribute`]s. As a [`Layer`] it
/// emits the 4-octet generic payload header (via [`write_generic_payload_header`])
/// followed by the body `CFG Type (1) | RESERVED (3, zero) | Configuration
/// Attributes`. The generic-header Next Payload, Critical flag, and Payload Length
/// are the shared overridable fields carried in [`PayloadHeaderFields`].
///
/// The crate carries each attribute Value verbatim and never interprets an
/// attribute; the caller supplies the type and bytes.
#[derive(Debug, Clone)]
pub struct IkeConfigPayload {
    /// CFG Type (RFC 7296 §3.15; see `CFG_*` constants and [`CfgType`]).
    cfg_type: Field<u8>,
    /// The Configuration Attributes, in order (RFC 7296 §3.15.1).
    attributes: Vec<ConfigAttribute>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeConfigPayload {
    /// A Configuration payload of the given CFG Type with no attributes
    /// (RFC 7296 §3.15). Add attributes with [`IkeConfigPayload::attribute`] or
    /// [`IkeConfigPayload::attributes`].
    ///
    /// The CFG Type accepts anything convertible into a [`CfgType`] (a named
    /// variant, a `CfgType::Unknown`, or a bare `u8`).
    pub fn new(cfg_type: impl Into<CfgType>) -> Self {
        Self {
            cfg_type: Field::user(cfg_type.into().codepoint()),
            attributes: Vec::new(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// A CFG_REQUEST Configuration payload (CFG Type 1; RFC 7296 §3.15).
    pub fn request() -> Self {
        Self::new(CfgType::Request)
    }

    /// A CFG_REPLY Configuration payload (CFG Type 2; RFC 7296 §3.15).
    pub fn reply() -> Self {
        Self::new(CfgType::Reply)
    }

    /// Set the CFG Type (RFC 7296 §3.15), accepting a named [`CfgType`], a
    /// `CfgType::Unknown`, or a bare `u8`.
    pub fn cfg_type(mut self, cfg_type: impl Into<CfgType>) -> Self {
        self.cfg_type.set_user(cfg_type.into().codepoint());
        self
    }

    /// Append one Configuration Attribute (RFC 7296 §3.15.1), consuming-builder
    /// style.
    pub fn attribute(mut self, attribute: ConfigAttribute) -> Self {
        self.attributes.push(attribute);
        self
    }

    /// Replace the Configuration Attribute list (RFC 7296 §3.15.1).
    pub fn attributes(mut self, attributes: impl Into<Vec<ConfigAttribute>>) -> Self {
        self.attributes = attributes.into();
        self
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

    /// The raw CFG Type codepoint (RFC 7296 §3.15).
    pub fn cfg_type_value(&self) -> u8 {
        self.cfg_type.value().copied().unwrap_or(0)
    }

    /// The CFG Type as a [`CfgType`] (RFC 7296 §3.15).
    pub fn cfg_type_kind(&self) -> CfgType {
        CfgType::from(self.cfg_type_value())
    }

    /// The Configuration Attributes, in order (RFC 7296 §3.15.1).
    pub fn config_attributes(&self) -> &[ConfigAttribute] {
        &self.attributes
    }

    /// The Configuration body (everything after the 4-octet generic header), per
    /// RFC 7296 §3.15: CFG Type (1) | RESERVED (3, zero) | Configuration
    /// Attributes.
    fn config_body(&self) -> Vec<u8> {
        let attributes_len: usize = self
            .attributes
            .iter()
            .map(ConfigAttribute::encoded_len)
            .sum();
        let mut out = Vec::with_capacity(CONFIG_FIXED_LEN + attributes_len);
        out.push(self.cfg_type_value());
        out.extend_from_slice(&[0u8, 0u8, 0u8]); // RESERVED (3 octets).
        for attribute in &self.attributes {
            attribute.write(&mut out);
        }
        out
    }
}

impl IkePayload for IkeConfigPayload {
    fn payload_type(&self) -> PayloadType {
        PayloadType::Configuration
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.config_body())
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

impl Layer for IkeConfigPayload {
    fn name(&self) -> &'static str {
        IKE_CONFIG_PAYLOAD_NAME
    }

    fn summary(&self) -> String {
        format!(
            "IkeConfigPayload(cfg_type={}, attributes={})",
            self.cfg_type_value(),
            self.attributes.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("cfg_type", self.cfg_type_value().to_string()),
            ("attributes", self.attributes.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        let attributes_len: usize = self
            .attributes
            .iter()
            .map(ConfigAttribute::encoded_len)
            .sum();
        super::GENERIC_PAYLOAD_HEADER_LEN + CONFIG_FIXED_LEN + attributes_len
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // Configuration body (CFG Type | RESERVED | Configuration Attributes).
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

    impl_layer_object!(IkeConfigPayload);
}

impl_layer_div!(IkeConfigPayload);

// --- Local parse helper (Step 45 closes the full registry decode) -----------

/// Parse a Configuration payload **body** (the bytes after the 4-octet generic
/// header) per RFC 7296 §3.15. Local to this step; the registry-driven chain
/// decode lands in Step 45.
///
/// The CFG Type is read from the first octet, the three RESERVED octets are
/// ignored, and the remainder is parsed as a sequence of Configuration Attributes
/// (RFC 7296 §3.15.1) until the body is consumed. A buffer shorter than the fixed
/// body header, or an attribute whose Length runs past the end, is a structured
/// error rather than a panic. The reserved high bit of each attribute type word
/// is masked off on decode.
#[cfg(test)]
fn parse_config_payload_body(bytes: &[u8]) -> Result<IkeConfigPayload> {
    if bytes.len() < CONFIG_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.config",
            CONFIG_FIXED_LEN,
            bytes.len(),
        ));
    }
    let cfg_type = bytes[0];
    // bytes[1..4] are RESERVED and ignored on decode.
    let mut attributes = Vec::new();
    let mut offset = CONFIG_FIXED_LEN;
    while offset < bytes.len() {
        let header_end = offset + CONFIG_ATTRIBUTE_FIXED_LEN;
        if bytes.len() < header_end {
            return Err(CrafterError::buffer_too_short(
                "ikev2.config.attribute",
                header_end,
                bytes.len(),
            ));
        }
        let attribute_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) & 0x7FFF;
        let length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        let value_end = header_end + length;
        if bytes.len() < value_end {
            return Err(CrafterError::buffer_too_short(
                "ikev2.config.attribute.value",
                value_end,
                bytes.len(),
            ));
        }
        let value = bytes[header_end..value_end].to_vec();
        attributes.push(ConfigAttribute::new(attribute_type, value));
        offset = value_end;
    }
    Ok(IkeConfigPayload::new(cfg_type).attributes(attributes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ikev2::payload::GENERIC_PAYLOAD_HEADER_LEN;

    /// Attribute type INTERNAL_IP4_ADDRESS (RFC 7296 §3.15.1; IANA registry).
    const ATTR_INTERNAL_IP4_ADDRESS: u16 = 1;
    /// Attribute type INTERNAL_IP4_DNS (RFC 7296 §3.15.1; IANA registry).
    const ATTR_INTERNAL_IP4_DNS: u16 = 3;

    /// Compile a standalone Configuration payload and return its full bytes
    /// (generic header + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeConfigPayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative CFG_REPLY carrying an INTERNAL_IP4_ADDRESS
    /// (192.0.2.10, documentation address space) and an INTERNAL_IP4_DNS
    /// (192.0.2.53) attribute (RFC 7296 §3.15.1).
    fn cfg_reply_payload() -> IkeConfigPayload {
        IkeConfigPayload::reply()
            .attribute(ConfigAttribute::new(
                ATTR_INTERNAL_IP4_ADDRESS,
                vec![192u8, 0, 2, 10],
            ))
            .attribute(ConfigAttribute::new(
                ATTR_INTERNAL_IP4_DNS,
                vec![192u8, 0, 2, 53],
            ))
    }

    #[test]
    fn config_constants_match_manifest() {
        // RFC 7296 §3.15 / IANA "IKEv2 Configuration Payload CFG Types".
        assert_eq!(CONFIG_FIXED_LEN, 4);
        assert_eq!(CONFIG_ATTRIBUTE_FIXED_LEN, 4);
        assert_eq!(CFG_REQUEST, 1);
        assert_eq!(CFG_REPLY, 2);
        assert_eq!(CFG_SET, 3);
        assert_eq!(CFG_ACK, 4);
        // The CP payload-type codepoint (RFC 7296 §3.2 / §3.15).
        assert_eq!(PayloadType::Configuration.codepoint(), 47);
    }

    #[test]
    fn cfg_type_round_trips_through_u8() {
        // u8 -> CfgType -> u8 is the identity for every codepoint, named or
        // unassigned (preserved verbatim as Unknown).
        for value in 0u8..=255 {
            let cfg_type = CfgType::from(value);
            assert_eq!(cfg_type.codepoint(), value);
            assert_eq!(u8::from(cfg_type), value);
        }
    }

    #[test]
    fn named_cfg_types_map_to_codepoints() {
        // RFC 7296 §3.15: the four named CFG Types map to their codepoints.
        assert_eq!(CfgType::from(CFG_REQUEST), CfgType::Request);
        assert_eq!(CfgType::from(CFG_REPLY), CfgType::Reply);
        assert_eq!(CfgType::from(CFG_SET), CfgType::Set);
        assert_eq!(CfgType::from(CFG_ACK), CfgType::Ack);
    }

    #[test]
    fn unknown_cfg_type_is_preserved() {
        // A codepoint outside the named set survives as Unknown and round-trips.
        let unassigned = 200u8;
        assert_eq!(CfgType::from(unassigned), CfgType::Unknown(unassigned));
        assert_eq!(CfgType::Unknown(unassigned).codepoint(), unassigned);
    }

    #[test]
    fn payload_type_and_name() {
        let payload = cfg_reply_payload();
        assert_eq!(payload.payload_type(), PayloadType::Configuration);
        // The layer name is registered for the chain next-payload derivation.
        assert_eq!(payload.name(), IKE_CONFIG_PAYLOAD_NAME);
    }

    #[test]
    fn body_lays_out_cfg_type_reserved_then_attributes() {
        // RFC 7296 §3.15: CFG Type (1) | RESERVED (3, zero) | attributes. Each
        // attribute is Reserved+Type (2) | Length (2) | Value.
        let payload = cfg_reply_payload();
        let body = payload.config_body();
        assert_eq!(body[0], CFG_REPLY);
        assert_eq!(&body[1..4], &[0, 0, 0]); // RESERVED.

        // First attribute: INTERNAL_IP4_ADDRESS, length 4, value 192.0.2.10.
        assert_eq!(
            u16::from_be_bytes([body[4], body[5]]),
            ATTR_INTERNAL_IP4_ADDRESS
        );
        assert_eq!(u16::from_be_bytes([body[6], body[7]]), 4);
        assert_eq!(&body[8..12], &[192, 0, 2, 10]);

        // Second attribute: INTERNAL_IP4_DNS, length 4, value 192.0.2.53.
        assert_eq!(
            u16::from_be_bytes([body[12], body[13]]),
            ATTR_INTERNAL_IP4_DNS
        );
        assert_eq!(u16::from_be_bytes([body[14], body[15]]), 4);
        assert_eq!(&body[16..20], &[192, 0, 2, 53]);

        assert_eq!(body.len(), CONFIG_FIXED_LEN + 8 + 8);
    }

    #[test]
    fn attribute_reserved_high_bit_is_masked() {
        // A type value with the reserved high bit set is masked off on the wire
        // (the high bit is Reserved per RFC 7296 §3.15.1).
        let attribute = ConfigAttribute::new(0x8000 | ATTR_INTERNAL_IP4_ADDRESS, vec![0u8; 0]);
        assert_eq!(attribute.attribute_type(), ATTR_INTERNAL_IP4_ADDRESS);
        let mut out = Vec::new();
        attribute.write(&mut out);
        assert_eq!(
            u16::from_be_bytes([out[0], out[1]]),
            ATTR_INTERNAL_IP4_ADDRESS
        );
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 0); // Empty value length.
    }

    #[test]
    fn empty_value_attribute_round_trips() {
        // A CFG_REQUEST commonly carries attributes with empty values (the
        // requester asks for a value). The attribute is just its 4-octet header.
        let payload = IkeConfigPayload::request().attribute(ConfigAttribute::new(
            ATTR_INTERNAL_IP4_ADDRESS,
            Vec::<u8>::new(),
        ));
        let body = payload.config_body();
        assert_eq!(body[0], CFG_REQUEST);
        assert_eq!(u16::from_be_bytes([body[6], body[7]]), 0); // Length 0.
        assert_eq!(body.len(), CONFIG_FIXED_LEN + CONFIG_ATTRIBUTE_FIXED_LEN);
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the Configuration body.
        let payload = cfg_reply_payload();
        let bytes = compile_payload(payload.clone());

        assert_eq!(bytes[0], 0); // Next Payload terminator.
        assert_eq!(bytes[1], 0); // Critical clear.
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
        assert_eq!(
            &bytes[GENERIC_PAYLOAD_HEADER_LEN..],
            &payload.config_body()[..]
        );
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive.
        let payload = cfg_reply_payload()
            .next_payload(48)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 48);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn chain_next_payload_points_at_config() {
        // A Configuration payload following another layer derives the preceding
        // header's Next Payload through payload_type_for_layer_name (registered
        // this step) as the CP codepoint (47).
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_CP,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_CONFIG_PAYLOAD_NAME),
            Some(PayloadType::Configuration)
        );
        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / cfg_reply_payload();
        let ctx = LayerContext::new(&packet, 0);
        assert_eq!(following_next_payload(&ctx), PAYLOAD_CP);
    }

    #[test]
    fn round_trip_preserves_cfg_type_and_attributes() {
        // Build a CFG_REPLY with two attributes, compile to wire, parse the body
        // back, and confirm every field round-trips byte-for-byte (Step 45 closes
        // the registry decode; this is the local parse helper).
        let payload = cfg_reply_payload();
        let bytes = compile_payload(payload.clone());

        let parsed = parse_config_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.cfg_type_value(), CFG_REPLY);
        assert_eq!(parsed.cfg_type_kind(), CfgType::Reply);
        let attributes = parsed.config_attributes();
        assert_eq!(attributes.len(), 2);
        assert_eq!(attributes[0].attribute_type(), ATTR_INTERNAL_IP4_ADDRESS);
        assert_eq!(attributes[0].value(), &[192, 0, 2, 10]);
        assert_eq!(attributes[1].attribute_type(), ATTR_INTERNAL_IP4_DNS);
        assert_eq!(attributes[1].value(), &[192, 0, 2, 53]);

        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn round_trip_empty_attribute_list() {
        // A Configuration payload with no attributes is just CFG Type + RESERVED;
        // it round-trips byte-for-byte.
        let payload = IkeConfigPayload::request();
        let bytes = compile_payload(payload.clone());
        let parsed = parse_config_payload_body(&bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.cfg_type_value(), CFG_REQUEST);
        assert!(parsed.config_attributes().is_empty());
        assert_eq!(compile_payload(parsed), bytes);
    }

    #[test]
    fn parse_rejects_truncated_fixed_header() {
        // A buffer shorter than the fixed Configuration body header is a
        // structured error, not a panic.
        let err = parse_config_payload_body(&[1u8, 0, 0]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    #[test]
    fn parse_rejects_attribute_length_past_end() {
        // An attribute whose Length runs past the available bytes is a structured
        // error. CFG Type 1 | RESERVED | type 1 | length 8 | (only 2 value bytes).
        let body = [1u8, 0, 0, 0, 0x00, 0x01, 0x00, 0x08, 0xAA, 0xBB];
        let err = parse_config_payload_body(&body).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
