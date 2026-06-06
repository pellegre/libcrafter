//! EAPOL base layer.

use core::any::Any;
use core::ops::Div;

use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw};

/// Fixed EAPOL base header length.
pub const EAPOL_HEADER_LEN: usize = 4;

/// EAPOL protocol version 1.
pub const EAPOL_VERSION_1: u8 = 1;
/// EAPOL protocol version 2.
pub const EAPOL_VERSION_2: u8 = 2;
/// EAPOL protocol version 3.
pub const EAPOL_VERSION_3: u8 = 3;

/// EAPOL EAP-Packet packet type.
pub const EAPOL_TYPE_EAP_PACKET: u8 = 0;
/// EAPOL-Start packet type.
pub const EAPOL_TYPE_START: u8 = 1;
/// EAPOL-Logoff packet type.
pub const EAPOL_TYPE_LOGOFF: u8 = 2;
/// EAPOL-Key packet type.
pub const EAPOL_TYPE_KEY: u8 = 3;
/// EAPOL-Encapsulated-ASF-Alert packet type.
pub const EAPOL_TYPE_ASF_ALERT: u8 = 4;

const EAPOL_KEY_INFORMATION_LEN: usize = 2;
const EAPOL_KEY_INFO_DESCRIPTOR_VERSION_MASK: u16 = 0x0007;
const EAPOL_KEY_INFO_DESCRIPTOR_VERSION_SHIFT: u8 = 0;
const EAPOL_KEY_INFO_KEY_TYPE: u16 = 0x0008;
const EAPOL_KEY_INFO_RESERVED_LOW: u16 = 0x0030;
const EAPOL_KEY_INFO_INSTALL: u16 = 0x0040;
const EAPOL_KEY_INFO_KEY_ACK: u16 = 0x0080;
const EAPOL_KEY_INFO_KEY_MIC: u16 = 0x0100;
const EAPOL_KEY_INFO_SECURE: u16 = 0x0200;
const EAPOL_KEY_INFO_ERROR: u16 = 0x0400;
const EAPOL_KEY_INFO_REQUEST: u16 = 0x0800;
const EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA: u16 = 0x1000;
const EAPOL_KEY_INFO_SMK_MESSAGE: u16 = 0x2000;
const EAPOL_KEY_INFO_RESERVED_HIGH: u16 = 0xc000;
const EAPOL_KEY_INFO_RESERVED_MASK: u16 =
    EAPOL_KEY_INFO_RESERVED_LOW | EAPOL_KEY_INFO_RESERVED_HIGH;

/// EAPOL packet type codepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EapolType {
    /// EAP-Packet body.
    EapPacket,
    /// EAPOL-Start bodyless notification.
    Start,
    /// EAPOL-Logoff bodyless notification.
    Logoff,
    /// EAPOL-Key body.
    Key,
    /// Encapsulated ASF alert body.
    AsfAlert,
    /// Unknown caller-supplied or decoded packet type.
    Unknown(u8),
}

impl EapolType {
    /// Create a packet type from its raw numeric value.
    pub const fn from_raw(value: u8) -> Self {
        match value {
            EAPOL_TYPE_EAP_PACKET => Self::EapPacket,
            EAPOL_TYPE_START => Self::Start,
            EAPOL_TYPE_LOGOFF => Self::Logoff,
            EAPOL_TYPE_KEY => Self::Key,
            EAPOL_TYPE_ASF_ALERT => Self::AsfAlert,
            value => Self::Unknown(value),
        }
    }

    /// Raw numeric value.
    pub const fn raw(self) -> u8 {
        match self {
            Self::EapPacket => EAPOL_TYPE_EAP_PACKET,
            Self::Start => EAPOL_TYPE_START,
            Self::Logoff => EAPOL_TYPE_LOGOFF,
            Self::Key => EAPOL_TYPE_KEY,
            Self::AsfAlert => EAPOL_TYPE_ASF_ALERT,
            Self::Unknown(value) => value,
        }
    }

    /// Short stable label.
    pub fn label(self) -> String {
        eapol_type_label(self.raw())
    }
}

impl From<u8> for EapolType {
    fn from(value: u8) -> Self {
        Self::from_raw(value)
    }
}

impl From<EapolType> for u8 {
    fn from(value: EapolType) -> Self {
        value.raw()
    }
}

/// Return a stable label for an EAPOL packet type.
pub fn eapol_type_label(packet_type: u8) -> String {
    match packet_type {
        EAPOL_TYPE_EAP_PACKET => "eap-packet".to_string(),
        EAPOL_TYPE_START => "start".to_string(),
        EAPOL_TYPE_LOGOFF => "logoff".to_string(),
        EAPOL_TYPE_KEY => "key".to_string(),
        EAPOL_TYPE_ASF_ALERT => "asf-alert".to_string(),
        _ => format!("unknown-eapol-type({packet_type})"),
    }
}

/// RSN EAPOL-Key Key Information field.
///
/// The field is a 16-bit big-endian EAPOL-Key subfield. Accessors expose the
/// source-backed RSN bits while the raw word remains available so reserved or
/// future bits round-trip unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EapolKeyInformation {
    bits: u16,
}

impl EapolKeyInformation {
    /// Create an empty Key Information word.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Create a Key Information value from its raw host-endian bit word.
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Create a Key Information value from its raw host-endian bit word.
    pub const fn from_raw(bits: u16) -> Self {
        Self::from_bits(bits)
    }

    /// Decode a Key Information field from exactly two big-endian wire bytes.
    pub const fn from_be_bytes(bytes: [u8; 2]) -> Self {
        Self {
            bits: u16::from_be_bytes(bytes),
        }
    }

    /// Decode a Key Information field from a byte slice.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < EAPOL_KEY_INFORMATION_LEN {
            return Err(CrafterError::buffer_too_short(
                "eapol.key_information",
                EAPOL_KEY_INFORMATION_LEN,
                bytes.len(),
            ));
        }

        Ok(Self::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Return the raw host-endian Key Information bit word.
    pub const fn bits(&self) -> u16 {
        self.bits
    }

    /// Return the raw host-endian Key Information bit word.
    pub const fn raw(&self) -> u16 {
        self.bits
    }

    /// Set the raw host-endian Key Information bit word.
    pub const fn raw_set(mut self, bits: u16) -> Self {
        self.bits = bits;
        self
    }

    /// Builder alias for [`Self::raw_set`].
    pub const fn with_raw(self, bits: u16) -> Self {
        self.raw_set(bits)
    }

    /// Compile the Key Information field to big-endian wire bytes.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.bits.to_be_bytes()
    }

    /// Compile the Key Information field to big-endian wire bytes.
    pub const fn encode(self) -> [u8; 2] {
        self.to_be_bytes()
    }

    /// Three-bit Key Descriptor Version subfield.
    pub const fn descriptor_version(&self) -> u8 {
        ((self.bits & EAPOL_KEY_INFO_DESCRIPTOR_VERSION_MASK)
            >> EAPOL_KEY_INFO_DESCRIPTOR_VERSION_SHIFT) as u8
    }

    /// Compatibility alias for [`Self::descriptor_version`].
    pub const fn key_descriptor_version(&self) -> u8 {
        self.descriptor_version()
    }

    /// Return true when the Key Type bit is set.
    pub const fn key_type(&self) -> bool {
        self.has_flag(EAPOL_KEY_INFO_KEY_TYPE)
    }

    /// Return true when the Install bit is set.
    pub const fn install(&self) -> bool {
        self.has_flag(EAPOL_KEY_INFO_INSTALL)
    }

    /// Return true when the Key ACK bit is set.
    pub const fn key_ack(&self) -> bool {
        self.has_flag(EAPOL_KEY_INFO_KEY_ACK)
    }

    /// Return true when the Key MIC bit is set.
    pub const fn key_mic(&self) -> bool {
        self.has_flag(EAPOL_KEY_INFO_KEY_MIC)
    }

    /// Return true when the Secure bit is set.
    pub const fn secure(&self) -> bool {
        self.has_flag(EAPOL_KEY_INFO_SECURE)
    }

    /// Return true when the Error bit is set.
    pub const fn error(&self) -> bool {
        self.has_flag(EAPOL_KEY_INFO_ERROR)
    }

    /// Return true when the Request bit is set.
    pub const fn request(&self) -> bool {
        self.has_flag(EAPOL_KEY_INFO_REQUEST)
    }

    /// Return true when the Encrypted Key Data bit is set.
    pub const fn encrypted_key_data(&self) -> bool {
        self.has_flag(EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA)
    }

    /// Return true when the SMK Message bit is set.
    pub const fn smk_message(&self) -> bool {
        self.has_flag(EAPOL_KEY_INFO_SMK_MESSAGE)
    }

    /// Reserved bits as they appear in the raw 16-bit word.
    pub const fn reserved_bits(&self) -> u16 {
        self.bits & EAPOL_KEY_INFO_RESERVED_MASK
    }

    /// Set the three-bit Key Descriptor Version subfield.
    ///
    /// Only the low three bits of `descriptor_version` are representable. Use
    /// [`Self::raw_set`] to set an exact 16-bit word.
    pub const fn descriptor_version_set(mut self, descriptor_version: u8) -> Self {
        self.bits = set_key_info_subfield(
            self.bits,
            EAPOL_KEY_INFO_DESCRIPTOR_VERSION_MASK,
            EAPOL_KEY_INFO_DESCRIPTOR_VERSION_SHIFT,
            descriptor_version,
        );
        self
    }

    /// Builder alias for [`Self::descriptor_version_set`].
    pub const fn with_descriptor_version(self, descriptor_version: u8) -> Self {
        self.descriptor_version_set(descriptor_version)
    }

    /// Set or clear the Key Type bit.
    pub const fn key_type_set(mut self, enabled: bool) -> Self {
        self.bits = set_key_info_flag(self.bits, EAPOL_KEY_INFO_KEY_TYPE, enabled);
        self
    }

    /// Builder alias for [`Self::key_type_set`].
    pub const fn with_key_type(self, enabled: bool) -> Self {
        self.key_type_set(enabled)
    }

    /// Set or clear the Install bit.
    pub const fn install_set(mut self, enabled: bool) -> Self {
        self.bits = set_key_info_flag(self.bits, EAPOL_KEY_INFO_INSTALL, enabled);
        self
    }

    /// Builder alias for [`Self::install_set`].
    pub const fn with_install(self, enabled: bool) -> Self {
        self.install_set(enabled)
    }

    /// Set or clear the Key ACK bit.
    pub const fn key_ack_set(mut self, enabled: bool) -> Self {
        self.bits = set_key_info_flag(self.bits, EAPOL_KEY_INFO_KEY_ACK, enabled);
        self
    }

    /// Builder alias for [`Self::key_ack_set`].
    pub const fn with_key_ack(self, enabled: bool) -> Self {
        self.key_ack_set(enabled)
    }

    /// Set or clear the Key MIC bit.
    pub const fn key_mic_set(mut self, enabled: bool) -> Self {
        self.bits = set_key_info_flag(self.bits, EAPOL_KEY_INFO_KEY_MIC, enabled);
        self
    }

    /// Builder alias for [`Self::key_mic_set`].
    pub const fn with_key_mic(self, enabled: bool) -> Self {
        self.key_mic_set(enabled)
    }

    /// Set or clear the Secure bit.
    pub const fn secure_set(mut self, enabled: bool) -> Self {
        self.bits = set_key_info_flag(self.bits, EAPOL_KEY_INFO_SECURE, enabled);
        self
    }

    /// Builder alias for [`Self::secure_set`].
    pub const fn with_secure(self, enabled: bool) -> Self {
        self.secure_set(enabled)
    }

    /// Set or clear the Error bit.
    pub const fn error_set(mut self, enabled: bool) -> Self {
        self.bits = set_key_info_flag(self.bits, EAPOL_KEY_INFO_ERROR, enabled);
        self
    }

    /// Builder alias for [`Self::error_set`].
    pub const fn with_error(self, enabled: bool) -> Self {
        self.error_set(enabled)
    }

    /// Set or clear the Request bit.
    pub const fn request_set(mut self, enabled: bool) -> Self {
        self.bits = set_key_info_flag(self.bits, EAPOL_KEY_INFO_REQUEST, enabled);
        self
    }

    /// Builder alias for [`Self::request_set`].
    pub const fn with_request(self, enabled: bool) -> Self {
        self.request_set(enabled)
    }

    /// Set or clear the Encrypted Key Data bit.
    pub const fn encrypted_key_data_set(mut self, enabled: bool) -> Self {
        self.bits = set_key_info_flag(self.bits, EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA, enabled);
        self
    }

    /// Builder alias for [`Self::encrypted_key_data_set`].
    pub const fn with_encrypted_key_data(self, enabled: bool) -> Self {
        self.encrypted_key_data_set(enabled)
    }

    /// Set or clear the SMK Message bit.
    pub const fn smk_message_set(mut self, enabled: bool) -> Self {
        self.bits = set_key_info_flag(self.bits, EAPOL_KEY_INFO_SMK_MESSAGE, enabled);
        self
    }

    /// Builder alias for [`Self::smk_message_set`].
    pub const fn with_smk_message(self, enabled: bool) -> Self {
        self.smk_message_set(enabled)
    }

    /// Set the reserved bits that this phase does not interpret.
    pub const fn reserved_bits_set(mut self, reserved_bits: u16) -> Self {
        self.bits = (self.bits & !EAPOL_KEY_INFO_RESERVED_MASK)
            | (reserved_bits & EAPOL_KEY_INFO_RESERVED_MASK);
        self
    }

    /// Builder alias for [`Self::reserved_bits_set`].
    pub const fn with_reserved_bits(self, reserved_bits: u16) -> Self {
        self.reserved_bits_set(reserved_bits)
    }

    const fn has_flag(&self, flag: u16) -> bool {
        self.bits & flag != 0
    }
}

/// Extensible Authentication Protocol over LAN base header.
///
/// The base layer owns the EAPOL header and optional opaque body bytes. The
/// crate-internal decode path preserves body bytes as following [`Raw`] bytes
/// so future typed body layers can slot into the same packet stack shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eapol {
    version: Field<u8>,
    packet_type: Field<u8>,
    body_length: Field<u16>,
    body: Vec<u8>,
}

impl Eapol {
    /// Create an EAPOL header with deterministic packet-builder defaults.
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(EAPOL_VERSION_2),
            packet_type: Field::defaulted(EAPOL_TYPE_EAP_PACKET),
            body_length: Field::unset(),
            body: Vec::new(),
        }
    }

    /// Create an EAPOL-Start frame.
    pub fn start() -> Self {
        Self::new().packet_type(EapolType::Start)
    }

    /// Create an EAPOL-Logoff frame.
    pub fn logoff() -> Self {
        Self::new().packet_type(EapolType::Logoff)
    }

    /// Create an EAPOL-Key frame header.
    pub fn key() -> Self {
        Self::new().packet_type(EapolType::Key)
    }

    /// Set the EAPOL protocol version byte.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the EAPOL packet type.
    pub fn packet_type(mut self, packet_type: EapolType) -> Self {
        self.packet_type.set_user(packet_type.raw());
        self
    }

    /// Set the EAPOL packet type as a raw byte.
    pub fn packet_type_raw(mut self, packet_type: u8) -> Self {
        self.packet_type.set_user(packet_type);
        self
    }

    /// Set the EAPOL packet body length explicitly.
    pub fn body_length(mut self, body_length: u16) -> Self {
        self.body_length.set_user(body_length);
        self
    }

    /// Compatibility alias for EAPOL packet body length.
    pub fn len(self, body_length: u16) -> Self {
        self.body_length(body_length)
    }

    /// Set opaque body bytes stored inside this layer.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// EAPOL protocol version byte.
    pub fn version_value(&self) -> u8 {
        value_or_copy(&self.version, EAPOL_VERSION_2)
    }

    /// Raw EAPOL packet type byte.
    pub fn packet_type_value(&self) -> u8 {
        value_or_copy(&self.packet_type, EAPOL_TYPE_EAP_PACKET)
    }

    /// Typed EAPOL packet type view.
    pub fn packet_type_kind(&self) -> EapolType {
        EapolType::from_raw(self.packet_type_value())
    }

    /// Stored EAPOL packet body length, when explicit or decoded.
    pub fn body_length_value(&self) -> Option<u16> {
        self.body_length.value().copied()
    }

    /// Opaque body bytes stored inside this layer.
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    /// Mutably borrow opaque body bytes stored inside this layer.
    pub fn body_bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }

    /// Consume the layer and return its stored opaque body bytes.
    pub fn into_body_bytes(self) -> Vec<u8> {
        self.body
    }

    fn display_body_length(&self) -> String {
        self.body_length_value()
            .map(|value| value.to_string())
            .unwrap_or_else(|| {
                if self.body.is_empty() {
                    "auto".to_string()
                } else {
                    self.body.len().to_string()
                }
            })
    }

    fn effective_body_length(&self, trailing_body_len: usize) -> Result<u16> {
        if let Some(length) = self.body_length.value().copied() {
            return Ok(length);
        }

        let total = self
            .body
            .len()
            .checked_add(trailing_body_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("eapol.body_length", "EAPOL body length overflow")
            })?;
        u16::try_from(total).map_err(|_| {
            CrafterError::invalid_field_value("eapol.body_length", "EAPOL body exceeds 65535 bytes")
        })
    }
}

impl Default for Eapol {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Eapol {
    fn name(&self) -> &'static str {
        "Eapol"
    }

    fn summary(&self) -> String {
        format!(
            "Eapol(version={}, type={}, body_len={})",
            self.version_value(),
            self.packet_type_kind().label(),
            self.display_body_length()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("version", self.version_value().to_string()),
            ("packet_type", self.packet_type_kind().label()),
            (
                "packet_type_raw",
                format!("0x{:02x}", self.packet_type_value()),
            ),
            ("body_length", self.display_body_length()),
            ("body_bytes_len", self.body.len().to_string()),
        ];
        if !self.body.is_empty() {
            fields.push(("body_bytes", hex_bytes(&self.body)));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        EAPOL_HEADER_LEN + self.body.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let trailing_body_len = eapol_trailing_body_len(*ctx)?;

        out.push(self.version_value());
        out.push(self.packet_type_value());
        out.extend_from_slice(&self.effective_body_length(trailing_body_len)?.to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(())
    }

    fn clone_layer(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<R> Div<R> for Eapol
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

/// Append a decoded EAPOL frame and preserve opaque body bytes as `Raw`.
pub(crate) fn append_eapol_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (eapol, body, surplus) = decode_eapol_parts(bytes)?;
    packet = packet.push(eapol);
    if !body.is_empty() {
        packet = packet.push(Raw::from_bytes(body));
    }
    if !surplus.is_empty() {
        packet = packet.push(Raw::from_bytes(surplus));
    }
    Ok(packet)
}

fn decode_eapol_parts(bytes: &[u8]) -> Result<(Eapol, &[u8], &[u8])> {
    if bytes.len() < EAPOL_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "eapol.header",
            EAPOL_HEADER_LEN,
            bytes.len(),
        ));
    }

    let body_length = read_u16_be(&bytes[2..4])? as usize;
    let required = EAPOL_HEADER_LEN.checked_add(body_length).ok_or_else(|| {
        CrafterError::invalid_field_value("eapol.body_length", "EAPOL body length overflow")
    })?;
    if bytes.len() < required {
        return Err(CrafterError::buffer_too_short(
            "eapol.body",
            required,
            bytes.len(),
        ));
    }

    let eapol = Eapol {
        version: Field::user(bytes[0]),
        packet_type: Field::user(bytes[1]),
        body_length: Field::user(body_length as u16),
        body: Vec::new(),
    };

    Ok((
        eapol,
        &bytes[EAPOL_HEADER_LEN..required],
        &bytes[required..],
    ))
}

fn eapol_trailing_body_len(ctx: LayerContext<'_>) -> Result<usize> {
    let mut len = 0usize;
    for (index, layer) in ctx.packet().iter().enumerate().skip(ctx.index() + 1) {
        let layer_ctx = LayerContext::new(ctx.packet(), index);
        len = len
            .checked_add(layer.encoded_len_with_context(&layer_ctx))
            .ok_or_else(|| {
                CrafterError::invalid_field_value("eapol.body_length", "EAPOL body length overflow")
            })?;
    }
    Ok(len)
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

const fn set_key_info_flag(bits: u16, flag: u16, enabled: bool) -> u16 {
    if enabled {
        bits | flag
    } else {
        bits & !flag
    }
}

const fn set_key_info_subfield(bits: u16, mask: u16, shift: u8, value: u8) -> u16 {
    let field = ((value as u16) << shift) & mask;
    (bits & !mask) | field
}

#[cfg(test)]
mod tests {
    use super::{
        append_eapol_packet, eapol_type_label, Eapol, EapolKeyInformation, EapolType,
        EAPOL_HEADER_LEN, EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA, EAPOL_KEY_INFO_ERROR,
        EAPOL_KEY_INFO_INSTALL, EAPOL_KEY_INFO_KEY_ACK, EAPOL_KEY_INFO_KEY_MIC,
        EAPOL_KEY_INFO_KEY_TYPE, EAPOL_KEY_INFO_REQUEST, EAPOL_KEY_INFO_RESERVED_MASK,
        EAPOL_KEY_INFO_SECURE, EAPOL_KEY_INFO_SMK_MESSAGE, EAPOL_TYPE_EAP_PACKET, EAPOL_TYPE_KEY,
        EAPOL_TYPE_LOGOFF, EAPOL_TYPE_START, EAPOL_VERSION_2,
    };
    use crate::{CrafterError, Layer, LlcSnap, Packet, Raw, EAPOL_TYPE_ASF_ALERT, ETHERTYPE_EAPOL};

    #[test]
    fn eapol_layer_compile_uses_defaults_and_autofills_body_length() {
        let packet = Eapol::new() / Raw::from_bytes([0x01, 0x02, 0x03]);
        let bytes = packet.compile().unwrap();

        assert_eq!(
            bytes.as_bytes(),
            &[
                EAPOL_VERSION_2,
                EAPOL_TYPE_EAP_PACKET,
                0x00,
                0x03,
                0x01,
                0x02,
                0x03
            ]
        );
    }

    #[test]
    fn eapol_layer_compile_preserves_explicit_body_length_override() {
        let packet = Eapol::key().body_length(0x1234) / Raw::from_bytes([0xde, 0xad]);
        let bytes = packet.compile().unwrap();

        assert_eq!(
            bytes.as_bytes(),
            &[EAPOL_VERSION_2, EAPOL_TYPE_KEY, 0x12, 0x34, 0xde, 0xad]
        );
    }

    #[test]
    fn eapol_layer_compile_can_store_opaque_body_bytes_on_layer() {
        let packet = Packet::from_layer(Eapol::new().body([0x05, 0x06]));
        let bytes = packet.compile().unwrap();

        assert_eq!(
            bytes.as_bytes(),
            &[
                EAPOL_VERSION_2,
                EAPOL_TYPE_EAP_PACKET,
                0x00,
                0x02,
                0x05,
                0x06
            ]
        );
    }

    #[test]
    fn eapol_layer_decode_preserves_header_and_body_as_raw() {
        let packet =
            append_eapol_packet(Packet::new(), &[0x02, 0x03, 0x00, 0x02, 0xaa, 0xbb]).unwrap();

        let eapol = packet.layer::<Eapol>().unwrap();
        let raw = packet.layer::<Raw>().unwrap();

        assert_eq!(eapol.version_value(), 2);
        assert_eq!(eapol.packet_type_kind(), EapolType::Key);
        assert_eq!(eapol.body_length_value(), Some(2));
        assert_eq!(raw.as_bytes(), &[0xaa, 0xbb]);
        assert_eq!(
            packet.compile().unwrap().as_bytes(),
            &[0x02, 0x03, 0x00, 0x02, 0xaa, 0xbb]
        );
    }

    #[test]
    fn eapol_layer_decode_preserves_surplus_bytes_after_declared_body() {
        let packet =
            append_eapol_packet(Packet::new(), &[0x02, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc])
                .unwrap();

        let raw_layers = packet.layers::<Raw>().collect::<Vec<_>>();

        assert_eq!(raw_layers.len(), 2);
        assert_eq!(raw_layers[0].as_bytes(), &[0xaa]);
        assert_eq!(raw_layers[1].as_bytes(), &[0xbb, 0xcc]);
        assert_eq!(
            packet.compile().unwrap().as_bytes(),
            &[0x02, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc]
        );
    }

    #[test]
    fn eapol_layer_decode_short_header_is_structured_error() {
        let error = append_eapol_packet(Packet::new(), &[0x02, 0x00, 0x00]).unwrap_err();

        assert_eq!(
            error,
            CrafterError::buffer_too_short("eapol.header", EAPOL_HEADER_LEN, 3)
        );
    }

    #[test]
    fn eapol_layer_decode_truncated_body_is_structured_error() {
        let error =
            append_eapol_packet(Packet::new(), &[0x02, 0x03, 0x00, 0x05, 0xaa]).unwrap_err();

        assert_eq!(error, CrafterError::buffer_too_short("eapol.body", 9, 5));
    }

    #[test]
    fn eapol_layer_summary_and_inspection_expose_wire_fields() {
        let eapol = Eapol::new()
            .version(3)
            .packet_type_raw(0x7f)
            .body([0xde, 0xad]);

        assert_eq!(
            eapol.summary(),
            "Eapol(version=3, type=unknown-eapol-type(127), body_len=2)"
        );
        assert_eq!(
            eapol.inspection_fields(),
            vec![
                ("version", "3".to_string()),
                ("packet_type", "unknown-eapol-type(127)".to_string()),
                ("packet_type_raw", "0x7f".to_string()),
                ("body_length", "2".to_string()),
                ("body_bytes_len", "2".to_string()),
                ("body_bytes", "de:ad".to_string()),
            ]
        );
    }

    #[test]
    fn eapol_layer_type_labels_cover_known_and_unknown_codepoints() {
        assert_eq!(eapol_type_label(EAPOL_TYPE_EAP_PACKET), "eap-packet");
        assert_eq!(eapol_type_label(EAPOL_TYPE_START), "start");
        assert_eq!(eapol_type_label(EAPOL_TYPE_LOGOFF), "logoff");
        assert_eq!(eapol_type_label(EAPOL_TYPE_KEY), "key");
        assert_eq!(eapol_type_label(EAPOL_TYPE_ASF_ALERT), "asf-alert");
        assert_eq!(EapolType::from_raw(0x7f), EapolType::Unknown(0x7f));
        assert_eq!(EapolType::Unknown(0x80).raw(), 0x80);
    }

    #[test]
    fn eapol_layer_llc_snap_infers_eapol_ethertype() {
        let bytes = (LlcSnap::new() / Eapol::start()).compile().unwrap();

        assert_eq!(&bytes.as_bytes()[6..8], &ETHERTYPE_EAPOL.to_be_bytes());
        assert_eq!(
            bytes.as_bytes(),
            &[
                0xaa,
                0xaa,
                0x03,
                0x00,
                0x00,
                0x00,
                0x88,
                0x8e,
                EAPOL_VERSION_2,
                EAPOL_TYPE_START,
                0x00,
                0x00,
            ]
        );
    }

    #[test]
    fn eapol_key_information_decode_encode_big_endian_round_trip() {
        let key_info = EapolKeyInformation::decode([0x33, 0xca]).unwrap();

        assert_eq!(key_info.bits(), 0x33ca);
        assert_eq!(key_info.raw(), 0x33ca);
        assert_eq!(key_info.descriptor_version(), 2);
        assert_eq!(key_info.key_descriptor_version(), 2);
        assert!(key_info.key_type());
        assert!(key_info.install());
        assert!(key_info.key_ack());
        assert!(key_info.key_mic());
        assert!(key_info.secure());
        assert!(!key_info.error());
        assert!(!key_info.request());
        assert!(key_info.encrypted_key_data());
        assert!(key_info.smk_message());
        assert_eq!(key_info.encode(), [0x33, 0xca]);
        assert_eq!(EapolKeyInformation::from_be_bytes([0x33, 0xca]), key_info);
    }

    #[test]
    fn eapol_key_information_decode_short_field_is_structured_error() {
        let error = EapolKeyInformation::decode([0x12]).unwrap_err();

        assert_eq!(
            error,
            CrafterError::buffer_too_short("eapol.key_information", 2, 1)
        );
    }

    #[test]
    fn eapol_key_information_descriptor_version_boundaries_are_three_bits() {
        let unset = EapolKeyInformation::new().with_descriptor_version(0);
        let max = EapolKeyInformation::new().with_descriptor_version(7);
        let masked = EapolKeyInformation::from_bits(0xfff8).with_descriptor_version(0xff);

        assert_eq!(unset.bits(), 0x0000);
        assert_eq!(unset.descriptor_version(), 0);
        assert_eq!(max.bits(), 0x0007);
        assert_eq!(max.descriptor_version(), 7);
        assert_eq!(masked.bits(), 0xffff);
        assert_eq!(masked.descriptor_version(), 7);
    }

    #[test]
    fn eapol_key_information_flag_boundaries_cover_each_source_backed_flag() {
        let cases: &[(
            &str,
            u16,
            fn(EapolKeyInformation, bool) -> EapolKeyInformation,
            fn(&EapolKeyInformation) -> bool,
        )] = &[
            (
                "key_type",
                EAPOL_KEY_INFO_KEY_TYPE,
                EapolKeyInformation::with_key_type,
                EapolKeyInformation::key_type,
            ),
            (
                "install",
                EAPOL_KEY_INFO_INSTALL,
                EapolKeyInformation::with_install,
                EapolKeyInformation::install,
            ),
            (
                "key_ack",
                EAPOL_KEY_INFO_KEY_ACK,
                EapolKeyInformation::with_key_ack,
                EapolKeyInformation::key_ack,
            ),
            (
                "key_mic",
                EAPOL_KEY_INFO_KEY_MIC,
                EapolKeyInformation::with_key_mic,
                EapolKeyInformation::key_mic,
            ),
            (
                "secure",
                EAPOL_KEY_INFO_SECURE,
                EapolKeyInformation::with_secure,
                EapolKeyInformation::secure,
            ),
            (
                "error",
                EAPOL_KEY_INFO_ERROR,
                EapolKeyInformation::with_error,
                EapolKeyInformation::error,
            ),
            (
                "request",
                EAPOL_KEY_INFO_REQUEST,
                EapolKeyInformation::with_request,
                EapolKeyInformation::request,
            ),
            (
                "encrypted_key_data",
                EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA,
                EapolKeyInformation::with_encrypted_key_data,
                EapolKeyInformation::encrypted_key_data,
            ),
            (
                "smk_message",
                EAPOL_KEY_INFO_SMK_MESSAGE,
                EapolKeyInformation::with_smk_message,
                EapolKeyInformation::smk_message,
            ),
        ];

        for (name, mask, setter, getter) in cases {
            let set = setter(EapolKeyInformation::new(), true);
            assert_eq!(set.bits(), *mask, "{name} setter chose the wrong bit");
            assert!(getter(&set), "{name} getter did not observe the set bit");

            let cleared = setter(EapolKeyInformation::from_bits(u16::MAX), false);
            assert_eq!(
                cleared.bits() & mask,
                0,
                "{name} setter did not clear the bit"
            );
            assert!(!getter(&cleared), "{name} getter observed a cleared bit");
            assert_eq!(
                cleared.bits() & !mask,
                u16::MAX & !mask,
                "{name} setter disturbed neighboring bits"
            );
        }
    }

    #[test]
    fn eapol_key_information_reserved_bits_round_trip_without_interpretation() {
        let key_info = EapolKeyInformation::new().with_reserved_bits(u16::MAX);

        assert_eq!(key_info.bits(), EAPOL_KEY_INFO_RESERVED_MASK);
        assert_eq!(key_info.reserved_bits(), EAPOL_KEY_INFO_RESERVED_MASK);
        assert_eq!(
            key_info.to_be_bytes(),
            EAPOL_KEY_INFO_RESERVED_MASK.to_be_bytes()
        );
        assert_eq!(
            EapolKeyInformation::from_bits(0xffff)
                .with_key_type(false)
                .with_install(false)
                .with_key_ack(false)
                .with_key_mic(false)
                .with_secure(false)
                .with_error(false)
                .with_request(false)
                .with_encrypted_key_data(false)
                .with_smk_message(false)
                .reserved_bits(),
            EAPOL_KEY_INFO_RESERVED_MASK
        );
    }
}
