//! IEEE 802.11 frame-control field.

use super::util::{set_flag, set_subfield};
use super::*;

/// IEEE 802.11 frame-control field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Dot11FrameControl {
    bits: u16,
}

impl Dot11FrameControl {
    /// Create an empty frame-control word.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Create a frame-control value from its raw host-endian bit word.
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Decode a frame-control field from exactly two little-endian wire bytes.
    pub const fn from_le_bytes(bytes: [u8; DOT11_FRAME_CONTROL_LEN]) -> Self {
        Self {
            bits: (bytes[0] as u16) | ((bytes[1] as u16) << 8),
        }
    }

    /// Decode a frame-control field from a byte slice.
    pub fn decode(bytes: impl AsRef<[u8]>) -> crate::Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < DOT11_FRAME_CONTROL_LEN {
            return Err(crate::CrafterError::buffer_too_short(
                "dot11.frame_control",
                DOT11_FRAME_CONTROL_LEN,
                bytes.len(),
            ));
        }

        Ok(Self::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Return the raw host-endian frame-control bit word.
    pub const fn bits(&self) -> u16 {
        self.bits
    }

    /// Set the raw host-endian frame-control bit word.
    pub const fn raw(mut self, bits: u16) -> Self {
        self.bits = bits;
        self
    }

    /// Compile the frame-control field to little-endian wire bytes.
    pub const fn to_le_bytes(self) -> [u8; DOT11_FRAME_CONTROL_LEN] {
        [(self.bits & 0x00ff) as u8, (self.bits >> 8) as u8]
    }

    /// Compile the frame-control field to little-endian wire bytes.
    pub const fn compile(self) -> [u8; DOT11_FRAME_CONTROL_LEN] {
        self.to_le_bytes()
    }

    /// Protocol version subfield.
    pub const fn protocol_version(&self) -> u8 {
        ((self.bits & DOT11_FC_PROTOCOL_VERSION_MASK) >> DOT11_FC_PROTOCOL_VERSION_SHIFT) as u8
    }

    /// Frame type subfield.
    pub const fn frame_type(&self) -> u8 {
        ((self.bits & DOT11_FC_TYPE_MASK) >> DOT11_FC_TYPE_SHIFT) as u8
    }

    /// Typed frame type subfield.
    pub const fn frame_type_value(&self) -> Dot11FrameType {
        Dot11FrameType::from_raw(self.frame_type())
    }

    /// Frame subtype subfield.
    pub const fn subtype(&self) -> u8 {
        ((self.bits & DOT11_FC_SUBTYPE_MASK) >> DOT11_FC_SUBTYPE_SHIFT) as u8
    }

    /// Typed management subtype when this is a management frame.
    pub const fn management_subtype_value(&self) -> Option<Dot11ManagementSubtype> {
        match self.frame_type_value() {
            Dot11FrameType::Management => Some(Dot11ManagementSubtype::from_raw(self.subtype())),
            _ => None,
        }
    }

    /// Typed control subtype when this is a control frame.
    pub const fn control_subtype_value(&self) -> Option<Dot11ControlSubtype> {
        match self.frame_type_value() {
            Dot11FrameType::Control => Some(Dot11ControlSubtype::from_raw(self.subtype())),
            _ => None,
        }
    }

    /// Typed data subtype when this is a data frame.
    pub const fn data_subtype_value(&self) -> Option<Dot11DataSubtype> {
        match self.frame_type_value() {
            Dot11FrameType::Data => Some(Dot11DataSubtype::from_raw(self.subtype())),
            _ => None,
        }
    }

    /// Return true when the To DS flag is set.
    pub const fn to_ds(&self) -> bool {
        self.has_flag(DOT11_FC_TO_DS)
    }

    /// Return true when the From DS flag is set.
    pub const fn from_ds(&self) -> bool {
        self.has_flag(DOT11_FC_FROM_DS)
    }

    /// Return true when the More Fragments flag is set.
    pub const fn more_fragments(&self) -> bool {
        self.has_flag(DOT11_FC_MORE_FRAGMENTS)
    }

    /// Return true when the Retry flag is set.
    pub const fn retry(&self) -> bool {
        self.has_flag(DOT11_FC_RETRY)
    }

    /// Return true when the Power Management flag is set.
    pub const fn power_management(&self) -> bool {
        self.has_flag(DOT11_FC_POWER_MANAGEMENT)
    }

    /// Return true when the More Data flag is set.
    pub const fn more_data(&self) -> bool {
        self.has_flag(DOT11_FC_MORE_DATA)
    }

    /// Return true when the Protected Frame flag is set.
    pub const fn protected(&self) -> bool {
        self.has_flag(DOT11_FC_PROTECTED)
    }

    /// Return true when the Order/+HTC flag is set.
    pub const fn order(&self) -> bool {
        self.has_flag(DOT11_FC_ORDER)
    }

    /// Set the two-bit protocol-version subfield.
    ///
    /// Only the low two bits of `protocol_version` are representable in the
    /// frame-control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn protocol_version_set(mut self, protocol_version: u8) -> Self {
        self.bits = set_subfield(
            self.bits,
            DOT11_FC_PROTOCOL_VERSION_MASK,
            DOT11_FC_PROTOCOL_VERSION_SHIFT,
            protocol_version,
        );
        self
    }

    /// Builder alias for [`Self::protocol_version_set`].
    pub const fn with_protocol_version(self, protocol_version: u8) -> Self {
        self.protocol_version_set(protocol_version)
    }

    /// Set the two-bit frame type subfield.
    ///
    /// Only the low two bits of `frame_type` are representable in the
    /// frame-control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn frame_type_set(mut self, frame_type: u8) -> Self {
        self.bits = set_subfield(
            self.bits,
            DOT11_FC_TYPE_MASK,
            DOT11_FC_TYPE_SHIFT,
            frame_type,
        );
        self
    }

    /// Builder alias for [`Self::frame_type_set`].
    pub const fn with_frame_type(self, frame_type: u8) -> Self {
        self.frame_type_set(frame_type)
    }

    /// Set the four-bit frame subtype subfield.
    ///
    /// Only the low four bits of `subtype` are representable in the
    /// frame-control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn subtype_set(mut self, subtype: u8) -> Self {
        self.bits = set_subfield(
            self.bits,
            DOT11_FC_SUBTYPE_MASK,
            DOT11_FC_SUBTYPE_SHIFT,
            subtype,
        );
        self
    }

    /// Builder alias for [`Self::subtype_set`].
    pub const fn with_subtype(self, subtype: u8) -> Self {
        self.subtype_set(subtype)
    }

    /// Set or clear the To DS flag.
    pub const fn to_ds_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_TO_DS, enabled);
        self
    }

    /// Builder alias for [`Self::to_ds_set`].
    pub const fn with_to_ds(self, enabled: bool) -> Self {
        self.to_ds_set(enabled)
    }

    /// Set or clear the From DS flag.
    pub const fn from_ds_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_FROM_DS, enabled);
        self
    }

    /// Builder alias for [`Self::from_ds_set`].
    pub const fn with_from_ds(self, enabled: bool) -> Self {
        self.from_ds_set(enabled)
    }

    /// Set or clear the More Fragments flag.
    pub const fn more_fragments_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_MORE_FRAGMENTS, enabled);
        self
    }

    /// Builder alias for [`Self::more_fragments_set`].
    pub const fn with_more_fragments(self, enabled: bool) -> Self {
        self.more_fragments_set(enabled)
    }

    /// Set or clear the Retry flag.
    pub const fn retry_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_RETRY, enabled);
        self
    }

    /// Builder alias for [`Self::retry_set`].
    pub const fn with_retry(self, enabled: bool) -> Self {
        self.retry_set(enabled)
    }

    /// Set or clear the Power Management flag.
    pub const fn power_management_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_POWER_MANAGEMENT, enabled);
        self
    }

    /// Builder alias for [`Self::power_management_set`].
    pub const fn with_power_management(self, enabled: bool) -> Self {
        self.power_management_set(enabled)
    }

    /// Set or clear the More Data flag.
    pub const fn more_data_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_MORE_DATA, enabled);
        self
    }

    /// Builder alias for [`Self::more_data_set`].
    pub const fn with_more_data(self, enabled: bool) -> Self {
        self.more_data_set(enabled)
    }

    /// Set or clear the Protected Frame flag.
    pub const fn protected_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_PROTECTED, enabled);
        self
    }

    /// Builder alias for [`Self::protected_set`].
    pub const fn with_protected(self, enabled: bool) -> Self {
        self.protected_set(enabled)
    }

    /// Set or clear the Order/+HTC flag.
    pub const fn order_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_FC_ORDER, enabled);
        self
    }

    /// Builder alias for [`Self::order_set`].
    pub const fn with_order(self, enabled: bool) -> Self {
        self.order_set(enabled)
    }

    const fn has_flag(&self, flag: u16) -> bool {
        self.bits & flag != 0
    }
}
