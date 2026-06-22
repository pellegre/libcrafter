//! IEEE 802.11 QoS control field.

use super::util::{set_flag, set_subfield};
use super::*;

/// IEEE 802.11 QoS control field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Dot11QosControl {
    bits: u16,
}

impl Dot11QosControl {
    /// Create an empty QoS control word.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Create a QoS control value from its raw host-endian bit word.
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Decode a QoS control field from exactly two little-endian wire bytes.
    pub const fn from_le_bytes(bytes: [u8; DOT11_QOS_CONTROL_LEN]) -> Self {
        Self {
            bits: (bytes[0] as u16) | ((bytes[1] as u16) << 8),
        }
    }

    /// Decode a QoS control field from a byte slice.
    pub fn decode(bytes: impl AsRef<[u8]>) -> crate::Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < DOT11_QOS_CONTROL_LEN {
            return Err(crate::CrafterError::buffer_too_short(
                "dot11.qos_control",
                DOT11_QOS_CONTROL_LEN,
                bytes.len(),
            ));
        }

        Ok(Self::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Return the raw host-endian QoS control bit word.
    pub const fn bits(&self) -> u16 {
        self.bits
    }

    /// Set the raw host-endian QoS control bit word.
    pub const fn raw(mut self, bits: u16) -> Self {
        self.bits = bits;
        self
    }

    /// Compile the QoS control field to little-endian wire bytes.
    pub const fn to_le_bytes(self) -> [u8; DOT11_QOS_CONTROL_LEN] {
        [(self.bits & 0x00ff) as u8, (self.bits >> 8) as u8]
    }

    /// Compile the QoS control field to little-endian wire bytes.
    pub const fn compile(self) -> [u8; DOT11_QOS_CONTROL_LEN] {
        self.to_le_bytes()
    }

    /// Traffic Identifier subfield.
    pub const fn tid(&self) -> u8 {
        ((self.bits & DOT11_QOS_TID_MASK) >> DOT11_QOS_TID_SHIFT) as u8
    }

    /// Return true when the End of Service Period bit is set.
    pub const fn eosp(&self) -> bool {
        self.has_flag(DOT11_QOS_EOSP)
    }

    /// ACK policy subfield.
    pub const fn ack_policy(&self) -> u8 {
        ((self.bits & DOT11_QOS_ACK_POLICY_MASK) >> DOT11_QOS_ACK_POLICY_SHIFT) as u8
    }

    /// Return true when the A-MSDU Present bit is set.
    pub const fn a_msdu_present(&self) -> bool {
        self.has_flag(DOT11_QOS_A_MSDU_PRESENT)
    }

    /// Context-dependent TXOP/queue-size octet.
    pub const fn txop_queue_size(&self) -> u8 {
        ((self.bits & DOT11_QOS_TXOP_QUEUE_SIZE_MASK) >> DOT11_QOS_TXOP_QUEUE_SIZE_SHIFT) as u8
    }

    /// Set the four-bit Traffic Identifier subfield.
    ///
    /// Only the low four bits of `tid` are representable in the QoS control
    /// word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn tid_set(mut self, tid: u8) -> Self {
        self.bits = set_subfield(self.bits, DOT11_QOS_TID_MASK, DOT11_QOS_TID_SHIFT, tid);
        self
    }

    /// Builder alias for [`Self::tid_set`].
    pub const fn with_tid(self, tid: u8) -> Self {
        self.tid_set(tid)
    }

    /// Set or clear the End of Service Period bit.
    pub const fn eosp_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_QOS_EOSP, enabled);
        self
    }

    /// Builder alias for [`Self::eosp_set`].
    pub const fn with_eosp(self, enabled: bool) -> Self {
        self.eosp_set(enabled)
    }

    /// Set the two-bit ACK policy subfield.
    ///
    /// Only the low two bits of `ack_policy` are representable in the QoS
    /// control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn ack_policy_set(mut self, ack_policy: u8) -> Self {
        self.bits = set_subfield(
            self.bits,
            DOT11_QOS_ACK_POLICY_MASK,
            DOT11_QOS_ACK_POLICY_SHIFT,
            ack_policy,
        );
        self
    }

    /// Builder alias for [`Self::ack_policy_set`].
    pub const fn with_ack_policy(self, ack_policy: u8) -> Self {
        self.ack_policy_set(ack_policy)
    }

    /// Set or clear the A-MSDU Present bit.
    pub const fn a_msdu_present_set(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, DOT11_QOS_A_MSDU_PRESENT, enabled);
        self
    }

    /// Builder alias for [`Self::a_msdu_present_set`].
    pub const fn with_a_msdu_present(self, enabled: bool) -> Self {
        self.a_msdu_present_set(enabled)
    }

    /// Set the context-dependent TXOP/queue-size octet.
    pub const fn txop_queue_size_set(mut self, value: u8) -> Self {
        self.bits = set_subfield(
            self.bits,
            DOT11_QOS_TXOP_QUEUE_SIZE_MASK,
            DOT11_QOS_TXOP_QUEUE_SIZE_SHIFT,
            value,
        );
        self
    }

    /// Builder alias for [`Self::txop_queue_size_set`].
    pub const fn with_txop_queue_size(self, value: u8) -> Self {
        self.txop_queue_size_set(value)
    }

    const fn has_flag(&self, flag: u16) -> bool {
        self.bits & flag != 0
    }
}

impl From<u16> for Dot11QosControl {
    fn from(value: u16) -> Self {
        Self::from_bits(value)
    }
}

impl From<Dot11QosControl> for u16 {
    fn from(value: Dot11QosControl) -> Self {
        value.bits()
    }
}
