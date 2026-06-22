//! IEEE 802.11 sequence-control field.

use super::util::set_subfield;
use super::*;

/// IEEE 802.11 sequence-control field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Dot11SequenceControl {
    bits: u16,
}

impl Dot11SequenceControl {
    /// Create an empty sequence-control word.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Create a sequence-control value from its raw host-endian bit word.
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Decode a sequence-control field from exactly two little-endian wire bytes.
    pub const fn from_le_bytes(bytes: [u8; DOT11_SEQUENCE_CONTROL_LEN]) -> Self {
        Self {
            bits: (bytes[0] as u16) | ((bytes[1] as u16) << 8),
        }
    }

    /// Decode a sequence-control field from a byte slice.
    pub fn decode(bytes: impl AsRef<[u8]>) -> crate::Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < DOT11_SEQUENCE_CONTROL_LEN {
            return Err(crate::CrafterError::buffer_too_short(
                "dot11.sequence_control",
                DOT11_SEQUENCE_CONTROL_LEN,
                bytes.len(),
            ));
        }

        Ok(Self::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Return the raw host-endian sequence-control bit word.
    pub const fn bits(&self) -> u16 {
        self.bits
    }

    /// Set the raw host-endian sequence-control bit word.
    pub const fn raw(mut self, bits: u16) -> Self {
        self.bits = bits;
        self
    }

    /// Compile the sequence-control field to little-endian wire bytes.
    pub const fn to_le_bytes(self) -> [u8; DOT11_SEQUENCE_CONTROL_LEN] {
        [(self.bits & 0x00ff) as u8, (self.bits >> 8) as u8]
    }

    /// Compile the sequence-control field to little-endian wire bytes.
    pub const fn compile(self) -> [u8; DOT11_SEQUENCE_CONTROL_LEN] {
        self.to_le_bytes()
    }

    /// Fragment number subfield.
    pub const fn fragment_number(&self) -> u8 {
        ((self.bits & DOT11_SEQUENCE_FRAGMENT_NUMBER_MASK) >> DOT11_SEQUENCE_FRAGMENT_NUMBER_SHIFT)
            as u8
    }

    /// Sequence number subfield.
    pub const fn sequence_number(&self) -> u16 {
        (self.bits & DOT11_SEQUENCE_NUMBER_MASK) >> DOT11_SEQUENCE_NUMBER_SHIFT
    }

    /// Set the four-bit fragment-number subfield.
    ///
    /// Only the low four bits of `fragment_number` are representable in the
    /// sequence-control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn fragment_number_set(mut self, fragment_number: u8) -> Self {
        self.bits = set_subfield(
            self.bits,
            DOT11_SEQUENCE_FRAGMENT_NUMBER_MASK,
            DOT11_SEQUENCE_FRAGMENT_NUMBER_SHIFT,
            fragment_number,
        );
        self
    }

    /// Builder alias for [`Self::fragment_number_set`].
    pub const fn with_fragment_number(self, fragment_number: u8) -> Self {
        self.fragment_number_set(fragment_number)
    }

    /// Set the twelve-bit sequence-number subfield.
    ///
    /// Only the low twelve bits of `sequence_number` are representable in the
    /// sequence-control word. Use [`Self::raw`] to set an exact 16-bit word.
    pub const fn sequence_number_set(mut self, sequence_number: u16) -> Self {
        self.bits = (self.bits & !DOT11_SEQUENCE_NUMBER_MASK)
            | ((sequence_number << DOT11_SEQUENCE_NUMBER_SHIFT) & DOT11_SEQUENCE_NUMBER_MASK);
        self
    }

    /// Builder alias for [`Self::sequence_number_set`].
    pub const fn with_sequence_number(self, sequence_number: u16) -> Self {
        self.sequence_number_set(sequence_number)
    }
}
