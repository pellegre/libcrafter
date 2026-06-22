//! IEEE 802.11 frame type subfield.

use super::*;

/// IEEE 802.11 frame type subfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dot11FrameType {
    /// Management frame.
    Management,
    /// Control frame.
    Control,
    /// Data frame.
    Data,
    /// Extension frame.
    Extension,
    /// Unknown caller-supplied value preserved verbatim.
    Unknown(u8),
}

impl Dot11FrameType {
    /// Create a frame type from its raw numeric value.
    pub const fn from_raw(value: u8) -> Self {
        match value {
            DOT11_FRAME_TYPE_MANAGEMENT => Self::Management,
            DOT11_FRAME_TYPE_CONTROL => Self::Control,
            DOT11_FRAME_TYPE_DATA => Self::Data,
            DOT11_FRAME_TYPE_EXTENSION => Self::Extension,
            value => Self::Unknown(value),
        }
    }

    /// Raw numeric value.
    pub const fn raw(self) -> u8 {
        match self {
            Self::Management => DOT11_FRAME_TYPE_MANAGEMENT,
            Self::Control => DOT11_FRAME_TYPE_CONTROL,
            Self::Data => DOT11_FRAME_TYPE_DATA,
            Self::Extension => DOT11_FRAME_TYPE_EXTENSION,
            Self::Unknown(value) => value,
        }
    }

    /// Short stable label.
    pub fn label(self) -> String {
        dot11_frame_type_label(self.raw())
    }
}

impl From<u8> for Dot11FrameType {
    fn from(value: u8) -> Self {
        Self::from_raw(value)
    }
}

impl From<Dot11FrameType> for u8 {
    fn from(value: Dot11FrameType) -> Self {
        value.raw()
    }
}
