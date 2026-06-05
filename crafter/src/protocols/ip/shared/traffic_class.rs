//! Version-neutral IP traffic-class helpers.

use crate::error::{CrafterError, Result};

pub(crate) const DSCP_SHIFT: u8 = 2;
const DSCP_MAX: u8 = 0x3f;
pub(crate) const ECN_MASK: u8 = 0x03;

/// Six-bit Differentiated Services Code Point from the IP DS field.
///
/// RFC 2474 defines the DSCP as the six most significant bits of the
/// historical IPv4 TOS octet and the IPv6 traffic class octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dscp(u8);

impl Dscp {
    /// Create a DSCP value when it fits the six-bit wire field.
    pub const fn new(value: u8) -> Result<Self> {
        if value <= DSCP_MAX {
            Ok(Self(value))
        } else {
            Err(CrafterError::invalid_field_value(
                "ipv4.dscp",
                "DSCP must fit in six bits",
            ))
        }
    }

    pub(crate) const fn from_u6(value: u8) -> Self {
        Self(value)
    }

    /// Extract the DSCP bits from a full IP DS/traffic-class octet.
    pub const fn from_ds_field(value: u8) -> Self {
        Self(value >> DSCP_SHIFT)
    }

    /// Raw six-bit DSCP value.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Default Forwarding / Class Selector 0 codepoint (CS0, 0).
    pub const fn default_forwarding() -> Self {
        Self::cs0()
    }

    /// Class Selector 0 codepoint (CS0, 0).
    pub const fn cs0() -> Self {
        Self::from_u6(0)
    }

    /// Class Selector 1 codepoint (CS1, 8).
    pub const fn cs1() -> Self {
        Self::from_u6(8)
    }

    /// Class Selector 2 codepoint (CS2, 16).
    pub const fn cs2() -> Self {
        Self::from_u6(16)
    }

    /// Class Selector 3 codepoint (CS3, 24).
    pub const fn cs3() -> Self {
        Self::from_u6(24)
    }

    /// Class Selector 4 codepoint (CS4, 32).
    pub const fn cs4() -> Self {
        Self::from_u6(32)
    }

    /// Class Selector 5 codepoint (CS5, 40).
    pub const fn cs5() -> Self {
        Self::from_u6(40)
    }

    /// Class Selector 6 codepoint (CS6, 48).
    pub const fn cs6() -> Self {
        Self::from_u6(48)
    }

    /// Class Selector 7 codepoint (CS7, 56).
    pub const fn cs7() -> Self {
        Self::from_u6(56)
    }

    /// Create an RFC 2474 Class Selector codepoint from a selector 0..=7.
    pub const fn class_selector(selector: u8) -> Result<Self> {
        if selector <= 7 {
            Ok(Self(selector << 3))
        } else {
            Err(CrafterError::invalid_field_value(
                "ip.dscp.class_selector",
                "Class Selector must be in the range 0..=7",
            ))
        }
    }

    /// Expedited Forwarding codepoint (EF, 46).
    pub const fn ef() -> Self {
        Self::from_u6(46)
    }
}

impl Default for Dscp {
    fn default() -> Self {
        Self::default_forwarding()
    }
}

impl TryFrom<u8> for Dscp {
    type Error = CrafterError;

    fn try_from(value: u8) -> Result<Self> {
        Self::new(value)
    }
}

impl From<Dscp> for u8 {
    fn from(value: Dscp) -> Self {
        value.value()
    }
}

/// Explicit Congestion Notification value from the IP DS field.
///
/// RFC 3168 defines the two least significant bits as Not-ECT, ECT(1),
/// ECT(0), and CE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ecn {
    /// Not ECN-capable transport.
    NotEct = 0,
    /// ECN-capable transport, ECT(1).
    Ect1 = 1,
    /// ECN-capable transport, ECT(0).
    Ect0 = 2,
    /// Congestion experienced.
    Ce = 3,
}

impl Ecn {
    /// Create an ECN value when it fits the two-bit wire field.
    pub const fn new(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::NotEct),
            1 => Ok(Self::Ect1),
            2 => Ok(Self::Ect0),
            3 => Ok(Self::Ce),
            _ => Err(CrafterError::invalid_field_value(
                "ipv4.ecn",
                "ECN must fit in two bits",
            )),
        }
    }

    pub(crate) const fn from_u2(value: u8) -> Self {
        match value & ECN_MASK {
            0 => Self::NotEct,
            1 => Self::Ect1,
            2 => Self::Ect0,
            _ => Self::Ce,
        }
    }

    /// Extract the ECN bits from a full IP DS/traffic-class octet.
    pub const fn from_ds_field(value: u8) -> Self {
        Self::from_u2(value)
    }

    /// Raw two-bit ECN value.
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Not ECN-Capable Transport (Not-ECT, 0b00).
    pub const fn not_ect() -> Self {
        Self::NotEct
    }

    /// ECN-Capable Transport codepoint ECT(1), 0b01.
    pub const fn ect1() -> Self {
        Self::Ect1
    }

    /// ECN-Capable Transport codepoint ECT(0), 0b10.
    pub const fn ect0() -> Self {
        Self::Ect0
    }

    /// Alias for ECN-Capable Transport codepoint ECT(0).
    pub const fn capable_0() -> Self {
        Self::Ect0
    }

    /// Alias for ECN-Capable Transport codepoint ECT(1).
    pub const fn capable_1() -> Self {
        Self::Ect1
    }

    /// Congestion Experienced (CE, 0b11).
    pub const fn ce() -> Self {
        Self::Ce
    }
}

impl Default for Ecn {
    fn default() -> Self {
        Self::NotEct
    }
}

impl TryFrom<u8> for Ecn {
    type Error = CrafterError;

    fn try_from(value: u8) -> Result<Self> {
        Self::new(value)
    }
}

impl From<Ecn> for u8 {
    fn from(value: Ecn) -> Self {
        value.value()
    }
}
