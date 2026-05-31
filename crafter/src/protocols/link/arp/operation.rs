use super::constants::*;

/// ARP operation value.
///
/// Source-backed known operation codepoints from IANA registry
/// arp-parameters-1 (`target/arp-rfc/scope.md`). Base ARP behavior is built
/// around [`ArpOperation::Request`] and [`ArpOperation::Reply`] (RFC 826); the
/// remaining ARP-family operations are exposed as named codepoints only, with
/// no extension-specific behavior. Unknown numeric values are never blocked:
/// use [`crate::protocols::link::Arp::opcode`] for any value this enum does not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u16)]
pub enum ArpOperation {
    /// ARP who-has request (RFC 826).
    Request = ARP_OP_REQUEST,
    /// ARP is-at reply (RFC 826).
    Reply = ARP_OP_REPLY,
    /// RARP request (RFC 903).
    RarpRequest = ARP_OP_RARP_REQUEST,
    /// RARP reply (RFC 903).
    RarpReply = ARP_OP_RARP_REPLY,
    /// DRARP request (RFC 1931).
    DrarpRequest = ARP_OP_DRARP_REQUEST,
    /// DRARP reply (RFC 1931).
    DrarpReply = ARP_OP_DRARP_REPLY,
    /// DRARP error (RFC 1931).
    DrarpError = ARP_OP_DRARP_ERROR,
    /// Inverse ARP request (RFC 2390).
    InArpRequest = ARP_OP_INARP_REQUEST,
    /// Inverse ARP reply (RFC 2390).
    InArpReply = ARP_OP_INARP_REPLY,
    /// ARP-NAK (RFC 1577).
    ArpNak = ARP_OP_ARP_NAK,
    /// MAPOS UNARP (RFC 2176).
    MaposUnarp = ARP_OP_MAPOS_UNARP,
}

impl ArpOperation {
    /// Map a raw operation opcode to a named [`ArpOperation`].
    ///
    /// Returns `None` for any value not named by this enum (reserved,
    /// experimental, MARS, or unassigned codepoints, and any other unknown
    /// number). Those values stay usable through
    /// [`crate::protocols::link::Arp::opcode`] and remain round-trippable; this
    /// conversion only reports whether a name exists.
    pub fn from_opcode(opcode: u16) -> Option<Self> {
        match opcode {
            ARP_OP_REQUEST => Some(Self::Request),
            ARP_OP_REPLY => Some(Self::Reply),
            ARP_OP_RARP_REQUEST => Some(Self::RarpRequest),
            ARP_OP_RARP_REPLY => Some(Self::RarpReply),
            ARP_OP_DRARP_REQUEST => Some(Self::DrarpRequest),
            ARP_OP_DRARP_REPLY => Some(Self::DrarpReply),
            ARP_OP_DRARP_ERROR => Some(Self::DrarpError),
            ARP_OP_INARP_REQUEST => Some(Self::InArpRequest),
            ARP_OP_INARP_REPLY => Some(Self::InArpReply),
            ARP_OP_ARP_NAK => Some(Self::ArpNak),
            ARP_OP_MAPOS_UNARP => Some(Self::MaposUnarp),
            _ => None,
        }
    }

    /// Numeric opcode for this operation (IANA arp-parameters-1).
    pub fn opcode(self) -> u16 {
        self as u16
    }

    /// Short, stable label for this operation.
    ///
    /// `Request`/`Reply` keep the `request`/`reply` labels base ARP summaries
    /// have always used; the remaining ARP-family operations use compact names.
    pub fn label(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Reply => "reply",
            Self::RarpRequest => "rarp-request",
            Self::RarpReply => "rarp-reply",
            Self::DrarpRequest => "drarp-request",
            Self::DrarpReply => "drarp-reply",
            Self::DrarpError => "drarp-error",
            Self::InArpRequest => "inarp-request",
            Self::InArpReply => "inarp-reply",
            Self::ArpNak => "arp-nak",
            Self::MaposUnarp => "mapos-unarp",
        }
    }
}

impl From<ArpOperation> for u16 {
    fn from(value: ArpOperation) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for ArpOperation {
    type Error = u16;

    /// Convert a raw opcode into a named operation, returning the original
    /// value as the error when it is not a known codepoint so callers can keep
    /// it via [`crate::protocols::link::Arp::opcode`].
    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        Self::from_opcode(value).ok_or(value)
    }
}
