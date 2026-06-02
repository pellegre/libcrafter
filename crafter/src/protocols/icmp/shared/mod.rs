//! Version-neutral ICMP core shared by the ICMPv4 and ICMPv6 implementations.
//!
//! This module holds the contract both versions speak: the common
//! [`IcmpKind`] message kind (with its per-version type mappings) and the
//! [`IcmpLayer`] trait that ping-style tools use without caring which IP
//! version carried the message. The version-specific codepoint constants those
//! mappings reference stay in `icmp/constants.rs` (re-exported at the `icmp`
//! module root); this is a pure internal move, so every existing path —
//! `crate::protocols::icmp::IcmpKind`, the `protocols::mod.rs` re-exports, and
//! the prelude — keeps resolving to the same names.

use crate::packet::Layer;

use super::{
    ICMPV6_DESTINATION_UNREACHABLE, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST,
    ICMPV6_PARAMETER_PROBLEM, ICMPV6_TIME_EXCEEDED, ICMP_DESTINATION_UNREACHABLE, ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST, ICMP_PARAMETER_PROBLEM, ICMP_TIME_EXCEEDED,
};

// The RFC 4884/4950/5837/8335 multi-part extension framework is version-neutral
// (it attaches to both ICMPv4 and ICMPv6 error messages), so it lives in the
// shared core. Re-export its public types here; the `icmp` root re-exports
// `self::shared::*`, so the `protocols::mod.rs` names (`IcmpExtension`,
// `IcmpExtensionObject`, `IcmpExtensionMpls`, `IcmpExtensionInterfaceInfo`,
// `IcmpExtensionInterfaceId`, `IcmpInterfaceIpAddress`) keep resolving unchanged.
mod extensions;
pub use self::extensions::*;

/// ICMP message kind shared by IPv4 and IPv6 builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcmpKind {
    /// Destination unreachable.
    DestinationUnreachable,
    /// Time exceeded.
    TimeExceeded,
    /// Parameter problem.
    ParameterProblem,
    /// Echo request.
    EchoRequest,
    /// Echo reply.
    EchoReply,
}

impl IcmpKind {
    /// ICMPv4 type value for this common kind.
    pub const fn ipv4_type(self) -> u8 {
        match self {
            Self::DestinationUnreachable => ICMP_DESTINATION_UNREACHABLE,
            Self::TimeExceeded => ICMP_TIME_EXCEEDED,
            Self::ParameterProblem => ICMP_PARAMETER_PROBLEM,
            Self::EchoRequest => ICMP_ECHO_REQUEST,
            Self::EchoReply => ICMP_ECHO_REPLY,
        }
    }

    /// ICMPv6 type value for this common kind.
    pub const fn ipv6_type(self) -> u8 {
        match self {
            Self::DestinationUnreachable => ICMPV6_DESTINATION_UNREACHABLE,
            Self::TimeExceeded => ICMPV6_TIME_EXCEEDED,
            Self::ParameterProblem => ICMPV6_PARAMETER_PROBLEM,
            Self::EchoRequest => ICMPV6_ECHO_REQUEST,
            Self::EchoReply => ICMPV6_ECHO_REPLY,
        }
    }
}

/// Version-independent ICMP behavior used by ping-style tools.
pub trait IcmpLayer: Layer {
    /// Raw ICMP type value.
    fn icmp_type_value(&self) -> u8;

    /// Raw ICMP code value.
    fn code_value(&self) -> u8;

    /// Stored checksum value, when explicit or decoded.
    fn checksum_value(&self) -> Option<u16>;

    /// Echo identifier when this layer carries one.
    fn identifier_value(&self) -> Option<u16>;

    /// Echo sequence number when this layer carries one.
    fn sequence_number_value(&self) -> Option<u16>;

    /// Common message kind, when the type maps cleanly across ICMP versions.
    fn kind(&self) -> Option<IcmpKind>;

    /// Return true for echo requests.
    fn is_echo_request(&self) -> bool {
        self.kind() == Some(IcmpKind::EchoRequest)
    }

    /// Return true for echo replies.
    fn is_echo_reply(&self) -> bool {
        self.kind() == Some(IcmpKind::EchoReply)
    }
}
