//! IGMP validation helpers.
//!
//! Validation is added incrementally and must preserve caller-set malformed
//! values when bytes can be represented.

use core::net::Ipv4Addr;

/// IPv4 all-systems multicast group used by IGMP queries.
///
/// Source: RFC 1112 section 6.4 and the reviewed IGMP codepoint handoff.
pub const IGMP_ALL_SYSTEMS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
/// IPv4 all-routers multicast group used by IGMPv2 leave processing.
///
/// Source: RFC 2236 section 8 and the reviewed IGMP codepoint handoff.
pub const IGMP_ALL_ROUTERS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);

/// Diagnostic classification for the IGMP Group Address field.
///
/// The classification is intentionally passive: it helps generated tools and
/// tests explain a packet, but it never rejects caller-supplied bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgmpGroupAddressClass {
    /// The zero Group Address used by General Query messages.
    Zero,
    /// The all-systems group `224.0.0.1`.
    AllSystems,
    /// The all-routers group `224.0.0.2`.
    AllRouters,
    /// Any other IPv4 multicast group in `224.0.0.0/4`.
    Multicast,
    /// A representable but non-multicast address.
    NonMulticast,
}

impl IgmpGroupAddressClass {
    /// Stable diagnostic label for this classification.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::AllSystems => "all-systems",
            Self::AllRouters => "all-routers",
            Self::Multicast => "multicast",
            Self::NonMulticast => "non-multicast",
        }
    }

    /// Whether this class is within the IPv4 multicast address block.
    pub const fn is_multicast(self) -> bool {
        match self {
            Self::AllSystems | Self::AllRouters | Self::Multicast => true,
            Self::Zero | Self::NonMulticast => false,
        }
    }
}

/// Classify an IGMP Group Address without rejecting malformed values.
pub fn igmp_group_address_class(address: Ipv4Addr) -> IgmpGroupAddressClass {
    if address == Ipv4Addr::UNSPECIFIED {
        IgmpGroupAddressClass::Zero
    } else if address == IGMP_ALL_SYSTEMS_GROUP {
        IgmpGroupAddressClass::AllSystems
    } else if address == IGMP_ALL_ROUTERS_GROUP {
        IgmpGroupAddressClass::AllRouters
    } else if address.is_multicast() {
        IgmpGroupAddressClass::Multicast
    } else {
        IgmpGroupAddressClass::NonMulticast
    }
}

/// Return the stable diagnostic label for an IGMP Group Address.
pub fn igmp_group_address_class_name(address: Ipv4Addr) -> &'static str {
    igmp_group_address_class(address).name()
}

#[cfg(test)]
mod igmp_group_address {
    use super::*;

    #[test]
    fn classifies_source_backed_group_addresses() {
        assert_eq!(
            igmp_group_address_class(Ipv4Addr::UNSPECIFIED),
            IgmpGroupAddressClass::Zero
        );
        assert_eq!(
            igmp_group_address_class(IGMP_ALL_SYSTEMS_GROUP),
            IgmpGroupAddressClass::AllSystems
        );
        assert_eq!(
            igmp_group_address_class(IGMP_ALL_ROUTERS_GROUP),
            IgmpGroupAddressClass::AllRouters
        );
        assert_eq!(
            igmp_group_address_class(Ipv4Addr::new(233, 252, 0, 42)),
            IgmpGroupAddressClass::Multicast
        );
        assert_eq!(
            igmp_group_address_class(Ipv4Addr::new(192, 0, 2, 42)),
            IgmpGroupAddressClass::NonMulticast
        );
    }

    #[test]
    fn exposes_stable_diagnostic_names() {
        assert_eq!(IgmpGroupAddressClass::Zero.name(), "zero");
        assert_eq!(IgmpGroupAddressClass::AllSystems.name(), "all-systems");
        assert_eq!(IgmpGroupAddressClass::AllRouters.name(), "all-routers");
        assert_eq!(IgmpGroupAddressClass::Multicast.name(), "multicast");
        assert_eq!(IgmpGroupAddressClass::NonMulticast.name(), "non-multicast");

        assert!(!IgmpGroupAddressClass::Zero.is_multicast());
        assert!(IgmpGroupAddressClass::AllSystems.is_multicast());
        assert!(IgmpGroupAddressClass::AllRouters.is_multicast());
        assert!(IgmpGroupAddressClass::Multicast.is_multicast());
        assert!(!IgmpGroupAddressClass::NonMulticast.is_multicast());
    }
}
