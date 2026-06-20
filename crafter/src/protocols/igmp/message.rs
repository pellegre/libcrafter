//! IGMP fixed-header message model.
//!
//! IGMP starts with the same 8-octet fixed header for the bootstrap v1/v2
//! message shapes and the leading bytes of the v3 report format: Type, Code
//! or Max Response Code, Checksum, and Group Address. Later steps add packet
//! layer compilation, decode registration, and typed v3 bodies.

use core::net::Ipv4Addr;

use crate::field::Field;

use super::constants::{IGMP_DEFAULT_CODE, IGMP_TYPE_MEMBERSHIP_QUERY};
use super::registry::{
    igmp_code_meta, igmp_type, igmp_type_meta, IgmpCodeMeta, IgmpType, IgmpTypeMeta,
};

/// Internet Group Management Protocol fixed header.
///
/// The fixed header fields use [`Field`] wrappers so later `compile()` support
/// can fill unset values such as the checksum without clobbering values that a
/// caller set deliberately. The raw Type and Code bytes remain representable
/// even for reserved, unassigned, experimental, or not-yet-typed IGMP values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Igmp {
    /// IGMP Type octet from the IANA IGMP Type Numbers registry.
    pub(crate) igmp_type: Field<u8>,
    /// IGMP Code octet, or Max Response Code for membership queries.
    pub(crate) code: Field<u8>,
    /// IGMP checksum over the IGMP message.
    pub(crate) checksum: Field<u16>,
    /// Group Address field from the common IGMP fixed header.
    pub(crate) group_address: Field<Ipv4Addr>,
}

impl Igmp {
    /// Create an IGMP header with conservative membership-query defaults.
    ///
    /// The source manifest names IGMP Membership Query (`0x11`) and the scoped
    /// Code value `0` for IGMPv1. The group address defaults to `0.0.0.0`,
    /// the all-systems/general-query address in the fixed header, while the
    /// checksum remains unset for compile-time calculation.
    pub fn new() -> Self {
        Self {
            igmp_type: Field::defaulted(IGMP_TYPE_MEMBERSHIP_QUERY),
            code: Field::defaulted(IGMP_DEFAULT_CODE),
            checksum: Field::unset(),
            group_address: Field::defaulted(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Raw IGMP Type value.
    pub fn igmp_type_value(&self) -> u8 {
        value_or_copy(&self.igmp_type, IGMP_TYPE_MEMBERSHIP_QUERY)
    }

    /// Raw IGMP Type value, using the packet-field spelling.
    pub fn type_value(&self) -> u8 {
        self.igmp_type_value()
    }

    /// Source-backed IGMP Type classification.
    pub fn igmp_type(&self) -> IgmpType {
        igmp_type(self.igmp_type_value())
    }

    /// Source-backed IGMP Type registry metadata.
    pub fn type_meta(&self) -> IgmpTypeMeta {
        igmp_type_meta(self.igmp_type_value())
    }

    /// Raw Code field value.
    pub fn code_value(&self) -> u8 {
        value_or_copy(&self.code, IGMP_DEFAULT_CODE)
    }

    /// Raw Max Response Code byte.
    ///
    /// For membership queries this is the same octet as the scoped Code field:
    /// Code `0` is the IGMPv1 query form, and `1..=255` carries IGMPv2-or-later
    /// max-response timing semantics. For other Types this accessor still
    /// returns the raw byte so explicit overrides remain inspectable.
    pub fn max_response_code_value(&self) -> u8 {
        self.code_value()
    }

    /// Source-backed scoped Code registry metadata.
    pub fn code_meta(&self) -> IgmpCodeMeta {
        igmp_code_meta(self.igmp_type_value(), self.code_value())
    }

    /// Stored checksum value, when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Raw Group Address field value.
    pub fn group_address_value(&self) -> Ipv4Addr {
        value_or_copy(&self.group_address, Ipv4Addr::UNSPECIFIED)
    }
}

impl Default for Igmp {
    fn default() -> Self {
        Self::new()
    }
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldState;
    use crate::protocols::igmp::constants::IGMP_TYPE_EXPERIMENTAL_FIRST;
    use crate::protocols::igmp::registry::IgmpTypeStatus;

    #[test]
    fn igmp_message_model_defaults_to_membership_query() {
        let igmp = Igmp::default();

        assert_eq!(igmp.igmp_type.state(), FieldState::Defaulted);
        assert_eq!(igmp.code.state(), FieldState::Defaulted);
        assert_eq!(igmp.checksum.state(), FieldState::Unset);
        assert_eq!(igmp.group_address.state(), FieldState::Defaulted);

        assert_eq!(igmp.igmp_type_value(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(igmp.type_value(), IGMP_TYPE_MEMBERSHIP_QUERY);
        assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Assigned);
        assert_eq!(igmp.code_value(), IGMP_DEFAULT_CODE);
        assert_eq!(igmp.max_response_code_value(), IGMP_DEFAULT_CODE);
        assert_eq!(igmp.code_meta().name, "IGMP Version 1");
        assert_eq!(igmp.checksum_value(), None);
        assert_eq!(igmp.group_address_value(), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn igmp_message_model_preserves_explicit_raw_fields() {
        let mut igmp = Igmp::default();
        igmp.igmp_type.set_user(IGMP_TYPE_EXPERIMENTAL_FIRST);
        igmp.code.set_user(0xaa);
        igmp.checksum.set_user(0x1234);
        igmp.group_address.set_user(Ipv4Addr::new(239, 255, 0, 1));

        assert_eq!(
            igmp.igmp_type(),
            IgmpType::Experimental(IGMP_TYPE_EXPERIMENTAL_FIRST)
        );
        assert_eq!(igmp.type_meta().status, IgmpTypeStatus::Experimental);
        assert_eq!(igmp.code_value(), 0xaa);
        assert_eq!(igmp.max_response_code_value(), 0xaa);
        assert_eq!(igmp.code_meta().status, IgmpTypeStatus::Experimental);
        assert_eq!(igmp.checksum_value(), Some(0x1234));
        assert_eq!(igmp.group_address_value(), Ipv4Addr::new(239, 255, 0, 1));
    }
}
