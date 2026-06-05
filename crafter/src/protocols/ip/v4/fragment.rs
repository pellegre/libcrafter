//! IPv4 fragmentation metadata and helpers.

use crate::error::{CrafterError, Result};

use super::constants::{
    IPV4_FLAG_DONT_FRAGMENT, IPV4_FLAG_MORE_FRAGMENTS, IPV4_FLAG_RESERVED, IPV4_MAX_FLAGS,
    IPV4_MAX_FRAGMENT_OFFSET,
};

/// Snapshot of IPv4 fragmentation-related header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4FragmentInfo {
    identification: u16,
    flags: u8,
    fragment_offset: u16,
}

impl Ipv4FragmentInfo {
    pub(super) const fn new(identification: u16, flags: u8, fragment_offset: u16) -> Self {
        Self {
            identification,
            flags,
            fragment_offset,
        }
    }

    /// Identification field carried by the IPv4 header.
    pub const fn identification(self) -> u16 {
        self.identification
    }

    /// Raw three-bit IPv4 flags field.
    pub const fn flags(self) -> u8 {
        self.flags
    }

    /// Return true when the reserved IPv4 flag bit is set.
    pub const fn is_reserved_flag_set(self) -> bool {
        self.flags & IPV4_FLAG_RESERVED != 0
    }

    /// Return true when the "don't fragment" flag is set.
    pub const fn is_dont_fragment(self) -> bool {
        self.flags & IPV4_FLAG_DONT_FRAGMENT != 0
    }

    /// Return true when the "more fragments" flag is set.
    pub const fn has_more_fragments(self) -> bool {
        self.flags & IPV4_FLAG_MORE_FRAGMENTS != 0
    }

    /// Fragment offset in 8-byte units.
    pub const fn fragment_offset(self) -> u16 {
        self.fragment_offset
    }

    /// Return true when this header marks a fragmented datagram.
    pub const fn is_fragmented(self) -> bool {
        self.has_more_fragments() || self.fragment_offset != 0
    }
}

pub(super) const fn compose_flags_fragment(flags: u8, fragment_offset: u16) -> u16 {
    ((flags as u16) << 13) | fragment_offset
}

pub(super) const fn flags_from_flags_fragment(flags_fragment: u16) -> u8 {
    (flags_fragment >> 13) as u8
}

pub(super) const fn fragment_offset_from_flags_fragment(flags_fragment: u16) -> u16 {
    flags_fragment & IPV4_MAX_FRAGMENT_OFFSET
}

pub(super) fn validate_fragment_fields(flags: u8, fragment_offset: u16) -> Result<()> {
    if flags > IPV4_MAX_FLAGS {
        return Err(CrafterError::invalid_field_value(
            "ipv4.flags",
            "IPv4 flags must fit in three bits",
        ));
    }
    if fragment_offset > IPV4_MAX_FRAGMENT_OFFSET {
        return Err(CrafterError::invalid_field_value(
            "ipv4.fragment_offset",
            "fragment offset must fit in 13 bits",
        ));
    }
    Ok(())
}

pub(super) fn flags_summary(flags: u8) -> String {
    let mut names = Vec::new();
    if flags & IPV4_FLAG_RESERVED != 0 {
        names.push("reserved");
    }
    if flags & IPV4_FLAG_DONT_FRAGMENT != 0 {
        names.push("DF");
    }
    if flags & IPV4_FLAG_MORE_FRAGMENTS != 0 {
        names.push("MF");
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join("|")
    }
}
