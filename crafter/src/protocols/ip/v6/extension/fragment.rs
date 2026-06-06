use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ip::shared::IPPROTO_TCP;

use super::super::constants::{IPV6_FRAGMENT_HEADER_LEN, IPV6_MAX_FRAGMENT_OFFSET};
use super::super::display::{ipv6_fragment_header_status_label, next_header_summary};
use super::super::{layer_ipv6_next_header, value_or_copy};

/// Source-backed classification for an IPv6 Fragment Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6FragmentHeaderStatus {
    /// Fragment Offset is zero and the M flag is clear.
    Atomic,
    /// Fragment Offset is zero and the M flag is set.
    Initial,
    /// Fragment Offset is nonzero.
    NonInitial,
}

impl Ipv6FragmentHeaderStatus {
    /// Whether this status is an RFC 6946 atomic fragment.
    pub const fn is_atomic(self) -> bool {
        matches!(self, Self::Atomic)
    }

    /// Whether this status carries the first bytes of the fragmentable part.
    pub const fn is_initial(self) -> bool {
        matches!(self, Self::Atomic | Self::Initial)
    }

    /// Whether this status is a non-initial fragment.
    pub const fn is_non_initial(self) -> bool {
        matches!(self, Self::NonInitial)
    }

    /// Human-readable status label.
    pub const fn label(self) -> &'static str {
        ipv6_fragment_header_status_label(self)
    }
}

/// IPv6 Fragment Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6FragmentHeader {
    next_header: Field<u8>,
    reserved: Field<u8>,
    fragment_offset: Field<u16>,
    res: Field<u8>,
    more_fragments: Field<bool>,
    identification: Field<u32>,
}

impl Ipv6FragmentHeader {
    /// Create a fragment header with deterministic defaults.
    pub fn new() -> Self {
        Self {
            next_header: Field::defaulted(IPPROTO_TCP),
            reserved: Field::defaulted(0),
            fragment_offset: Field::defaulted(0),
            res: Field::defaulted(0),
            more_fragments: Field::defaulted(false),
            identification: Field::defaulted(0),
        }
    }

    /// Set the next header after this fragment header.
    pub fn next_header(mut self, next_header: u8) -> Self {
        self.next_header.set_user(next_header);
        self
    }

    /// Compatibility alias for next header.
    pub fn nh(self, next_header: u8) -> Self {
        self.next_header(next_header)
    }

    /// Set the reserved byte.
    pub fn reserved(mut self, reserved: u8) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Set the fragment offset in 8-byte units.
    pub fn fragment_offset(mut self, fragment_offset: u16) -> Self {
        self.fragment_offset.set_user(fragment_offset);
        self
    }

    /// Alias for fragment offset.
    pub fn offset(self, fragment_offset: u16) -> Self {
        self.fragment_offset(fragment_offset)
    }

    /// Compatibility alias for fragment offset.
    pub fn frag(self, fragment_offset: u16) -> Self {
        self.fragment_offset(fragment_offset)
    }

    /// Set the two reserved flag bits in the fragment field.
    pub fn res(mut self, res: u8) -> Self {
        self.res.set_user(res);
        self
    }

    /// Set or clear the more-fragments flag.
    pub fn more_fragments(mut self, more_fragments: bool) -> Self {
        self.more_fragments.set_user(more_fragments);
        self
    }

    /// libcrafter-style alias for more-fragments flag.
    pub fn mflag(self, more_fragments: bool) -> Self {
        self.more_fragments(more_fragments)
    }

    /// Set the fragment identification.
    pub fn identification(mut self, identification: u32) -> Self {
        self.identification.set_user(identification);
        self
    }

    /// Compatibility alias for identification.
    pub fn id(self, identification: u32) -> Self {
        self.identification(identification)
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, IPPROTO_TCP)
    }

    /// Reserved byte value.
    pub fn reserved_value(&self) -> u8 {
        value_or_copy(&self.reserved, 0)
    }

    /// Fragment offset in 8-byte units.
    pub fn fragment_offset_value(&self) -> u16 {
        value_or_copy(&self.fragment_offset, 0)
    }

    /// Alias for the Fragment Offset field in 8-octet units.
    pub fn offset_value(&self) -> u16 {
        self.fragment_offset_value()
    }

    /// Fragment Offset field in RFC 8200 8-octet units.
    pub fn fragment_offset_units(&self) -> u16 {
        self.fragment_offset_value()
    }

    /// Fragment Offset field converted to octets.
    pub fn fragment_offset_bytes(&self) -> u32 {
        u32::from(self.fragment_offset_value()) * 8
    }

    /// Two reserved bits in the fragment field.
    pub fn res_value(&self) -> u8 {
        value_or_copy(&self.res, 0)
    }

    /// Reserved byte value.
    pub fn reserved_byte_value(&self) -> u8 {
        self.reserved_value()
    }

    /// Two reserved bits in the fragment field.
    pub fn reserved_bits_value(&self) -> u8 {
        self.res_value()
    }

    /// Whether the two fragment-field reserved bits are zero.
    pub fn reserved_bits_are_zero(&self) -> bool {
        self.reserved_bits_value() == 0
    }

    /// Whether all reserved Fragment Header fields are zero.
    pub fn reserved_fields_are_zero(&self) -> bool {
        self.reserved_byte_value() == 0 && self.reserved_bits_are_zero()
    }

    /// Return true when the more-fragments flag is set.
    pub fn has_more_fragments(&self) -> bool {
        value_or_copy(&self.more_fragments, false)
    }

    /// More-fragments flag value.
    pub fn more_fragments_value(&self) -> bool {
        self.has_more_fragments()
    }

    /// Compatibility alias for the more-fragments flag value.
    pub fn mflag_value(&self) -> bool {
        self.has_more_fragments()
    }

    /// Whether this header marks the last fragment.
    pub fn is_last_fragment(&self) -> bool {
        !self.has_more_fragments()
    }

    /// Fragment identification value.
    pub fn identification_value(&self) -> u32 {
        value_or_copy(&self.identification, 0)
    }

    /// Compatibility alias for the fragment identification value.
    pub fn id_value(&self) -> u32 {
        self.identification_value()
    }

    /// RFC 6946/RFC 8200 classification from Fragment Offset and M flag.
    pub fn fragment_status(&self) -> Ipv6FragmentHeaderStatus {
        match (self.fragment_offset_value(), self.has_more_fragments()) {
            (0, false) => Ipv6FragmentHeaderStatus::Atomic,
            (0, true) => Ipv6FragmentHeaderStatus::Initial,
            _ => Ipv6FragmentHeaderStatus::NonInitial,
        }
    }

    /// Alias for the Fragment Header classification.
    pub fn status(&self) -> Ipv6FragmentHeaderStatus {
        self.fragment_status()
    }

    /// Human-readable Fragment Header classification.
    pub fn fragment_status_label(&self) -> &'static str {
        self.fragment_status().label()
    }

    /// Whether this header is an RFC 6946 atomic fragment.
    pub fn is_atomic_fragment(&self) -> bool {
        self.fragment_status().is_atomic()
    }

    /// Whether the Fragment Offset field is zero.
    pub fn is_initial_fragment(&self) -> bool {
        self.fragment_status().is_initial()
    }

    /// Whether the Fragment Offset field is nonzero.
    pub fn is_non_initial_fragment(&self) -> bool {
        self.fragment_status().is_non_initial()
    }

    fn effective_next_header(&self, next: Option<&dyn Layer>) -> u8 {
        if self.next_header.is_user_set() {
            return self.next_header_value();
        }

        next.and_then(layer_ipv6_next_header)
            .or_else(|| self.next_header.value().copied())
            .unwrap_or(IPPROTO_TCP)
    }

    fn validate(&self) -> Result<()> {
        if self.fragment_offset_value() > IPV6_MAX_FRAGMENT_OFFSET {
            return Err(CrafterError::invalid_field_value(
                "ipv6.fragment.fragment_offset",
                "fragment offset must fit in 13 bits",
            ));
        }
        if self.res_value() > 0x03 {
            return Err(CrafterError::invalid_field_value(
                "ipv6.fragment.res",
                "fragment reserved bits must fit in two bits",
            ));
        }
        Ok(())
    }
}

impl Default for Ipv6FragmentHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6FragmentHeader {
    fn name(&self) -> &'static str {
        "Ipv6FragmentHeader"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv6FragmentHeader(offset={}, m={}, next={})",
            self.fragment_offset_value(),
            self.has_more_fragments(),
            next_header_summary(self.next_header_value())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("next_header", next_header_summary(self.next_header_value())),
            ("reserved", format!("0x{:02x}", self.reserved_value())),
            ("fragment_offset", self.fragment_offset_value().to_string()),
            (
                "fragment_offset_bytes",
                self.fragment_offset_bytes().to_string(),
            ),
            ("fragment_status", self.fragment_status_label().to_string()),
            ("res", self.res_value().to_string()),
            (
                "reserved_bits",
                format!("0b{:02b}", self.reserved_bits_value()),
            ),
            (
                "reserved_fields_zero",
                self.reserved_fields_are_zero().to_string(),
            ),
            ("more_fragments", self.has_more_fragments().to_string()),
            (
                "identification",
                format!("0x{:08x}", self.identification_value()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        IPV6_FRAGMENT_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        let fragment_field = (self.fragment_offset_value() << 3)
            | ((self.res_value() as u16) << 1)
            | u16::from(self.has_more_fragments());

        out.push(self.effective_next_header(ctx.next()));
        out.push(self.reserved_value());
        out.extend_from_slice(&fragment_field.to_be_bytes());
        out.extend_from_slice(&self.identification_value().to_be_bytes());
        Ok(())
    }

    impl_ipv6_extension_layer_object!(Ipv6FragmentHeader);
}

impl_ipv6_extension_layer_div!(Ipv6FragmentHeader);

pub(in crate::protocols::ip::v6) fn decode_fragment_header(
    bytes: &[u8],
) -> Result<(Ipv6FragmentHeader, u8, &[u8])> {
    if bytes.len() < IPV6_FRAGMENT_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ipv6 fragment header",
            IPV6_FRAGMENT_HEADER_LEN,
            bytes.len(),
        ));
    }

    let fragment_field = read_u16_be(&bytes[2..4])?;
    let fragment = Ipv6FragmentHeader {
        next_header: Field::user(bytes[0]),
        reserved: Field::user(bytes[1]),
        fragment_offset: Field::user(fragment_field >> 3),
        res: Field::user(((fragment_field >> 1) & 0x03) as u8),
        more_fragments: Field::user(fragment_field & 1 != 0),
        identification: Field::user(read_u32_be(&bytes[4..8])?),
    };

    Ok((fragment, bytes[0], &bytes[IPV6_FRAGMENT_HEADER_LEN..]))
}
