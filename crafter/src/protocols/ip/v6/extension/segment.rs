use core::net::Ipv6Addr;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext};

use super::super::constants::{
    IPV6_EXTENSION_MIN_LEN, IPV6_ROUTING_TYPE_SEGMENT, IPV6_SEGMENT_BASE_LEN,
    IPV6_SEGMENT_HMAC_LEN, IPV6_SEGMENT_POLICY_UNSET,
};
use super::super::decode::validate_segment_routing_tlv_shape;
use super::super::display::{
    hex_bytes, ipv6_list_summary, ipv6_routing_type_label, ipv6_routing_type_status,
    next_header_summary, routing_type_summary,
};
use super::super::{layer_ipv6_next_header, parse_ipv6, value_or_copy};
use super::{header_ext_len_from_total, round_up_to_8, validate_extension_total_len};

use super::routing::Ipv6RoutingTypeStatus;

/// IPv6 Segment Routing Header (Routing Header type 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6SegmentRoutingHeader {
    pub(in crate::protocols::ip::v6) next_header: Field<u8>,
    pub(in crate::protocols::ip::v6) header_ext_len: Field<u8>,
    pub(in crate::protocols::ip::v6) routing_type: Field<u8>,
    pub(in crate::protocols::ip::v6) segments_left: Field<u8>,
    pub(in crate::protocols::ip::v6) last_entry: Field<u8>,
    pub(in crate::protocols::ip::v6) flags: Field<u8>,
    pub(in crate::protocols::ip::v6) tag: Field<u16>,
    pub(in crate::protocols::ip::v6) policy_flag1: Field<u8>,
    pub(in crate::protocols::ip::v6) policy_flag2: Field<u8>,
    pub(in crate::protocols::ip::v6) policy_flag3: Field<u8>,
    pub(in crate::protocols::ip::v6) policy_flag4: Field<u8>,
    pub(in crate::protocols::ip::v6) hmac_key_id: Field<u8>,
    pub(in crate::protocols::ip::v6) segments: Vec<Ipv6Addr>,
    pub(in crate::protocols::ip::v6) policies: [Ipv6Addr; 4],
    pub(in crate::protocols::ip::v6) hmac: [u8; IPV6_SEGMENT_HMAC_LEN],
    pub(in crate::protocols::ip::v6) trailing_data: Vec<u8>,
}

impl Ipv6SegmentRoutingHeader {
    /// Create an empty segment routing header.
    pub fn new() -> Self {
        Self {
            next_header: Field::defaulted(0),
            header_ext_len: Field::unset(),
            routing_type: Field::defaulted(IPV6_ROUTING_TYPE_SEGMENT),
            segments_left: Field::unset(),
            last_entry: Field::unset(),
            flags: Field::defaulted(0),
            tag: Field::defaulted(0),
            policy_flag1: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
            policy_flag2: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
            policy_flag3: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
            policy_flag4: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
            hmac_key_id: Field::defaulted(0),
            segments: Vec::new(),
            policies: [Ipv6Addr::UNSPECIFIED; 4],
            hmac: [0; IPV6_SEGMENT_HMAC_LEN],
            trailing_data: Vec::new(),
        }
    }

    /// Set the next header after this segment routing header.
    pub fn next_header(mut self, next_header: u8) -> Self {
        self.next_header.set_user(next_header);
        self
    }

    /// Compatibility alias for next header.
    pub fn nh(self, next_header: u8) -> Self {
        self.next_header(next_header)
    }

    /// Set the encoded header extension length.
    pub fn header_ext_len(mut self, header_ext_len: u8) -> Self {
        self.header_ext_len.set_user(header_ext_len);
        self
    }

    /// Set the routing type field.
    pub fn routing_type(mut self, routing_type: u8) -> Self {
        self.routing_type.set_user(routing_type);
        self
    }

    /// Set the segments-left field.
    pub fn segments_left(mut self, segments_left: u8) -> Self {
        self.segments_left.set_user(segments_left);
        self
    }

    /// libcrafter-style alias for segments left.
    pub fn segleft(self, segments_left: u8) -> Self {
        self.segments_left(segments_left)
    }

    /// Set the RFC 8754 Last Entry field.
    pub fn last_entry(mut self, last_entry: u8) -> Self {
        self.last_entry.set_user(last_entry);
        self
    }

    /// Compatibility alias for the RFC 8754 Last Entry field.
    pub fn first_segment(self, first_segment: u8) -> Self {
        self.last_entry(first_segment)
    }

    /// Set the RFC 8754 Flags byte.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set the RFC 8754 Tag field.
    pub fn tag(mut self, tag: u16) -> Self {
        self.tag.set_user(tag);
        self
    }

    /// Set or clear the cleanup flag.
    pub fn c_flag(mut self, c_flag: bool) -> Self {
        self.set_flag_bit(0x80, c_flag);
        self
    }

    /// Set or clear the protected flag.
    pub fn p_flag(mut self, p_flag: bool) -> Self {
        self.set_flag_bit(0x40, p_flag);
        self
    }

    /// libcrafter-style alias for protected flag.
    pub fn pflag(self, p_flag: bool) -> Self {
        self.p_flag(p_flag)
    }

    /// Set the two reserved bits.
    pub fn reserved(mut self, reserved: u8) -> Self {
        let mut flags = self.flags_value();
        flags &= !0x30;
        flags |= (reserved & 0x03) << 4;
        self.flags.set_user(flags);
        self
    }

    /// Set policy flag 1.
    pub fn policy_flag1(mut self, policy_flag: u8) -> Self {
        self.policy_flag1.set_user(policy_flag);
        self
    }

    /// Set policy flag 2.
    pub fn policy_flag2(mut self, policy_flag: u8) -> Self {
        self.policy_flag2.set_user(policy_flag);
        self
    }

    /// Set policy flag 3.
    pub fn policy_flag3(mut self, policy_flag: u8) -> Self {
        self.policy_flag3.set_user(policy_flag);
        self
    }

    /// Set policy flag 4.
    pub fn policy_flag4(mut self, policy_flag: u8) -> Self {
        self.policy_flag4.set_user(policy_flag);
        self
    }

    /// Set one policy flag by zero-based policy index.
    pub fn policy_flag(mut self, index: usize, policy_flag: u8) -> Result<Self> {
        self.set_policy_flag(index, policy_flag)?;
        Ok(self)
    }

    /// Set the HMAC key identifier.
    pub fn hmac_key_id(mut self, hmac_key_id: u8) -> Self {
        self.hmac_key_id.set_user(hmac_key_id);
        self
    }

    /// Replace the HMAC bytes.
    pub fn hmac(mut self, hmac: [u8; IPV6_SEGMENT_HMAC_LEN]) -> Self {
        self.hmac = hmac;
        self
    }

    /// Append a segment address.
    pub fn segment(mut self, segment: Ipv6Addr) -> Self {
        self.segments.push(segment);
        self
    }

    /// libcrafter-style alias for appending a segment.
    pub fn push_segment(self, segment: Ipv6Addr) -> Self {
        self.segment(segment)
    }

    /// Append a textual segment address.
    pub fn segment_str(self, segment: &str) -> Result<Self> {
        Ok(self.segment(parse_ipv6(segment)?))
    }

    /// libcrafter-style alias for appending a textual segment.
    pub fn push_ipv6_segment(self, segment: &str) -> Result<Self> {
        self.segment_str(segment)
    }

    /// Set a policy address and flag by zero-based policy index.
    pub fn policy(mut self, index: usize, policy: Ipv6Addr, policy_flag: u8) -> Result<Self> {
        self.set_policy(index, policy, policy_flag)?;
        Ok(self)
    }

    /// Set a textual policy address and flag by zero-based policy index.
    pub fn policy_str(self, index: usize, policy: &str, policy_flag: u8) -> Result<Self> {
        self.policy(index, parse_ipv6(policy)?, policy_flag)
    }

    /// Preserve or append raw bytes after the RFC 8754 Segment List.
    pub fn raw_trailing_data(mut self, raw_trailing_data: impl Into<Vec<u8>>) -> Self {
        self.trailing_data = raw_trailing_data.into();
        self
    }

    /// Compatibility alias for raw bytes after the RFC 8754 Segment List.
    pub fn extra_data(mut self, extra_data: impl Into<Vec<u8>>) -> Self {
        self.trailing_data = extra_data.into();
        self
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, 0)
    }

    /// Header extension length when explicit or decoded.
    pub fn header_ext_len_value(&self) -> Option<u8> {
        self.header_ext_len.value().copied()
    }

    /// Routing type.
    pub fn routing_type_value(&self) -> u8 {
        value_or_copy(&self.routing_type, IPV6_ROUTING_TYPE_SEGMENT)
    }

    /// Routing type label from the IANA IPv6 Routing Types registry.
    pub fn routing_type_label(&self) -> &'static str {
        ipv6_routing_type_label(self.routing_type_value())
    }

    /// Routing type status from the IANA IPv6 Routing Types registry.
    pub fn routing_type_status(&self) -> Ipv6RoutingTypeStatus {
        ipv6_routing_type_status(self.routing_type_value())
    }

    /// Segments-left value.
    pub fn segments_left_value(&self) -> u8 {
        self.segments_left
            .value()
            .copied()
            .unwrap_or_else(|| saturating_last_index(self.segments.len()))
    }

    /// RFC 8754 Last Entry value.
    pub fn last_entry_value(&self) -> u8 {
        self.last_entry
            .value()
            .copied()
            .unwrap_or_else(|| saturating_last_index(self.segments.len()))
    }

    /// Compatibility alias for the RFC 8754 Last Entry value.
    pub fn first_segment_value(&self) -> u8 {
        self.last_entry_value()
    }

    /// RFC 8754 Flags byte.
    pub fn flags_value(&self) -> u8 {
        value_or_copy(&self.flags, 0)
    }

    /// RFC 8754 Tag value.
    pub fn tag_value(&self) -> u16 {
        value_or_copy(&self.tag, 0)
    }

    /// Return true when the cleanup flag is set.
    pub fn c_flag_value(&self) -> bool {
        self.flags_value() & 0x80 != 0
    }

    /// Return true when the protected flag is set.
    pub fn p_flag_value(&self) -> bool {
        self.flags_value() & 0x40 != 0
    }

    /// Reserved two-bit value.
    pub fn reserved_value(&self) -> u8 {
        (self.flags_value() >> 4) & 0x03
    }

    /// Policy flags.
    pub fn policy_flags(&self) -> [u8; 4] {
        [
            value_or_copy(&self.policy_flag1, IPV6_SEGMENT_POLICY_UNSET),
            value_or_copy(&self.policy_flag2, IPV6_SEGMENT_POLICY_UNSET),
            value_or_copy(&self.policy_flag3, IPV6_SEGMENT_POLICY_UNSET),
            value_or_copy(&self.policy_flag4, IPV6_SEGMENT_POLICY_UNSET),
        ]
    }

    /// HMAC key identifier.
    pub fn hmac_key_id_value(&self) -> u8 {
        value_or_copy(&self.hmac_key_id, 0)
    }

    /// Segment addresses.
    pub fn segments(&self) -> &[Ipv6Addr] {
        &self.segments
    }

    /// RFC 8754 Segment List entries in encoded order.
    pub fn segment_list(&self) -> &[Ipv6Addr] {
        &self.segments
    }

    /// Policy addresses.
    pub fn policies(&self) -> &[Ipv6Addr; 4] {
        &self.policies
    }

    /// HMAC bytes.
    pub fn hmac_bytes(&self) -> &[u8; IPV6_SEGMENT_HMAC_LEN] {
        &self.hmac
    }

    /// Raw bytes preserved after the RFC 8754 Segment List.
    pub fn raw_trailing_data_bytes(&self) -> &[u8] {
        &self.trailing_data
    }

    /// Compatibility alias for raw bytes preserved after the RFC 8754 Segment List.
    pub fn extra_data_bytes(&self) -> &[u8] {
        &self.trailing_data
    }

    fn set_flag_bit(&mut self, mask: u8, enabled: bool) {
        let mut flags = self.flags_value();
        if enabled {
            flags |= mask;
        } else {
            flags &= !mask;
        }
        self.flags.set_user(flags);
    }

    fn set_policy(&mut self, index: usize, policy: Ipv6Addr, policy_flag: u8) -> Result<()> {
        if index >= self.policies.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.policy",
                "policy index must be in the range 0..4",
            ));
        }
        self.policies[index] = policy;
        self.set_policy_flag(index, policy_flag)
    }

    fn set_policy_flag(&mut self, index: usize, policy_flag: u8) -> Result<()> {
        if policy_flag > 0x07 {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.policy_flag",
                "policy flag must fit in three bits",
            ));
        }
        match index {
            0 => self.policy_flag1.set_user(policy_flag),
            1 => self.policy_flag2.set_user(policy_flag),
            2 => self.policy_flag3.set_user(policy_flag),
            3 => self.policy_flag4.set_user(policy_flag),
            _ => {
                return Err(CrafterError::invalid_field_value(
                    "ipv6.segment.policy",
                    "policy index must be in the range 0..4",
                ))
            }
        }
        Ok(())
    }

    fn known_variable_len(&self) -> usize {
        self.segments.len() * 16 + self.trailing_data.len()
    }

    fn effective_total_len(&self) -> usize {
        self.header_ext_len
            .value()
            .map(|value| IPV6_EXTENSION_MIN_LEN + *value as usize * 8)
            .unwrap_or_else(|| round_up_to_8(IPV6_SEGMENT_BASE_LEN + self.known_variable_len()))
    }

    fn effective_header_ext_len(&self) -> Result<u8> {
        header_ext_len_from_total("ipv6.segment.header_ext_len", self.effective_total_len())
    }

    fn effective_next_header(&self, next: Option<&dyn Layer>) -> u8 {
        if self.next_header.is_user_set() {
            return self.next_header_value();
        }

        next.and_then(layer_ipv6_next_header)
            .or_else(|| self.next_header.value().copied())
            .unwrap_or(0)
    }

    fn validate(&self) -> Result<()> {
        validate_extension_total_len("ipv6.segment.header_ext_len", self.effective_total_len())?;
        if self.routing_type_value() != IPV6_ROUTING_TYPE_SEGMENT {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.routing_type",
                "segment routing header type must be 4",
            ));
        }
        if self.segments.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.segments",
                "segment routing header requires at least one segment",
            ));
        }
        if self.last_entry_value() as usize >= self.segments.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.last_entry",
                "last entry must refer to an existing segment",
            ));
        }
        if self.segments_left_value() as usize >= self.segments.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.segments_left",
                "segments left must refer to an existing segment",
            ));
        }
        if self.policy_flags().iter().any(|flag| *flag > 0x07) {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.policy_flag",
                "policy flags must fit in three bits",
            ));
        }
        if self.effective_total_len() < IPV6_SEGMENT_BASE_LEN + self.known_variable_len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.header_ext_len",
                "header extension length is too small for segment data",
            ));
        }
        validate_segment_routing_tlv_shape(&self.trailing_data)?;
        Ok(())
    }
}

impl Default for Ipv6SegmentRoutingHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6SegmentRoutingHeader {
    fn name(&self) -> &'static str {
        "Ipv6SegmentRoutingHeader"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv6SegmentRoutingHeader(type={}, segments={}, segleft={}, flags=0x{:02x}, tag=0x{:04x}, next={})",
            routing_type_summary(self.routing_type_value()),
            self.segments.len(),
            self.segments_left_value(),
            self.flags_value(),
            self.tag_value(),
            next_header_summary(self.next_header_value())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("next_header", next_header_summary(self.next_header_value())),
            (
                "header_ext_len",
                self.header_ext_len_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            (
                "routing_type",
                routing_type_summary(self.routing_type_value()),
            ),
            (
                "routing_type_status",
                format!("{:?}", self.routing_type_status()),
            ),
            ("segments_left", self.segments_left_value().to_string()),
            ("last_entry", self.last_entry_value().to_string()),
            ("first_segment", self.first_segment_value().to_string()),
            ("flags", format!("0x{:02x}", self.flags_value())),
            ("c_flag", self.c_flag_value().to_string()),
            ("p_flag", self.p_flag_value().to_string()),
            ("tag", format!("0x{:04x}", self.tag_value())),
            ("reserved", self.reserved_value().to_string()),
            ("policy_flags", format!("{:?}", self.policy_flags())),
            ("hmac_key_id", self.hmac_key_id_value().to_string()),
            ("segment_list", ipv6_list_summary(&self.segments)),
            ("raw_trailing_data", hex_bytes(&self.trailing_data)),
            ("extra_data", hex_bytes(&self.trailing_data)),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.effective_total_len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        let start = out.len();
        let total_len = self.effective_total_len();

        out.push(self.effective_next_header(ctx.next()));
        out.push(self.effective_header_ext_len()?);
        out.push(self.routing_type_value());
        out.push(self.segments_left_value());
        out.push(self.last_entry_value());
        out.push(self.flags_value());
        out.extend_from_slice(&self.tag_value().to_be_bytes());
        for segment in &self.segments {
            out.extend_from_slice(&segment.octets());
        }
        out.extend_from_slice(&self.trailing_data);
        out.resize(start + total_len, 0);
        Ok(())
    }

    impl_ipv6_extension_layer_object!(Ipv6SegmentRoutingHeader);
}

impl_ipv6_extension_layer_div!(Ipv6SegmentRoutingHeader);

fn saturating_last_index(len: usize) -> u8 {
    len.saturating_sub(1).min(u8::MAX as usize) as u8
}
