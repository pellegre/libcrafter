//! IPv4 fixed header layer implementation.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::str::FromStr;

use crate::checksum::ipv4_header_checksum;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, TransportChecksumContext};
use crate::protocols::icmp::Icmpv4;
use crate::protocols::ip::shared::{Dscp, Ecn, DSCP_SHIFT, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};
use crate::protocols::transport::{Tcp, Udp};

use super::constants::{
    IPV4_FLAG_DONT_FRAGMENT, IPV4_FLAG_MORE_FRAGMENTS, IPV4_FLAG_RESERVED, IPV4_MAX_HEADER_LEN,
    IPV4_MAX_IHL, IPV4_MIN_HEADER_LEN,
};
use super::display;
use super::fragment::{compose_flags_fragment, validate_fragment_fields, Ipv4FragmentInfo};
use super::options::{padded_options_len, validate_ipv4_options, Ipv4Option, Ipv4OptionIter};
use super::protocol::Ipv4Protocol;

macro_rules! impl_layer_object {
    ($type:ty) => {
        fn clone_layer(&self) -> Box<dyn Layer> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    };
}

macro_rules! impl_layer_div {
    ($type:ty) => {
        impl<R> Div<R> for $type
        where
            R: IntoPacket,
        {
            type Output = Packet;

            fn div(self, rhs: R) -> Self::Output {
                Packet::from_layer(self).concat(rhs)
            }
        }
    };
}

/// Decode-time validation status for the IPv4 header checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ipv4ChecksumStatus {
    /// Checksum validation was not attempted.
    NotChecked,
    /// The decoded IPv4 header checksum validates.
    Valid,
    /// The decoded IPv4 header checksum failed validation.
    Invalid,
}

/// IPv4 packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4 {
    pub(super) version: Field<u8>,
    pub(super) ihl: Field<u8>,
    pub(super) tos: Field<u8>,
    pub(super) total_length: Field<u16>,
    pub(super) identification: Field<u16>,
    pub(super) flags: Field<u8>,
    pub(super) fragment_offset: Field<u16>,
    pub(super) ttl: Field<u8>,
    pub(super) protocol: Field<u8>,
    pub(super) checksum: Field<u16>,
    pub(super) checksum_status: Ipv4ChecksumStatus,
    pub(super) source: Field<Ipv4Addr>,
    pub(super) destination: Field<Ipv4Addr>,
    pub(super) options: Vec<u8>,
}

impl Ipv4 {
    /// Create an IPv4 header with deterministic packet-builder defaults.
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(4),
            ihl: Field::unset(),
            tos: Field::defaulted(0),
            total_length: Field::unset(),
            identification: Field::defaulted(1),
            flags: Field::defaulted(0),
            fragment_offset: Field::defaulted(0),
            ttl: Field::defaulted(64),
            protocol: Field::defaulted(0),
            checksum: Field::unset(),
            checksum_status: Ipv4ChecksumStatus::NotChecked,
            source: Field::defaulted(Ipv4Addr::LOCALHOST),
            destination: Field::defaulted(Ipv4Addr::LOCALHOST),
            options: Vec::new(),
        }
    }

    /// Create an IPv4 header with explicit source and destination addresses.
    pub fn with_addresses(source: Ipv4Addr, destination: Ipv4Addr) -> Self {
        Self::new().src(source).dst(destination)
    }

    /// Set the IP version field.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the internet header length in 32-bit words.
    pub fn ihl(mut self, ihl: u8) -> Self {
        self.ihl.set_user(ihl);
        self
    }

    /// Set the type-of-service / DSCP+ECN byte.
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos.set_user(tos);
        self
    }

    /// Set the full Differentiated Services field byte.
    pub fn ds_field(self, ds_field: u8) -> Self {
        self.tos(ds_field)
    }

    /// Set the DSCP subfield, preserving the current ECN bits.
    pub fn dscp(mut self, dscp: Dscp) -> Self {
        let ecn = self.ecn_value();
        self.tos.set_user(compose_ds_field(dscp, ecn));
        self
    }

    /// Set the ECN subfield, preserving the current DSCP bits.
    pub fn ecn(mut self, ecn: Ecn) -> Self {
        let dscp = self.dscp_value();
        self.tos.set_user(compose_ds_field(dscp, ecn));
        self
    }

    /// Set the total length field.
    pub fn total_length(mut self, total_length: u16) -> Self {
        self.total_length.set_user(total_length);
        self
    }

    /// Compatibility alias for total length.
    pub fn len(self, total_length: u16) -> Self {
        self.total_length(total_length)
    }

    /// Set the identification field.
    pub fn identification(mut self, identification: u16) -> Self {
        self.identification.set_user(identification);
        self
    }

    /// Compatibility alias for identification.
    pub fn id(self, identification: u16) -> Self {
        self.identification(identification)
    }

    /// Set the raw three IPv4 flag bits.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set or clear the reserved IPv4 flag bit.
    pub fn reserved_flag(mut self, enabled: bool) -> Self {
        let mut flags = self.flags_value();
        if enabled {
            flags |= IPV4_FLAG_RESERVED;
        } else {
            flags &= !IPV4_FLAG_RESERVED;
        }
        self.flags.set_user(flags);
        self
    }

    /// Set or clear the "don't fragment" flag.
    pub fn dont_fragment(mut self, enabled: bool) -> Self {
        let mut flags = self.flags_value();
        if enabled {
            flags |= IPV4_FLAG_DONT_FRAGMENT;
        } else {
            flags &= !IPV4_FLAG_DONT_FRAGMENT;
        }
        self.flags.set_user(flags);
        self
    }

    /// Set or clear the "more fragments" flag.
    pub fn more_fragments(mut self, enabled: bool) -> Self {
        let mut flags = self.flags_value();
        if enabled {
            flags |= IPV4_FLAG_MORE_FRAGMENTS;
        } else {
            flags &= !IPV4_FLAG_MORE_FRAGMENTS;
        }
        self.flags.set_user(flags);
        self
    }

    /// Set the fragment offset in 8-byte units.
    pub fn fragment_offset(mut self, fragment_offset: u16) -> Self {
        self.fragment_offset.set_user(fragment_offset);
        self
    }

    /// Compatibility alias for fragment offset.
    pub fn frag(self, fragment_offset: u16) -> Self {
        self.fragment_offset(fragment_offset)
    }

    /// Set the time-to-live value.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl.set_user(ttl);
        self
    }

    /// Set the raw protocol number.
    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol.set_user(protocol);
        self
    }

    /// Set a known IPv4 protocol number.
    pub fn ipv4_protocol(self, protocol: Ipv4Protocol) -> Self {
        self.protocol(protocol.into())
    }

    /// Set the IPv4 header checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Compatibility alias for checksum.
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Set the source IPv4 address.
    pub fn src(mut self, source: Ipv4Addr) -> Self {
        self.source.set_user(source);
        self
    }

    /// Set the source IPv4 address from dotted-quad text.
    pub fn src_str(self, source: &str) -> Result<Self> {
        Ok(self.src(parse_ipv4(source)?))
    }

    /// Set the destination IPv4 address.
    pub fn dst(mut self, destination: Ipv4Addr) -> Self {
        self.destination.set_user(destination);
        self
    }

    /// Set the destination IPv4 address from dotted-quad text.
    pub fn dst_str(self, destination: &str) -> Result<Self> {
        Ok(self.dst(parse_ipv4(destination)?))
    }

    /// Append raw IPv4 option bytes.
    pub fn option(mut self, option: impl AsRef<[u8]>) -> Self {
        self.options.extend_from_slice(option.as_ref());
        self
    }

    /// Append a typed IPv4 option.
    pub fn ipv4_option(mut self, option: Ipv4Option) -> Result<Self> {
        self.options.extend_from_slice(&option.encode()?);
        Ok(self)
    }

    /// Replace all IPv4 option bytes.
    pub fn options(mut self, options: impl Into<Vec<u8>>) -> Self {
        self.options = options.into();
        self
    }

    /// Remove all IPv4 option bytes.
    pub fn clear_options(mut self) -> Self {
        self.options.clear();
        self
    }

    /// IP version value.
    pub fn version_value(&self) -> u8 {
        value_or_copy(&self.version, 4)
    }

    /// Header length in 32-bit words.
    pub fn ihl_value(&self) -> u8 {
        self.effective_ihl()
    }

    /// Header length in bytes.
    pub fn header_len(&self) -> usize {
        self.effective_header_len()
    }

    /// Type-of-service / DSCP+ECN value.
    pub fn tos_value(&self) -> u8 {
        value_or_copy(&self.tos, 0)
    }

    /// Full Differentiated Services field byte.
    pub fn ds_field_value(&self) -> u8 {
        self.tos_value()
    }

    /// DSCP subfield of the IPv4 DS/TOS octet.
    pub fn dscp_value(&self) -> Dscp {
        Dscp::from_ds_field(self.tos_value())
    }

    /// ECN subfield of the IPv4 DS/TOS octet.
    pub fn ecn_value(&self) -> Ecn {
        Ecn::from_ds_field(self.tos_value())
    }

    /// Total length field value when explicitly stored or decoded.
    pub fn total_length_value(&self) -> Option<u16> {
        self.total_length.value().copied()
    }

    /// Identification field.
    pub fn identification_value(&self) -> u16 {
        value_or_copy(&self.identification, 1)
    }

    /// Raw three-bit flags value.
    pub fn flags_value(&self) -> u8 {
        value_or_copy(&self.flags, 0)
    }

    /// Inspect the IPv4 fragmentation-related header fields together.
    pub fn fragment_info(&self) -> Ipv4FragmentInfo {
        Ipv4FragmentInfo::new(
            self.identification_value(),
            self.flags_value(),
            self.fragment_offset_value(),
        )
    }

    /// Return true when the reserved IPv4 flag bit is set.
    pub fn is_reserved_flag_set(&self) -> bool {
        self.fragment_info().is_reserved_flag_set()
    }

    /// Return true when the "don't fragment" flag is set.
    pub fn is_dont_fragment(&self) -> bool {
        self.fragment_info().is_dont_fragment()
    }

    /// Return true when the "more fragments" flag is set.
    pub fn has_more_fragments(&self) -> bool {
        self.fragment_info().has_more_fragments()
    }

    /// Fragment offset in 8-byte units.
    pub fn fragment_offset_value(&self) -> u16 {
        value_or_copy(&self.fragment_offset, 0)
    }

    /// Return true when this header marks a fragmented datagram.
    pub fn is_fragmented(&self) -> bool {
        self.fragment_info().is_fragmented()
    }

    /// Time-to-live value.
    pub fn ttl_value(&self) -> u8 {
        value_or_copy(&self.ttl, 64)
    }

    /// Protocol number.
    pub fn protocol_value(&self) -> u8 {
        value_or_copy(&self.protocol, 0)
    }

    /// Header checksum when explicitly stored or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Decode-time IPv4 header checksum validation status.
    pub const fn checksum_status(&self) -> Ipv4ChecksumStatus {
        self.checksum_status
    }

    /// Source address.
    pub fn source(&self) -> Ipv4Addr {
        value_or_copy(&self.source, Ipv4Addr::LOCALHOST)
    }

    /// Destination address.
    pub fn destination(&self) -> Ipv4Addr {
        value_or_copy(&self.destination, Ipv4Addr::LOCALHOST)
    }

    /// Raw IPv4 option bytes, including decode-time padding bytes.
    pub fn option_bytes(&self) -> &[u8] {
        &self.options
    }

    /// Iterate over decoded IPv4 options.
    pub fn option_iter(&self) -> Ipv4OptionIter<'_> {
        Ipv4OptionIter::new(&self.options)
    }

    /// Decode IPv4 options into typed values.
    pub fn parsed_options(&self) -> Result<Vec<Ipv4Option>> {
        Ipv4Option::decode_all(&self.options)
    }

    fn effective_ihl(&self) -> u8 {
        self.ihl
            .value()
            .copied()
            .unwrap_or((self.effective_header_len() / 4) as u8)
    }

    fn effective_header_len(&self) -> usize {
        if let Some(ihl) = self.ihl.value().copied() {
            (ihl as usize) * 4
        } else {
            IPV4_MIN_HEADER_LEN + padded_options_len(self.options.len())
        }
    }

    fn effective_total_length(&self, payload_len: usize) -> Result<u16> {
        if let Some(total_length) = self.total_length.value().copied() {
            return Ok(total_length);
        }

        let total = self.effective_header_len() + payload_len;
        u16::try_from(total).map_err(|_| {
            CrafterError::invalid_field_value("ipv4.total_length", "packet length exceeds 65535")
        })
    }

    fn effective_protocol(&self, next: Option<&dyn Layer>) -> u8 {
        if self.protocol.is_user_set() {
            return self.protocol_value();
        }

        next.and_then(layer_ipv4_protocol)
            .or_else(|| self.protocol.value().copied())
            .unwrap_or(0)
    }

    fn effective_checksum(&self, header: &[u8]) -> u16 {
        self.checksum
            .value()
            .copied()
            .unwrap_or_else(|| ipv4_header_checksum(header))
    }

    fn validate(&self, payload_len: usize) -> Result<()> {
        if self.version_value() != 4 {
            return Err(CrafterError::invalid_field_value(
                "ipv4.version",
                "IPv4 layer version must be 4",
            ));
        }
        if self.effective_ihl() < 5 {
            return Err(CrafterError::invalid_field_value(
                "ipv4.ihl",
                "internet header length must be at least 5 words",
            ));
        }
        if self.effective_ihl() > IPV4_MAX_IHL {
            return Err(CrafterError::invalid_field_value(
                "ipv4.ihl",
                "internet header length must be <= 15 words",
            ));
        }
        if self.effective_header_len() < IPV4_MIN_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ipv4.ihl",
                "internet header length must be at least 20 bytes",
            ));
        }
        if self.effective_header_len() > IPV4_MAX_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ipv4.ihl",
                "internet header length must be <= 60 bytes",
            ));
        }
        if self.options.len() > IPV4_MAX_HEADER_LEN - IPV4_MIN_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ipv4.options",
                "IPv4 options must fit within the 60-byte maximum header",
            ));
        }
        validate_ipv4_options(&self.options)?;
        if self.effective_header_len() < IPV4_MIN_HEADER_LEN + self.options.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv4.ihl",
                "internet header length is too small for option bytes",
            ));
        }
        validate_fragment_fields(self.flags_value(), self.fragment_offset_value())?;
        if self.effective_total_length(payload_len)? < self.effective_header_len() as u16 {
            return Err(CrafterError::invalid_field_value(
                "ipv4.total_length",
                "total length must be at least the IPv4 header length",
            ));
        }
        Ok(())
    }
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv4 {
    fn name(&self) -> &'static str {
        "Ipv4"
    }

    fn summary(&self) -> String {
        display::summary(self)
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        display::inspection_fields(self)
    }

    fn encoded_len(&self) -> usize {
        self.effective_header_len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let payload_len = payload_len_after(*ctx);
        self.validate(payload_len)?;

        let header_len = self.effective_header_len();
        let ihl = (header_len / 4) as u8;
        let total_length = self.effective_total_length(payload_len)?;
        let flags_fragment =
            compose_flags_fragment(self.flags_value(), self.fragment_offset_value());
        let protocol = self.effective_protocol(ctx.next());

        let start = out.len();
        out.reserve(header_len);
        out.push((self.version_value() << 4) | ihl);
        out.push(self.tos_value());
        out.extend_from_slice(&total_length.to_be_bytes());
        out.extend_from_slice(&self.identification_value().to_be_bytes());
        out.extend_from_slice(&flags_fragment.to_be_bytes());
        out.push(self.ttl_value());
        out.push(protocol);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.source().octets());
        out.extend_from_slice(&self.destination().octets());
        out.extend_from_slice(&self.options);
        out.resize(start + header_len, 0);

        let checksum = self.effective_checksum(&out[start..start + header_len]);
        out[start + 10..start + 12].copy_from_slice(&checksum.to_be_bytes());
        Ok(())
    }

    fn transport_checksum_context(
        &self,
        transport_protocol: u8,
    ) -> Option<TransportChecksumContext> {
        Some(TransportChecksumContext::Ipv4 {
            source: self.source(),
            destination: self.destination(),
            protocol: if self.protocol.is_user_set() {
                self.protocol_value()
            } else {
                transport_protocol
            },
        })
    }

    impl_layer_object!(Ipv4);
}

impl_layer_div!(Ipv4);

fn payload_len_after(ctx: LayerContext<'_>) -> usize {
    ctx.packet().encoded_len_after(ctx.index())
}

fn layer_ipv4_protocol(layer: &dyn Layer) -> Option<u8> {
    if layer.as_any().is::<Tcp>() {
        Some(IPPROTO_TCP)
    } else if layer.as_any().is::<Udp>() {
        Some(IPPROTO_UDP)
    } else if layer.as_any().is::<Icmpv4>() {
        Some(IPPROTO_ICMP)
    } else {
        None
    }
}

fn parse_ipv4(input: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(input).map_err(|_| {
        CrafterError::invalid_field_value("ipv4_address", "expected dotted-quad IPv4 address")
    })
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn compose_ds_field(dscp: Dscp, ecn: Ecn) -> u8 {
    (dscp.value() << DSCP_SHIFT) | ecn.value()
}
