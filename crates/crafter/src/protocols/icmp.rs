//! ICMP, ICMPv6, and ICMP extension implementations.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;
use core::str::FromStr;

use crate::checksum::internet_checksum;
use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw, TransportChecksumContext};
use crate::protocols::ip::IPPROTO_ICMPV6;

/// ICMPv4 echo reply type.
pub const ICMP_ECHO_REPLY: u8 = 0;
/// ICMPv4 destination unreachable type.
pub const ICMP_DESTINATION_UNREACHABLE: u8 = 3;
/// ICMPv4 source quench type.
pub const ICMP_SOURCE_QUENCH: u8 = 4;
/// ICMPv4 redirect type.
pub const ICMP_REDIRECT: u8 = 5;
/// ICMPv4 echo request type.
pub const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMPv4 time exceeded type.
pub const ICMP_TIME_EXCEEDED: u8 = 11;
/// ICMPv4 parameter problem type.
pub const ICMP_PARAMETER_PROBLEM: u8 = 12;

/// ICMPv6 destination unreachable type.
pub const ICMPV6_DESTINATION_UNREACHABLE: u8 = 1;
/// ICMPv6 packet-too-big type.
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
/// ICMPv6 time exceeded type.
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
/// ICMPv6 parameter problem type.
pub const ICMPV6_PARAMETER_PROBLEM: u8 = 4;
/// ICMPv6 echo request type.
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
/// ICMPv6 echo reply type.
pub const ICMPV6_ECHO_REPLY: u8 = 129;

/// ICMP extension object class for MPLS labels.
pub const ICMP_EXTENSION_CLASS_MPLS: u8 = 1;
/// ICMP extension object C-Type for an incoming MPLS label stack.
pub const ICMP_EXTENSION_CTYPE_MPLS_INCOMING: u8 = 1;

const ICMP_HEADER_LEN: usize = 8;
const ICMP_EXTENSION_HEADER_LEN: usize = 4;
const ICMP_EXTENSION_OBJECT_LEN: usize = 4;
const ICMP_EXTENSION_MPLS_LEN: usize = 4;
const MPLS_MAX_LABEL: u32 = 0x000f_ffff;
const MPLS_MAX_EXP: u8 = 0x07;

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

/// Internet Control Message Protocol for IPv4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp {
    icmp_type: Field<u8>,
    code: Field<u8>,
    checksum: Field<u16>,
    rest_of_header: Field<[u8; 4]>,
    identifier: Field<u16>,
    sequence_number: Field<u16>,
    pointer: Field<u8>,
    gateway: Field<Ipv4Addr>,
    length: Field<u8>,
    mtu_next_hop: Field<u16>,
}

impl Icmp {
    /// Create an ICMP echo-request header with deterministic defaults.
    pub fn new() -> Self {
        Self {
            icmp_type: Field::defaulted(ICMP_ECHO_REQUEST),
            code: Field::defaulted(0),
            checksum: Field::unset(),
            rest_of_header: Field::defaulted([0; 4]),
            identifier: Field::defaulted(0),
            sequence_number: Field::defaulted(0),
            pointer: Field::unset(),
            gateway: Field::unset(),
            length: Field::unset(),
            mtu_next_hop: Field::unset(),
        }
    }

    /// Create an echo request.
    pub fn echo_request() -> Self {
        Self::new().kind(IcmpKind::EchoRequest)
    }

    /// Create an echo reply.
    pub fn echo_reply() -> Self {
        Self::new().kind(IcmpKind::EchoReply)
    }

    /// Create a time-exceeded message.
    pub fn time_exceeded() -> Self {
        Self::new().kind(IcmpKind::TimeExceeded)
    }

    /// Create a destination-unreachable message.
    pub fn destination_unreachable() -> Self {
        Self::new().kind(IcmpKind::DestinationUnreachable)
    }

    /// Set the ICMP type from a common kind.
    pub fn kind(mut self, kind: IcmpKind) -> Self {
        self.icmp_type.set_user(kind.ipv4_type());
        self
    }

    /// Set the raw ICMP type.
    pub fn icmp_type(mut self, icmp_type: u8) -> Self {
        self.icmp_type.set_user(icmp_type);
        self
    }

    /// Alias for generated code that wants the protocol field name.
    pub fn type_(self, icmp_type: u8) -> Self {
        self.icmp_type(icmp_type)
    }

    /// Set the ICMP code.
    pub fn code(mut self, code: u8) -> Self {
        self.code.set_user(code);
        self
    }

    /// Set the checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Compatibility alias for checksum.
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Set the raw four-byte rest-of-header field.
    pub fn rest_of_header(mut self, rest_of_header: [u8; 4]) -> Self {
        self.rest_of_header.set_user(rest_of_header);
        self
    }

    /// Set the echo identifier.
    pub fn identifier(mut self, identifier: u16) -> Self {
        self.identifier.set_user(identifier);
        self
    }

    /// Compatibility alias for identifier.
    pub fn id(self, identifier: u16) -> Self {
        self.identifier(identifier)
    }

    /// Set the echo sequence number.
    pub fn sequence_number(mut self, sequence_number: u16) -> Self {
        self.sequence_number.set_user(sequence_number);
        self
    }

    /// Compatibility alias for sequence number.
    pub fn seq(self, sequence_number: u16) -> Self {
        self.sequence_number(sequence_number)
    }

    /// Set the parameter-problem pointer byte.
    pub fn pointer(mut self, pointer: u8) -> Self {
        self.pointer.set_user(pointer);
        self
    }

    /// Set the redirect gateway address.
    pub fn gateway(mut self, gateway: Ipv4Addr) -> Self {
        self.gateway.set_user(gateway);
        self
    }

    /// Set the redirect gateway address from dotted-quad text.
    pub fn gateway_str(self, gateway: &str) -> Result<Self> {
        Ok(self.gateway(parse_ipv4(gateway)?))
    }

    /// Set the RFC 4884 original datagram length field explicitly.
    pub fn length(mut self, length: u8) -> Self {
        self.length.set_user(length);
        self
    }

    /// Compatibility alias for RFC 4884 length.
    pub fn len(self, length: u8) -> Self {
        self.length(length)
    }

    /// Set the next-hop MTU field used by destination-unreachable messages.
    pub fn mtu_next_hop(mut self, mtu_next_hop: u16) -> Self {
        self.mtu_next_hop.set_user(mtu_next_hop);
        self
    }

    /// Compatibility alias for next-hop MTU.
    pub fn mtu(self, mtu_next_hop: u16) -> Self {
        self.mtu_next_hop(mtu_next_hop)
    }

    /// Raw ICMP type value.
    pub fn icmp_type_value(&self) -> u8 {
        value_or_copy(&self.icmp_type, ICMP_ECHO_REQUEST)
    }

    /// ICMP code value.
    pub fn code_value(&self) -> u8 {
        value_or_copy(&self.code, 0)
    }

    /// Stored checksum value, when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Echo identifier value when meaningful for the current type.
    pub fn identifier_value(&self) -> Option<u16> {
        if is_echo_v4(self.icmp_type_value()) {
            Some(value_or_u16_from_rest(
                &self.identifier,
                &self.rest_of_header,
                0,
            ))
        } else {
            None
        }
    }

    /// Echo sequence number when meaningful for the current type.
    pub fn sequence_number_value(&self) -> Option<u16> {
        if is_echo_v4(self.icmp_type_value()) {
            Some(value_or_u16_from_rest(
                &self.sequence_number,
                &self.rest_of_header,
                2,
            ))
        } else {
            None
        }
    }

    /// Raw four-byte rest-of-header value after applying typed fields.
    pub fn rest_of_header_value(&self) -> [u8; 4] {
        self.effective_rest_of_header(None, 4).unwrap_or([0; 4])
    }

    /// RFC 4884 length field when explicit or decoded.
    pub fn length_value(&self) -> Option<u8> {
        self.length.value().copied()
    }

    /// Common ICMP kind, when the type is version-independent.
    pub fn kind_value(&self) -> Option<IcmpKind> {
        match self.icmp_type_value() {
            ICMP_DESTINATION_UNREACHABLE => Some(IcmpKind::DestinationUnreachable),
            ICMP_TIME_EXCEEDED => Some(IcmpKind::TimeExceeded),
            ICMP_PARAMETER_PROBLEM => Some(IcmpKind::ParameterProblem),
            ICMP_ECHO_REQUEST => Some(IcmpKind::EchoRequest),
            ICMP_ECHO_REPLY => Some(IcmpKind::EchoReply),
            _ => None,
        }
    }

    fn effective_rest_of_header(
        &self,
        ctx: Option<LayerContext<'_>>,
        extension_unit: usize,
    ) -> Result<[u8; 4]> {
        let mut rest = value_or_copy(&self.rest_of_header, [0; 4]);

        match self.icmp_type_value() {
            ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY => {
                let identifier = value_or_u16_from_rest(&self.identifier, &self.rest_of_header, 0);
                let sequence =
                    value_or_u16_from_rest(&self.sequence_number, &self.rest_of_header, 2);
                rest[..2].copy_from_slice(&identifier.to_be_bytes());
                rest[2..4].copy_from_slice(&sequence.to_be_bytes());
            }
            ICMP_DESTINATION_UNREACHABLE => {
                if let Some(length) = self.effective_extension_length(ctx, extension_unit)? {
                    rest[1] = length;
                }
                if let Some(mtu) = self.mtu_next_hop.value().copied() {
                    rest[2..4].copy_from_slice(&mtu.to_be_bytes());
                }
            }
            ICMP_REDIRECT => {
                if let Some(gateway) = self.gateway.value().copied() {
                    rest = gateway.octets();
                }
            }
            ICMP_TIME_EXCEEDED => {
                if let Some(length) = self.effective_extension_length(ctx, extension_unit)? {
                    rest[1] = length;
                }
            }
            ICMP_PARAMETER_PROBLEM => {
                if let Some(pointer) = self.pointer.value().copied() {
                    rest[0] = pointer;
                }
                if let Some(length) = self.effective_extension_length(ctx, extension_unit)? {
                    rest[1] = length;
                }
            }
            _ => {}
        }

        Ok(rest)
    }

    fn effective_extension_length(
        &self,
        ctx: Option<LayerContext<'_>>,
        unit: usize,
    ) -> Result<Option<u8>> {
        if let Some(length) = self.length.value().copied() {
            return Ok(Some(length));
        }
        let Some(ctx) = ctx else {
            return Ok(None);
        };
        if !icmpv4_type_allows_extensions(self.icmp_type_value()) {
            return Ok(None);
        }

        let len = encoded_len_until_extension(ctx);
        u8::try_from(len / unit).map(Some).map_err(|_| {
            CrafterError::invalid_field_value(
                "icmp.length",
                "ICMP original datagram length does not fit in one byte",
            )
        })
    }

    fn effective_checksum(&self, header: &[u8], payload: &[u8]) -> u16 {
        if let Some(checksum) = self.checksum.value().copied() {
            return checksum;
        }

        let mut segment = Vec::with_capacity(header.len() + payload.len());
        segment.extend_from_slice(header);
        segment.extend_from_slice(payload);
        internet_checksum(&segment)
    }
}

impl Default for Icmp {
    fn default() -> Self {
        Self::new()
    }
}

impl IcmpLayer for Icmp {
    fn icmp_type_value(&self) -> u8 {
        Icmp::icmp_type_value(self)
    }

    fn code_value(&self) -> u8 {
        Icmp::code_value(self)
    }

    fn checksum_value(&self) -> Option<u16> {
        Icmp::checksum_value(self)
    }

    fn identifier_value(&self) -> Option<u16> {
        Icmp::identifier_value(self)
    }

    fn sequence_number_value(&self) -> Option<u16> {
        Icmp::sequence_number_value(self)
    }

    fn kind(&self) -> Option<IcmpKind> {
        self.kind_value()
    }
}

impl Layer for Icmp {
    fn name(&self) -> &'static str {
        "Icmp"
    }

    fn summary(&self) -> String {
        format!(
            "Icmp(type={}, code={}, id={}, seq={})",
            icmpv4_type_summary(self.icmp_type_value()),
            self.code_value(),
            self.identifier_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.sequence_number_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("type", icmpv4_type_summary(self.icmp_type_value())),
            ("code", self.code_value().to_string()),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("rest_of_header", hex_bytes(&self.rest_of_header_value())),
            (
                "identifier",
                self.identifier_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "sequence_number",
                self.sequence_number_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "length",
                self.length_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let payload = payload_bytes_after(*ctx)?;
        let mut header = Vec::with_capacity(ICMP_HEADER_LEN);
        header.push(self.icmp_type_value());
        header.push(self.code_value());
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&self.effective_rest_of_header(Some(*ctx), 4)?);

        let checksum = self.effective_checksum(&header, &payload);
        header[2..4].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        Ok(())
    }

    impl_layer_object!(Icmp);
}

impl_layer_div!(Icmp);

/// Internet Control Message Protocol for IPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6 {
    icmp_type: Field<u8>,
    code: Field<u8>,
    checksum: Field<u16>,
    rest_of_header: Field<[u8; 4]>,
    identifier: Field<u16>,
    sequence_number: Field<u16>,
    length: Field<u8>,
    mtu: Field<u32>,
    pointer: Field<u32>,
}

impl Icmpv6 {
    /// Create an ICMPv6 echo-request header with deterministic defaults.
    pub fn new() -> Self {
        Self {
            icmp_type: Field::defaulted(ICMPV6_ECHO_REQUEST),
            code: Field::defaulted(0),
            checksum: Field::unset(),
            rest_of_header: Field::defaulted([0; 4]),
            identifier: Field::defaulted(0),
            sequence_number: Field::defaulted(0),
            length: Field::unset(),
            mtu: Field::unset(),
            pointer: Field::unset(),
        }
    }

    /// Create an echo request.
    pub fn echo_request() -> Self {
        Self::new().kind(IcmpKind::EchoRequest)
    }

    /// Create an echo reply.
    pub fn echo_reply() -> Self {
        Self::new().kind(IcmpKind::EchoReply)
    }

    /// Create a time-exceeded message.
    pub fn time_exceeded() -> Self {
        Self::new().kind(IcmpKind::TimeExceeded)
    }

    /// Create a destination-unreachable message.
    pub fn destination_unreachable() -> Self {
        Self::new().kind(IcmpKind::DestinationUnreachable)
    }

    /// Create a packet-too-big message.
    pub fn packet_too_big() -> Self {
        Self::new().icmp_type(ICMPV6_PACKET_TOO_BIG)
    }

    /// Set the ICMPv6 type from a common kind.
    pub fn kind(mut self, kind: IcmpKind) -> Self {
        self.icmp_type.set_user(kind.ipv6_type());
        self
    }

    /// Set the raw ICMPv6 type.
    pub fn icmp_type(mut self, icmp_type: u8) -> Self {
        self.icmp_type.set_user(icmp_type);
        self
    }

    /// Alias for generated code that wants the protocol field name.
    pub fn type_(self, icmp_type: u8) -> Self {
        self.icmp_type(icmp_type)
    }

    /// Set the ICMPv6 code.
    pub fn code(mut self, code: u8) -> Self {
        self.code.set_user(code);
        self
    }

    /// Set the checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Compatibility alias for checksum.
    pub fn chksum(self, checksum: u16) -> Self {
        self.checksum(checksum)
    }

    /// Set the raw four-byte rest-of-header field.
    pub fn rest_of_header(mut self, rest_of_header: [u8; 4]) -> Self {
        self.rest_of_header.set_user(rest_of_header);
        self
    }

    /// Set the echo identifier.
    pub fn identifier(mut self, identifier: u16) -> Self {
        self.identifier.set_user(identifier);
        self
    }

    /// Compatibility alias for identifier.
    pub fn id(self, identifier: u16) -> Self {
        self.identifier(identifier)
    }

    /// Set the echo sequence number.
    pub fn sequence_number(mut self, sequence_number: u16) -> Self {
        self.sequence_number.set_user(sequence_number);
        self
    }

    /// Compatibility alias for sequence number.
    pub fn seq(self, sequence_number: u16) -> Self {
        self.sequence_number(sequence_number)
    }

    /// Set the RFC 4884 original datagram length field explicitly.
    pub fn length(mut self, length: u8) -> Self {
        self.length.set_user(length);
        self
    }

    /// Compatibility alias for RFC 4884 length.
    pub fn len(self, length: u8) -> Self {
        self.length(length)
    }

    /// Set the packet-too-big MTU field.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu.set_user(mtu);
        self
    }

    /// Set the parameter-problem pointer field.
    pub fn pointer(mut self, pointer: u32) -> Self {
        self.pointer.set_user(pointer);
        self
    }

    /// Raw ICMPv6 type value.
    pub fn icmp_type_value(&self) -> u8 {
        value_or_copy(&self.icmp_type, ICMPV6_ECHO_REQUEST)
    }

    /// ICMPv6 code value.
    pub fn code_value(&self) -> u8 {
        value_or_copy(&self.code, 0)
    }

    /// Stored checksum value, when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// Echo identifier value when meaningful for the current type.
    pub fn identifier_value(&self) -> Option<u16> {
        if is_echo_v6(self.icmp_type_value()) {
            Some(value_or_u16_from_rest(
                &self.identifier,
                &self.rest_of_header,
                0,
            ))
        } else {
            None
        }
    }

    /// Echo sequence number when meaningful for the current type.
    pub fn sequence_number_value(&self) -> Option<u16> {
        if is_echo_v6(self.icmp_type_value()) {
            Some(value_or_u16_from_rest(
                &self.sequence_number,
                &self.rest_of_header,
                2,
            ))
        } else {
            None
        }
    }

    /// Raw four-byte rest-of-header value after applying typed fields.
    pub fn rest_of_header_value(&self) -> [u8; 4] {
        self.effective_rest_of_header(None, 8).unwrap_or([0; 4])
    }

    /// RFC 4884 length field when explicit or decoded.
    pub fn length_value(&self) -> Option<u8> {
        self.length.value().copied()
    }

    /// Common ICMP kind, when the type is version-independent.
    pub fn kind_value(&self) -> Option<IcmpKind> {
        match self.icmp_type_value() {
            ICMPV6_DESTINATION_UNREACHABLE => Some(IcmpKind::DestinationUnreachable),
            ICMPV6_TIME_EXCEEDED => Some(IcmpKind::TimeExceeded),
            ICMPV6_PARAMETER_PROBLEM => Some(IcmpKind::ParameterProblem),
            ICMPV6_ECHO_REQUEST => Some(IcmpKind::EchoRequest),
            ICMPV6_ECHO_REPLY => Some(IcmpKind::EchoReply),
            _ => None,
        }
    }

    fn effective_rest_of_header(
        &self,
        ctx: Option<LayerContext<'_>>,
        extension_unit: usize,
    ) -> Result<[u8; 4]> {
        let mut rest = value_or_copy(&self.rest_of_header, [0; 4]);

        match self.icmp_type_value() {
            ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY => {
                let identifier = value_or_u16_from_rest(&self.identifier, &self.rest_of_header, 0);
                let sequence =
                    value_or_u16_from_rest(&self.sequence_number, &self.rest_of_header, 2);
                rest[..2].copy_from_slice(&identifier.to_be_bytes());
                rest[2..4].copy_from_slice(&sequence.to_be_bytes());
            }
            ICMPV6_DESTINATION_UNREACHABLE | ICMPV6_TIME_EXCEEDED => {
                if let Some(length) = self.effective_extension_length(ctx, extension_unit)? {
                    rest[0] = length;
                }
            }
            ICMPV6_PACKET_TOO_BIG => {
                if let Some(mtu) = self.mtu.value().copied() {
                    rest.copy_from_slice(&mtu.to_be_bytes());
                }
            }
            ICMPV6_PARAMETER_PROBLEM => {
                if let Some(pointer) = self.pointer.value().copied() {
                    rest.copy_from_slice(&pointer.to_be_bytes());
                }
            }
            _ => {}
        }

        Ok(rest)
    }

    fn effective_extension_length(
        &self,
        ctx: Option<LayerContext<'_>>,
        unit: usize,
    ) -> Result<Option<u8>> {
        if let Some(length) = self.length.value().copied() {
            return Ok(Some(length));
        }
        let Some(ctx) = ctx else {
            return Ok(None);
        };
        if !icmpv6_type_allows_extensions(self.icmp_type_value()) {
            return Ok(None);
        }

        let len = encoded_len_until_extension(ctx);
        u8::try_from(len / unit).map(Some).map_err(|_| {
            CrafterError::invalid_field_value(
                "icmpv6.length",
                "ICMPv6 original datagram length does not fit in one byte",
            )
        })
    }

    fn effective_checksum(&self, ctx: LayerContext<'_>, header: &[u8], payload: &[u8]) -> u16 {
        if let Some(checksum) = self.checksum.value().copied() {
            return checksum;
        }

        let mut segment = Vec::with_capacity(header.len() + payload.len());
        segment.extend_from_slice(header);
        segment.extend_from_slice(payload);
        checksum_context(ctx, IPPROTO_ICMPV6)
            .map(|pseudo_header| pseudo_header.checksum(&segment))
            .unwrap_or(0)
    }
}

impl Default for Icmpv6 {
    fn default() -> Self {
        Self::new()
    }
}

impl IcmpLayer for Icmpv6 {
    fn icmp_type_value(&self) -> u8 {
        Icmpv6::icmp_type_value(self)
    }

    fn code_value(&self) -> u8 {
        Icmpv6::code_value(self)
    }

    fn checksum_value(&self) -> Option<u16> {
        Icmpv6::checksum_value(self)
    }

    fn identifier_value(&self) -> Option<u16> {
        Icmpv6::identifier_value(self)
    }

    fn sequence_number_value(&self) -> Option<u16> {
        Icmpv6::sequence_number_value(self)
    }

    fn kind(&self) -> Option<IcmpKind> {
        self.kind_value()
    }
}

impl Layer for Icmpv6 {
    fn name(&self) -> &'static str {
        "Icmpv6"
    }

    fn summary(&self) -> String {
        format!(
            "Icmpv6(type={}, code={}, id={}, seq={})",
            icmpv6_type_summary(self.icmp_type_value()),
            self.code_value(),
            self.identifier_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.sequence_number_value()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("type", icmpv6_type_summary(self.icmp_type_value())),
            ("code", self.code_value().to_string()),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("rest_of_header", hex_bytes(&self.rest_of_header_value())),
            (
                "identifier",
                self.identifier_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "sequence_number",
                self.sequence_number_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "length",
                self.length_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let payload = payload_bytes_after(*ctx)?;
        let mut header = Vec::with_capacity(ICMP_HEADER_LEN);
        header.push(self.icmp_type_value());
        header.push(self.code_value());
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&self.effective_rest_of_header(Some(*ctx), 8)?);

        let checksum = self.effective_checksum(*ctx, &header, &payload);
        header[2..4].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        Ok(())
    }

    impl_layer_object!(Icmpv6);
}

impl_layer_div!(Icmpv6);

/// RFC 4884 ICMP extension header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtension {
    version: Field<u8>,
    reserved: Field<u16>,
    checksum: Field<u16>,
}

impl IcmpExtension {
    /// Create an ICMP extension header.
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(2),
            reserved: Field::defaulted(0),
            checksum: Field::unset(),
        }
    }

    /// Set the extension version.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the 12-bit reserved field.
    pub fn reserved(mut self, reserved: u16) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Set the extension checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Version value.
    pub fn version_value(&self) -> u8 {
        value_or_copy(&self.version, 2)
    }

    /// Reserved field value.
    pub fn reserved_value(&self) -> u16 {
        value_or_copy(&self.reserved, 0)
    }

    /// Stored checksum when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    fn validate(&self) -> Result<()> {
        if self.version_value() > 0x0f {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension.version",
                "version must fit in four bits",
            ));
        }
        if self.reserved_value() > 0x0fff {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension.reserved",
                "reserved field must fit in 12 bits",
            ));
        }
        Ok(())
    }
}

impl Default for IcmpExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtension {
    fn name(&self) -> &'static str {
        "IcmpExtension"
    }

    fn summary(&self) -> String {
        format!("IcmpExtension(version={})", self.version_value())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("version", self.version_value().to_string()),
            ("reserved", format!("0x{:03x}", self.reserved_value())),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_EXTENSION_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;

        let mut header = Vec::with_capacity(ICMP_EXTENSION_HEADER_LEN);
        let version_reserved =
            ((self.version_value() as u16) << 12) | (self.reserved_value() & 0x0fff);
        header.extend_from_slice(&version_reserved.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        let payload = payload_bytes_after(*ctx)?;
        let checksum = self.checksum.value().copied().unwrap_or_else(|| {
            let mut bytes = Vec::with_capacity(header.len() + payload.len());
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(&payload);
            internet_checksum(&bytes)
        });
        header[2..4].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        Ok(())
    }

    impl_layer_object!(IcmpExtension);
}

impl_layer_div!(IcmpExtension);

/// RFC 4884 ICMP extension object header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtensionObject {
    length: Field<u16>,
    class_num: Field<u8>,
    c_type: Field<u8>,
}

impl IcmpExtensionObject {
    /// Create an extension object header.
    pub fn new() -> Self {
        Self {
            length: Field::unset(),
            class_num: Field::defaulted(0),
            c_type: Field::defaulted(0),
        }
    }

    /// Set the object length explicitly.
    pub fn length(mut self, length: u16) -> Self {
        self.length.set_user(length);
        self
    }

    /// Set the object class number.
    pub fn class_num(mut self, class_num: u8) -> Self {
        self.class_num.set_user(class_num);
        self
    }

    /// Set the object C-Type.
    pub fn c_type(mut self, c_type: u8) -> Self {
        self.c_type.set_user(c_type);
        self
    }

    /// Object length when explicit or decoded.
    pub fn length_value(&self) -> Option<u16> {
        self.length.value().copied()
    }

    /// Object class number.
    pub fn class_num_value(&self) -> u8 {
        value_or_copy(&self.class_num, 0)
    }

    /// Object C-Type.
    pub fn c_type_value(&self) -> u8 {
        value_or_copy(&self.c_type, 0)
    }

    fn effective_length(&self, ctx: LayerContext<'_>) -> Result<u16> {
        if let Some(length) = self.length.value().copied() {
            return Ok(length);
        }

        u16::try_from(ICMP_EXTENSION_OBJECT_LEN + extension_object_payload_len(ctx)).map_err(|_| {
            CrafterError::invalid_field_value(
                "icmp_extension_object.length",
                "extension object length exceeds 65535 bytes",
            )
        })
    }

    fn effective_class_num(&self, next: Option<&dyn Layer>) -> u8 {
        if self.class_num.is_user_set() {
            return self.class_num_value();
        }
        if next
            .map(|layer| layer.as_any().is::<IcmpExtensionMpls>())
            .unwrap_or(false)
        {
            ICMP_EXTENSION_CLASS_MPLS
        } else {
            self.class_num_value()
        }
    }

    fn effective_c_type(&self, next: Option<&dyn Layer>) -> u8 {
        if self.c_type.is_user_set() {
            return self.c_type_value();
        }
        if next
            .map(|layer| layer.as_any().is::<IcmpExtensionMpls>())
            .unwrap_or(false)
        {
            ICMP_EXTENSION_CTYPE_MPLS_INCOMING
        } else {
            self.c_type_value()
        }
    }
}

impl Default for IcmpExtensionObject {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtensionObject {
    fn name(&self) -> &'static str {
        "IcmpExtensionObject"
    }

    fn summary(&self) -> String {
        format!(
            "IcmpExtensionObject(class={}, ctype={})",
            self.class_num_value(),
            self.c_type_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "length",
                self.length_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("class_num", self.class_num_value().to_string()),
            ("c_type", self.c_type_value().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_EXTENSION_OBJECT_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.effective_length(*ctx)?.to_be_bytes());
        out.push(self.effective_class_num(ctx.next()));
        out.push(self.effective_c_type(ctx.next()));
        Ok(())
    }

    impl_layer_object!(IcmpExtensionObject);
}

impl_layer_div!(IcmpExtensionObject);

/// MPLS label stack entry for ICMP extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtensionMpls {
    label: Field<u32>,
    experimental: Field<u8>,
    bottom_of_stack: Field<bool>,
    ttl: Field<u8>,
}

impl IcmpExtensionMpls {
    /// Create an MPLS extension entry.
    pub fn new() -> Self {
        Self {
            label: Field::defaulted(0),
            experimental: Field::defaulted(0),
            bottom_of_stack: Field::unset(),
            ttl: Field::defaulted(0),
        }
    }

    /// Set the MPLS label.
    pub fn label(mut self, label: u32) -> Self {
        self.label.set_user(label);
        self
    }

    /// Set the experimental bits.
    pub fn experimental(mut self, experimental: u8) -> Self {
        self.experimental.set_user(experimental);
        self
    }

    /// Alias for the experimental bits.
    pub fn exp(self, experimental: u8) -> Self {
        self.experimental(experimental)
    }

    /// Set the bottom-of-stack bit explicitly.
    pub fn bottom_of_stack(mut self, bottom_of_stack: bool) -> Self {
        self.bottom_of_stack.set_user(bottom_of_stack);
        self
    }

    /// Set the MPLS TTL.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl.set_user(ttl);
        self
    }

    /// MPLS label value.
    pub fn label_value(&self) -> u32 {
        value_or_copy(&self.label, 0)
    }

    /// Experimental bits value.
    pub fn experimental_value(&self) -> u8 {
        value_or_copy(&self.experimental, 0)
    }

    /// Stored bottom-of-stack bit when explicit or decoded.
    pub fn bottom_of_stack_value(&self) -> Option<bool> {
        self.bottom_of_stack.value().copied()
    }

    /// MPLS TTL value.
    pub fn ttl_value(&self) -> u8 {
        value_or_copy(&self.ttl, 0)
    }

    fn effective_bottom_of_stack(&self, next: Option<&dyn Layer>) -> bool {
        self.bottom_of_stack.value().copied().unwrap_or_else(|| {
            !next
                .map(|layer| layer.as_any().is::<IcmpExtensionMpls>())
                .unwrap_or(false)
        })
    }

    fn validate(&self) -> Result<()> {
        if self.label_value() > MPLS_MAX_LABEL {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension_mpls.label",
                "MPLS label must fit in 20 bits",
            ));
        }
        if self.experimental_value() > MPLS_MAX_EXP {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension_mpls.experimental",
                "MPLS experimental field must fit in three bits",
            ));
        }
        Ok(())
    }
}

impl Default for IcmpExtensionMpls {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtensionMpls {
    fn name(&self) -> &'static str {
        "IcmpExtensionMpls"
    }

    fn summary(&self) -> String {
        format!(
            "IcmpExtensionMpls(label={}, ttl={})",
            self.label_value(),
            self.ttl_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("label", self.label_value().to_string()),
            ("experimental", self.experimental_value().to_string()),
            (
                "bottom_of_stack",
                self.bottom_of_stack_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("ttl", self.ttl_value().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_EXTENSION_MPLS_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;

        let word = (self.label_value() << 12)
            | ((self.experimental_value() as u32) << 9)
            | ((self.effective_bottom_of_stack(ctx.next()) as u32) << 8)
            | self.ttl_value() as u32;
        out.extend_from_slice(&word.to_be_bytes());
        Ok(())
    }

    impl_layer_object!(IcmpExtensionMpls);
}

impl_layer_div!(IcmpExtensionMpls);

/// Append a decoded ICMP packet to an existing packet stack.
pub(crate) fn append_icmp_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (icmp, payload) = decode_icmp_parts(bytes)?;
    packet = packet.push(icmp);
    if !payload.is_empty() {
        packet = packet.push(Raw::from_bytes(payload));
    }
    Ok(packet)
}

/// Append a decoded ICMPv6 packet to an existing packet stack.
pub(crate) fn append_icmpv6_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (icmpv6, payload) = decode_icmpv6_parts(bytes)?;
    packet = packet.push(icmpv6);
    if !payload.is_empty() {
        packet = packet.push(Raw::from_bytes(payload));
    }
    Ok(packet)
}

fn decode_icmp_parts(bytes: &[u8]) -> Result<(Icmp, &[u8])> {
    if bytes.len() < ICMP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmp header",
            ICMP_HEADER_LEN,
            bytes.len(),
        ));
    }

    let rest = copy_array_4(&bytes[4..8]);
    let icmp_type = bytes[0];
    let icmp = Icmp {
        icmp_type: Field::user(icmp_type),
        code: Field::user(bytes[1]),
        checksum: Field::user(read_u16_be(&bytes[2..4])?),
        rest_of_header: Field::user(rest),
        identifier: field_from_echo(icmp_type, &rest, 0, is_echo_v4),
        sequence_number: field_from_echo(icmp_type, &rest, 2, is_echo_v4),
        pointer: if icmp_type == ICMP_PARAMETER_PROBLEM {
            Field::user(rest[0])
        } else {
            Field::unset()
        },
        gateway: if icmp_type == ICMP_REDIRECT {
            Field::user(Ipv4Addr::from(rest))
        } else {
            Field::unset()
        },
        length: if icmpv4_type_allows_extensions(icmp_type) {
            Field::user(rest[1])
        } else {
            Field::unset()
        },
        mtu_next_hop: if icmp_type == ICMP_DESTINATION_UNREACHABLE {
            Field::user(u16::from_be_bytes([rest[2], rest[3]]))
        } else {
            Field::unset()
        },
    };

    Ok((icmp, &bytes[ICMP_HEADER_LEN..]))
}

fn decode_icmpv6_parts(bytes: &[u8]) -> Result<(Icmpv6, &[u8])> {
    if bytes.len() < ICMP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmpv6 header",
            ICMP_HEADER_LEN,
            bytes.len(),
        ));
    }

    let rest = copy_array_4(&bytes[4..8]);
    let icmp_type = bytes[0];
    let icmpv6 = Icmpv6 {
        icmp_type: Field::user(icmp_type),
        code: Field::user(bytes[1]),
        checksum: Field::user(read_u16_be(&bytes[2..4])?),
        rest_of_header: Field::user(rest),
        identifier: field_from_echo(icmp_type, &rest, 0, is_echo_v6),
        sequence_number: field_from_echo(icmp_type, &rest, 2, is_echo_v6),
        length: if icmpv6_type_allows_extensions(icmp_type) {
            Field::user(rest[0])
        } else {
            Field::unset()
        },
        mtu: if icmp_type == ICMPV6_PACKET_TOO_BIG {
            Field::user(u32::from_be_bytes(rest))
        } else {
            Field::unset()
        },
        pointer: if icmp_type == ICMPV6_PARAMETER_PROBLEM {
            Field::user(u32::from_be_bytes(rest))
        } else {
            Field::unset()
        },
    };

    Ok((icmpv6, &bytes[ICMP_HEADER_LEN..]))
}

fn payload_bytes_after(ctx: LayerContext<'_>) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for (index, layer) in ctx.packet().iter().enumerate().skip(ctx.index() + 1) {
        let layer_ctx = LayerContext::new(ctx.packet(), index);
        layer.compile(&layer_ctx, &mut payload)?;
    }
    Ok(payload)
}

fn encoded_len_until_extension(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .take_while(|layer| !layer.as_any().is::<IcmpExtension>())
        .map(Layer::encoded_len)
        .sum()
}

fn extension_object_payload_len(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .skip(ctx.index() + 1)
        .take_while(|layer| {
            !layer.as_any().is::<IcmpExtensionObject>() && !layer.as_any().is::<IcmpExtension>()
        })
        .map(Layer::encoded_len)
        .sum()
}

fn checksum_context(
    ctx: LayerContext<'_>,
    transport_protocol: u8,
) -> Option<TransportChecksumContext> {
    (0..ctx.index()).rev().find_map(|index| {
        ctx.packet()
            .get(index)
            .and_then(|layer| layer.transport_checksum_context(transport_protocol))
    })
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn value_or_u16_from_rest(field: &Field<u16>, rest: &Field<[u8; 4]>, offset: usize) -> u16 {
    field.value().copied().unwrap_or_else(|| {
        let rest = rest.value().copied().unwrap_or([0; 4]);
        u16::from_be_bytes([rest[offset], rest[offset + 1]])
    })
}

fn field_from_echo(
    icmp_type: u8,
    rest: &[u8; 4],
    offset: usize,
    is_echo: fn(u8) -> bool,
) -> Field<u16> {
    if is_echo(icmp_type) {
        Field::user(u16::from_be_bytes([rest[offset], rest[offset + 1]]))
    } else {
        Field::unset()
    }
}

fn is_echo_v4(icmp_type: u8) -> bool {
    matches!(icmp_type, ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY)
}

fn is_echo_v6(icmp_type: u8) -> bool {
    matches!(icmp_type, ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY)
}

fn icmpv4_type_allows_extensions(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMP_DESTINATION_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER_PROBLEM
    )
}

fn icmpv6_type_allows_extensions(icmp_type: u8) -> bool {
    matches!(
        icmp_type,
        ICMPV6_DESTINATION_UNREACHABLE | ICMPV6_TIME_EXCEEDED
    )
}

fn parse_ipv4(input: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(input).map_err(|_| {
        CrafterError::invalid_field_value("ipv4_address", "expected dotted-quad IPv4 address")
    })
}

fn icmpv4_type_summary(icmp_type: u8) -> String {
    match icmp_type {
        ICMP_ECHO_REPLY => "echo-reply(0)".to_string(),
        ICMP_DESTINATION_UNREACHABLE => "destination-unreachable(3)".to_string(),
        ICMP_SOURCE_QUENCH => "source-quench(4)".to_string(),
        ICMP_REDIRECT => "redirect(5)".to_string(),
        ICMP_ECHO_REQUEST => "echo-request(8)".to_string(),
        ICMP_TIME_EXCEEDED => "time-exceeded(11)".to_string(),
        ICMP_PARAMETER_PROBLEM => "parameter-problem(12)".to_string(),
        value => value.to_string(),
    }
}

fn icmpv6_type_summary(icmp_type: u8) -> String {
    match icmp_type {
        ICMPV6_DESTINATION_UNREACHABLE => "destination-unreachable(1)".to_string(),
        ICMPV6_PACKET_TOO_BIG => "packet-too-big(2)".to_string(),
        ICMPV6_TIME_EXCEEDED => "time-exceeded(3)".to_string(),
        ICMPV6_PARAMETER_PROBLEM => "parameter-problem(4)".to_string(),
        ICMPV6_ECHO_REQUEST => "echo-request(128)".to_string(),
        ICMPV6_ECHO_REPLY => "echo-reply(129)".to_string(),
        value => value.to_string(),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}

fn copy_array_4(bytes: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&bytes[..4]);
    out
}

#[cfg(test)]
mod icmp_tests {
    use super::{
        Icmp, IcmpExtension, IcmpExtensionMpls, IcmpExtensionObject, IcmpKind, ICMP_ECHO_REQUEST,
        ICMP_TIME_EXCEEDED,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    const IPV4_ICMP_FIXTURE: &[u8] = fixture_bytes!("bytes/ipv4-icmp-echo-request.bin");

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn icmp_echo_request_matches_golden_bytes() {
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x1234)
            .dont_fragment(true)
            / Icmp::echo_request().id(0x4242).seq(1)
            / Raw::from("libcrafter-icmp");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes(), IPV4_ICMP_FIXTURE);
        assert_eq!(&bytes.as_bytes()[20..22], &[ICMP_ECHO_REQUEST, 0]);
        assert_eq!(&bytes.as_bytes()[22..24], &0xa7d0u16.to_be_bytes());
    }

    #[test]
    fn icmp_decode_from_ipv4_exposes_echo_fields_and_payload() {
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, IPV4_ICMP_FIXTURE).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(icmp.kind_value(), Some(IcmpKind::EchoRequest));
        assert_eq!(icmp.code_value(), 0);
        assert_eq!(icmp.checksum_value(), Some(0xa7d0));
        assert_eq!(icmp.identifier_value(), Some(0x4242));
        assert_eq!(icmp.sequence_number_value(), Some(1));
        assert_eq!(raw.as_bytes(), b"libcrafter-icmp");
        assert_eq!(decoded.compile().unwrap().as_bytes(), IPV4_ICMP_FIXTURE);
    }

    #[test]
    fn icmp_explicit_checksum_is_preserved() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmp::echo_request().id(7).seq(8).checksum(0x1111)
            / Raw::from("abc"))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[22..24], &[0x11, 0x11]);
    }

    #[test]
    fn icmp_time_exceeded_autofills_length_and_extension_objects() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::time_exceeded().code(0)
            / (Ipv4::new()
                .src(Ipv4Addr::new(5, 6, 7, 8))
                .dst(Ipv4Addr::new(10, 11, 12, 13))
                .proto(IpProtocol::Udp)
                / Udp::new().sport(53).dport(1111)
                / Raw::from("data"))
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1234).ttl(100)
            / IcmpExtensionMpls::new()
                .label(2345)
                .experimental(6)
                .ttl(150);
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[20], ICMP_TIME_EXCEEDED);
        assert_eq!(bytes.as_bytes()[25], 8);
        assert_eq!(&bytes.as_bytes()[60..62], &[0x20, 0x00]);
        assert_eq!(&bytes.as_bytes()[64..68], &[0x00, 0x0c, 0x01, 0x01]);
        assert_eq!(bytes.as_bytes()[70] & 0x01, 0);
        assert_eq!(bytes.as_bytes()[74] & 0x01, 1);
    }

    #[test]
    fn icmp_decode_rejects_short_inputs() {
        let short = (Ipv4::new().proto(IpProtocol::Icmp) / Raw::from_bytes([0u8; 7]))
            .compile()
            .unwrap();
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, short.as_bytes()).is_err());
    }
}

#[cfg(test)]
mod icmpv6 {
    use super::{IcmpKind, Icmpv6, ICMPV6_ECHO_REQUEST};
    use crate::{Ipv6, NetworkLayer, Packet, Raw};
    use core::net::Ipv6Addr;

    const IPV6_ICMP_FIXTURE: &[u8] = fixture_bytes!("bytes/ipv6-icmp-echo-request.bin");

    fn src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 0x0010)
    }

    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 0x0020)
    }

    #[test]
    fn icmpv6_echo_request_matches_golden_bytes() {
        let packet = Ipv6::new().src(src()).dst(dst()).fl(0x12345).hlim(64)
            / Icmpv6::echo_request().id(0x4242).seq(2)
            / Raw::from("libcrafter-ipv6");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes(), IPV6_ICMP_FIXTURE);
        assert_eq!(&bytes.as_bytes()[40..42], &[ICMPV6_ECHO_REQUEST, 0]);
        assert_eq!(&bytes.as_bytes()[42..44], &0x00d0u16.to_be_bytes());
    }

    #[test]
    fn icmpv6_decode_from_ipv6_exposes_echo_fields_and_payload() {
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, IPV6_ICMP_FIXTURE).unwrap();
        let ipv6 = decoded.layer::<Ipv6>().unwrap();
        let icmpv6 = decoded.layer::<Icmpv6>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(ipv6.source(), src());
        assert_eq!(ipv6.destination(), dst());
        assert_eq!(ipv6.flow_label_value(), 0x12345);
        assert_eq!(ipv6.payload_length_value(), Some(23));
        assert_eq!(icmpv6.kind_value(), Some(IcmpKind::EchoRequest));
        assert_eq!(icmpv6.checksum_value(), Some(0x00d0));
        assert_eq!(icmpv6.identifier_value(), Some(0x4242));
        assert_eq!(icmpv6.sequence_number_value(), Some(2));
        assert_eq!(raw.as_bytes(), b"libcrafter-ipv6");
        assert_eq!(decoded.compile().unwrap().as_bytes(), IPV6_ICMP_FIXTURE);
    }

    #[test]
    fn icmpv6_explicit_checksum_is_preserved() {
        let bytes = (Ipv6::new().src(src()).dst(dst())
            / Icmpv6::echo_request().id(7).seq(8).checksum(0x2222)
            / Raw::from("abc"))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[42..44], &[0x22, 0x22]);
    }

    #[test]
    fn icmpv6_decode_rejects_short_inputs() {
        let short = (Ipv6::new().nh(crate::IPPROTO_ICMPV6) / Raw::from_bytes([0u8; 7]))
            .compile()
            .unwrap();
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, short.as_bytes()).is_err());
    }
}

#[cfg(test)]
mod ping_roundtrip {
    use super::{Icmp, IcmpKind, IcmpLayer, Icmpv6};
    use crate::{Ipv4, Ipv6, NetworkLayer, Packet, Raw};
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn echo_reply_matches(request: &dyn IcmpLayer, reply: &dyn IcmpLayer) -> bool {
        request.kind() == Some(IcmpKind::EchoRequest)
            && reply.kind() == Some(IcmpKind::EchoReply)
            && request.identifier_value() == reply.identifier_value()
            && request.sequence_number_value() == reply.sequence_number_value()
    }

    #[test]
    fn ping_roundtrip_matches_ipv4_echo_reply_by_id_and_sequence() {
        let src = Ipv4Addr::new(192, 0, 2, 10);
        let dst = Ipv4Addr::new(198, 51, 100, 20);
        let request = Ipv4::new().src(src).dst(dst)
            / Icmp::echo_request().id(0x7777).seq(9)
            / Raw::from("ping");
        let reply = Ipv4::new().src(dst).dst(src)
            / Icmp::echo_reply().id(0x7777).seq(9)
            / Raw::from("ping");

        let decoded_request =
            Packet::decode_from_l3(NetworkLayer::Ipv4, request.compile().unwrap()).unwrap();
        let decoded_reply =
            Packet::decode_from_l3(NetworkLayer::Ipv4, reply.compile().unwrap()).unwrap();

        assert!(echo_reply_matches(
            decoded_request.layer::<Icmp>().unwrap(),
            decoded_reply.layer::<Icmp>().unwrap()
        ));
    }

    #[test]
    fn ping_roundtrip_matches_ipv6_echo_reply_by_id_and_sequence() {
        let src = Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 2);
        let request = Ipv6::new().src(src).dst(dst)
            / Icmpv6::echo_request().id(0x8888).seq(10)
            / Raw::from("ping6");
        let reply = Ipv6::new().src(dst).dst(src)
            / Icmpv6::echo_reply().id(0x8888).seq(10)
            / Raw::from("ping6");

        let decoded_request =
            Packet::decode_from_l3(NetworkLayer::Ipv6, request.compile().unwrap()).unwrap();
        let decoded_reply =
            Packet::decode_from_l3(NetworkLayer::Ipv6, reply.compile().unwrap()).unwrap();

        assert!(echo_reply_matches(
            decoded_request.layer::<Icmpv6>().unwrap(),
            decoded_reply.layer::<Icmpv6>().unwrap()
        ));
    }
}
