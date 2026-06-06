//! IPv6 option types, encoding, decoding, and label helpers.

use core::net::Ipv6Addr;
use core::str::FromStr;

use crate::error::{CrafterError, Result};

use super::constants::{
    IPV6_HOME_ADDRESS_DATA_LEN, IPV6_JUMBO_PAYLOAD_DATA_LEN, IPV6_OPTION_ACTION_SHIFT,
    IPV6_OPTION_CHANGE_EN_ROUTE_MASK, IPV6_OPTION_DATA_MAX_LEN, IPV6_OPTION_HEADER_LEN,
    IPV6_OPTION_HOME_ADDRESS, IPV6_OPTION_JUMBO_PAYLOAD, IPV6_OPTION_NUMBER_MASK, IPV6_OPTION_PAD1,
    IPV6_OPTION_PADN, IPV6_OPTION_ROUTER_ALERT, IPV6_ROUTER_ALERT_ACTIVE_NETWORKS,
    IPV6_ROUTER_ALERT_DATA_LEN, IPV6_ROUTER_ALERT_MLD, IPV6_ROUTER_ALERT_MPLS_OAM,
    IPV6_ROUTER_ALERT_RESERVED, IPV6_ROUTER_ALERT_RSVP,
};

/// Action encoded in the high two bits of an IPv6 option type.
///
/// RFC 8200 section 4.2 defines these bits for unrecognized options. RFC 9673
/// updates hop-by-hop processing behavior, but the wire encoding remains the
/// same. The action bits are part of the full 8-bit option type, not a separate
/// namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ipv6OptionAction {
    /// Skip over this option and continue processing the header.
    Skip,
    /// Discard the packet.
    Discard,
    /// Discard and send ICMP Parameter Problem, Code 2.
    DiscardSendIcmp,
    /// Discard and send ICMP Parameter Problem, Code 2 if the destination is
    /// not multicast.
    DiscardSendIcmpIfNotMulticast,
}

impl Ipv6OptionAction {
    /// Raw two-bit action value.
    pub const fn bits(self) -> u8 {
        match self {
            Self::Skip => 0,
            Self::Discard => 1,
            Self::DiscardSendIcmp => 2,
            Self::DiscardSendIcmpIfNotMulticast => 3,
        }
    }

    /// Decode action bits from a full IPv6 option type byte.
    pub const fn from_option_type(option_type: u8) -> Self {
        match option_type >> IPV6_OPTION_ACTION_SHIFT {
            0 => Self::Skip,
            1 => Self::Discard,
            2 => Self::DiscardSendIcmp,
            _ => Self::DiscardSendIcmpIfNotMulticast,
        }
    }

    /// Decode an explicit two-bit action value.
    pub fn from_bits(bits: u8) -> Result<Self> {
        match bits {
            0 => Ok(Self::Skip),
            1 => Ok(Self::Discard),
            2 => Ok(Self::DiscardSendIcmp),
            3 => Ok(Self::DiscardSendIcmpIfNotMulticast),
            _ => Err(CrafterError::invalid_field_value(
                "ipv6.option.action",
                "IPv6 option action must fit in two bits",
            )),
        }
    }
}

impl TryFrom<u8> for Ipv6OptionAction {
    type Error = CrafterError;

    fn try_from(value: u8) -> Result<Self> {
        Self::from_bits(value)
    }
}

/// Parsed or constructible IPv6 option shared by Hop-by-Hop and Destination
/// Options headers.
///
/// Backed by RFC 8200 section 4.2 and the IANA "Destination Options and
/// Hop-by-Hop Options" registry. The model intentionally does not introduce
/// Hop-by-Hop or Destination Options header layers; it only preserves and
/// exposes the option TLVs that those future layers will share.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ipv6Option {
    /// Pad1 one-byte padding option.
    Pad1,
    /// PadN padding option. Data bytes are preserved exactly.
    PadN {
        /// Option data bytes after the type and length fields.
        data: Vec<u8>,
    },
    /// Router Alert option. The two value octets are stored in network byte
    /// order so the option data remains directly inspectable.
    RouterAlert {
        /// Two-octet Router Alert value field in network byte order.
        value_bytes: [u8; 2],
    },
    /// Jumbo Payload option. The four value octets are stored in network byte
    /// order so malformed-packet tests can inspect the exact field bytes.
    JumboPayload {
        /// Four-octet Jumbo Payload Length field in network byte order.
        length_bytes: [u8; 4],
    },
    /// Home Address option. The sixteen address octets are stored in network
    /// byte order so option data remains directly inspectable.
    HomeAddress {
        /// IPv6 Home Address option data field.
        address_bytes: [u8; 16],
    },
    /// Unknown or caller-defined option with a standard IPv6 option length
    /// byte. The full 8-bit option type, including action and change bits, is
    /// preserved verbatim.
    Generic {
        /// Raw option type byte.
        option_type: u8,
        /// Option data bytes after the type and length fields.
        data: Vec<u8>,
    },
}

impl Ipv6Option {
    /// Create a one-byte Pad1 option.
    pub const fn pad1() -> Self {
        Self::Pad1
    }

    /// Create a PadN option carrying `total_len` bytes of padding.
    ///
    /// RFC 8200 defines PadN as two or more octets. `total_len == 2` produces a
    /// zero-length Option Data field; larger values fill the data with zeroes.
    pub fn padn(total_len: usize) -> Result<Self> {
        if total_len < IPV6_OPTION_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ipv6.option.padn.length",
                "PadN total length must be at least 2 bytes",
            ));
        }

        Self::padn_data(vec![0; total_len - IPV6_OPTION_HEADER_LEN])
    }

    /// Compatibility alias for [`Self::padn`].
    pub fn pad_n(total_len: usize) -> Result<Self> {
        Self::padn(total_len)
    }

    /// Create a PadN option from explicit option data bytes.
    ///
    /// The bytes are preserved verbatim, including deliberately nonzero padding
    /// data for stack-behavior tests.
    pub fn padn_data(data: impl Into<Vec<u8>>) -> Result<Self> {
        let data = data.into();
        validate_ipv6_option_data_len("ipv6.option.padn.length", data.len())?;
        Ok(Self::PadN { data })
    }

    /// Compatibility alias for [`Self::padn_data`].
    pub fn pad_n_data(data: impl Into<Vec<u8>>) -> Result<Self> {
        Self::padn_data(data)
    }

    /// Create an RFC 2711 Router Alert option with a two-octet value field.
    ///
    /// The option is explicit-only: no IPv6 builder inserts Router Alert unless
    /// the caller adds this option to a Hop-by-Hop Options header.
    pub const fn router_alert(value: u16) -> Self {
        Self::RouterAlert {
            value_bytes: [(value >> 8) as u8, value as u8],
        }
    }

    /// Create an RFC 2675 Jumbo Payload option with a four-octet length field.
    ///
    /// The Jumbo Payload Length is the IPv6 packet payload length excluding
    /// the IPv6 base header, but including Hop-by-Hop and other extension
    /// headers.
    ///
    /// RFC 2675 requires a valid Jumbo Payload Length to be greater than
    /// 65,535 and the IPv6 Payload Length field to be zero. This builder
    /// preserves the caller-supplied value; large-payload generation and
    /// transport-layer jumbogram semantics are intentionally out of scope.
    pub const fn jumbo_payload(length: u32) -> Self {
        Self::JumboPayload {
            length_bytes: [
                (length >> 24) as u8,
                (length >> 16) as u8,
                (length >> 8) as u8,
                length as u8,
            ],
        }
    }

    /// Create an RFC 6275 Home Address option for a Destination Options header.
    ///
    /// The packet-layer option only stores and emits the address field. Mobile
    /// IPv6 Binding Cache state machines and placement policy are out of scope.
    pub fn home_address(address: Ipv6Addr) -> Self {
        Self::HomeAddress {
            address_bytes: address.octets(),
        }
    }

    /// Create a Home Address option from text.
    pub fn home_address_str(address: &str) -> Result<Self> {
        let address = Ipv6Addr::from_str(address).map_err(|_| {
            CrafterError::invalid_field_value("ipv6_address", "expected textual IPv6 address")
        })?;
        Ok(Self::home_address(address))
    }

    /// Create an unknown or caller-defined option.
    pub fn generic(option_type: u8, data: impl Into<Vec<u8>>) -> Result<Self> {
        validate_ipv6_generic_option_type(option_type)?;
        let data = data.into();
        validate_ipv6_option_data_len("ipv6.option.length", data.len())?;
        Ok(Self::Generic { option_type, data })
    }

    /// Compatibility alias for [`Self::generic`].
    pub fn unknown(option_type: u8, data: impl Into<Vec<u8>>) -> Result<Self> {
        Self::generic(option_type, data)
    }

    /// Raw option type byte.
    pub const fn option_type(&self) -> u8 {
        match self {
            Self::Pad1 => IPV6_OPTION_PAD1,
            Self::PadN { .. } => IPV6_OPTION_PADN,
            Self::RouterAlert { .. } => IPV6_OPTION_ROUTER_ALERT,
            Self::JumboPayload { .. } => IPV6_OPTION_JUMBO_PAYLOAD,
            Self::HomeAddress { .. } => IPV6_OPTION_HOME_ADDRESS,
            Self::Generic { option_type, .. } => *option_type,
        }
    }

    /// Compatibility alias for [`Self::option_type`].
    pub const fn kind(&self) -> u8 {
        self.option_type()
    }

    /// Option data bytes after the type and length fields.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Pad1 => &[],
            Self::PadN { data } | Self::Generic { data, .. } => data,
            Self::RouterAlert { value_bytes } => value_bytes,
            Self::JumboPayload { length_bytes } => length_bytes,
            Self::HomeAddress { address_bytes } => address_bytes,
        }
    }

    /// Router Alert value when this is a typed Router Alert option.
    pub const fn router_alert_value(&self) -> Option<u16> {
        match self {
            Self::RouterAlert { value_bytes } => {
                Some(((value_bytes[0] as u16) << 8) | value_bytes[1] as u16)
            }
            _ => None,
        }
    }

    /// Source-backed Router Alert value label when this is a Router Alert option.
    pub const fn router_alert_value_label(&self) -> Option<&'static str> {
        match self.router_alert_value() {
            Some(value) => Some(ipv6_router_alert_value_label(value)),
            None => None,
        }
    }

    /// Jumbo Payload Length when this is a typed Jumbo Payload option.
    pub const fn jumbo_payload_length(&self) -> Option<u32> {
        match self {
            Self::JumboPayload { length_bytes } => Some(
                ((length_bytes[0] as u32) << 24)
                    | ((length_bytes[1] as u32) << 16)
                    | ((length_bytes[2] as u32) << 8)
                    | length_bytes[3] as u32,
            ),
            _ => None,
        }
    }

    /// Home Address value when this is a typed Home Address option.
    pub fn home_address_value(&self) -> Option<Ipv6Addr> {
        match self {
            Self::HomeAddress { address_bytes } => Some(Ipv6Addr::from(*address_bytes)),
            _ => None,
        }
    }

    /// Raw two-bit action value from the high-order option-type bits.
    pub const fn action_bits(&self) -> u8 {
        self.option_type() >> IPV6_OPTION_ACTION_SHIFT
    }

    /// Source-backed action encoded in the high two option-type bits.
    pub const fn action(&self) -> Ipv6OptionAction {
        Ipv6OptionAction::from_option_type(self.option_type())
    }

    /// Return true when the Option Data may change en route.
    pub const fn change_en_route(&self) -> bool {
        self.option_type() & IPV6_OPTION_CHANGE_EN_ROUTE_MASK != 0
    }

    /// Compatibility alias for [`Self::change_en_route`].
    pub const fn may_change_en_route(&self) -> bool {
        self.change_en_route()
    }

    /// Low five bits of the option type, named `rest` in the IANA registry.
    pub const fn rest(&self) -> u8 {
        self.option_type() & IPV6_OPTION_NUMBER_MASK
    }

    /// Compatibility alias for [`Self::rest`].
    pub const fn option_number(&self) -> u8 {
        self.rest()
    }

    /// Encoded option length in bytes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Pad1 => 1,
            Self::RouterAlert { .. } => IPV6_OPTION_HEADER_LEN + IPV6_ROUTER_ALERT_DATA_LEN,
            Self::JumboPayload { .. } => IPV6_OPTION_HEADER_LEN + IPV6_JUMBO_PAYLOAD_DATA_LEN,
            Self::HomeAddress { .. } => IPV6_OPTION_HEADER_LEN + IPV6_HOME_ADDRESS_DATA_LEN,
            Self::PadN { data } | Self::Generic { data, .. } => IPV6_OPTION_HEADER_LEN + data.len(),
        }
    }

    /// Encode this option to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        match self {
            Self::Pad1 => bytes.push(IPV6_OPTION_PAD1),
            Self::PadN { data } => {
                validate_ipv6_option_data_len("ipv6.option.padn.length", data.len())?;
                bytes.extend_from_slice(&[IPV6_OPTION_PADN, data.len() as u8]);
                bytes.extend_from_slice(data);
            }
            Self::RouterAlert { value_bytes } => {
                bytes.extend_from_slice(&[
                    IPV6_OPTION_ROUTER_ALERT,
                    IPV6_ROUTER_ALERT_DATA_LEN as u8,
                ]);
                bytes.extend_from_slice(value_bytes);
            }
            Self::JumboPayload { length_bytes } => {
                bytes.extend_from_slice(&[
                    IPV6_OPTION_JUMBO_PAYLOAD,
                    IPV6_JUMBO_PAYLOAD_DATA_LEN as u8,
                ]);
                bytes.extend_from_slice(length_bytes);
            }
            Self::HomeAddress { address_bytes } => {
                bytes.extend_from_slice(&[
                    IPV6_OPTION_HOME_ADDRESS,
                    IPV6_HOME_ADDRESS_DATA_LEN as u8,
                ]);
                bytes.extend_from_slice(address_bytes);
            }
            Self::Generic { option_type, data } => {
                validate_ipv6_generic_option_type(*option_type)?;
                validate_ipv6_option_data_len("ipv6.option.length", data.len())?;
                bytes.extend_from_slice(&[*option_type, data.len() as u8]);
                bytes.extend_from_slice(data);
            }
        }
        Ok(bytes)
    }

    /// Decode all options from a raw IPv6 options byte slice.
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>> {
        Ipv6OptionIter::new(bytes).collect()
    }
}

/// Iterator over encoded IPv6 Hop-by-Hop or Destination option bytes.
#[derive(Debug, Clone)]
pub struct Ipv6OptionIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> Ipv6OptionIter<'a> {
    /// Create an iterator over raw IPv6 option bytes.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            done: false,
        }
    }
}

impl Iterator for Ipv6OptionIter<'_> {
    type Item = Result<Ipv6Option>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.bytes.len() {
            return None;
        }

        let start = self.offset;
        let option_type = self.bytes[start];
        if option_type == IPV6_OPTION_PAD1 {
            self.offset += 1;
            return Some(Ok(Ipv6Option::Pad1));
        }

        if start + IPV6_OPTION_HEADER_LEN > self.bytes.len() {
            self.done = true;
            return Some(Err(CrafterError::buffer_too_short(
                "ipv6.option.header",
                start + IPV6_OPTION_HEADER_LEN,
                self.bytes.len(),
            )));
        }

        let data_len = self.bytes[start + 1] as usize;
        let Some(end) = start
            .checked_add(IPV6_OPTION_HEADER_LEN)
            .and_then(|header_end| header_end.checked_add(data_len))
        else {
            self.done = true;
            return Some(Err(CrafterError::invalid_field_value(
                "ipv6.option.length",
                "IPv6 option length overflows the option area",
            )));
        };
        if end > self.bytes.len() {
            self.done = true;
            return Some(Err(CrafterError::buffer_too_short(
                "ipv6.option.data",
                end,
                self.bytes.len(),
            )));
        }

        self.offset = end;
        let data = self.bytes[start + IPV6_OPTION_HEADER_LEN..end].to_vec();
        if option_type == IPV6_OPTION_PADN {
            Some(Ok(Ipv6Option::PadN { data }))
        } else if option_type == IPV6_OPTION_JUMBO_PAYLOAD
            && data_len == IPV6_JUMBO_PAYLOAD_DATA_LEN
        {
            let mut length_bytes = [0; 4];
            length_bytes.copy_from_slice(&data);
            Some(Ok(Ipv6Option::JumboPayload { length_bytes }))
        } else if option_type == IPV6_OPTION_ROUTER_ALERT && data_len == IPV6_ROUTER_ALERT_DATA_LEN
        {
            let mut value_bytes = [0; 2];
            value_bytes.copy_from_slice(&data);
            Some(Ok(Ipv6Option::RouterAlert { value_bytes }))
        } else if option_type == IPV6_OPTION_HOME_ADDRESS && data_len == IPV6_HOME_ADDRESS_DATA_LEN
        {
            let mut address_bytes = [0; 16];
            address_bytes.copy_from_slice(&data);
            Some(Ok(Ipv6Option::HomeAddress { address_bytes }))
        } else {
            Some(Ok(Ipv6Option::Generic { option_type, data }))
        }
    }
}

/// Source-backed label for an IPv6 Router Alert value.
pub const fn ipv6_router_alert_value_label(value: u16) -> &'static str {
    match value {
        IPV6_ROUTER_ALERT_MLD => "MLD",
        IPV6_ROUTER_ALERT_RSVP => "RSVP",
        IPV6_ROUTER_ALERT_ACTIVE_NETWORKS => "Active Networks",
        IPV6_ROUTER_ALERT_RESERVED => "Reserved",
        4..=35 => "Aggregated Reservation Nesting Level",
        36..=67 => "QoS NSLP Aggregation Levels",
        68 => "NSIS NATFW NSLP",
        IPV6_ROUTER_ALERT_MPLS_OAM => "MPLS OAM (DEPRECATED)",
        70..=65502 => "Unassigned",
        65503..=65535 => "Reserved",
    }
}

fn validate_ipv6_option_data_len(field: &'static str, data_len: usize) -> Result<()> {
    if data_len > IPV6_OPTION_DATA_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            field,
            "IPv6 option data length must fit in one byte",
        ));
    }
    Ok(())
}

fn validate_ipv6_generic_option_type(option_type: u8) -> Result<()> {
    match option_type {
        IPV6_OPTION_PAD1 => Err(CrafterError::invalid_field_value(
            "ipv6.option.type",
            "Pad1 option does not carry length or data fields",
        )),
        IPV6_OPTION_PADN => Err(CrafterError::invalid_field_value(
            "ipv6.option.type",
            "PadN option should use the PadN option model",
        )),
        _ => Ok(()),
    }
}
