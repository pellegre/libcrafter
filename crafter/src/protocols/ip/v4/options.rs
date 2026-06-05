//! IPv4 option types, encoding, decoding, and display helpers.

use core::net::Ipv4Addr;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};

use super::constants::{
    IPV4_OPTION_CLASS_MASK, IPV4_OPTION_CLASS_SHIFT, IPV4_OPTION_COPIED_MASK, IPV4_OPTION_EOL,
    IPV4_OPTION_EXPERIMENTAL_1, IPV4_OPTION_EXPERIMENTAL_2, IPV4_OPTION_EXPERIMENTAL_3,
    IPV4_OPTION_EXPERIMENTAL_4, IPV4_OPTION_LOOSE_SOURCE_ROUTE, IPV4_OPTION_NOP,
    IPV4_OPTION_NUMBER_MASK, IPV4_OPTION_RECORD_ROUTE, IPV4_OPTION_ROUTER_ALERT,
    IPV4_OPTION_STRICT_SOURCE_ROUTE, IPV4_OPTION_TIMESTAMP, IPV4_OPTION_TRACEROUTE,
    IPV4_ROUTER_ALERT_LEN, IPV4_TIMESTAMP_ADDRESS_WORD_LEN,
    IPV4_TIMESTAMP_FLAG_ADDRESS_AND_TIMESTAMP, IPV4_TIMESTAMP_FLAG_PRESPECIFIED_ADDRESS,
    IPV4_TIMESTAMP_FLAG_TIMESTAMPS_ONLY, IPV4_TIMESTAMP_MAX_LEN, IPV4_TIMESTAMP_MIN_LEN,
    IPV4_TIMESTAMP_POINTER_MIN, IPV4_TIMESTAMP_WORD_LEN,
};

/// Metadata decoded from one IPv4 option kind byte.
///
/// RFC 791 and IANA IPv4 Parameters split the option type byte into a copied
/// flag, two class bits, and a five-bit option number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4OptionKind {
    value: u8,
}

impl Ipv4OptionKind {
    /// Split a raw IPv4 option kind byte into inspectable metadata.
    pub const fn new(value: u8) -> Self {
        Self { value }
    }

    /// Raw IPv4 option kind byte.
    pub const fn value(self) -> u8 {
        self.value
    }

    /// Return true when the IPv4 option copied flag is set.
    pub const fn copied(self) -> bool {
        self.value & IPV4_OPTION_COPIED_MASK != 0
    }

    /// Raw two-bit IPv4 option class value.
    pub const fn class(self) -> u8 {
        (self.value & IPV4_OPTION_CLASS_MASK) >> IPV4_OPTION_CLASS_SHIFT
    }

    /// Raw five-bit IPv4 option number value.
    pub const fn number(self) -> u8 {
        self.value & IPV4_OPTION_NUMBER_MASK
    }

    /// Return true for the RFC 4727 IPv4 option experiment values.
    pub const fn is_experimental(self) -> bool {
        matches!(
            self.value,
            IPV4_OPTION_EXPERIMENTAL_1
                | IPV4_OPTION_EXPERIMENTAL_2
                | IPV4_OPTION_EXPERIMENTAL_3
                | IPV4_OPTION_EXPERIMENTAL_4
        )
    }

    /// Human-readable RFC 4727 experiment classification, when applicable.
    pub const fn experimental_label(self) -> Option<&'static str> {
        if self.is_experimental() {
            Some("RFC3692-style Experiment")
        } else {
            None
        }
    }
}

impl From<u8> for Ipv4OptionKind {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<Ipv4OptionKind> for u8 {
    fn from(value: Ipv4OptionKind) -> Self {
        value.value()
    }
}

/// IPv4 route-style option family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ipv4RouteOptionKind {
    /// Record route.
    RecordRoute,
    /// Loose source and record route.
    LooseSourceRoute,
    /// Strict source and record route.
    StrictSourceRoute,
}

impl Ipv4RouteOptionKind {
    /// Raw IPv4 option kind byte.
    pub const fn kind(self) -> u8 {
        match self {
            Self::RecordRoute => IPV4_OPTION_RECORD_ROUTE,
            Self::LooseSourceRoute => IPV4_OPTION_LOOSE_SOURCE_ROUTE,
            Self::StrictSourceRoute => IPV4_OPTION_STRICT_SOURCE_ROUTE,
        }
    }
}

/// Parsed or constructible IPv4 option.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ipv4Option {
    /// End of option list.
    EndOfList,
    /// One-byte no-operation padding.
    NoOperation,
    /// Unknown or caller-defined option with a standard length byte.
    Generic {
        /// Raw option kind byte.
        kind: u8,
        /// Option payload bytes after kind and length.
        data: Vec<u8>,
    },
    /// RFC 791 timestamp option containing only timestamp words.
    Timestamp {
        /// One-based pointer value.
        pointer: u8,
        /// Four-bit overflow counter.
        overflow: u8,
        /// Timestamp words carried by the option.
        timestamps: Vec<u32>,
    },
    /// RFC 791 timestamp option with each timestamp preceded by an IPv4 address.
    TimestampWithAddresses {
        /// One-based pointer value.
        pointer: u8,
        /// Four-bit overflow counter.
        overflow: u8,
        /// IPv4 address and timestamp pairs carried by the option.
        entries: Vec<(Ipv4Addr, u32)>,
    },
    /// RFC 791 timestamp option with prespecified IPv4 address slots.
    TimestampPrespecified {
        /// One-based pointer value.
        pointer: u8,
        /// Four-bit overflow counter.
        overflow: u8,
        /// Prespecified IPv4 address and timestamp pairs carried by the option.
        entries: Vec<(Ipv4Addr, u32)>,
    },
    /// RFC 2113 Router Alert option.
    RouterAlert {
        /// Router Alert value field.
        value: u16,
    },
    /// Record-route, loose-source-route, or strict-source-route option.
    Route {
        /// Route option family.
        kind: Ipv4RouteOptionKind,
        /// One-based pointer value.
        pointer: u8,
        /// IPv4 slots carried by the option.
        routes: Vec<Ipv4Addr>,
    },
    /// RFC 1393 traceroute option.
    Traceroute {
        /// Traceroute ID number.
        id_number: u16,
        /// Outbound hop count.
        outbound_hop_count: u16,
        /// Return hop count.
        return_hop_count: u16,
        /// Originator IPv4 address.
        originator: Ipv4Addr,
    },
}

impl Ipv4Option {
    /// Create an end-of-option-list marker.
    pub const fn end_of_list() -> Self {
        Self::EndOfList
    }

    /// Create a no-operation padding option.
    pub const fn no_operation() -> Self {
        Self::NoOperation
    }

    /// Create a caller-defined option.
    pub fn generic(kind: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::Generic {
            kind,
            data: data.into(),
        }
    }

    /// Create an RFC 791 timestamp option containing only timestamp words.
    pub fn timestamp(pointer: u8, overflow: u8, timestamps: impl Into<Vec<u32>>) -> Self {
        Self::Timestamp {
            pointer,
            overflow,
            timestamps: timestamps.into(),
        }
    }

    /// Create an RFC 791 timestamp option with IPv4 address/timestamp pairs.
    pub fn timestamp_with_addresses(
        pointer: u8,
        overflow: u8,
        entries: impl Into<Vec<(Ipv4Addr, u32)>>,
    ) -> Self {
        Self::TimestampWithAddresses {
            pointer,
            overflow,
            entries: entries.into(),
        }
    }

    /// Create an RFC 791 timestamp option with prespecified IPv4 address slots.
    pub fn timestamp_prespecified(
        pointer: u8,
        overflow: u8,
        entries: impl Into<Vec<(Ipv4Addr, u32)>>,
    ) -> Self {
        Self::TimestampPrespecified {
            pointer,
            overflow,
            entries: entries.into(),
        }
    }

    /// Create an RFC 2113 Router Alert option.
    pub const fn router_alert(value: u16) -> Self {
        Self::RouterAlert { value }
    }

    /// Create a record-route option.
    pub fn record_route(pointer: u8, routes: impl Into<Vec<Ipv4Addr>>) -> Self {
        Self::Route {
            kind: Ipv4RouteOptionKind::RecordRoute,
            pointer,
            routes: routes.into(),
        }
    }

    /// Create a loose source-and-record-route option.
    pub fn loose_source_route(pointer: u8, routes: impl Into<Vec<Ipv4Addr>>) -> Self {
        Self::Route {
            kind: Ipv4RouteOptionKind::LooseSourceRoute,
            pointer,
            routes: routes.into(),
        }
    }

    /// Create a strict source-and-record-route option.
    pub fn strict_source_route(pointer: u8, routes: impl Into<Vec<Ipv4Addr>>) -> Self {
        Self::Route {
            kind: Ipv4RouteOptionKind::StrictSourceRoute,
            pointer,
            routes: routes.into(),
        }
    }

    /// Create an IPv4 traceroute option.
    pub const fn traceroute(
        id_number: u16,
        outbound_hop_count: u16,
        return_hop_count: u16,
        originator: Ipv4Addr,
    ) -> Self {
        Self::Traceroute {
            id_number,
            outbound_hop_count,
            return_hop_count,
            originator,
        }
    }

    /// Timestamp option pointer value, if this is a typed timestamp option.
    pub const fn timestamp_pointer(&self) -> Option<u8> {
        match self {
            Self::Timestamp { pointer, .. }
            | Self::TimestampWithAddresses { pointer, .. }
            | Self::TimestampPrespecified { pointer, .. } => Some(*pointer),
            _ => None,
        }
    }

    /// Timestamp option overflow counter, if this is a typed timestamp option.
    pub const fn timestamp_overflow(&self) -> Option<u8> {
        match self {
            Self::Timestamp { overflow, .. }
            | Self::TimestampWithAddresses { overflow, .. }
            | Self::TimestampPrespecified { overflow, .. } => Some(*overflow),
            _ => None,
        }
    }

    /// RFC 791 timestamp option flag value, if this is a typed timestamp option.
    pub const fn timestamp_flag(&self) -> Option<u8> {
        match self {
            Self::Timestamp { .. } => Some(IPV4_TIMESTAMP_FLAG_TIMESTAMPS_ONLY),
            Self::TimestampWithAddresses { .. } => Some(IPV4_TIMESTAMP_FLAG_ADDRESS_AND_TIMESTAMP),
            Self::TimestampPrespecified { .. } => Some(IPV4_TIMESTAMP_FLAG_PRESPECIFIED_ADDRESS),
            _ => None,
        }
    }

    /// Timestamp words for a timestamp-only option.
    pub fn timestamp_values(&self) -> Option<&[u32]> {
        match self {
            Self::Timestamp { timestamps, .. } => Some(timestamps),
            _ => None,
        }
    }

    /// IPv4 address/timestamp pairs for address-carrying timestamp options.
    pub fn timestamp_address_values(&self) -> Option<&[(Ipv4Addr, u32)]> {
        match self {
            Self::TimestampWithAddresses { entries, .. }
            | Self::TimestampPrespecified { entries, .. } => Some(entries),
            _ => None,
        }
    }

    /// Router Alert value, if this is a typed Router Alert option.
    pub const fn router_alert_value(&self) -> Option<u16> {
        match self {
            Self::RouterAlert { value } => Some(*value),
            _ => None,
        }
    }

    /// Raw option kind byte.
    pub const fn kind(&self) -> u8 {
        match self {
            Self::EndOfList => IPV4_OPTION_EOL,
            Self::NoOperation => IPV4_OPTION_NOP,
            Self::Generic { kind, .. } => *kind,
            Self::Timestamp { .. }
            | Self::TimestampWithAddresses { .. }
            | Self::TimestampPrespecified { .. } => IPV4_OPTION_TIMESTAMP,
            Self::RouterAlert { .. } => IPV4_OPTION_ROUTER_ALERT,
            Self::Route { kind, .. } => kind.kind(),
            Self::Traceroute { .. } => IPV4_OPTION_TRACEROUTE,
        }
    }

    /// Encoded option length in bytes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::EndOfList | Self::NoOperation => 1,
            Self::Generic { data, .. } => 2 + data.len(),
            Self::Timestamp { timestamps, .. } => {
                IPV4_TIMESTAMP_MIN_LEN + timestamps.len() * IPV4_TIMESTAMP_WORD_LEN
            }
            Self::TimestampWithAddresses { entries, .. }
            | Self::TimestampPrespecified { entries, .. } => {
                IPV4_TIMESTAMP_MIN_LEN + entries.len() * IPV4_TIMESTAMP_ADDRESS_WORD_LEN
            }
            Self::RouterAlert { .. } => IPV4_ROUTER_ALERT_LEN,
            Self::Route { routes, .. } => 3 + routes.len() * 4,
            Self::Traceroute { .. } => 12,
        }
    }

    /// Encode this option to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let len = self.encoded_len();
        if len > u8::MAX as usize {
            return Err(CrafterError::invalid_field_value(
                "ipv4.option.length",
                "IPv4 option length must fit in one byte",
            ));
        }

        let mut bytes = Vec::with_capacity(len);
        match self {
            Self::EndOfList => bytes.push(IPV4_OPTION_EOL),
            Self::NoOperation => bytes.push(IPV4_OPTION_NOP),
            Self::Generic { kind, data } => {
                if *kind == IPV4_OPTION_EOL || *kind == IPV4_OPTION_NOP {
                    return Err(CrafterError::invalid_field_value(
                        "ipv4.option.kind",
                        "EOL and NOP options do not carry a length byte",
                    ));
                }
                bytes.push(*kind);
                bytes.push(len as u8);
                bytes.extend_from_slice(data);
            }
            Self::Timestamp {
                pointer,
                overflow,
                timestamps,
            } => {
                validate_ipv4_timestamp(*pointer, *overflow, len)?;
                bytes.push(IPV4_OPTION_TIMESTAMP);
                bytes.push(len as u8);
                bytes.push(*pointer);
                bytes.push((*overflow << 4) | IPV4_TIMESTAMP_FLAG_TIMESTAMPS_ONLY);
                for timestamp in timestamps {
                    bytes.extend_from_slice(&timestamp.to_be_bytes());
                }
            }
            Self::TimestampWithAddresses {
                pointer,
                overflow,
                entries,
            } => {
                validate_ipv4_timestamp(*pointer, *overflow, len)?;
                bytes.push(IPV4_OPTION_TIMESTAMP);
                bytes.push(len as u8);
                bytes.push(*pointer);
                bytes.push((*overflow << 4) | IPV4_TIMESTAMP_FLAG_ADDRESS_AND_TIMESTAMP);
                for (address, timestamp) in entries {
                    bytes.extend_from_slice(&address.octets());
                    bytes.extend_from_slice(&timestamp.to_be_bytes());
                }
            }
            Self::TimestampPrespecified {
                pointer,
                overflow,
                entries,
            } => {
                validate_ipv4_timestamp(*pointer, *overflow, len)?;
                bytes.push(IPV4_OPTION_TIMESTAMP);
                bytes.push(len as u8);
                bytes.push(*pointer);
                bytes.push((*overflow << 4) | IPV4_TIMESTAMP_FLAG_PRESPECIFIED_ADDRESS);
                for (address, timestamp) in entries {
                    bytes.extend_from_slice(&address.octets());
                    bytes.extend_from_slice(&timestamp.to_be_bytes());
                }
            }
            Self::RouterAlert { value } => {
                bytes.push(IPV4_OPTION_ROUTER_ALERT);
                bytes.push(IPV4_ROUTER_ALERT_LEN as u8);
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            Self::Route {
                kind,
                pointer,
                routes,
            } => {
                validate_ipv4_route_pointer(*pointer, len)?;
                bytes.push(kind.kind());
                bytes.push(len as u8);
                bytes.push(*pointer);
                for route in routes {
                    bytes.extend_from_slice(&route.octets());
                }
            }
            Self::Traceroute {
                id_number,
                outbound_hop_count,
                return_hop_count,
                originator,
            } => {
                bytes.push(IPV4_OPTION_TRACEROUTE);
                bytes.push(12);
                bytes.extend_from_slice(&id_number.to_be_bytes());
                bytes.extend_from_slice(&outbound_hop_count.to_be_bytes());
                bytes.extend_from_slice(&return_hop_count.to_be_bytes());
                bytes.extend_from_slice(&originator.octets());
            }
        }
        Ok(bytes)
    }

    /// Decode all options from a raw IPv4 option byte slice.
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>> {
        Ipv4OptionIter::new(bytes).collect()
    }
}

/// Iterator over encoded IPv4 options.
#[derive(Debug, Clone)]
pub struct Ipv4OptionIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> Ipv4OptionIter<'a> {
    /// Create an iterator over raw IPv4 option bytes.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            done: false,
        }
    }
}

impl Iterator for Ipv4OptionIter<'_> {
    type Item = Result<Ipv4Option>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.bytes.len() {
            return None;
        }

        let start = self.offset;
        let kind = self.bytes[start];
        match kind {
            IPV4_OPTION_EOL => {
                self.done = true;
                self.offset = self.bytes.len();
                Some(Ok(Ipv4Option::EndOfList))
            }
            IPV4_OPTION_NOP => {
                self.offset += 1;
                Some(Ok(Ipv4Option::NoOperation))
            }
            _ => {
                if start + 2 > self.bytes.len() {
                    self.done = true;
                    return Some(Err(CrafterError::buffer_too_short(
                        "ipv4 option",
                        start + 2,
                        self.bytes.len(),
                    )));
                }

                let len = self.bytes[start + 1] as usize;
                if len < 2 {
                    self.done = true;
                    return Some(Err(CrafterError::invalid_field_value(
                        "ipv4.option.length",
                        "option length must be at least 2 bytes",
                    )));
                }
                if start + len > self.bytes.len() {
                    self.done = true;
                    return Some(Err(CrafterError::buffer_too_short(
                        "ipv4 option",
                        start + len,
                        self.bytes.len(),
                    )));
                }

                let option_bytes = &self.bytes[start..start + len];
                self.offset += len;
                Some(decode_ipv4_option(option_bytes))
            }
        }
    }
}

pub(super) fn validate_ipv4_options(options: &[u8]) -> Result<()> {
    for option in Ipv4OptionIter::new(options) {
        option?;
    }
    Ok(())
}

fn decode_ipv4_option(bytes: &[u8]) -> Result<Ipv4Option> {
    let kind = bytes[0];
    let data = &bytes[2..];
    match kind {
        IPV4_OPTION_RECORD_ROUTE
        | IPV4_OPTION_LOOSE_SOURCE_ROUTE
        | IPV4_OPTION_STRICT_SOURCE_ROUTE => decode_ipv4_route_option(kind, data, bytes.len()),
        IPV4_OPTION_TIMESTAMP => decode_ipv4_timestamp_option(data, bytes.len()),
        IPV4_OPTION_ROUTER_ALERT => decode_ipv4_router_alert_option(data, bytes.len()),
        IPV4_OPTION_TRACEROUTE => decode_ipv4_traceroute_option(data, bytes.len()),
        _ => Ok(Ipv4Option::Generic {
            kind,
            data: data.to_vec(),
        }),
    }
}

fn decode_ipv4_route_option(kind: u8, data: &[u8], len: usize) -> Result<Ipv4Option> {
    if len < 3 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.length",
            "route options must be at least 3 bytes",
        ));
    }

    let pointer = data[0];
    validate_ipv4_route_pointer(pointer, len)?;
    let route_bytes = &data[1..];
    if route_bytes.len() % 4 != 0 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.route",
            "route option payload must contain whole IPv4 addresses",
        ));
    }

    let routes = route_bytes
        .chunks_exact(4)
        .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
        .collect();
    let kind = match kind {
        IPV4_OPTION_RECORD_ROUTE => Ipv4RouteOptionKind::RecordRoute,
        IPV4_OPTION_LOOSE_SOURCE_ROUTE => Ipv4RouteOptionKind::LooseSourceRoute,
        IPV4_OPTION_STRICT_SOURCE_ROUTE => Ipv4RouteOptionKind::StrictSourceRoute,
        _ => unreachable!("caller filters route option kinds"),
    };

    Ok(Ipv4Option::Route {
        kind,
        pointer,
        routes,
    })
}

fn decode_ipv4_timestamp_option(data: &[u8], len: usize) -> Result<Ipv4Option> {
    if len < IPV4_TIMESTAMP_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.length",
            "timestamp option length must be at least 4 bytes",
        ));
    }
    if len > IPV4_TIMESTAMP_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.length",
            "timestamp option length must be at most 40 bytes",
        ));
    }

    let pointer = data[0];
    let overflow_flags = data[1];
    let overflow = overflow_flags >> 4;
    let flag = overflow_flags & 0x0f;
    let timestamp_data = &data[2..];

    match flag {
        IPV4_TIMESTAMP_FLAG_TIMESTAMPS_ONLY => {
            validate_ipv4_timestamp(pointer, overflow, len)?;
            if timestamp_data.len() % IPV4_TIMESTAMP_WORD_LEN != 0 {
                return Err(CrafterError::invalid_field_value(
                    "ipv4.option.timestamp",
                    "timestamp-only option data must contain whole 32-bit timestamps",
                ));
            }
            let timestamps = timestamp_data
                .chunks_exact(IPV4_TIMESTAMP_WORD_LEN)
                .map(read_u32_be)
                .collect::<Result<Vec<_>>>()?;
            Ok(Ipv4Option::Timestamp {
                pointer,
                overflow,
                timestamps,
            })
        }
        IPV4_TIMESTAMP_FLAG_ADDRESS_AND_TIMESTAMP | IPV4_TIMESTAMP_FLAG_PRESPECIFIED_ADDRESS => {
            validate_ipv4_timestamp(pointer, overflow, len)?;
            if timestamp_data.len() % IPV4_TIMESTAMP_ADDRESS_WORD_LEN != 0 {
                return Err(CrafterError::invalid_field_value(
                    "ipv4.option.timestamp",
                    "address timestamp option data must contain whole IPv4 address/timestamp pairs",
                ));
            }
            let entries = timestamp_data
                .chunks_exact(IPV4_TIMESTAMP_ADDRESS_WORD_LEN)
                .map(|chunk| {
                    Ok((
                        Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]),
                        read_u32_be(&chunk[4..8])?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;

            if flag == IPV4_TIMESTAMP_FLAG_ADDRESS_AND_TIMESTAMP {
                Ok(Ipv4Option::TimestampWithAddresses {
                    pointer,
                    overflow,
                    entries,
                })
            } else {
                Ok(Ipv4Option::TimestampPrespecified {
                    pointer,
                    overflow,
                    entries,
                })
            }
        }
        _ => Ok(Ipv4Option::Generic {
            kind: IPV4_OPTION_TIMESTAMP,
            data: data.to_vec(),
        }),
    }
}

fn decode_ipv4_router_alert_option(data: &[u8], len: usize) -> Result<Ipv4Option> {
    if len != IPV4_ROUTER_ALERT_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.length",
            "router alert option length must be 4 bytes",
        ));
    }

    Ok(Ipv4Option::RouterAlert {
        value: read_u16_be(data)?,
    })
}

fn decode_ipv4_traceroute_option(data: &[u8], len: usize) -> Result<Ipv4Option> {
    if len != 12 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.length",
            "traceroute option length must be 12 bytes",
        ));
    }

    Ok(Ipv4Option::Traceroute {
        id_number: read_u16_be(&data[0..2])?,
        outbound_hop_count: read_u16_be(&data[2..4])?,
        return_hop_count: read_u16_be(&data[4..6])?,
        originator: Ipv4Addr::new(data[6], data[7], data[8], data[9]),
    })
}

fn validate_ipv4_route_pointer(pointer: u8, len: usize) -> Result<()> {
    if pointer < 4 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.pointer",
            "route option pointer must be at least 4",
        ));
    }
    if pointer as usize > len + 1 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.pointer",
            "route option pointer must not exceed option length plus one",
        ));
    }
    Ok(())
}

fn validate_ipv4_timestamp(pointer: u8, overflow: u8, len: usize) -> Result<()> {
    if len > IPV4_TIMESTAMP_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.length",
            "timestamp option length must be at most 40 bytes",
        ));
    }
    if overflow > 0x0f {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.timestamp.overflow",
            "timestamp option overflow must fit in four bits",
        ));
    }
    if pointer < IPV4_TIMESTAMP_POINTER_MIN {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.pointer",
            "timestamp option pointer must be at least 5",
        ));
    }
    if pointer as usize > len + 1 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.option.pointer",
            "timestamp option pointer must not exceed option length plus one",
        ));
    }
    Ok(())
}

pub(super) fn padded_options_len(len: usize) -> usize {
    (len + 3) & !3
}

pub(super) fn option_count_summary(options: &[u8]) -> String {
    Ipv4OptionIter::new(options).count().to_string()
}
