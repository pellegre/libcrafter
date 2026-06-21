//! Internal IPv6 fragment record extraction helpers.
#![allow(dead_code)]

use core::borrow::Borrow;
use core::net::Ipv6Addr;

use crate::endian::{read_u16_be, read_u32_be, read_u32_le};
use crate::protocols::{
    ETHERTYPE_IPV6, ETHERTYPE_VLAN, IPPROTO_IPV6_AH, IPPROTO_IPV6_DSTOPTS, IPPROTO_IPV6_ESP,
    IPPROTO_IPV6_EXPERIMENTAL_1, IPPROTO_IPV6_EXPERIMENTAL_2, IPPROTO_IPV6_FRAGMENT,
    IPPROTO_IPV6_HIP, IPPROTO_IPV6_HOPOPTS, IPPROTO_IPV6_MOBILITY, IPPROTO_IPV6_ROUTE,
    IPPROTO_IPV6_SHIM6,
};
use crate::wire::backend::pcap::PcapLinkType;
use crate::wire::record::PacketRecord;
use crate::{
    CrafterError, Ethernet, Ipv6, Ipv6FragmentHeaderStatus, LinkType, LinuxSll, NullLoopback,
    Packet, Result, Vlan,
};

const IPV6_HEADER_LEN: usize = 40;
const IPV6_FRAGMENT_HEADER_LEN: usize = 8;
const IPV6_EXTENSION_MIN_LEN: usize = 8;
const IPV6_FRAGMENT_OFFSET_MASK: u16 = 0xfff8;
const IPV6_FRAGMENT_RESERVED_MASK: u16 = 0x0006;
const IPV6_FRAGMENT_MORE_MASK: u16 = 0x0001;
const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const LINUX_SLL_HEADER_LEN: usize = 16;
const NULL_LOOPBACK_HEADER_LEN: usize = 4;
const AF_INET6: u32 = 24;
pub(crate) const IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE: &str =
    "unsupported IPv6 extension chain outside Fragment Header extension scope";

/// Result of inspecting a packet record for an IPv6 Fragment Header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Ipv6FragmentExtract {
    /// The record contains an IPv6 packet with a Fragment Header.
    View(Ipv6FragmentView),
    /// The record is not an IPv6 Fragment Header packet handled by this helper.
    PassThrough(Ipv6FragmentPassThrough),
}

impl Ipv6FragmentExtract {
    /// Borrow the extracted view when this result contains an IPv6 fragment.
    pub(crate) const fn view(&self) -> Option<&Ipv6FragmentView> {
        match self {
            Self::View(view) => Some(view),
            Self::PassThrough(_) => None,
        }
    }

    /// Borrow the pass-through reason when this result is not handled as IPv6.
    pub(crate) const fn pass_through(&self) -> Option<&Ipv6FragmentPassThrough> {
        match self {
            Self::View(_) => None,
            Self::PassThrough(pass_through) => Some(pass_through),
        }
    }
}

/// Result of inspecting a packet record as a source-side IPv6 fragmentation
/// candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Ipv6FragmentableExtract {
    /// The record contains an IPv6 packet in the supported source-fragmentation scope.
    View(Ipv6FragmentableView),
    /// The record is not an IPv6 packet handled by source-side fragmentation.
    PassThrough(Ipv6FragmentPassThrough),
}

impl Ipv6FragmentableExtract {
    /// Borrow the extracted source-side view when present.
    pub(crate) const fn view(&self) -> Option<&Ipv6FragmentableView> {
        match self {
            Self::View(view) => Some(view),
            Self::PassThrough(_) => None,
        }
    }

    /// Borrow the pass-through reason when this record is not handled.
    pub(crate) const fn pass_through(&self) -> Option<&Ipv6FragmentPassThrough> {
        match self {
            Self::View(_) => None,
            Self::PassThrough(pass_through) => Some(pass_through),
        }
    }
}

/// Extracted IPv6 Fragment Header fields and fragmentable payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv6FragmentView {
    wrapper: Ipv6FragmentWrapper,
    source: Ipv6Addr,
    destination: Ipv6Addr,
    ipv6_next_header: u8,
    fragment_next_header: u8,
    identification: u32,
    fragment_offset: u16,
    reserved: u8,
    reserved_bits: u8,
    more_fragments: bool,
    fragment_status: Ipv6FragmentHeaderStatus,
    payload_length: usize,
    total_len: usize,
    header: Vec<u8>,
    extension_chain: Ipv6FragmentExtensionContext,
    fragment_header: Vec<u8>,
    fragmentable_payload: Vec<u8>,
}

impl Ipv6FragmentView {
    /// Link or L3 wrapper context around the IPv6 packet.
    pub(crate) const fn wrapper(&self) -> &Ipv6FragmentWrapper {
        &self.wrapper
    }

    /// IPv6 source address.
    pub(crate) const fn source(&self) -> Ipv6Addr {
        self.source
    }

    /// IPv6 destination address.
    pub(crate) const fn destination(&self) -> Ipv6Addr {
        self.destination
    }

    /// IPv6 base-header Next Header value.
    pub(crate) const fn ipv6_next_header(&self) -> u8 {
        self.ipv6_next_header
    }

    /// Next Header value carried by the Fragment Header.
    pub(crate) const fn fragment_next_header(&self) -> u8 {
        self.fragment_next_header
    }

    /// IPv6 Fragment Identification field.
    pub(crate) const fn identification(&self) -> u32 {
        self.identification
    }

    /// Fragment Offset field in 8-octet units.
    pub(crate) const fn fragment_offset(&self) -> u16 {
        self.fragment_offset
    }

    /// Fragment Offset field converted to octets.
    pub(crate) const fn fragment_offset_bytes(&self) -> u32 {
        (self.fragment_offset as u32) * 8
    }

    /// Fragment Header reserved byte.
    pub(crate) const fn reserved(&self) -> u8 {
        self.reserved
    }

    /// Fragment Header two reserved bits from the offset/reserved/M field.
    pub(crate) const fn reserved_bits(&self) -> u8 {
        self.reserved_bits
    }

    /// Return true when the Fragment Header M flag is set.
    pub(crate) const fn more_fragments(&self) -> bool {
        self.more_fragments
    }

    /// Source-backed Fragment Header classification.
    pub(crate) const fn fragment_status(&self) -> Ipv6FragmentHeaderStatus {
        self.fragment_status
    }

    /// Return true for RFC 6946 atomic fragments.
    pub(crate) const fn is_atomic(&self) -> bool {
        self.fragment_status.is_atomic()
    }

    /// IPv6 payload length from the fixed header.
    pub(crate) const fn payload_length(&self) -> usize {
        self.payload_length
    }

    /// IPv6 packet length in bytes, excluding wrapper prefix/suffix.
    pub(crate) const fn total_len(&self) -> usize {
        self.total_len
    }

    /// Raw IPv6 fixed-header bytes.
    pub(crate) fn header(&self) -> &[u8] {
        &self.header
    }

    /// Context needed to remove the Fragment Header and repair the extension chain.
    pub(crate) const fn extension_chain(&self) -> &Ipv6FragmentExtensionContext {
        &self.extension_chain
    }

    /// Raw Fragment Header bytes.
    pub(crate) fn fragment_header(&self) -> &[u8] {
        &self.fragment_header
    }

    /// Bytes after the Fragment Header within this fragment.
    pub(crate) fn fragmentable_payload(&self) -> &[u8] {
        &self.fragmentable_payload
    }
}

/// Extracted source-side IPv6 fields and fragmentable payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv6FragmentableView {
    wrapper: Ipv6FragmentWrapper,
    source: Ipv6Addr,
    destination: Ipv6Addr,
    ipv6_next_header: u8,
    fragment_next_header: u8,
    payload_length: usize,
    total_len: usize,
    header: Vec<u8>,
    extension_chain: Ipv6FragmentExtensionContext,
    fragmentable_payload: Vec<u8>,
}

impl Ipv6FragmentableView {
    /// Link or L3 wrapper context around the IPv6 packet.
    pub(crate) const fn wrapper(&self) -> &Ipv6FragmentWrapper {
        &self.wrapper
    }

    /// IPv6 source address.
    pub(crate) const fn source(&self) -> Ipv6Addr {
        self.source
    }

    /// IPv6 destination address.
    pub(crate) const fn destination(&self) -> Ipv6Addr {
        self.destination
    }

    /// IPv6 base-header Next Header value.
    pub(crate) const fn ipv6_next_header(&self) -> u8 {
        self.ipv6_next_header
    }

    /// Final Next Header value carried by the fragmentable part.
    pub(crate) const fn fragment_next_header(&self) -> u8 {
        self.fragment_next_header
    }

    /// IPv6 payload length from the fixed header.
    pub(crate) const fn payload_length(&self) -> usize {
        self.payload_length
    }

    /// IPv6 packet length in bytes, excluding wrapper prefix/suffix.
    pub(crate) const fn total_len(&self) -> usize {
        self.total_len
    }

    /// Raw IPv6 fixed-header bytes.
    pub(crate) fn header(&self) -> &[u8] {
        &self.header
    }

    /// Context needed to insert the Fragment Header into the extension chain.
    pub(crate) const fn extension_chain(&self) -> &Ipv6FragmentExtensionContext {
        &self.extension_chain
    }

    /// Fragmentable bytes that will be split across emitted fragments.
    pub(crate) fn fragmentable_payload(&self) -> &[u8] {
        &self.fragmentable_payload
    }
}

/// Narrow extension-chain context for IPv6 Fragment Header removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv6FragmentExtensionContext {
    fragment_header_offset: usize,
    previous_next_header_offset: usize,
    unfragmentable: Vec<u8>,
}

impl Ipv6FragmentExtensionContext {
    fn new(
        fragment_header_offset: usize,
        previous_next_header_offset: usize,
        datagram: &[u8],
    ) -> Self {
        Self {
            fragment_header_offset,
            previous_next_header_offset,
            unfragmentable: datagram[IPV6_HEADER_LEN..fragment_header_offset].to_vec(),
        }
    }

    /// Offset of the Fragment Header within the IPv6 packet.
    pub(crate) const fn fragment_header_offset(&self) -> usize {
        self.fragment_header_offset
    }

    /// Offset of the Next Header byte that points at the Fragment Header.
    pub(crate) const fn previous_next_header_offset(&self) -> usize {
        self.previous_next_header_offset
    }

    /// Extension bytes between the fixed IPv6 header and Fragment Header.
    pub(crate) fn unfragmentable(&self) -> &[u8] {
        &self.unfragmentable
    }
}

/// Link-layer or L3 context that wrapped the IPv6 packet in the record bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv6FragmentWrapper {
    kind: Ipv6FragmentWrapperKind,
    ipv6_offset: usize,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl Ipv6FragmentWrapper {
    fn new(
        kind: Ipv6FragmentWrapperKind,
        ipv6_offset: usize,
        bytes: &[u8],
        total_len: usize,
    ) -> Self {
        let end = ipv6_offset + total_len;
        Self {
            kind,
            ipv6_offset,
            prefix: bytes[..ipv6_offset].to_vec(),
            suffix: bytes[end..].to_vec(),
        }
    }

    /// Kind of wrapper that carried the IPv6 packet.
    pub(crate) const fn kind(&self) -> Ipv6FragmentWrapperKind {
        self.kind
    }

    /// Offset where the IPv6 header begins in the record bytes.
    pub(crate) const fn ipv6_offset(&self) -> usize {
        self.ipv6_offset
    }

    /// Bytes before the IPv6 packet, suitable for preserving link framing.
    pub(crate) fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Bytes after the IPv6 packet, suitable for preserving trailing capture data.
    pub(crate) fn suffix(&self) -> &[u8] {
        &self.suffix
    }
}

/// Supported record wrapper families for IPv6 extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Ipv6FragmentWrapperKind {
    /// Bare network-layer IPv6 bytes.
    L3,
    /// Ethernet II frame containing IPv6 directly.
    Ethernet,
    /// Ethernet II frame containing one or more 802.1Q VLAN tags before IPv6.
    EthernetVlan {
        /// Number of VLAN tags observed before IPv6.
        tags: usize,
    },
    /// Linux cooked capture v1 wrapper.
    LinuxSll,
    /// BSD null/loopback wrapper.
    NullLoopback,
}

/// Explicit reason a record was not extracted as an IPv6 fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv6FragmentPassThrough {
    reason: Ipv6FragmentPassThroughReason,
}

impl Ipv6FragmentPassThrough {
    fn new(reason: Ipv6FragmentPassThroughReason) -> Self {
        Self { reason }
    }

    /// Reason the record should pass through unchanged.
    pub(crate) const fn reason(&self) -> Ipv6FragmentPassThroughReason {
        self.reason
    }
}

/// Reasons this extractor intentionally leaves a record unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Ipv6FragmentPassThroughReason {
    /// The record had no bytes to inspect.
    Empty,
    /// The record is not an IPv6 packet.
    NonIpv6,
    /// The record is IPv6 but does not contain a Fragment Header.
    NoFragmentHeader,
    /// The record uses an IPv6 extension-chain shape outside this helper's scope.
    UnsupportedExtensionChain,
    /// The record uses a wrapper not handled by the IPv6 fragment transforms.
    UnsupportedWrapper,
}

impl Ipv6FragmentPassThroughReason {
    /// Trace note to attach when pass-through is part of the narrow Fragment Header scope.
    pub(crate) const fn trace_note(self) -> Option<&'static str> {
        match self {
            Self::UnsupportedExtensionChain => Some(IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE),
            Self::Empty | Self::NonIpv6 | Self::NoFragmentHeader | Self::UnsupportedWrapper => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv6Start {
    kind: Ipv6FragmentWrapperKind,
    offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv6Location {
    Found(Ipv6Start),
    PassThrough(Ipv6FragmentPassThroughReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FragmentHeaderStart {
    offset: usize,
    previous_next_header_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FragmentHeaderInsertion {
    offset: usize,
    previous_next_header_offset: usize,
    fragment_next_header: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FragmentHeaderLocation {
    Found(FragmentHeaderStart),
    PassThrough(Ipv6FragmentPassThroughReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FragmentInsertionLocation {
    Insert(FragmentHeaderInsertion),
    ExistingFragmentHeader,
    PassThrough(Ipv6FragmentPassThroughReason),
}

/// Extract an IPv6 fragment view from a packet record or return an explicit
/// pass-through reason. Malformed IPv6 or malformed supported wrappers return
/// structured [`CrafterError`] values.
pub(crate) fn extract_ipv6_fragment(record: &PacketRecord) -> Result<Ipv6FragmentExtract> {
    let bytes = record_bytes(record)?;
    let bytes = bytes.borrow();

    let start = match locate_ipv6(record, bytes)? {
        Ipv6Location::Found(start) => start,
        Ipv6Location::PassThrough(reason) => return Ok(pass_through(reason)),
    };

    if bytes.len() <= start.offset {
        return Ok(pass_through(Ipv6FragmentPassThroughReason::NonIpv6));
    }
    if bytes[start.offset] >> 4 != 6 {
        return Ok(pass_through(Ipv6FragmentPassThroughReason::NonIpv6));
    }

    parse_ipv6_view(start, bytes)
}

/// Extract a source-side IPv6 fragmentation view from a packet record or return
/// an explicit pass-through reason. Malformed IPv6 or malformed supported
/// wrappers return structured [`CrafterError`] values.
pub(crate) fn extract_ipv6_fragmentable(record: &PacketRecord) -> Result<Ipv6FragmentableExtract> {
    let bytes = record_bytes(record)?;
    let bytes = bytes.borrow();

    let start = match locate_ipv6(record, bytes)? {
        Ipv6Location::Found(start) => start,
        Ipv6Location::PassThrough(reason) => {
            return Ok(Ipv6FragmentableExtract::PassThrough(
                Ipv6FragmentPassThrough::new(reason),
            ))
        }
    };

    if bytes.len() <= start.offset {
        return Ok(Ipv6FragmentableExtract::PassThrough(
            Ipv6FragmentPassThrough::new(Ipv6FragmentPassThroughReason::NonIpv6),
        ));
    }
    if bytes[start.offset] >> 4 != 6 {
        return Ok(Ipv6FragmentableExtract::PassThrough(
            Ipv6FragmentPassThrough::new(Ipv6FragmentPassThroughReason::NonIpv6),
        ));
    }

    parse_ipv6_fragmentable_view(start, bytes)
}

fn pass_through(reason: Ipv6FragmentPassThroughReason) -> Ipv6FragmentExtract {
    Ipv6FragmentExtract::PassThrough(Ipv6FragmentPassThrough::new(reason))
}

fn record_bytes(record: &PacketRecord) -> Result<impl Borrow<[u8]> + '_> {
    if let Some(bytes) = record.metadata().captured_bytes() {
        return Ok(RecordBytes::Borrowed(bytes));
    }
    Ok(RecordBytes::Owned(
        record.packet().compile()?.as_bytes().to_vec(),
    ))
}

enum RecordBytes<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl Borrow<[u8]> for RecordBytes<'_> {
    fn borrow(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes.as_slice(),
        }
    }
}

fn locate_ipv6(record: &PacketRecord, bytes: &[u8]) -> Result<Ipv6Location> {
    if let Some(pcap_link_type) = record.metadata().pcap_link_type() {
        return locate_by_pcap_link_type(pcap_link_type, bytes);
    }
    if let Some(link_type) = record.metadata().link_type() {
        return locate_by_link_type(link_type, bytes);
    }
    locate_by_packet_shape(record.packet(), bytes)
}

fn locate_by_pcap_link_type(link_type: PcapLinkType, bytes: &[u8]) -> Result<Ipv6Location> {
    match link_type {
        PcapLinkType::RawIp => locate_l3(bytes),
        PcapLinkType::Ethernet => locate_ethernet(bytes),
        PcapLinkType::LinuxSll => locate_linux_sll(bytes),
        PcapLinkType::NullLoopback => locate_null_loopback(bytes),
        PcapLinkType::Ieee80211
        | PcapLinkType::Ieee80211Radiotap
        | PcapLinkType::BluetoothLeLl
        | PcapLinkType::Unknown(_) => Ok(Ipv6Location::PassThrough(
            Ipv6FragmentPassThroughReason::UnsupportedWrapper,
        )),
    }
}

fn locate_by_link_type(link_type: LinkType, bytes: &[u8]) -> Result<Ipv6Location> {
    match link_type {
        LinkType::Raw => locate_l3(bytes),
        LinkType::Ethernet => locate_ethernet(bytes),
        LinkType::LinuxCooked | LinkType::LinuxSll => locate_linux_sll(bytes),
        LinkType::NullLoopback => locate_null_loopback(bytes),
        LinkType::Ieee80211 | LinkType::Radiotap | LinkType::BluetoothLeLl => Ok(
            Ipv6Location::PassThrough(Ipv6FragmentPassThroughReason::UnsupportedWrapper),
        ),
    }
}

fn locate_by_packet_shape(packet: &Packet, bytes: &[u8]) -> Result<Ipv6Location> {
    let Some(first) = packet.get(0) else {
        let reason = if bytes.is_empty() {
            Ipv6FragmentPassThroughReason::Empty
        } else {
            Ipv6FragmentPassThroughReason::UnsupportedWrapper
        };
        return Ok(Ipv6Location::PassThrough(reason));
    };

    if first.as_any().is::<Ipv6>() {
        return locate_l3(bytes);
    }
    if first.as_any().is::<Ethernet>() {
        return locate_ethernet(bytes);
    }
    if first.as_any().is::<LinuxSll>() {
        return locate_linux_sll(bytes);
    }
    if first.as_any().is::<NullLoopback>() {
        return locate_null_loopback(bytes);
    }
    if first.as_any().is::<Vlan>() {
        return locate_stacked_vlan(bytes, 0);
    }
    if bytes.len() >= IPV6_HEADER_LEN && looks_like_ipv6(bytes) {
        return locate_l3(bytes);
    }

    Ok(Ipv6Location::PassThrough(
        Ipv6FragmentPassThroughReason::UnsupportedWrapper,
    ))
}

fn locate_l3(bytes: &[u8]) -> Result<Ipv6Location> {
    if bytes.is_empty() {
        return Ok(Ipv6Location::PassThrough(
            Ipv6FragmentPassThroughReason::Empty,
        ));
    }
    if !looks_like_ipv6(bytes) {
        return Ok(Ipv6Location::PassThrough(
            Ipv6FragmentPassThroughReason::NonIpv6,
        ));
    }

    Ok(Ipv6Location::Found(Ipv6Start {
        kind: Ipv6FragmentWrapperKind::L3,
        offset: 0,
    }))
}

fn locate_ethernet(bytes: &[u8]) -> Result<Ipv6Location> {
    ensure_len("ethernet header", ETHERNET_HEADER_LEN, bytes.len())?;

    match read_u16_be(&bytes[12..14])? {
        ETHERTYPE_IPV6 => Ok(Ipv6Location::Found(Ipv6Start {
            kind: Ipv6FragmentWrapperKind::Ethernet,
            offset: ETHERNET_HEADER_LEN,
        })),
        ETHERTYPE_VLAN => locate_stacked_vlan(bytes, ETHERNET_HEADER_LEN),
        _ => Ok(Ipv6Location::PassThrough(
            Ipv6FragmentPassThroughReason::NonIpv6,
        )),
    }
}

fn locate_stacked_vlan(bytes: &[u8], mut offset: usize) -> Result<Ipv6Location> {
    let mut tags = 0usize;
    loop {
        let available = bytes.len().saturating_sub(offset);
        ensure_len("vlan header", VLAN_HEADER_LEN, available)?;

        tags += 1;
        let ethertype = read_u16_be(&bytes[offset + 2..offset + 4])?;
        offset += VLAN_HEADER_LEN;

        if ethertype == ETHERTYPE_IPV6 {
            return Ok(Ipv6Location::Found(Ipv6Start {
                kind: Ipv6FragmentWrapperKind::EthernetVlan { tags },
                offset,
            }));
        }
        if ethertype != ETHERTYPE_VLAN {
            return Ok(Ipv6Location::PassThrough(
                Ipv6FragmentPassThroughReason::NonIpv6,
            ));
        }
    }
}

fn locate_linux_sll(bytes: &[u8]) -> Result<Ipv6Location> {
    ensure_len("linux sll header", LINUX_SLL_HEADER_LEN, bytes.len())?;

    if read_u16_be(&bytes[14..16])? != ETHERTYPE_IPV6 {
        return Ok(Ipv6Location::PassThrough(
            Ipv6FragmentPassThroughReason::NonIpv6,
        ));
    }

    Ok(Ipv6Location::Found(Ipv6Start {
        kind: Ipv6FragmentWrapperKind::LinuxSll,
        offset: LINUX_SLL_HEADER_LEN,
    }))
}

fn locate_null_loopback(bytes: &[u8]) -> Result<Ipv6Location> {
    ensure_len(
        "null loopback header",
        NULL_LOOPBACK_HEADER_LEN,
        bytes.len(),
    )?;

    let family_le = read_u32_le(&bytes[..4])?;
    let family_be = read_u32_be(&bytes[..4])?;
    if family_le != AF_INET6 && family_be != AF_INET6 {
        return Ok(Ipv6Location::PassThrough(
            Ipv6FragmentPassThroughReason::NonIpv6,
        ));
    }

    Ok(Ipv6Location::Found(Ipv6Start {
        kind: Ipv6FragmentWrapperKind::NullLoopback,
        offset: NULL_LOOPBACK_HEADER_LEN,
    }))
}

fn parse_ipv6_view(start: Ipv6Start, bytes: &[u8]) -> Result<Ipv6FragmentExtract> {
    let datagram = &bytes[start.offset..];
    ensure_len("ipv6 header", IPV6_HEADER_LEN, datagram.len())?;

    let version_class_flow = read_u32_be(&datagram[0..4])?;
    let version = (version_class_flow >> 28) as u8;
    if version != 6 {
        return Err(CrafterError::invalid_field_value(
            "ipv6.version",
            "IPv6 packets must have version 6",
        ));
    }

    let payload_length = read_u16_be(&datagram[4..6])? as usize;
    let total_len = IPV6_HEADER_LEN + payload_length;
    ensure_len("ipv6 packet", total_len, datagram.len())?;
    let datagram = &datagram[..total_len];

    let fragment_start = match locate_fragment_header(datagram)? {
        FragmentHeaderLocation::Found(fragment_start) => fragment_start,
        FragmentHeaderLocation::PassThrough(reason) => return Ok(pass_through(reason)),
    };

    let fragment_offset = fragment_start.offset;
    ensure_len(
        "ipv6 fragment header",
        fragment_offset + IPV6_FRAGMENT_HEADER_LEN,
        datagram.len(),
    )?;

    let fragment_header = &datagram[fragment_offset..fragment_offset + IPV6_FRAGMENT_HEADER_LEN];
    let fragment_field = read_u16_be(&fragment_header[2..4])?;
    let fragment_offset_units = (fragment_field & IPV6_FRAGMENT_OFFSET_MASK) >> 3;
    let more_fragments = fragment_field & IPV6_FRAGMENT_MORE_MASK != 0;
    let fragment_status = fragment_status(fragment_offset_units, more_fragments);
    let extension_chain = Ipv6FragmentExtensionContext::new(
        fragment_offset,
        fragment_start.previous_next_header_offset,
        datagram,
    );
    let wrapper = Ipv6FragmentWrapper::new(start.kind, start.offset, bytes, total_len);

    Ok(Ipv6FragmentExtract::View(Ipv6FragmentView {
        wrapper,
        source: Ipv6Addr::from(copy_array_16(&datagram[8..24])),
        destination: Ipv6Addr::from(copy_array_16(&datagram[24..40])),
        ipv6_next_header: datagram[6],
        fragment_next_header: fragment_header[0],
        identification: read_u32_be(&fragment_header[4..8])?,
        fragment_offset: fragment_offset_units,
        reserved: fragment_header[1],
        reserved_bits: ((fragment_field & IPV6_FRAGMENT_RESERVED_MASK) >> 1) as u8,
        more_fragments,
        fragment_status,
        payload_length,
        total_len,
        header: datagram[..IPV6_HEADER_LEN].to_vec(),
        extension_chain,
        fragment_header: fragment_header.to_vec(),
        fragmentable_payload: datagram[fragment_offset + IPV6_FRAGMENT_HEADER_LEN..].to_vec(),
    }))
}

fn parse_ipv6_fragmentable_view(start: Ipv6Start, bytes: &[u8]) -> Result<Ipv6FragmentableExtract> {
    let datagram = &bytes[start.offset..];
    ensure_len("ipv6 header", IPV6_HEADER_LEN, datagram.len())?;

    let version_class_flow = read_u32_be(&datagram[0..4])?;
    let version = (version_class_flow >> 28) as u8;
    if version != 6 {
        return Err(CrafterError::invalid_field_value(
            "ipv6.version",
            "IPv6 packets must have version 6",
        ));
    }

    let payload_length = read_u16_be(&datagram[4..6])? as usize;
    let total_len = IPV6_HEADER_LEN + payload_length;
    ensure_len("ipv6 packet", total_len, datagram.len())?;
    let datagram = &datagram[..total_len];

    let insertion = match locate_fragment_insertion(datagram)? {
        FragmentInsertionLocation::Insert(insertion) => insertion,
        FragmentInsertionLocation::ExistingFragmentHeader => {
            return Ok(Ipv6FragmentableExtract::PassThrough(
                Ipv6FragmentPassThrough::new(Ipv6FragmentPassThroughReason::NoFragmentHeader),
            ))
        }
        FragmentInsertionLocation::PassThrough(reason) => {
            return Ok(Ipv6FragmentableExtract::PassThrough(
                Ipv6FragmentPassThrough::new(reason),
            ))
        }
    };
    let extension_chain = Ipv6FragmentExtensionContext::new(
        insertion.offset,
        insertion.previous_next_header_offset,
        datagram,
    );
    let wrapper = Ipv6FragmentWrapper::new(start.kind, start.offset, bytes, total_len);

    Ok(Ipv6FragmentableExtract::View(Ipv6FragmentableView {
        wrapper,
        source: Ipv6Addr::from(copy_array_16(&datagram[8..24])),
        destination: Ipv6Addr::from(copy_array_16(&datagram[24..40])),
        ipv6_next_header: datagram[6],
        fragment_next_header: insertion.fragment_next_header,
        payload_length,
        total_len,
        header: datagram[..IPV6_HEADER_LEN].to_vec(),
        extension_chain,
        fragmentable_payload: datagram[insertion.offset..].to_vec(),
    }))
}

fn locate_fragment_header(datagram: &[u8]) -> Result<FragmentHeaderLocation> {
    let mut next_header = datagram[6];
    let mut previous_next_header_offset = 6usize;
    let mut cursor = IPV6_HEADER_LEN;

    loop {
        match next_header {
            IPPROTO_IPV6_FRAGMENT => {
                return Ok(FragmentHeaderLocation::Found(FragmentHeaderStart {
                    offset: cursor,
                    previous_next_header_offset,
                }));
            }
            _ if is_supported_fragment_scope_extension(next_header) => {
                ensure_len(
                    "ipv6 extension header",
                    cursor + IPV6_EXTENSION_MIN_LEN,
                    datagram.len(),
                )?;
                let total_len = IPV6_EXTENSION_MIN_LEN + datagram[cursor + 1] as usize * 8;
                ensure_len("ipv6 extension header", cursor + total_len, datagram.len())?;
                next_header = datagram[cursor];
                previous_next_header_offset = cursor;
                cursor += total_len;
            }
            _ if is_unsupported_fragment_scope_extension(next_header) => {
                return Ok(FragmentHeaderLocation::PassThrough(
                    Ipv6FragmentPassThroughReason::UnsupportedExtensionChain,
                ));
            }
            _ => {
                return Ok(FragmentHeaderLocation::PassThrough(
                    Ipv6FragmentPassThroughReason::NoFragmentHeader,
                ));
            }
        }
    }
}

fn locate_fragment_insertion(datagram: &[u8]) -> Result<FragmentInsertionLocation> {
    let mut next_header = datagram[6];
    let mut previous_next_header_offset = 6usize;
    let mut cursor = IPV6_HEADER_LEN;

    loop {
        match next_header {
            IPPROTO_IPV6_FRAGMENT => {
                return Ok(FragmentInsertionLocation::ExistingFragmentHeader);
            }
            _ if is_supported_fragment_scope_extension(next_header) => {
                ensure_len(
                    "ipv6 extension header",
                    cursor + IPV6_EXTENSION_MIN_LEN,
                    datagram.len(),
                )?;
                let total_len = IPV6_EXTENSION_MIN_LEN + datagram[cursor + 1] as usize * 8;
                ensure_len("ipv6 extension header", cursor + total_len, datagram.len())?;
                next_header = datagram[cursor];
                previous_next_header_offset = cursor;
                cursor += total_len;
            }
            _ if is_unsupported_fragment_scope_extension(next_header) => {
                return Ok(FragmentInsertionLocation::PassThrough(
                    Ipv6FragmentPassThroughReason::UnsupportedExtensionChain,
                ));
            }
            _ => {
                return Ok(FragmentInsertionLocation::Insert(FragmentHeaderInsertion {
                    offset: cursor,
                    previous_next_header_offset,
                    fragment_next_header: next_header,
                }));
            }
        }
    }
}

fn is_supported_fragment_scope_extension(next_header: u8) -> bool {
    matches!(
        next_header,
        IPPROTO_IPV6_HOPOPTS | IPPROTO_IPV6_DSTOPTS | IPPROTO_IPV6_ROUTE
    )
}

fn is_unsupported_fragment_scope_extension(next_header: u8) -> bool {
    matches!(
        next_header,
        IPPROTO_IPV6_AH
            | IPPROTO_IPV6_ESP
            | IPPROTO_IPV6_MOBILITY
            | IPPROTO_IPV6_HIP
            | IPPROTO_IPV6_SHIM6
            | IPPROTO_IPV6_EXPERIMENTAL_1
            | IPPROTO_IPV6_EXPERIMENTAL_2
    )
}

fn fragment_status(fragment_offset: u16, more_fragments: bool) -> Ipv6FragmentHeaderStatus {
    match (fragment_offset, more_fragments) {
        (0, false) => Ipv6FragmentHeaderStatus::Atomic,
        (0, true) => Ipv6FragmentHeaderStatus::Initial,
        _ => Ipv6FragmentHeaderStatus::NonInitial,
    }
}

fn ensure_len(context: &'static str, required: usize, available: usize) -> Result<()> {
    if available < required {
        Err(CrafterError::buffer_too_short(context, required, available))
    } else {
        Ok(())
    }
}

fn looks_like_ipv6(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|first| first >> 4 == 6)
}

fn copy_array_16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::{
        extract_ipv6_fragment, Ipv6FragmentExtract, Ipv6FragmentPassThroughReason,
        Ipv6FragmentWrapperKind,
    };
    use crate::wire::backend::pcap::{PcapLinkType, PcapTimestamp};
    use crate::wire::record::PacketRecord;
    use crate::{
        CrafterError, Ethernet, Ipv6, Ipv6DestinationOptionsHeader, Ipv6FragmentHeader,
        Ipv6FragmentHeaderStatus, LinkType, LinuxSll, NullLoopback, Packet, Raw, Vlan, IPPROTO_UDP,
    };
    use std::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        "2001:db8::1".parse().unwrap()
    }

    fn dst() -> Ipv6Addr {
        "2001:db8::2".parse().unwrap()
    }

    fn ipv6_fragment_packet() -> Packet {
        Ipv6::new().src(src()).dst(dst())
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(0x0102_0304)
                .fragment_offset(3)
                .more_fragments(true)
            / Raw::from_bytes([1, 2, 3, 4, 5, 6, 7, 8])
    }

    fn view(record: &PacketRecord) -> super::Ipv6FragmentView {
        match extract_ipv6_fragment(record).unwrap() {
            Ipv6FragmentExtract::View(view) => view,
            Ipv6FragmentExtract::PassThrough(pass) => {
                panic!("expected IPv6 view, got {:?}", pass.reason())
            }
        }
    }

    #[test]
    fn extracts_ipv6_fragment_from_l3_record() {
        let record = PacketRecord::new(ipv6_fragment_packet());

        let view = view(&record);

        assert_eq!(view.wrapper().kind(), Ipv6FragmentWrapperKind::L3);
        assert_eq!(view.wrapper().ipv6_offset(), 0);
        assert_eq!(view.source(), src());
        assert_eq!(view.destination(), dst());
        assert_eq!(view.ipv6_next_header(), crate::IPPROTO_IPV6_FRAGMENT);
        assert_eq!(view.fragment_next_header(), IPPROTO_UDP);
        assert_eq!(view.identification(), 0x0102_0304);
        assert_eq!(view.fragment_offset(), 3);
        assert_eq!(view.fragment_offset_bytes(), 24);
        assert!(view.more_fragments());
        assert_eq!(view.fragment_status(), Ipv6FragmentHeaderStatus::NonInitial);
        assert!(!view.is_atomic());
        assert_eq!(view.payload_length(), 16);
        assert_eq!(view.total_len(), 56);
        assert_eq!(view.header().len(), 40);
        assert_eq!(view.extension_chain().fragment_header_offset(), 40);
        assert_eq!(view.extension_chain().previous_next_header_offset(), 6);
        assert!(view.extension_chain().unfragmentable().is_empty());
        assert_eq!(view.fragment_header().len(), 8);
        assert_eq!(view.fragmentable_payload(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn extracts_ipv6_atomic_fragment_with_extension_context_from_vlan_record() {
        let packet = Ethernet::new()
            / Vlan::new().vlan_id(23)
            / Ipv6::new().src(src()).dst(dst())
            / Ipv6DestinationOptionsHeader::new()
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(0x0a0b_0c0d)
            / Raw::from_bytes([9, 8, 7, 6]);
        let record = PacketRecord::new(packet);

        let view = view(&record);

        assert_eq!(
            view.wrapper().kind(),
            Ipv6FragmentWrapperKind::EthernetVlan { tags: 1 }
        );
        assert_eq!(view.wrapper().ipv6_offset(), 18);
        assert_eq!(view.wrapper().prefix().len(), 18);
        assert!(view.wrapper().suffix().is_empty());
        assert_eq!(view.ipv6_next_header(), crate::IPPROTO_IPV6_DSTOPTS);
        assert_eq!(view.fragment_next_header(), IPPROTO_UDP);
        assert_eq!(view.identification(), 0x0a0b_0c0d);
        assert_eq!(view.fragment_offset(), 0);
        assert!(!view.more_fragments());
        assert_eq!(view.fragment_status(), Ipv6FragmentHeaderStatus::Atomic);
        assert!(view.is_atomic());
        assert_eq!(view.payload_length(), 20);
        assert_eq!(view.total_len(), 60);
        assert_eq!(view.extension_chain().fragment_header_offset(), 48);
        assert_eq!(view.extension_chain().previous_next_header_offset(), 40);
        assert_eq!(view.extension_chain().unfragmentable().len(), 8);
        assert_eq!(view.fragmentable_payload(), &[9, 8, 7, 6]);
    }

    #[test]
    fn extracts_ipv6_fragment_from_linux_sll_record() {
        let packet = LinuxSll::new() / ipv6_fragment_packet();
        let record = PacketRecord::new(packet);

        let view = view(&record);

        assert_eq!(view.wrapper().kind(), Ipv6FragmentWrapperKind::LinuxSll);
        assert_eq!(view.wrapper().ipv6_offset(), 16);
        assert_eq!(view.fragment_next_header(), IPPROTO_UDP);
        assert_eq!(view.identification(), 0x0102_0304);
    }

    #[test]
    fn extracts_ipv6_fragment_from_null_loopback_record() {
        let packet = NullLoopback::new().family(24).big_endian() / ipv6_fragment_packet();
        let record = PacketRecord::new(packet);

        let view = view(&record);

        assert_eq!(view.wrapper().kind(), Ipv6FragmentWrapperKind::NullLoopback);
        assert_eq!(view.wrapper().ipv6_offset(), 4);
        assert_eq!(view.fragment_offset(), 3);
    }

    #[test]
    fn captured_raw_ip_bytes_drive_extraction_before_compiled_packet() {
        let bytes = ipv6_fragment_packet()
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec();
        let record = PacketRecord::new(Raw::from("decoded-placeholder"))
            .with_pcap_metadata(
                PcapTimestamp::zero(),
                bytes.len() as u32,
                bytes.len() as u32,
                PcapLinkType::RawIp,
            )
            .with_captured_bytes(bytes);

        let view = view(&record);

        assert_eq!(view.wrapper().kind(), Ipv6FragmentWrapperKind::L3);
        assert_eq!(view.identification(), 0x0102_0304);
        assert_eq!(view.fragmentable_payload(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn non_ipv6_supported_wrappers_return_pass_through_reason() {
        let packet = Ethernet::new().ethertype(crate::ETHERTYPE_IPV4) / Raw::from("not-ipv6");
        let record = PacketRecord::new(packet);

        let extracted = extract_ipv6_fragment(&record).unwrap();

        assert_eq!(
            extracted.pass_through().map(|pass| pass.reason()),
            Some(Ipv6FragmentPassThroughReason::NonIpv6)
        );
    }

    #[test]
    fn ipv6_without_fragment_header_returns_pass_through_reason() {
        let record = PacketRecord::new(
            Ipv6::new().src(src()).dst(dst()).next_header(IPPROTO_UDP) / Raw::from("payload"),
        );

        let extracted = extract_ipv6_fragment(&record).unwrap();

        assert_eq!(
            extracted.pass_through().map(|pass| pass.reason()),
            Some(Ipv6FragmentPassThroughReason::NoFragmentHeader)
        );
        assert!(extracted.view().is_none());
    }

    #[test]
    fn unsupported_wrappers_return_pass_through_reason() {
        let record = PacketRecord::new(Raw::from("payload"));

        let extracted = extract_ipv6_fragment(&record).unwrap();

        assert_eq!(
            extracted.pass_through().map(|pass| pass.reason()),
            Some(Ipv6FragmentPassThroughReason::UnsupportedWrapper)
        );
        assert!(extracted.view().is_none());
    }

    #[test]
    fn short_raw_payload_with_ipv6_version_nibble_passes_through() {
        let record = PacketRecord::new(Raw::from("defrag"));

        let extracted = extract_ipv6_fragment(&record).unwrap();

        assert_eq!(
            extracted.pass_through().map(|pass| pass.reason()),
            Some(Ipv6FragmentPassThroughReason::UnsupportedWrapper)
        );
        assert!(extracted.view().is_none());
    }

    #[test]
    fn malformed_raw_ipv6_returns_structured_error() {
        let bytes = [
            0x60,
            0,
            0,
            0,
            0,
            8,
            crate::IPPROTO_IPV6_FRAGMENT,
            64,
            0x20,
            0x01,
            0x0d,
            0xb8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            0x20,
            0x01,
            0x0d,
            0xb8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            2,
            crate::IPPROTO_UDP,
            0,
            0,
        ];
        let record = PacketRecord::new(Raw::from_bytes(bytes))
            .with_pcap_link_type(PcapLinkType::RawIp)
            .with_captured_bytes(bytes);

        let error = extract_ipv6_fragment(&record).unwrap_err();

        assert_eq!(error, CrafterError::buffer_too_short("ipv6 packet", 48, 43));
    }

    #[test]
    fn unsupported_extension_chain_returns_pass_through_reason() {
        let mut bytes = (Ipv6::new()
            .src(src())
            .dst(dst())
            .next_header(crate::IPPROTO_IPV6_AH)
            / Raw::from_bytes([0u8; 8]))
        .compile()
        .unwrap()
        .as_bytes()
        .to_vec();
        bytes[40] = crate::IPPROTO_IPV6_FRAGMENT;
        let record = PacketRecord::new(Raw::from_bytes(&bytes))
            .with_pcap_link_type(PcapLinkType::RawIp)
            .with_captured_bytes(bytes);

        let extracted = extract_ipv6_fragment(&record).unwrap();

        assert_eq!(
            extracted.pass_through().map(|pass| pass.reason()),
            Some(Ipv6FragmentPassThroughReason::UnsupportedExtensionChain)
        );
    }

    #[test]
    fn truncated_link_wrapper_returns_structured_error() {
        let bytes = [0u8; 10];
        let record = PacketRecord::new(Raw::from_bytes(bytes))
            .with_link_type(LinkType::Ethernet)
            .with_captured_bytes(bytes);

        let error = extract_ipv6_fragment(&record).unwrap_err();

        assert_eq!(
            error,
            CrafterError::buffer_too_short("ethernet header", 14, 10)
        );
    }
}
