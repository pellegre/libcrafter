//! Internal IPv4 fragment record extraction helpers.
#![allow(dead_code)]

use core::borrow::Borrow;
use core::net::Ipv4Addr;

use crate::endian::{read_u16_be, read_u32_be, read_u32_le};
use crate::protocols::{ETHERTYPE_IPV4, ETHERTYPE_VLAN};
use crate::wire::backend::pcap::PcapLinkType;
use crate::wire::record::PacketRecord;
use crate::IPV4_FLAG_DONT_FRAGMENT;
use crate::{CrafterError, Ethernet, Ipv4, LinkType, LinuxSll, NullLoopback, Packet, Result, Vlan};

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_FRAGMENT_OFFSET_MASK: u16 = 0x1fff;
const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const LINUX_SLL_HEADER_LEN: usize = 16;
const NULL_LOOPBACK_HEADER_LEN: usize = 4;
const AF_INET: u32 = 2;

/// Result of inspecting a packet record for an IPv4 fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ipv4FragmentExtract {
    /// The record contains an IPv4 datagram and the header/payload fields were extracted.
    View(Ipv4FragmentView),
    /// The record is not an IPv4 datagram handled by this helper.
    PassThrough(Ipv4FragmentPassThrough),
}

impl Ipv4FragmentExtract {
    /// Borrow the extracted view when this result contains IPv4.
    pub(crate) const fn view(&self) -> Option<&Ipv4FragmentView> {
        match self {
            Self::View(view) => Some(view),
            Self::PassThrough(_) => None,
        }
    }

    /// Borrow the pass-through reason when this result is not handled as IPv4.
    pub(crate) const fn pass_through(&self) -> Option<&Ipv4FragmentPassThrough> {
        match self {
            Self::View(_) => None,
            Self::PassThrough(pass_through) => Some(pass_through),
        }
    }
}

/// Extracted IPv4 header fields and fragment payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv4FragmentView {
    wrapper: Ipv4FragmentWrapper,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    header_len: usize,
    total_len: usize,
    header: Vec<u8>,
    payload: Vec<u8>,
}

impl Ipv4FragmentView {
    /// Link or L3 wrapper context around the IPv4 datagram.
    pub(crate) const fn wrapper(&self) -> &Ipv4FragmentWrapper {
        &self.wrapper
    }

    /// IPv4 source address.
    pub(crate) const fn source(&self) -> Ipv4Addr {
        self.source
    }

    /// IPv4 destination address.
    pub(crate) const fn destination(&self) -> Ipv4Addr {
        self.destination
    }

    /// IPv4 protocol number.
    pub(crate) const fn protocol(&self) -> u8 {
        self.protocol
    }

    /// IPv4 identification field.
    pub(crate) const fn identification(&self) -> u16 {
        self.identification
    }

    /// Raw three-bit IPv4 flags value.
    pub(crate) const fn flags(&self) -> u8 {
        self.flags
    }

    /// IPv4 fragment offset in 8-byte units.
    pub(crate) const fn fragment_offset(&self) -> u16 {
        self.fragment_offset
    }

    /// IPv4 fragment offset in bytes.
    pub(crate) const fn fragment_offset_bytes(&self) -> u32 {
        (self.fragment_offset as u32) * 8
    }

    /// IPv4 header length in bytes.
    pub(crate) const fn header_len(&self) -> usize {
        self.header_len
    }

    /// IPv4 total length in bytes.
    pub(crate) const fn total_len(&self) -> usize {
        self.total_len
    }

    /// Raw IPv4 header bytes from the fragment.
    pub(crate) fn header(&self) -> &[u8] {
        &self.header
    }

    /// IPv4 payload bytes after the IPv4 header and before any wrapper suffix.
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Return true when the More Fragments flag is set.
    pub(crate) const fn more_fragments(&self) -> bool {
        self.flags & 0b001 != 0
    }

    /// Return true when the Don't Fragment flag is set.
    pub(crate) const fn is_dont_fragment(&self) -> bool {
        self.flags & IPV4_FLAG_DONT_FRAGMENT != 0
    }

    /// Return true when the IPv4 header marks this datagram as fragmented.
    pub(crate) const fn is_fragmented(&self) -> bool {
        self.more_fragments() || self.fragment_offset != 0
    }
}

/// Link-layer or L3 context that wrapped the IPv4 datagram in the record bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv4FragmentWrapper {
    kind: Ipv4FragmentWrapperKind,
    ipv4_offset: usize,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl Ipv4FragmentWrapper {
    fn new(
        kind: Ipv4FragmentWrapperKind,
        ipv4_offset: usize,
        bytes: &[u8],
        total_len: usize,
    ) -> Self {
        let end = ipv4_offset + total_len;
        Self {
            kind,
            ipv4_offset,
            prefix: bytes[..ipv4_offset].to_vec(),
            suffix: bytes[end..].to_vec(),
        }
    }

    /// Kind of wrapper that carried the IPv4 datagram.
    pub(crate) const fn kind(&self) -> Ipv4FragmentWrapperKind {
        self.kind
    }

    /// Offset where the IPv4 header begins in the record bytes.
    pub(crate) const fn ipv4_offset(&self) -> usize {
        self.ipv4_offset
    }

    /// Bytes before the IPv4 datagram, suitable for preserving link framing.
    pub(crate) fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Bytes after the IPv4 datagram, suitable for preserving trailing capture data.
    pub(crate) fn suffix(&self) -> &[u8] {
        &self.suffix
    }
}

/// Supported record wrapper families for IPv4 extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Ipv4FragmentWrapperKind {
    /// Bare network-layer IPv4 bytes.
    L3,
    /// Ethernet II frame containing IPv4 directly.
    Ethernet,
    /// Ethernet II frame containing one or more 802.1Q VLAN tags before IPv4.
    EthernetVlan {
        /// Number of VLAN tags observed before IPv4.
        tags: usize,
    },
    /// Linux cooked capture v1 wrapper.
    LinuxSll,
    /// BSD null/loopback wrapper.
    NullLoopback,
}

/// Explicit reason a record was not extracted as IPv4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipv4FragmentPassThrough {
    reason: Ipv4FragmentPassThroughReason,
}

impl Ipv4FragmentPassThrough {
    fn new(reason: Ipv4FragmentPassThroughReason) -> Self {
        Self { reason }
    }

    /// Reason the record should pass through unchanged.
    pub(crate) const fn reason(&self) -> Ipv4FragmentPassThroughReason {
        self.reason
    }
}

/// Reasons this extractor intentionally leaves a record unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Ipv4FragmentPassThroughReason {
    /// The record had no bytes to inspect.
    Empty,
    /// The record is not an IPv4 datagram.
    NonIpv4,
    /// The record uses a wrapper not handled by the IPv4 fragment transforms.
    UnsupportedWrapper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Start {
    kind: Ipv4FragmentWrapperKind,
    offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv4Location {
    Found(Ipv4Start),
    PassThrough(Ipv4FragmentPassThroughReason),
}

/// Extract an IPv4 fragment view from a packet record or return an explicit
/// pass-through reason. Malformed IPv4 or malformed supported wrappers return
/// structured [`CrafterError`] values.
pub(crate) fn extract_ipv4_fragment(record: &PacketRecord) -> Result<Ipv4FragmentExtract> {
    let bytes = record_bytes(record)?;
    let bytes = bytes.borrow();

    let start = match locate_ipv4(record, bytes)? {
        Ipv4Location::Found(start) => start,
        Ipv4Location::PassThrough(reason) => return Ok(pass_through(reason)),
    };

    if bytes.len() <= start.offset {
        return Ok(pass_through(Ipv4FragmentPassThroughReason::NonIpv4));
    }
    if bytes[start.offset] >> 4 != 4 {
        return Ok(pass_through(Ipv4FragmentPassThroughReason::NonIpv4));
    }

    parse_ipv4_view(start, bytes).map(Ipv4FragmentExtract::View)
}

fn pass_through(reason: Ipv4FragmentPassThroughReason) -> Ipv4FragmentExtract {
    Ipv4FragmentExtract::PassThrough(Ipv4FragmentPassThrough::new(reason))
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

fn locate_ipv4(record: &PacketRecord, bytes: &[u8]) -> Result<Ipv4Location> {
    if let Some(pcap_link_type) = record.metadata().pcap_link_type() {
        return locate_by_pcap_link_type(pcap_link_type, bytes);
    }
    if let Some(link_type) = record.metadata().link_type() {
        return locate_by_link_type(link_type, bytes);
    }
    locate_by_packet_shape(record.packet(), bytes)
}

fn locate_by_pcap_link_type(link_type: PcapLinkType, bytes: &[u8]) -> Result<Ipv4Location> {
    match link_type {
        PcapLinkType::RawIp => locate_l3(bytes),
        PcapLinkType::Ethernet => locate_ethernet(bytes),
        PcapLinkType::LinuxSll => locate_linux_sll(bytes),
        PcapLinkType::NullLoopback => locate_null_loopback(bytes),
        PcapLinkType::Ieee80211
        | PcapLinkType::Ieee80211Radiotap
        | PcapLinkType::BluetoothLeLl
        | PcapLinkType::Ieee802154WithFcs
        | PcapLinkType::Ieee802154NoFcs
        | PcapLinkType::Ieee802154Tap
        | PcapLinkType::Unknown(_) => Ok(Ipv4Location::PassThrough(
            Ipv4FragmentPassThroughReason::UnsupportedWrapper,
        )),
    }
}

fn locate_by_link_type(link_type: LinkType, bytes: &[u8]) -> Result<Ipv4Location> {
    match link_type {
        LinkType::Raw => locate_l3(bytes),
        LinkType::Ethernet => locate_ethernet(bytes),
        LinkType::LinuxCooked | LinkType::LinuxSll => locate_linux_sll(bytes),
        LinkType::NullLoopback => locate_null_loopback(bytes),
        LinkType::Ieee80211
        | LinkType::Radiotap
        | LinkType::BluetoothLeLl
        | LinkType::Ieee802154
        | LinkType::Ieee802154Tap => Ok(Ipv4Location::PassThrough(
            Ipv4FragmentPassThroughReason::UnsupportedWrapper,
        )),
    }
}

fn locate_by_packet_shape(packet: &Packet, bytes: &[u8]) -> Result<Ipv4Location> {
    let Some(first) = packet.get(0) else {
        let reason = if bytes.is_empty() {
            Ipv4FragmentPassThroughReason::Empty
        } else {
            Ipv4FragmentPassThroughReason::UnsupportedWrapper
        };
        return Ok(Ipv4Location::PassThrough(reason));
    };

    if first.as_any().is::<Ipv4>() {
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
    if looks_like_ipv4(bytes) {
        return locate_l3(bytes);
    }

    Ok(Ipv4Location::PassThrough(
        Ipv4FragmentPassThroughReason::UnsupportedWrapper,
    ))
}

fn locate_l3(bytes: &[u8]) -> Result<Ipv4Location> {
    if bytes.is_empty() {
        return Ok(Ipv4Location::PassThrough(
            Ipv4FragmentPassThroughReason::Empty,
        ));
    }
    if !looks_like_ipv4(bytes) {
        return Ok(Ipv4Location::PassThrough(
            Ipv4FragmentPassThroughReason::NonIpv4,
        ));
    }

    Ok(Ipv4Location::Found(Ipv4Start {
        kind: Ipv4FragmentWrapperKind::L3,
        offset: 0,
    }))
}

fn locate_ethernet(bytes: &[u8]) -> Result<Ipv4Location> {
    ensure_len("ethernet header", ETHERNET_HEADER_LEN, bytes.len())?;

    match read_u16_be(&bytes[12..14])? {
        ETHERTYPE_IPV4 => Ok(Ipv4Location::Found(Ipv4Start {
            kind: Ipv4FragmentWrapperKind::Ethernet,
            offset: ETHERNET_HEADER_LEN,
        })),
        ETHERTYPE_VLAN => locate_stacked_vlan(bytes, ETHERNET_HEADER_LEN),
        _ => Ok(Ipv4Location::PassThrough(
            Ipv4FragmentPassThroughReason::NonIpv4,
        )),
    }
}

fn locate_stacked_vlan(bytes: &[u8], mut offset: usize) -> Result<Ipv4Location> {
    let mut tags = 0usize;
    loop {
        let available = bytes.len().saturating_sub(offset);
        ensure_len("vlan header", VLAN_HEADER_LEN, available)?;

        tags += 1;
        let ethertype = read_u16_be(&bytes[offset + 2..offset + 4])?;
        offset += VLAN_HEADER_LEN;

        if ethertype == ETHERTYPE_IPV4 {
            return Ok(Ipv4Location::Found(Ipv4Start {
                kind: Ipv4FragmentWrapperKind::EthernetVlan { tags },
                offset,
            }));
        }
        if ethertype != ETHERTYPE_VLAN {
            return Ok(Ipv4Location::PassThrough(
                Ipv4FragmentPassThroughReason::NonIpv4,
            ));
        }
    }
}

fn locate_linux_sll(bytes: &[u8]) -> Result<Ipv4Location> {
    ensure_len("linux sll header", LINUX_SLL_HEADER_LEN, bytes.len())?;

    if read_u16_be(&bytes[14..16])? != ETHERTYPE_IPV4 {
        return Ok(Ipv4Location::PassThrough(
            Ipv4FragmentPassThroughReason::NonIpv4,
        ));
    }

    Ok(Ipv4Location::Found(Ipv4Start {
        kind: Ipv4FragmentWrapperKind::LinuxSll,
        offset: LINUX_SLL_HEADER_LEN,
    }))
}

fn locate_null_loopback(bytes: &[u8]) -> Result<Ipv4Location> {
    ensure_len(
        "null loopback header",
        NULL_LOOPBACK_HEADER_LEN,
        bytes.len(),
    )?;

    let family_le = read_u32_le(&bytes[..4])?;
    let family_be = read_u32_be(&bytes[..4])?;
    if family_le != AF_INET && family_be != AF_INET {
        return Ok(Ipv4Location::PassThrough(
            Ipv4FragmentPassThroughReason::NonIpv4,
        ));
    }

    Ok(Ipv4Location::Found(Ipv4Start {
        kind: Ipv4FragmentWrapperKind::NullLoopback,
        offset: NULL_LOOPBACK_HEADER_LEN,
    }))
}

fn parse_ipv4_view(start: Ipv4Start, bytes: &[u8]) -> Result<Ipv4FragmentView> {
    let datagram = &bytes[start.offset..];
    ensure_len("ipv4 header", IPV4_MIN_HEADER_LEN, datagram.len())?;

    let version = datagram[0] >> 4;
    if version != 4 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.version",
            "IPv4 packets must have version 4",
        ));
    }

    let ihl = datagram[0] & 0x0f;
    if ihl < 5 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.ihl",
            "internet header length must be at least 5 words",
        ));
    }

    let header_len = (ihl as usize) * 4;
    ensure_len("ipv4 header", header_len, datagram.len())?;

    let total_len = read_u16_be(&datagram[2..4])? as usize;
    if total_len < header_len {
        return Err(CrafterError::invalid_field_value(
            "ipv4.total_length",
            "total length must be at least the IPv4 header length",
        ));
    }
    ensure_len("ipv4 packet", total_len, datagram.len())?;

    let identification = read_u16_be(&datagram[4..6])?;
    let flags_fragment = read_u16_be(&datagram[6..8])?;
    let flags = (flags_fragment >> 13) as u8;
    let fragment_offset = flags_fragment & IPV4_FRAGMENT_OFFSET_MASK;
    let header = datagram[..header_len].to_vec();
    let payload = datagram[header_len..total_len].to_vec();
    let wrapper = Ipv4FragmentWrapper::new(start.kind, start.offset, bytes, total_len);

    Ok(Ipv4FragmentView {
        wrapper,
        source: Ipv4Addr::new(datagram[12], datagram[13], datagram[14], datagram[15]),
        destination: Ipv4Addr::new(datagram[16], datagram[17], datagram[18], datagram[19]),
        protocol: datagram[9],
        identification,
        flags,
        fragment_offset,
        header_len,
        total_len,
        header,
        payload,
    })
}

fn ensure_len(context: &'static str, required: usize, available: usize) -> Result<()> {
    if available < required {
        Err(CrafterError::buffer_too_short(context, required, available))
    } else {
        Ok(())
    }
}

fn looks_like_ipv4(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|first| first >> 4 == 4)
}

#[cfg(test)]
mod tests {
    use super::{
        extract_ipv4_fragment, Ipv4FragmentExtract, Ipv4FragmentPassThroughReason,
        Ipv4FragmentWrapperKind,
    };
    use crate::wire::backend::pcap::{PcapLinkType, PcapTimestamp};
    use crate::wire::record::PacketRecord;
    use crate::{
        CrafterError, Ethernet, Ipv4, LinkType, LinuxSll, NullLoopback, Packet, Raw, Vlan,
    };
    use std::net::Ipv4Addr;

    fn ipv4_fragment_packet() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 2))
            .protocol(17)
            .identification(0x4567)
            .more_fragments(true)
            .fragment_offset(3)
            / Raw::from_bytes([1, 2, 3, 4, 5, 6, 7, 8])
    }

    fn view(record: &PacketRecord) -> super::Ipv4FragmentView {
        match extract_ipv4_fragment(record).unwrap() {
            Ipv4FragmentExtract::View(view) => view,
            Ipv4FragmentExtract::PassThrough(pass) => {
                panic!("expected IPv4 view, got {:?}", pass.reason())
            }
        }
    }

    #[test]
    fn extracts_ipv4_fragment_from_l3_record() {
        let record = PacketRecord::new(ipv4_fragment_packet());

        let view = view(&record);

        assert_eq!(view.wrapper().kind(), Ipv4FragmentWrapperKind::L3);
        assert_eq!(view.wrapper().ipv4_offset(), 0);
        assert_eq!(view.source(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(view.destination(), Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(view.protocol(), 17);
        assert_eq!(view.identification(), 0x4567);
        assert_eq!(view.flags(), 0b001);
        assert_eq!(view.fragment_offset(), 3);
        assert_eq!(view.fragment_offset_bytes(), 24);
        assert_eq!(view.header_len(), 20);
        assert_eq!(view.total_len(), 28);
        assert_eq!(view.payload(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(view.more_fragments());
        assert!(view.is_fragmented());
    }

    #[test]
    fn extracts_ipv4_fragment_from_ethernet_vlan_record() {
        let packet = Ethernet::new() / Vlan::new().vlan_id(23) / ipv4_fragment_packet();
        let record = PacketRecord::new(packet);

        let view = view(&record);

        assert_eq!(
            view.wrapper().kind(),
            Ipv4FragmentWrapperKind::EthernetVlan { tags: 1 }
        );
        assert_eq!(view.wrapper().ipv4_offset(), 18);
        assert_eq!(view.wrapper().prefix().len(), 18);
        assert!(view.wrapper().suffix().is_empty());
        assert_eq!(view.identification(), 0x4567);
        assert_eq!(view.fragment_offset(), 3);
    }

    #[test]
    fn extracts_ipv4_fragment_from_linux_sll_record() {
        let packet = LinuxSll::new() / ipv4_fragment_packet();
        let record = PacketRecord::new(packet);

        let view = view(&record);

        assert_eq!(view.wrapper().kind(), Ipv4FragmentWrapperKind::LinuxSll);
        assert_eq!(view.wrapper().ipv4_offset(), 16);
        assert_eq!(view.protocol(), 17);
        assert_eq!(view.identification(), 0x4567);
    }

    #[test]
    fn extracts_ipv4_fragment_from_null_loopback_record() {
        let packet = NullLoopback::ipv4().big_endian() / ipv4_fragment_packet();
        let record = PacketRecord::new(packet);

        let view = view(&record);

        assert_eq!(view.wrapper().kind(), Ipv4FragmentWrapperKind::NullLoopback);
        assert_eq!(view.wrapper().ipv4_offset(), 4);
        assert_eq!(view.fragment_offset(), 3);
    }

    #[test]
    fn captured_raw_ip_bytes_drive_extraction_before_compiled_packet() {
        let bytes = ipv4_fragment_packet()
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

        assert_eq!(view.wrapper().kind(), Ipv4FragmentWrapperKind::L3);
        assert_eq!(view.identification(), 0x4567);
        assert_eq!(view.payload(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn non_ipv4_supported_wrappers_return_pass_through_reason() {
        let packet = Ethernet::new().ethertype(0x0806) / Raw::from("not-ipv4");
        let record = PacketRecord::new(packet);

        let extracted = extract_ipv4_fragment(&record).unwrap();

        assert_eq!(
            extracted.pass_through().map(|pass| pass.reason()),
            Some(Ipv4FragmentPassThroughReason::NonIpv4)
        );
    }

    #[test]
    fn unsupported_wrappers_return_pass_through_reason() {
        let record = PacketRecord::new(Raw::from("payload"));

        let extracted = extract_ipv4_fragment(&record).unwrap();

        assert_eq!(
            extracted.pass_through().map(|pass| pass.reason()),
            Some(Ipv4FragmentPassThroughReason::UnsupportedWrapper)
        );
        assert!(extracted.view().is_none());
    }

    #[test]
    fn malformed_raw_ipv4_returns_structured_error() {
        let bytes = [
            0x45, 0, 0, 19, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2,
        ];
        let record = PacketRecord::new(Raw::from_bytes(bytes))
            .with_pcap_link_type(PcapLinkType::RawIp)
            .with_captured_bytes(bytes);

        let error = extract_ipv4_fragment(&record).unwrap_err();

        assert_eq!(
            error,
            CrafterError::invalid_field_value(
                "ipv4.total_length",
                "total length must be at least the IPv4 header length"
            )
        );
    }

    #[test]
    fn truncated_link_wrapper_returns_structured_error() {
        let bytes = [0u8; 10];
        let record = PacketRecord::new(Raw::from_bytes(bytes))
            .with_link_type(LinkType::Ethernet)
            .with_captured_bytes(bytes);

        let error = extract_ipv4_fragment(&record).unwrap_err();

        assert_eq!(
            error,
            CrafterError::buffer_too_short("ethernet header", 14, 10)
        );
    }
}
