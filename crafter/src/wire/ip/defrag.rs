//! Receive-side IP defragmentation transform.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::ipv4::{
    extract_ipv4_fragment, Ipv4FragmentExtract, Ipv4FragmentView, Ipv4FragmentWrapper,
    Ipv4FragmentWrapperKind,
};
use super::range::{RangeMap, RangeMapConflict, RangeMapInsert};
use super::{
    IpDefragConfig, IpDefragEvictionReason, IpDefragMetadata, IpDefragOverlapPolicy,
    IpFragmentFamily, IpFragmentRange,
};
use crate::pcap::PcapTimestamp;
use crate::protocols::ipv4::append_ipv4_packet_with_registry;
use crate::protocols::link::{append_vlan_packet_with_registry, ETHERTYPE_IPV4, ETHERTYPE_VLAN};
use crate::registry::ProtocolRegistry;
use crate::wire::record::{PacketMetadata, PacketOrigin, PacketRecord, TransformTrace};
use crate::wire::transform::{PacketTransform, TransformOutput};
use crate::wire::Result;
use crate::{CrafterError, Ipv4, LinkType, NetworkLayer, Packet, Raw};

const IPV4_MIN_HEADER_LEN: usize = 20;

/// Receive-side IP defragmentation transform.
#[derive(Debug, Clone, Default)]
pub struct IpDefrag {
    config: IpDefragConfig,
    ipv4_datagrams: BTreeMap<Ipv4DefragKey, Ipv4DatagramState>,
    input_count: usize,
    emitted_count: usize,
}

impl IpDefrag {
    /// Create an IP defragmentation transform with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the defragmentation configuration.
    pub const fn with_config(mut self, config: IpDefragConfig) -> Self {
        self.config = config;
        self
    }

    /// Replace the defragmentation configuration after validating it.
    pub fn try_with_config(mut self, config: IpDefragConfig) -> Result<Self> {
        config.validate()?;
        self.config = config;
        Ok(self)
    }

    /// Borrow the current configuration.
    pub const fn config(&self) -> &IpDefragConfig {
        &self.config
    }

    /// Number of input records seen.
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Number of records successfully emitted.
    pub const fn emitted_count(&self) -> usize {
        self.emitted_count
    }

    /// Run the transform and collect emitted records into a small buffer.
    pub fn defrag_record(&mut self, record: PacketRecord) -> Result<TransformOutput> {
        self.transform_to_output(record)
    }

    fn observe_ipv4_fragment(
        &mut self,
        record: &PacketRecord,
        view: &Ipv4FragmentView,
    ) -> Ipv4DefragObservation {
        let key = Ipv4DefragKey::from_view(view);
        let outcome = {
            let state = self
                .ipv4_datagrams
                .entry(key.clone())
                .or_insert_with(|| Ipv4DatagramState::new(key.clone(), record));
            state.observe_fragment(record, view);
            if state.has_conflict() {
                Ipv4DefragObservationKind::Conflict
            } else if state.is_complete() {
                Ipv4DefragObservationKind::Complete
            } else {
                Ipv4DefragObservationKind::Buffered
            }
        };

        match outcome {
            Ipv4DefragObservationKind::Buffered => Ipv4DefragObservation::Buffered,
            Ipv4DefragObservationKind::Complete => {
                let state = self
                    .ipv4_datagrams
                    .remove(&key)
                    .expect("complete IPv4 defrag state must remain in the map");
                Ipv4DefragObservation::Complete(state)
            }
            Ipv4DefragObservationKind::Conflict => {
                let state = self
                    .ipv4_datagrams
                    .remove(&key)
                    .expect("conflicting IPv4 defrag state must remain in the map");
                Ipv4DefragObservation::Conflict(state)
            }
        }
    }

    fn handle_ipv4_conflict(
        &mut self,
        mut record: PacketRecord,
        state: Ipv4DatagramState,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        match self.config.configured_overlap_policy() {
            IpDefragOverlapPolicy::RejectConflicting => Err(CrafterError::invalid_field_value(
                "ip.defrag.ipv4.overlap",
                "conflicting IPv4 fragment overlap is ambiguous",
            )
            .into()),
            IpDefragOverlapPolicy::DropConflicting => Ok(()),
            IpDefragOverlapPolicy::PassThroughConflicting => {
                record.metadata_mut().push_ip_defrag_metadata(
                    state.eviction_metadata(IpDefragEvictionReason::Conflict),
                );
                record.metadata_mut().push_transform_trace(
                    TransformTrace::new(self.name()).with_note(
                        state.conflict_trace_note(self.config.configured_overlap_policy()),
                    ),
                );
                emit(record)?;
                self.emitted_count += 1;
                Ok(())
            }
        }
    }
}

impl PacketTransform for IpDefrag {
    fn name(&self) -> &'static str {
        "ip-defrag"
    }

    fn transform(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.config.validate()?;
        self.input_count += 1;

        if let Ipv4FragmentExtract::View(view) = extract_ipv4_fragment(&record)? {
            if view.is_fragmented() {
                match self.observe_ipv4_fragment(&record, &view) {
                    Ipv4DefragObservation::Buffered => {}
                    Ipv4DefragObservation::Complete(state) => {
                        emit(state.reassembled_record(self.name())?)?;
                        self.emitted_count += 1;
                    }
                    Ipv4DefragObservation::Conflict(state) => {
                        self.handle_ipv4_conflict(record, state, emit)?;
                    }
                }
                return Ok(());
            }
        }

        let mut record = record;
        if self.config.traces_passthrough() {
            record
                .metadata_mut()
                .push_transform_trace(TransformTrace::new(self.name()).with_note("passthrough"));
        }

        emit(record)?;
        self.emitted_count += 1;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv4DefragObservationKind {
    Buffered,
    Complete,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ipv4DefragObservation {
    Buffered,
    Complete(Ipv4DatagramState),
    Conflict(Ipv4DatagramState),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Ipv4DefragKey {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    identification: u16,
}

impl Ipv4DefragKey {
    const fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        identification: u16,
    ) -> Self {
        Self {
            source,
            destination,
            protocol,
            identification,
        }
    }

    fn from_view(view: &Ipv4FragmentView) -> Self {
        Self::new(
            view.source(),
            view.destination(),
            view.protocol(),
            view.identification(),
        )
    }

    fn summary(&self) -> String {
        format!(
            "{}>{} proto={} id=0x{:04x}",
            self.source, self.destination, self.protocol, self.identification
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv4DatagramState {
    key: Ipv4DefragKey,
    ranges: RangeMap,
    first_fragment: Option<Ipv4FirstFragment>,
    total_expected: Option<u32>,
    fragment_count: usize,
    duplicate_count: usize,
    conflict_count: usize,
    first_conflict: Option<RangeMapConflict>,
    first_timestamp: Option<PcapTimestamp>,
    last_timestamp: Option<PcapTimestamp>,
    input_metadata: Ipv4DefragInputMetadata,
}

impl Ipv4DatagramState {
    fn new(key: Ipv4DefragKey, record: &PacketRecord) -> Self {
        let timestamp = record.metadata().timestamp();
        Self {
            key,
            ranges: RangeMap::new(),
            first_fragment: None,
            total_expected: None,
            fragment_count: 0,
            duplicate_count: 0,
            conflict_count: 0,
            first_conflict: None,
            first_timestamp: timestamp,
            last_timestamp: timestamp,
            input_metadata: Ipv4DefragInputMetadata::from_record(record),
        }
    }

    fn observe_fragment(&mut self, record: &PacketRecord, view: &Ipv4FragmentView) {
        self.update_timestamps(record.metadata().timestamp());

        if view.fragment_offset_bytes() == 0 && self.first_fragment.is_none() {
            self.first_fragment = Some(Ipv4FirstFragment::from_record(record, view));
        }

        match self
            .ranges
            .insert(view.fragment_offset_bytes(), view.payload())
        {
            RangeMapInsert::Inserted { .. } | RangeMapInsert::Empty { .. } => {
                self.fragment_count += 1;
            }
            RangeMapInsert::Duplicate { .. } => {}
            RangeMapInsert::Conflict(conflict) => self.record_conflict(conflict),
        }
        self.duplicate_count = self.ranges.duplicate_count();

        if !view.more_fragments() {
            let total_expected = view
                .fragment_offset_bytes()
                .saturating_add(view.payload().len() as u32);
            match self.ranges.set_total_len(total_expected) {
                Ok(()) => self.total_expected = Some(total_expected),
                Err(conflict) => self.record_conflict(conflict),
            }
        }
    }

    fn update_timestamps(&mut self, timestamp: Option<PcapTimestamp>) {
        let Some(timestamp) = timestamp else {
            return;
        };
        if self.first_timestamp.is_none() {
            self.first_timestamp = Some(timestamp);
        }
        self.last_timestamp = Some(timestamp);
    }

    fn record_conflict(&mut self, conflict: RangeMapConflict) {
        self.conflict_count += 1;
        if self.first_conflict.is_none() {
            self.first_conflict = Some(conflict);
        }
    }

    fn has_conflict(&self) -> bool {
        self.first_conflict.is_some() || self.ranges.has_conflict()
    }

    fn is_complete(&self) -> bool {
        self.first_fragment.is_some() && self.ranges.is_complete()
    }

    fn reassembled_record(&self, transform_name: &'static str) -> Result<PacketRecord> {
        let first_fragment = self.first_fragment.as_ref().ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ip.defrag.ipv4.first_fragment",
                "complete IPv4 defragmentation state requires a first fragment",
            )
        })?;
        let payload = self.ranges.contiguous_payload().ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ip.defrag.ipv4.payload",
                "complete IPv4 defragmentation state requires contiguous payload bytes",
            )
        })?;
        let (packet, emitted_len, total_len) = first_fragment.reassembled_packet(&payload)?;
        let metadata = first_fragment
            .input_metadata
            .metadata
            .clone()
            .with_origin(PacketOrigin::Transformed)
            .with_original_len(emitted_len)
            .with_captured_len(emitted_len)
            .with_emitted_len(emitted_len)
            .with_ip_defrag_metadata(self.reassembled_metadata(total_len))
            .with_transform_trace(
                TransformTrace::new(transform_name)
                    .with_note("reassembled")
                    .with_output_len(emitted_len),
            );

        Ok(PacketRecord::from_packet_metadata(packet, metadata))
    }

    fn metadata(&self) -> IpDefragMetadata {
        IpDefragMetadata::new(IpFragmentFamily::Ipv4, self.key.identification as u32)
            .with_datagram_key(self.key.summary())
            .with_fragment_count(self.fragment_count)
            .with_duplicate_count(self.duplicate_count)
            .with_overlap_status(self.ranges.overlap_status())
            .with_byte_ranges(
                self.ranges
                    .ranges()
                    .into_iter()
                    .map(|range| IpFragmentRange::new(range.start(), range.end())),
            )
    }

    fn reassembled_metadata(&self, total_len: u32) -> IpDefragMetadata {
        self.metadata().with_total_len(total_len)
    }

    fn eviction_metadata(&self, eviction_reason: IpDefragEvictionReason) -> IpDefragMetadata {
        let metadata = match self.known_packet_total_len() {
            Some(total_len) => self.metadata().with_total_len(total_len),
            None => self.metadata(),
        };
        metadata.with_eviction_reason(eviction_reason)
    }

    fn known_packet_total_len(&self) -> Option<u32> {
        let payload_len = self.total_expected.or_else(|| self.ranges.total_len())?;
        let header_len = u32::try_from(self.first_fragment.as_ref()?.header.len()).ok()?;
        header_len.checked_add(payload_len)
    }

    fn conflict_trace_note(&self, policy: IpDefragOverlapPolicy) -> String {
        let action = match policy {
            IpDefragOverlapPolicy::RejectConflicting => "reject",
            IpDefragOverlapPolicy::DropConflicting => "drop",
            IpDefragOverlapPolicy::PassThroughConflicting => "pass-through",
        };

        let Some(conflict) = self
            .first_conflict
            .as_ref()
            .or_else(|| self.ranges.conflict())
        else {
            return format!("ambiguous conflicting IPv4 overlap: policy={action}");
        };

        format!(
            "ambiguous conflicting IPv4 overlap: policy={action} reason={:?} offset={} incoming={:?} existing={:?} incoming_byte={:?} existing_byte={:?}",
            conflict.reason(),
            conflict.offset(),
            conflict.incoming(),
            conflict.existing(),
            conflict.incoming_byte(),
            conflict.existing_byte()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv4FirstFragment {
    header: Vec<u8>,
    wrapper: Ipv4FragmentWrapper,
    input_metadata: Ipv4DefragInputMetadata,
}

impl Ipv4FirstFragment {
    fn from_record(record: &PacketRecord, view: &Ipv4FragmentView) -> Self {
        Self {
            header: view.header().to_vec(),
            wrapper: view.wrapper().clone(),
            input_metadata: Ipv4DefragInputMetadata::from_record(record),
        }
    }

    fn reassembled_packet(&self, payload: &[u8]) -> Result<(Packet, u32, u32)> {
        let l3_packet = Packet::new()
            .push(ipv4_layer_from_header(&self.header)?)
            .push(Raw::from_bytes(payload));
        let l3_bytes = l3_packet.compile()?.as_bytes().to_vec();
        let total_len = u32::try_from(l3_bytes.len()).map_err(|_| {
            CrafterError::invalid_field_value("ipv4.total_length", "packet length exceeds u32")
        })?;
        let frame_bytes = self.wrapper.wrap_l3(&l3_bytes);
        let packet = self.wrapper.decode_packet(&frame_bytes)?;
        let emitted_len = u32::try_from(frame_bytes.len()).map_err(|_| {
            CrafterError::invalid_field_value("ip.defrag.output_len", "packet length exceeds u32")
        })?;

        Ok((packet, emitted_len, total_len))
    }
}

impl Ipv4FragmentWrapper {
    fn wrap_l3(&self, l3_bytes: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.prefix().len() + l3_bytes.len());
        bytes.extend_from_slice(self.prefix());
        bytes.extend_from_slice(l3_bytes);
        bytes
    }

    fn decode_packet(&self, bytes: &[u8]) -> Result<Packet> {
        let registry = ipv4_defrag_registry();
        match self.kind() {
            Ipv4FragmentWrapperKind::L3 => Ok(Packet::decode_from_l3_with_registry(
                &registry,
                NetworkLayer::Ipv4,
                bytes,
            )?),
            Ipv4FragmentWrapperKind::Ethernet | Ipv4FragmentWrapperKind::EthernetVlan { .. } => Ok(
                Packet::decode_from_link_with_registry(&registry, LinkType::Ethernet, bytes)?,
            ),
            Ipv4FragmentWrapperKind::LinuxSll => Ok(Packet::decode_from_link_with_registry(
                &registry,
                LinkType::LinuxSll,
                bytes,
            )?),
            Ipv4FragmentWrapperKind::NullLoopback => Ok(Packet::decode_from_link_with_registry(
                &registry,
                LinkType::NullLoopback,
                bytes,
            )?),
        }
    }
}

fn ipv4_defrag_registry() -> ProtocolRegistry {
    let mut registry = ProtocolRegistry::empty();
    registry.bind_ethertype_with_registry(ETHERTYPE_IPV4, |registry, packet, payload| {
        append_ipv4_packet_with_registry(registry, packet, payload)
    });
    registry.bind_ethertype_with_registry(ETHERTYPE_VLAN, |registry, packet, payload| {
        append_vlan_packet_with_registry(registry, packet, payload)
    });
    registry
}

fn ipv4_layer_from_header(header: &[u8]) -> Result<Ipv4> {
    if header.len() < IPV4_MIN_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ipv4 header",
            IPV4_MIN_HEADER_LEN,
            header.len(),
        )
        .into());
    }

    let options = if header.len() > IPV4_MIN_HEADER_LEN {
        header[IPV4_MIN_HEADER_LEN..].to_vec()
    } else {
        Vec::new()
    };

    Ok(Ipv4::new()
        .version(header[0] >> 4)
        .ihl(header[0] & 0x0f)
        .tos(header[1])
        .identification(u16::from_be_bytes([header[4], header[5]]))
        .flags(0)
        .fragment_offset(0)
        .ttl(header[8])
        .protocol(header[9])
        .src(Ipv4Addr::new(
            header[12], header[13], header[14], header[15],
        ))
        .dst(Ipv4Addr::new(
            header[16], header[17], header[18], header[19],
        ))
        .options(options))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv4DefragInputMetadata {
    metadata: PacketMetadata,
}

impl Ipv4DefragInputMetadata {
    fn from_record(record: &PacketRecord) -> Self {
        Self {
            metadata: record.metadata().clone().clear_captured_bytes(),
        }
    }
}

#[cfg(test)]
mod ipv4_reassembles {
    use super::*;
    use crate::pcap::PcapTimestamp;
    use crate::wire::ip::{IpDefragOverlapStatus, IpFragmentFamily, IpFragmentRange};
    use crate::wire::record::{BackendKind, PacketOrigin, PacketRecord};
    use crate::{Ipv4, Ipv4ChecksumStatus, Raw};

    const PROTOCOL_UDP: u8 = 17;
    const IDENTIFICATION: u16 = 0x4567;

    fn source() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn other_source() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 9)
    }

    fn destination() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 2)
    }

    fn fragment_record(
        source: Ipv4Addr,
        fragment_offset: u16,
        more_fragments: bool,
        payload: &[u8],
        timestamp: PcapTimestamp,
        interface: &str,
    ) -> PacketRecord {
        let packet = Ipv4::new()
            .src(source)
            .dst(destination())
            .protocol(PROTOCOL_UDP)
            .identification(IDENTIFICATION)
            .more_fragments(more_fragments)
            .fragment_offset(fragment_offset)
            / Raw::from_bytes(payload);

        PacketRecord::new(packet)
            .with_timestamp(timestamp)
            .with_backend(BackendKind::PcapFile)
            .with_interface(interface)
    }

    fn key_for(source: Ipv4Addr) -> Ipv4DefragKey {
        Ipv4DefragKey::new(source, destination(), PROTOCOL_UDP, IDENTIFICATION)
    }

    #[test]
    fn ipv4_reassembles_complete_out_of_order_fragments() {
        let first_seen_timestamp = PcapTimestamp::micros(10, 200).unwrap();
        let first_fragment_timestamp = PcapTimestamp::micros(10, 100).unwrap();
        let mut transform = IpDefrag::new();

        let final_output = transform
            .defrag_record(fragment_record(
                source(),
                1,
                false,
                b"ijkl",
                first_seen_timestamp,
                "wan0",
            ))
            .unwrap();
        let first_output = transform
            .defrag_record(fragment_record(
                source(),
                0,
                true,
                b"abcdefgh",
                first_fragment_timestamp,
                "wan1",
            ))
            .unwrap();

        assert_eq!(final_output.len(), 0);
        assert_eq!(first_output.len(), 1);
        assert_eq!(transform.input_count(), 2);
        assert_eq!(transform.emitted_count(), 1);
        assert!(!transform.ipv4_datagrams.contains_key(&key_for(source())));

        let record = &first_output.records()[0];
        let ipv4 = record.packet().layer::<Ipv4>().unwrap();
        let raw = record.packet().layer::<Raw>().unwrap();
        assert_eq!(ipv4.source(), source());
        assert_eq!(ipv4.destination(), destination());
        assert_eq!(ipv4.protocol_value(), PROTOCOL_UDP);
        assert_eq!(ipv4.identification_value(), IDENTIFICATION);
        assert_eq!(ipv4.flags_value(), 0);
        assert_eq!(ipv4.fragment_offset_value(), 0);
        assert!(!ipv4.is_fragmented());
        assert_eq!(ipv4.total_length_value(), Some(32));
        assert_eq!(ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
        assert_eq!(raw.as_bytes(), b"abcdefghijkl");

        let compiled = record.packet().compile().unwrap();
        assert_eq!(
            u16::from_be_bytes([compiled.as_bytes()[2], compiled.as_bytes()[3]]),
            32
        );
        assert_eq!(
            u16::from_be_bytes([compiled.as_bytes()[6], compiled.as_bytes()[7]]),
            0
        );

        assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
        assert_eq!(record.metadata().backend(), &BackendKind::PcapFile);
        assert_eq!(record.metadata().interface(), Some("wan1"));
        assert_eq!(
            record.metadata().timestamp(),
            Some(first_fragment_timestamp)
        );
        assert_eq!(record.metadata().original_len(), Some(32));
        assert_eq!(record.metadata().captured_len(), Some(32));
        assert_eq!(record.metadata().emitted_len(), Some(32));

        let metadata = &record.metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
        assert_eq!(metadata.identification(), IDENTIFICATION as u32);
        assert_eq!(
            metadata.datagram_key(),
            Some("192.0.2.1>198.51.100.2 proto=17 id=0x4567")
        );
        assert_eq!(metadata.fragment_count(), 2);
        assert_eq!(metadata.duplicate_count(), 0);
        assert_eq!(metadata.overlap_status(), IpDefragOverlapStatus::None);
        assert_eq!(
            metadata.byte_ranges(),
            &[IpFragmentRange::new(0, 8), IpFragmentRange::new(8, 12)]
        );
        assert_eq!(metadata.total_len(), Some(32));

        let trace = &record.metadata().transforms()[0];
        assert_eq!(trace.name(), "ip-defrag");
        assert_eq!(trace.note(), Some("reassembled"));
        assert_eq!(trace.output_len(), Some(32));
    }

    #[test]
    fn ipv4_datagram_state_keys_fragment_identity() {
        let timestamp = PcapTimestamp::micros(11, 0).unwrap();
        let mut transform = IpDefrag::new();

        transform
            .defrag_record(fragment_record(
                source(),
                0,
                true,
                b"abcdefgh",
                timestamp,
                "wan0",
            ))
            .unwrap();
        transform
            .defrag_record(fragment_record(
                other_source(),
                0,
                true,
                b"abcdefgh",
                timestamp,
                "wan0",
            ))
            .unwrap();

        assert_eq!(transform.ipv4_datagrams.len(), 2);
        assert!(transform.ipv4_datagrams.contains_key(&key_for(source())));
        assert!(transform
            .ipv4_datagrams
            .contains_key(&key_for(other_source())));
    }

    #[test]
    fn ipv4_datagram_state_tracks_duplicates_and_conflicts() {
        let timestamp = PcapTimestamp::micros(12, 0).unwrap();
        let first = fragment_record(source(), 0, true, b"abcdefgh", timestamp, "wan0");
        let duplicate = fragment_record(source(), 0, true, b"abcdefgh", timestamp, "wan0");
        let conflict = fragment_record(source(), 0, true, b"abcdWXYZ", timestamp, "wan0");
        let mut state = Ipv4DatagramState::new(key_for(source()), &first);

        for record in [&first, &duplicate, &conflict] {
            let Ipv4FragmentExtract::View(view) = extract_ipv4_fragment(record).unwrap() else {
                panic!("expected IPv4 fragment view");
            };
            state.observe_fragment(record, &view);
        }

        assert_eq!(state.fragment_count, 1);
        assert_eq!(state.duplicate_count, 1);
        assert_eq!(state.conflict_count, 1);
        assert!(state.first_conflict.is_some());
        assert!(state.ranges.has_conflict());
    }
}

#[cfg(test)]
mod ipv4_overlap {
    use super::*;
    use crate::wire::ip::{
        IpDefragOverlapPolicy, IpDefragOverlapStatus, IpFragmentFamily, IpFragmentRange,
    };
    use crate::wire::record::{BackendKind, PacketRecord};
    use crate::wire::WireError;
    use crate::Raw;

    const PROTOCOL_UDP: u8 = 17;
    const IDENTIFICATION: u16 = 0x789a;

    fn source() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn destination() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn fragment_record(fragment_offset: u16, more_fragments: bool, payload: &[u8]) -> PacketRecord {
        let packet = Ipv4::new()
            .src(source())
            .dst(destination())
            .protocol(PROTOCOL_UDP)
            .identification(IDENTIFICATION)
            .more_fragments(more_fragments)
            .fragment_offset(fragment_offset)
            / Raw::from_bytes(payload);

        PacketRecord::new(packet).with_backend(BackendKind::PcapFile)
    }

    fn key() -> Ipv4DefragKey {
        Ipv4DefragKey::new(source(), destination(), PROTOCOL_UDP, IDENTIFICATION)
    }

    fn start_conflict_sequence(transform: &mut IpDefrag) -> PacketRecord {
        let first = fragment_record(0, true, b"abcdefghijklmnop");
        let conflicting = fragment_record(1, false, b"QRSTUVWX");

        let output = transform.defrag_record(first).unwrap();
        assert!(output.is_empty());

        conflicting
    }

    #[test]
    fn exact_duplicate_fragments_reassemble_and_record_duplicate_count() {
        let mut transform = IpDefrag::new();

        assert!(transform
            .defrag_record(fragment_record(0, true, b"abcdefgh"))
            .unwrap()
            .is_empty());
        assert!(transform
            .defrag_record(fragment_record(0, true, b"abcdefgh"))
            .unwrap()
            .is_empty());
        let output = transform
            .defrag_record(fragment_record(1, false, b"ijkl"))
            .unwrap();

        assert_eq!(output.len(), 1);
        assert!(!transform.ipv4_datagrams.contains_key(&key()));

        let record = &output.records()[0];
        let raw = record.packet().layer::<Raw>().unwrap();
        assert_eq!(raw.as_bytes(), b"abcdefghijkl");

        let metadata = &record.metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
        assert_eq!(metadata.fragment_count(), 2);
        assert_eq!(metadata.duplicate_count(), 1);
        assert_eq!(metadata.overlap_status(), IpDefragOverlapStatus::None);
        assert_eq!(
            metadata.byte_ranges(),
            &[IpFragmentRange::new(0, 8), IpFragmentRange::new(8, 12)]
        );
        assert_eq!(metadata.total_len(), Some(32));
    }

    #[test]
    fn default_rejects_conflicting_overlaps_as_ambiguous() {
        let mut transform = IpDefrag::new();
        let conflicting = start_conflict_sequence(&mut transform);

        let error = transform.defrag_record(conflicting).unwrap_err();

        match error {
            WireError::Packet(CrafterError::InvalidFieldValue { field, reason }) => {
                assert_eq!(field, "ip.defrag.ipv4.overlap");
                assert!(reason.contains("ambiguous"));
            }
            other => panic!("expected structured ambiguous overlap error, got {other:?}"),
        }
        assert!(!transform.ipv4_datagrams.contains_key(&key()));
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn drop_policy_discards_ambiguous_ipv4_datagram() {
        let config = IpDefragConfig::new().overlap_policy(IpDefragOverlapPolicy::DropConflicting);
        let mut transform = IpDefrag::new().with_config(config);
        let conflicting = start_conflict_sequence(&mut transform);

        let output = transform.defrag_record(conflicting).unwrap();

        assert!(output.is_empty());
        assert!(!transform.ipv4_datagrams.contains_key(&key()));
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn pass_through_policy_emits_conflicting_fragment_with_trace_metadata() {
        let config =
            IpDefragConfig::new().overlap_policy(IpDefragOverlapPolicy::PassThroughConflicting);
        let mut transform = IpDefrag::new().with_config(config);
        let conflicting = start_conflict_sequence(&mut transform);

        let output = transform.defrag_record(conflicting).unwrap();

        assert_eq!(output.len(), 1);
        assert!(!transform.ipv4_datagrams.contains_key(&key()));
        assert_eq!(transform.emitted_count(), 1);

        let record = &output.records()[0];
        let metadata = &record.metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
        assert_eq!(metadata.duplicate_count(), 0);
        assert_eq!(
            metadata.overlap_status(),
            IpDefragOverlapStatus::Conflicting
        );
        assert_eq!(
            metadata.eviction_reason(),
            Some(&IpDefragEvictionReason::Conflict)
        );
        assert_eq!(metadata.byte_ranges(), &[IpFragmentRange::new(0, 16)]);
        assert_eq!(metadata.total_len(), Some(36));

        let trace = &record.metadata().transforms()[0];
        assert_eq!(trace.name(), "ip-defrag");
        let note = trace.note().unwrap();
        assert!(note.contains("ambiguous"));
        assert!(note.contains("ByteMismatch"));
        assert!(note.contains("offset=8"));
    }
}
