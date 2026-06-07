//! Receive-side IP defragmentation transform.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

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
    eviction_count: usize,
    timeout_eviction_count: usize,
    datagram_limit_eviction_count: usize,
    byte_limit_eviction_count: usize,
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

    /// Number of incomplete datagram states evicted before reassembly.
    pub const fn eviction_count(&self) -> usize {
        self.eviction_count
    }

    /// Number of datagrams evicted because they exceeded `max_age`.
    pub const fn timeout_eviction_count(&self) -> usize {
        self.timeout_eviction_count
    }

    /// Number of datagrams evicted because `max_datagrams` was exceeded.
    pub const fn datagram_limit_eviction_count(&self) -> usize {
        self.datagram_limit_eviction_count
    }

    /// Number of datagrams evicted because `max_bytes_per_datagram` was exceeded.
    pub const fn byte_limit_eviction_count(&self) -> usize {
        self.byte_limit_eviction_count
    }

    /// Run the transform and collect emitted records into a small buffer.
    pub fn defrag_record(&mut self, record: PacketRecord) -> Result<TransformOutput> {
        self.transform_to_output(record)
    }

    fn evict_ipv4_expired(
        &mut self,
        timestamp: Option<PcapTimestamp>,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        let Some(timestamp) = timestamp else {
            return Ok(());
        };

        let max_age = self.config.max_age_limit();
        let keys = self
            .ipv4_datagrams
            .iter()
            .filter_map(|(key, state)| {
                state
                    .exceeds_max_age(timestamp, max_age)
                    .then(|| key.clone())
            })
            .collect::<Vec<_>>();

        for key in keys {
            let state = self
                .ipv4_datagrams
                .remove(&key)
                .expect("expired IPv4 defrag state must remain in the map");
            self.evict_ipv4_state(state, IpDefragEvictionReason::Timeout, emit)?;
        }

        Ok(())
    }

    fn observe_ipv4_fragment(
        &mut self,
        record: &PacketRecord,
        view: &Ipv4FragmentView,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Ipv4DefragObservation {
        let key = Ipv4DefragKey::from_view(view);
        let outcome = {
            let input_order = self.input_count;
            let trace_evictions = self.config.traces_evictions();
            let state = self.ipv4_datagrams.entry(key.clone()).or_insert_with(|| {
                Ipv4DatagramState::new(key.clone(), record, input_order, trace_evictions)
            });
            state.observe_fragment(record, view, input_order, trace_evictions);
            if state.has_conflict() {
                Ipv4DefragObservationKind::Conflict
            } else if state.exceeds_max_bytes(self.config.max_bytes_per_datagram_limit()) {
                Ipv4DefragObservationKind::ByteLimit
            } else if state.is_complete() {
                Ipv4DefragObservationKind::Complete
            } else {
                Ipv4DefragObservationKind::Buffered
            }
        };

        match outcome {
            Ipv4DefragObservationKind::Buffered => {
                if let Err(error) = self.evict_ipv4_to_datagram_limit(emit) {
                    return Ipv4DefragObservation::Error(error);
                }
                Ipv4DefragObservation::Buffered
            }
            Ipv4DefragObservationKind::ByteLimit => {
                let state = self
                    .ipv4_datagrams
                    .remove(&key)
                    .expect("byte-limited IPv4 defrag state must remain in the map");
                if let Err(error) =
                    self.evict_ipv4_state(state, IpDefragEvictionReason::ByteLimit, emit)
                {
                    return Ipv4DefragObservation::Error(error);
                }
                Ipv4DefragObservation::Evicted
            }
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

    fn evict_ipv4_to_datagram_limit(
        &mut self,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        let max_datagrams = self.config.max_datagrams_limit();
        while self.ipv4_datagrams.len() > max_datagrams {
            let key = self
                .ipv4_datagrams
                .iter()
                .min_by(|(left_key, left), (right_key, right)| {
                    left.eviction_order()
                        .cmp(&right.eviction_order())
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(key, _)| key.clone())
                .expect("IPv4 defrag state must be non-empty when over datagram limit");
            let state = self
                .ipv4_datagrams
                .remove(&key)
                .expect("datagram-limited IPv4 defrag state must remain in the map");
            self.evict_ipv4_state(state, IpDefragEvictionReason::DatagramLimit, emit)?;
        }

        Ok(())
    }

    fn evict_ipv4_state(
        &mut self,
        state: Ipv4DatagramState,
        reason: IpDefragEvictionReason,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.record_eviction(&reason);
        if self.config.traces_evictions() {
            if let Some(record) = state.eviction_record(reason, self.name()) {
                emit(record)?;
                self.emitted_count += 1;
            }
        }
        Ok(())
    }

    fn record_eviction(&mut self, reason: &IpDefragEvictionReason) {
        self.eviction_count += 1;
        match reason {
            IpDefragEvictionReason::Timeout => self.timeout_eviction_count += 1,
            IpDefragEvictionReason::DatagramLimit => self.datagram_limit_eviction_count += 1,
            IpDefragEvictionReason::ByteLimit => self.byte_limit_eviction_count += 1,
            IpDefragEvictionReason::Conflict | IpDefragEvictionReason::Other(_) => {}
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

        self.evict_ipv4_expired(record.metadata().timestamp(), emit)?;

        if let Ipv4FragmentExtract::View(view) = extract_ipv4_fragment(&record)? {
            if view.is_fragmented() {
                match self.observe_ipv4_fragment(&record, &view, emit) {
                    Ipv4DefragObservation::Buffered => {}
                    Ipv4DefragObservation::Evicted => {}
                    Ipv4DefragObservation::Complete(state) => {
                        emit(state.reassembled_record(self.name())?)?;
                        self.emitted_count += 1;
                    }
                    Ipv4DefragObservation::Conflict(state) => {
                        self.handle_ipv4_conflict(record, state, emit)?;
                    }
                    Ipv4DefragObservation::Error(error) => return Err(error),
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
    ByteLimit,
}

#[derive(Debug)]
enum Ipv4DefragObservation {
    Buffered,
    Evicted,
    Complete(Ipv4DatagramState),
    Conflict(Ipv4DatagramState),
    Error(crate::wire::WireError),
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

#[derive(Debug, Clone)]
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
    first_seen_order: usize,
    last_seen_order: usize,
    trace_record: Option<PacketRecord>,
}

impl Ipv4DatagramState {
    fn new(
        key: Ipv4DefragKey,
        record: &PacketRecord,
        input_order: usize,
        keep_trace_record: bool,
    ) -> Self {
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
            first_seen_order: input_order,
            last_seen_order: input_order,
            trace_record: keep_trace_record.then(|| trace_record_snapshot(record)),
        }
    }

    fn observe_fragment(
        &mut self,
        record: &PacketRecord,
        view: &Ipv4FragmentView,
        input_order: usize,
        keep_trace_record: bool,
    ) {
        self.last_seen_order = input_order;
        if self.trace_record.is_none() && keep_trace_record {
            self.trace_record = Some(trace_record_snapshot(record));
        }
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

    fn byte_len(&self) -> usize {
        self.ranges.byte_len()
    }

    fn exceeds_max_bytes(&self, max_bytes: usize) -> bool {
        self.byte_len() > max_bytes
    }

    fn exceeds_max_age(&self, now: PcapTimestamp, max_age: Duration) -> bool {
        let Some(first_timestamp) = self.first_timestamp else {
            return false;
        };
        now.as_duration()
            .checked_sub(first_timestamp.as_duration())
            .is_some_and(|age| age > max_age)
    }

    fn eviction_order(&self) -> (usize, usize) {
        (self.first_seen_order, self.last_seen_order)
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

    fn eviction_record(
        &self,
        eviction_reason: IpDefragEvictionReason,
        transform_name: &'static str,
    ) -> Option<PacketRecord> {
        let mut record = self.trace_record.clone()?;
        record
            .metadata_mut()
            .push_ip_defrag_metadata(self.eviction_metadata(eviction_reason.clone()));
        record.metadata_mut().push_transform_trace(
            TransformTrace::new(transform_name)
                .with_note(self.eviction_trace_note(&eviction_reason)),
        );
        Some(record)
    }

    fn eviction_trace_note(&self, eviction_reason: &IpDefragEvictionReason) -> String {
        let reason = match eviction_reason {
            IpDefragEvictionReason::Timeout => "max_age",
            IpDefragEvictionReason::DatagramLimit => "max_datagrams",
            IpDefragEvictionReason::ByteLimit => "max_bytes",
            IpDefragEvictionReason::Conflict => "conflict",
            IpDefragEvictionReason::Other(reason) => reason.as_str(),
        };
        format!(
            "evicted incomplete IPv4 defrag state: reason={reason} key={} fragments={} bytes={}",
            self.key.summary(),
            self.fragment_count,
            self.byte_len()
        )
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

fn trace_record_snapshot(record: &PacketRecord) -> PacketRecord {
    PacketRecord::from_packet_metadata(
        record.packet().clone(),
        record.metadata().clone().clear_captured_bytes(),
    )
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
        let mut state = Ipv4DatagramState::new(key_for(source()), &first, 1, false);

        for record in [&first, &duplicate, &conflict] {
            let Ipv4FragmentExtract::View(view) = extract_ipv4_fragment(record).unwrap() else {
                panic!("expected IPv4 fragment view");
            };
            state.observe_fragment(record, &view, 1, false);
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

#[cfg(test)]
mod ipv4_limits {
    use super::*;
    use std::time::Duration;

    use crate::wire::ip::{IpFragmentFamily, IpFragmentRange};
    use crate::wire::record::{BackendKind, PacketRecord};
    use crate::Raw;

    const PROTOCOL_UDP: u8 = 17;
    const IDENTIFICATION: u16 = 0x3456;

    fn source_one() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 40)
    }

    fn source_two() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 41)
    }

    fn destination() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 40)
    }

    fn fragment_record(
        source: Ipv4Addr,
        fragment_offset: u16,
        more_fragments: bool,
        payload: &[u8],
        seconds: u64,
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
            .with_timestamp(PcapTimestamp::micros(seconds, 0).unwrap())
            .with_backend(BackendKind::PcapFile)
    }

    fn key_for(source: Ipv4Addr) -> Ipv4DefragKey {
        Ipv4DefragKey::new(source, destination(), PROTOCOL_UDP, IDENTIFICATION)
    }

    #[test]
    fn max_bytes_evicts_without_emitting_incomplete_datagram() {
        let config = IpDefragConfig::new().max_bytes_per_datagram(8);
        let mut transform = IpDefrag::new().with_config(config);

        let first = transform
            .defrag_record(fragment_record(source_one(), 0, true, b"abcdefgh", 1))
            .unwrap();
        let second = transform
            .defrag_record(fragment_record(source_one(), 1, false, b"ijkl", 2))
            .unwrap();

        assert!(first.is_empty());
        assert!(second.is_empty());
        assert!(!transform
            .ipv4_datagrams
            .contains_key(&key_for(source_one())));
        assert_eq!(transform.eviction_count(), 1);
        assert_eq!(transform.byte_limit_eviction_count(), 1);
        assert_eq!(transform.datagram_limit_eviction_count(), 0);
        assert_eq!(transform.timeout_eviction_count(), 0);
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn max_datagrams_evicts_oldest_state_deterministically() {
        let config = IpDefragConfig::new().max_datagrams(1);
        let mut transform = IpDefrag::new().with_config(config);

        let first = transform
            .defrag_record(fragment_record(source_one(), 0, true, b"abcdefgh", 1))
            .unwrap();
        let second = transform
            .defrag_record(fragment_record(source_two(), 0, true, b"abcdefgh", 1))
            .unwrap();

        assert!(first.is_empty());
        assert!(second.is_empty());
        assert!(!transform
            .ipv4_datagrams
            .contains_key(&key_for(source_one())));
        assert!(transform
            .ipv4_datagrams
            .contains_key(&key_for(source_two())));
        assert_eq!(transform.eviction_count(), 1);
        assert_eq!(transform.datagram_limit_eviction_count(), 1);

        let late_final = transform
            .defrag_record(fragment_record(source_one(), 1, false, b"ijkl", 2))
            .unwrap();

        assert!(late_final.is_empty());
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn max_age_evicts_expired_state_before_later_fragments() {
        let config = IpDefragConfig::new().max_age(Duration::from_secs(1));
        let mut transform = IpDefrag::new().with_config(config);

        let first = transform
            .defrag_record(fragment_record(source_one(), 0, true, b"abcdefgh", 1))
            .unwrap();
        let late_final = transform
            .defrag_record(fragment_record(source_one(), 1, false, b"ijkl", 3))
            .unwrap();

        assert!(first.is_empty());
        assert!(late_final.is_empty());
        assert_eq!(transform.eviction_count(), 1);
        assert_eq!(transform.timeout_eviction_count(), 1);
        assert_eq!(transform.emitted_count(), 0);

        let state = transform
            .ipv4_datagrams
            .get(&key_for(source_one()))
            .expect("late final fragment should start new incomplete state");
        assert_eq!(state.fragment_count, 1);
        assert!(state.first_fragment.is_none());
        assert_eq!(
            state.ranges.ranges(),
            vec![super::super::range::RangeMapRange::new(8, 12)]
        );
    }

    #[test]
    fn trace_evictions_emits_representative_record_with_eviction_metadata() {
        let config = IpDefragConfig::new()
            .max_bytes_per_datagram(8)
            .trace_evictions(true);
        let mut transform = IpDefrag::new().with_config(config);

        let first = transform
            .defrag_record(fragment_record(source_one(), 0, true, b"abcdefgh", 1))
            .unwrap();
        let second = transform
            .defrag_record(fragment_record(source_one(), 1, false, b"ijkl", 2))
            .unwrap();

        assert!(first.is_empty());
        assert_eq!(second.len(), 1);
        assert_eq!(transform.eviction_count(), 1);
        assert_eq!(transform.byte_limit_eviction_count(), 1);
        assert_eq!(transform.emitted_count(), 1);

        let record = &second.records()[0];
        let ipv4 = record.packet().layer::<Ipv4>().unwrap();
        assert!(ipv4.is_fragmented());

        let metadata = &record.metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
        assert_eq!(metadata.identification(), IDENTIFICATION as u32);
        assert_eq!(metadata.fragment_count(), 2);
        assert_eq!(
            metadata.eviction_reason(),
            Some(&IpDefragEvictionReason::ByteLimit)
        );
        assert_eq!(
            metadata.byte_ranges(),
            &[IpFragmentRange::new(0, 8), IpFragmentRange::new(8, 12)]
        );

        let trace = &record.metadata().transforms()[0];
        assert_eq!(trace.name(), "ip-defrag");
        let note = trace.note().unwrap();
        assert!(note.contains("max_bytes"));
        assert!(note.contains("evicted incomplete IPv4 defrag state"));
    }
}
