//! Receive-side IP defragmentation transform.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::ipv4::{
    extract_ipv4_fragment, Ipv4FragmentExtract, Ipv4FragmentView, Ipv4FragmentWrapper,
};
use super::range::{RangeMap, RangeMapConflict, RangeMapInsert};
use super::IpDefragConfig;
use crate::pcap::PcapTimestamp;
use crate::wire::record::{PacketMetadata, PacketRecord, TransformTrace};
use crate::wire::transform::{PacketTransform, TransformOutput};
use crate::wire::Result;

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

    fn observe_ipv4_fragment(&mut self, record: &PacketRecord, view: &Ipv4FragmentView) {
        let key = Ipv4DefragKey::from_view(view);
        self.ipv4_datagrams
            .entry(key.clone())
            .or_insert_with(|| Ipv4DatagramState::new(key, record))
            .observe_fragment(record, view);
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
                self.observe_ipv4_fragment(&record, &view);
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

    #[cfg(test)]
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

    #[cfg(test)]
    fn is_complete(&self) -> bool {
        self.first_fragment.is_some() && self.ranges.is_complete()
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
mod tests {
    use super::*;
    use crate::pcap::PcapTimestamp;
    use crate::wire::record::{BackendKind, PacketRecord};
    use crate::{Ipv4, Raw};

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
    fn ipv4_datagram_state_tracks_out_of_order_fragments() {
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
        assert_eq!(first_output.len(), 0);
        assert_eq!(transform.input_count(), 2);
        assert_eq!(transform.emitted_count(), 0);

        let state = transform.ipv4_datagrams.get(&key_for(source())).unwrap();
        assert_eq!(
            state.key.summary(),
            "192.0.2.1>198.51.100.2 proto=17 id=0x4567"
        );
        assert_eq!(state.total_expected, Some(12));
        assert_eq!(state.fragment_count, 2);
        assert_eq!(state.duplicate_count, 0);
        assert_eq!(state.conflict_count, 0);
        assert_eq!(state.first_timestamp, Some(first_seen_timestamp));
        assert_eq!(state.last_timestamp, Some(first_fragment_timestamp));
        assert_eq!(
            state.ranges.contiguous_payload(),
            Some(b"abcdefghijkl".to_vec())
        );
        assert!(state.is_complete());

        let first_fragment = state.first_fragment.as_ref().unwrap();
        assert_eq!(first_fragment.header.len(), 20);
        assert_eq!(first_fragment.header[4..6], IDENTIFICATION.to_be_bytes());
        assert_eq!(
            first_fragment.input_metadata.metadata.interface(),
            Some("wan1")
        );
        assert_eq!(state.input_metadata.metadata.interface(), Some("wan0"));
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
                source(),
                0,
                true,
                b"abcdWXYZ",
                timestamp,
                "wan0",
            ))
            .unwrap();

        let state = transform.ipv4_datagrams.get(&key_for(source())).unwrap();
        assert_eq!(state.fragment_count, 1);
        assert_eq!(state.duplicate_count, 1);
        assert_eq!(state.conflict_count, 1);
        assert!(state.first_conflict.is_some());
        assert!(state.ranges.has_conflict());
    }
}
