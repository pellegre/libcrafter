//! Receive-side IP defragmentation transform.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::ipv4::{
    extract_ipv4_fragment, Ipv4FragmentExtract, Ipv4FragmentView, Ipv4FragmentWrapper,
    Ipv4FragmentWrapperKind,
};
use super::ipv6::{
    extract_ipv6_fragment, Ipv6FragmentExtensionContext, Ipv6FragmentExtract, Ipv6FragmentView,
    Ipv6FragmentWrapper,
};
use super::range::{RangeMap, RangeMapConflict, RangeMapInsert};
use super::{
    IpDefragConfig, IpDefragEvictionReason, IpDefragMetadata, IpDefragOverlapPolicy,
    IpFragmentFamily, IpFragmentRange, Ipv6AtomicFragmentPolicy,
};
use crate::protocols::ipv4::append_ipv4_packet_with_registry;
use crate::protocols::ipv6::append_ipv6_packet_with_registry;
use crate::protocols::link::{
    append_vlan_packet_with_registry, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN,
};
use crate::registry::ProtocolRegistry;
use crate::wire::backend::pcap::PcapTimestamp;
use crate::wire::record::{PacketMetadata, PacketOrigin, PacketRecord, TransformTrace};
use crate::wire::transform::{PacketTransform, TransformOutput};
use crate::wire::{Result, WireError};
use crate::{CrafterError, Ipv4, Ipv6FragmentHeaderStatus, LinkType, NetworkLayer, Packet, Raw};

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_ATOMIC_FRAGMENT_NORMALIZED_NOTE: &str = "atomic fragment normalized";
const IPV6_ATOMIC_FRAGMENT_PASSTHROUGH_NOTE: &str = "atomic fragment pass-through";

fn defrag_transform_error(reason: &'static str) -> WireError {
    WireError::transform("ip-defrag", reason)
}

/// Receive-side IP defragmentation transform.
///
/// `IpDefrag` is a [`PacketTransform`] for inbound packet streams. It buffers
/// IPv4 fragments and supported IPv6 Fragment Header records until a datagram
/// is complete, then emits one packet-shaped [`PacketRecord`] with
/// [`IpDefragMetadata`] attached. Non-fragmented records pass through by
/// default.
///
/// Use it directly on offline records when testing transform behavior:
///
/// ```
/// use std::net::Ipv4Addr;
///
/// use crafter::prelude::*;
///
/// let packet = (Ipv4::with_addresses(
///     Ipv4Addr::new(192, 0, 2, 1),
///     Ipv4Addr::new(198, 51, 100, 1),
/// )
/// .protocol(17)
///     / Raw::from_bytes(b"not fragmented"));
/// let source = VecPacketSource::from_packets([packet]);
///
/// let records = Sniffer::new(source)
///     .with(IpDefrag::new().trace_passthrough(true))
///     .collect_records()
///     .unwrap();
///
/// assert_eq!(records.len(), 1);
/// assert_eq!(records[0].metadata().transforms()[0].name(), "ip-defrag");
/// ```
///
/// Reassembled records expose defragmentation metadata through
/// [`PacketMetadata::ip_defrag_metadata`]:
///
/// ```
/// use std::net::Ipv4Addr;
///
/// use crafter::prelude::*;
///
/// let src = Ipv4Addr::new(192, 0, 2, 10);
/// let dst = Ipv4Addr::new(198, 51, 100, 20);
/// let first = PacketRecord::new(
///     Ipv4::with_addresses(src, dst)
///         .protocol(17)
///         .identification(0x1234)
///         .more_fragments(true)
///         .fragment_offset(0)
///         / Raw::from_bytes(b"abcdefgh"),
/// );
/// let final_fragment = PacketRecord::new(
///     Ipv4::with_addresses(src, dst)
///         .protocol(17)
///         .identification(0x1234)
///         .fragment_offset(1)
///         / Raw::from_bytes(b"ijkl"),
/// );
/// let source = VecPacketSource::new([final_fragment, first]);
///
/// let records = Sniffer::new(source)
///     .with(IpDefrag::new())
///     .collect_records()
///     .unwrap();
///
/// let metadata = &records[0].metadata().ip_defrag_metadata()[0];
/// assert_eq!(metadata.fragment_count(), 2);
/// assert_eq!(metadata.duplicate_count(), 0);
/// ```
#[derive(Clone, Default)]
pub struct IpDefrag {
    config: IpDefragConfig,
    ipv4_datagrams: BTreeMap<Ipv4DefragKey, Ipv4DatagramState>,
    ipv6_datagrams: BTreeMap<Ipv6DefragKey, Ipv6DatagramState>,
    input_count: usize,
    emitted_count: usize,
    pass_through_count: usize,
    fragments_observed: usize,
    completed_datagram_count: usize,
    eviction_count: usize,
    timeout_eviction_count: usize,
    datagram_limit_eviction_count: usize,
    byte_limit_eviction_count: usize,
    conflict_count: usize,
    error_count: usize,
}

/// Compact counters for an [`IpDefrag`] transform.
///
/// These counters summarize transform activity without exposing buffered
/// fragment payloads or per-datagram state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpDefragStats {
    input_count: usize,
    emitted_count: usize,
    pass_through_count: usize,
    fragments_observed: usize,
    completed_datagrams: usize,
    evicted_datagrams: usize,
    conflicts: usize,
    errors: usize,
}

impl IpDefragStats {
    /// Number of input records seen.
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Number of records successfully emitted.
    pub const fn emitted_count(&self) -> usize {
        self.emitted_count
    }

    /// Number of records emitted without fragment reassembly.
    pub const fn pass_through_count(&self) -> usize {
        self.pass_through_count
    }

    /// Number of fragment records observed by the transform.
    pub const fn fragments_observed(&self) -> usize {
        self.fragments_observed
    }

    /// Number of fragmented datagrams completed by reassembly or normalization.
    pub const fn completed_datagrams(&self) -> usize {
        self.completed_datagrams
    }

    /// Number of incomplete datagrams evicted before reassembly.
    pub const fn evicted_datagrams(&self) -> usize {
        self.evicted_datagrams
    }

    /// Number of conflicting fragment datagrams observed.
    pub const fn conflicts(&self) -> usize {
        self.conflicts
    }

    /// Number of transform calls that returned an error.
    pub const fn errors(&self) -> usize {
        self.errors
    }
}

impl IpDefrag {
    /// Create an IP defragmentation transform with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an IP defragmentation transform from an explicit configuration.
    pub fn from_config(config: IpDefragConfig) -> Self {
        Self::default().with_config(config)
    }

    /// Create an IP defragmentation transform from a validated configuration.
    pub fn try_from_config(config: IpDefragConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self::from_config(config))
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

    /// Configure whether records that are not handled as fragments pass through.
    pub const fn pass_non_fragments(mut self, pass_non_fragments: bool) -> Self {
        self.config = self.config.pass_non_fragments(pass_non_fragments);
        self
    }

    /// Set the maximum number of incomplete datagrams retained at once.
    pub const fn max_datagrams(mut self, max_datagrams: usize) -> Self {
        self.config = self.config.max_datagrams(max_datagrams);
        self
    }

    /// Set the maximum number of incomplete datagrams retained at once.
    pub fn try_max_datagrams(mut self, max_datagrams: usize) -> Result<Self> {
        self.config = self.config.try_max_datagrams(max_datagrams)?;
        Ok(self)
    }

    /// Set the maximum bytes retained for one incomplete datagram.
    pub const fn max_bytes_per_datagram(mut self, max_bytes_per_datagram: usize) -> Self {
        self.config = self.config.max_bytes_per_datagram(max_bytes_per_datagram);
        self
    }

    /// Set the maximum bytes retained for one incomplete datagram.
    pub fn try_max_bytes_per_datagram(mut self, max_bytes_per_datagram: usize) -> Result<Self> {
        self.config = self
            .config
            .try_max_bytes_per_datagram(max_bytes_per_datagram)?;
        Ok(self)
    }

    /// Set the maximum age for an incomplete datagram.
    pub const fn max_age(mut self, max_age: Duration) -> Self {
        self.config = self.config.max_age(max_age);
        self
    }

    /// Set the maximum age for an incomplete datagram.
    pub fn try_max_age(mut self, max_age: Duration) -> Result<Self> {
        self.config = self.config.try_max_age(max_age)?;
        Ok(self)
    }

    /// Set the conflicting-overlap handling policy.
    pub const fn overlap_policy(mut self, overlap_policy: IpDefragOverlapPolicy) -> Self {
        self.config = self.config.overlap_policy(overlap_policy);
        self
    }

    /// Set the IPv6 atomic fragment handling policy.
    pub const fn ipv6_atomic_fragments(
        mut self,
        ipv6_atomic_fragment_policy: Ipv6AtomicFragmentPolicy,
    ) -> Self {
        self.config = self
            .config
            .ipv6_atomic_fragments(ipv6_atomic_fragment_policy);
        self
    }

    /// Configure whether records emitted unchanged receive transform traces.
    pub const fn trace_passthrough(mut self, trace_passthrough: bool) -> Self {
        self.config = self.config.trace_passthrough(trace_passthrough);
        self
    }

    /// Configure whether evictions emit representative trace records.
    pub const fn trace_evictions(mut self, trace_evictions: bool) -> Self {
        self.config = self.config.trace_evictions(trace_evictions);
        self
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

    /// Number of records emitted without fragment reassembly.
    pub const fn pass_through_count(&self) -> usize {
        self.pass_through_count
    }

    /// Number of fragment records observed by the transform.
    pub const fn fragments_observed(&self) -> usize {
        self.fragments_observed
    }

    /// Number of fragmented datagrams completed by reassembly or normalization.
    pub const fn completed_datagrams(&self) -> usize {
        self.completed_datagram_count
    }

    /// Number of incomplete datagrams evicted before reassembly.
    pub const fn evicted_datagrams(&self) -> usize {
        self.eviction_count
    }

    /// Number of conflicting fragment datagrams observed.
    pub const fn conflicts(&self) -> usize {
        self.conflict_count
    }

    /// Number of transform calls that returned an error.
    pub const fn errors(&self) -> usize {
        self.error_count
    }

    /// Return a compact snapshot of transform counters.
    pub const fn stats(&self) -> IpDefragStats {
        IpDefragStats {
            input_count: self.input_count,
            emitted_count: self.emitted_count,
            pass_through_count: self.pass_through_count,
            fragments_observed: self.fragments_observed,
            completed_datagrams: self.completed_datagram_count,
            evicted_datagrams: self.eviction_count,
            conflicts: self.conflict_count,
            errors: self.error_count,
        }
    }

    /// Number of incomplete IPv4 datagrams currently buffered.
    pub fn pending_ipv4_datagram_count(&self) -> usize {
        self.ipv4_datagrams.len()
    }

    /// Number of incomplete IPv6 datagrams currently buffered.
    pub fn pending_ipv6_datagram_count(&self) -> usize {
        self.ipv6_datagrams.len()
    }

    /// Number of incomplete IPv4 and IPv6 datagrams currently buffered.
    pub fn pending_datagram_count(&self) -> usize {
        self.pending_ipv4_datagram_count() + self.pending_ipv6_datagram_count()
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
            let Some(state) = self.ipv4_datagrams.remove(&key) else {
                return Err(defrag_transform_error(
                    "expired IPv4 defrag state disappeared",
                ));
            };
            self.evict_ipv4_state(state, IpDefragEvictionReason::Timeout, emit)?;
        }

        Ok(())
    }

    fn evict_ipv6_expired(
        &mut self,
        timestamp: Option<PcapTimestamp>,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        let Some(timestamp) = timestamp else {
            return Ok(());
        };

        let max_age = self.config.max_age_limit();
        let keys = self
            .ipv6_datagrams
            .iter()
            .filter_map(|(key, state)| {
                state
                    .exceeds_max_age(timestamp, max_age)
                    .then(|| key.clone())
            })
            .collect::<Vec<_>>();

        for key in keys {
            let Some(state) = self.ipv6_datagrams.remove(&key) else {
                return Err(defrag_transform_error(
                    "expired IPv6 defrag state disappeared",
                ));
            };
            self.evict_ipv6_state(state, IpDefragEvictionReason::Timeout, emit)?;
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
                if let Err(error) = self.evict_to_datagram_limit(emit) {
                    return Ipv4DefragObservation::Error(error);
                }
                Ipv4DefragObservation::Buffered
            }
            Ipv4DefragObservationKind::ByteLimit => {
                let Some(state) = self.ipv4_datagrams.remove(&key) else {
                    return Ipv4DefragObservation::Error(defrag_transform_error(
                        "byte-limited IPv4 defrag state disappeared",
                    ));
                };
                if let Err(error) =
                    self.evict_ipv4_state(state, IpDefragEvictionReason::ByteLimit, emit)
                {
                    return Ipv4DefragObservation::Error(error);
                }
                Ipv4DefragObservation::Evicted
            }
            Ipv4DefragObservationKind::Complete => {
                let Some(state) = self.ipv4_datagrams.remove(&key) else {
                    return Ipv4DefragObservation::Error(defrag_transform_error(
                        "complete IPv4 defrag state disappeared",
                    ));
                };
                Ipv4DefragObservation::Complete(state)
            }
            Ipv4DefragObservationKind::Conflict => {
                let Some(state) = self.ipv4_datagrams.remove(&key) else {
                    return Ipv4DefragObservation::Error(defrag_transform_error(
                        "conflicting IPv4 defrag state disappeared",
                    ));
                };
                Ipv4DefragObservation::Conflict(state)
            }
        }
    }

    fn observe_ipv6_fragment(
        &mut self,
        record: &PacketRecord,
        view: &Ipv6FragmentView,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Ipv6DefragObservation {
        let key = Ipv6DefragKey::from_view(view);
        let outcome = {
            let input_order = self.input_count;
            let trace_evictions = self.config.traces_evictions();
            let state = self.ipv6_datagrams.entry(key.clone()).or_insert_with(|| {
                Ipv6DatagramState::new(key.clone(), record, input_order, trace_evictions)
            });
            state.observe_fragment(record, view, input_order, trace_evictions);
            if state.has_conflict() {
                Ipv6DefragObservationKind::Conflict
            } else if state.exceeds_max_bytes(self.config.max_bytes_per_datagram_limit()) {
                Ipv6DefragObservationKind::ByteLimit
            } else if state.is_complete() {
                Ipv6DefragObservationKind::Complete
            } else {
                Ipv6DefragObservationKind::Buffered
            }
        };

        match outcome {
            Ipv6DefragObservationKind::Buffered => {
                if let Err(error) = self.evict_to_datagram_limit(emit) {
                    return Ipv6DefragObservation::Error(error);
                }
                Ipv6DefragObservation::Buffered
            }
            Ipv6DefragObservationKind::ByteLimit => {
                let state = self
                    .ipv6_datagrams
                    .remove(&key)
                    .expect("byte-limited IPv6 defrag state must remain in the map");
                if let Err(error) =
                    self.evict_ipv6_state(state, IpDefragEvictionReason::ByteLimit, emit)
                {
                    return Ipv6DefragObservation::Error(error);
                }
                Ipv6DefragObservation::Evicted
            }
            Ipv6DefragObservationKind::Complete => {
                let state = self
                    .ipv6_datagrams
                    .remove(&key)
                    .expect("complete IPv6 defrag state must remain in the map");
                Ipv6DefragObservation::Complete(state)
            }
            Ipv6DefragObservationKind::Conflict => {
                let state = self
                    .ipv6_datagrams
                    .remove(&key)
                    .expect("conflicting IPv6 defrag state must remain in the map");
                Ipv6DefragObservation::Conflict(state)
            }
        }
    }

    fn evict_to_datagram_limit(
        &mut self,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        let max_datagrams = self.config.max_datagrams_limit();
        while self.pending_datagram_count() > max_datagrams {
            match self.oldest_datagram_key() {
                Some(DefragDatagramKey::Ipv4(key)) => {
                    let state = self
                        .ipv4_datagrams
                        .remove(&key)
                        .expect("datagram-limited IPv4 defrag state must remain in the map");
                    self.evict_ipv4_state(state, IpDefragEvictionReason::DatagramLimit, emit)?;
                }
                Some(DefragDatagramKey::Ipv6(key)) => {
                    let state = self
                        .ipv6_datagrams
                        .remove(&key)
                        .expect("datagram-limited IPv6 defrag state must remain in the map");
                    self.evict_ipv6_state(state, IpDefragEvictionReason::DatagramLimit, emit)?;
                }
                None => break,
            }
        }

        Ok(())
    }

    fn oldest_datagram_key(&self) -> Option<DefragDatagramKey> {
        let oldest_ipv4 = self
            .ipv4_datagrams
            .iter()
            .min_by(|(left_key, left), (right_key, right)| {
                left.eviction_order()
                    .cmp(&right.eviction_order())
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(key, state)| (state.eviction_order(), DefragDatagramKey::Ipv4(key.clone())));
        let oldest_ipv6 = self
            .ipv6_datagrams
            .iter()
            .min_by(|(left_key, left), (right_key, right)| {
                left.eviction_order()
                    .cmp(&right.eviction_order())
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(key, state)| (state.eviction_order(), DefragDatagramKey::Ipv6(key.clone())));

        match (oldest_ipv4, oldest_ipv6) {
            (Some((ipv4_order, ipv4_key)), Some((ipv6_order, ipv6_key))) => {
                if ipv4_order <= ipv6_order {
                    Some(ipv4_key)
                } else {
                    Some(ipv6_key)
                }
            }
            (Some((_, key)), None) | (None, Some((_, key))) => Some(key),
            (None, None) => None,
        }
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

    fn evict_ipv6_state(
        &mut self,
        state: Ipv6DatagramState,
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

    fn handle_ipv6_conflict(
        &mut self,
        mut record: PacketRecord,
        state: Ipv6DatagramState,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        match self.config.configured_overlap_policy() {
            IpDefragOverlapPolicy::RejectConflicting => Err(CrafterError::invalid_field_value(
                "ip.defrag.ipv6.overlap",
                "conflicting IPv6 fragment overlap is ambiguous",
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

    fn emit_pass_through(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.emit_pass_through_with_note(record, None, emit)
    }

    fn emit_pass_through_with_note(
        &mut self,
        mut record: PacketRecord,
        note: Option<&'static str>,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        if !self.config.emits_non_fragments() {
            return Ok(());
        }

        if let Some(note) =
            note.or_else(|| self.config.traces_passthrough().then_some("passthrough"))
        {
            record
                .metadata_mut()
                .push_transform_trace(TransformTrace::new(self.name()).with_note(note));
        }

        emit(record)?;
        self.emitted_count += 1;
        self.pass_through_count += 1;
        Ok(())
    }

    fn handle_ipv6_atomic_fragment(
        &mut self,
        record: PacketRecord,
        view: &Ipv6FragmentView,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        match self.config.ipv6_atomic_fragment_policy() {
            Ipv6AtomicFragmentPolicy::Normalize => {
                self.emit_normalized_ipv6_atomic_fragment(&record, view, emit)
            }
            Ipv6AtomicFragmentPolicy::PassThrough => {
                self.emit_ipv6_atomic_pass_through(record, emit)
            }
            Ipv6AtomicFragmentPolicy::Drop => Ok(()),
        }
    }

    fn emit_normalized_ipv6_atomic_fragment(
        &mut self,
        record: &PacketRecord,
        view: &Ipv6FragmentView,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        let input_len = ipv6_fragment_record_len(view)?;
        let initial_fragment = Ipv6InitialFragment::from_record(record, view);
        let (packet, emitted_len, total_len) =
            initial_fragment.reassembled_packet(view.fragmentable_payload())?;
        let metadata = record
            .metadata()
            .clone()
            .clear_captured_bytes()
            .with_origin(PacketOrigin::Transformed)
            .with_original_len(input_len)
            .with_captured_len(input_len)
            .with_emitted_len(emitted_len)
            .with_ip_defrag_metadata(ipv6_atomic_fragment_metadata(view, total_len)?)
            .with_transform_trace(
                TransformTrace::new(self.name())
                    .with_note(IPV6_ATOMIC_FRAGMENT_NORMALIZED_NOTE)
                    .with_input_len(input_len)
                    .with_output_len(emitted_len),
            );

        emit(PacketRecord::from_packet_metadata(packet, metadata))?;
        self.emitted_count += 1;
        self.completed_datagram_count += 1;
        Ok(())
    }

    fn emit_ipv6_atomic_pass_through(
        &mut self,
        mut record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        record.metadata_mut().push_transform_trace(
            TransformTrace::new(self.name()).with_note(IPV6_ATOMIC_FRAGMENT_PASSTHROUGH_NOTE),
        );
        emit(record)?;
        self.emitted_count += 1;
        self.pass_through_count += 1;
        Ok(())
    }
}

impl fmt::Debug for IpDefrag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpDefrag")
            .field("config", &self.config)
            .field("pending_ipv4_datagrams", &self.ipv4_datagrams.len())
            .field("pending_ipv6_datagrams", &self.ipv6_datagrams.len())
            .field("input_count", &self.input_count)
            .field("emitted_count", &self.emitted_count)
            .field("pass_through_count", &self.pass_through_count)
            .field("fragments_observed", &self.fragments_observed)
            .field("completed_datagrams", &self.completed_datagram_count)
            .field("eviction_count", &self.eviction_count)
            .field("timeout_eviction_count", &self.timeout_eviction_count)
            .field(
                "datagram_limit_eviction_count",
                &self.datagram_limit_eviction_count,
            )
            .field("byte_limit_eviction_count", &self.byte_limit_eviction_count)
            .field("conflicts", &self.conflict_count)
            .field("errors", &self.error_count)
            .finish_non_exhaustive()
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
        let result = self.try_transform(record, emit);
        if result.is_err() {
            self.error_count += 1;
        }
        result
    }
}

impl IpDefrag {
    fn try_transform(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.config.validate()?;
        self.input_count += 1;

        self.evict_ipv4_expired(record.metadata().timestamp(), emit)?;
        self.evict_ipv6_expired(record.metadata().timestamp(), emit)?;

        if let Ipv4FragmentExtract::View(view) = extract_ipv4_fragment(&record)? {
            if view.is_fragmented() {
                self.fragments_observed += 1;
                match self.observe_ipv4_fragment(&record, &view, emit) {
                    Ipv4DefragObservation::Buffered => {}
                    Ipv4DefragObservation::Evicted => {}
                    Ipv4DefragObservation::Complete(state) => {
                        emit(state.reassembled_record(self.name())?)?;
                        self.emitted_count += 1;
                        self.completed_datagram_count += 1;
                    }
                    Ipv4DefragObservation::Conflict(state) => {
                        self.conflict_count += 1;
                        self.handle_ipv4_conflict(record, state, emit)?;
                    }
                    Ipv4DefragObservation::Error(error) => return Err(error),
                }
                return Ok(());
            }
        }

        match extract_ipv6_fragment(&record)? {
            Ipv6FragmentExtract::View(view) => {
                self.fragments_observed += 1;
                if view.is_atomic() {
                    return self.handle_ipv6_atomic_fragment(record, &view, emit);
                }
                match self.observe_ipv6_fragment(&record, &view, emit) {
                    Ipv6DefragObservation::Buffered => {}
                    Ipv6DefragObservation::Evicted => {}
                    Ipv6DefragObservation::Complete(state) => {
                        emit(state.reassembled_record(self.name())?)?;
                        self.emitted_count += 1;
                        self.completed_datagram_count += 1;
                    }
                    Ipv6DefragObservation::Conflict(state) => {
                        self.conflict_count += 1;
                        self.handle_ipv6_conflict(record, state, emit)?;
                    }
                    Ipv6DefragObservation::Error(error) => return Err(error),
                }
                return Ok(());
            }
            Ipv6FragmentExtract::PassThrough(pass_through) => {
                if let Some(note) = pass_through.reason().trace_note() {
                    return self.emit_pass_through_with_note(record, Some(note), emit);
                }
            }
        }

        self.emit_pass_through(record, emit)
    }
}

#[derive(Debug, Clone)]
enum DefragDatagramKey {
    Ipv4(Ipv4DefragKey),
    Ipv6(Ipv6DefragKey),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv6DefragObservationKind {
    Buffered,
    Complete,
    Conflict,
    ByteLimit,
}

#[derive(Debug)]
enum Ipv6DefragObservation {
    Buffered,
    Evicted,
    Complete(Ipv6DatagramState),
    Conflict(Ipv6DatagramState),
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Ipv6DefragKey {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identification: u32,
}

impl Ipv6DefragKey {
    const fn new(source: Ipv6Addr, destination: Ipv6Addr, identification: u32) -> Self {
        Self {
            source,
            destination,
            identification,
        }
    }

    fn from_view(view: &Ipv6FragmentView) -> Self {
        Self::new(view.source(), view.destination(), view.identification())
    }

    fn summary(&self) -> String {
        format!(
            "{}>{} id=0x{:08x}",
            self.source, self.destination, self.identification
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

#[derive(Debug, Clone)]
struct Ipv6DatagramState {
    key: Ipv6DefragKey,
    ranges: RangeMap,
    initial_fragment: Option<Ipv6InitialFragment>,
    fragment_next_header: Option<u8>,
    observed_fragment_next_headers: BTreeMap<u8, usize>,
    total_expected_fragmentable_payload_len: Option<u32>,
    fragment_count: usize,
    duplicate_count: usize,
    conflict_count: usize,
    first_conflict: Option<RangeMapConflict>,
    reserved_field_observations: Vec<Ipv6ReservedFieldObservation>,
    first_timestamp: Option<PcapTimestamp>,
    last_timestamp: Option<PcapTimestamp>,
    first_seen_order: usize,
    last_seen_order: usize,
    trace_record: Option<PacketRecord>,
}

impl Ipv6DatagramState {
    fn new(
        key: Ipv6DefragKey,
        record: &PacketRecord,
        input_order: usize,
        keep_trace_record: bool,
    ) -> Self {
        let timestamp = record.metadata().timestamp();
        Self {
            key,
            ranges: RangeMap::new(),
            initial_fragment: None,
            fragment_next_header: None,
            observed_fragment_next_headers: BTreeMap::new(),
            total_expected_fragmentable_payload_len: None,
            fragment_count: 0,
            duplicate_count: 0,
            conflict_count: 0,
            first_conflict: None,
            reserved_field_observations: Vec::new(),
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
        view: &Ipv6FragmentView,
        input_order: usize,
        keep_trace_record: bool,
    ) {
        self.last_seen_order = input_order;
        if self.trace_record.is_none() && keep_trace_record {
            self.trace_record = Some(trace_record_snapshot(record));
        }
        self.update_timestamps(record.metadata().timestamp());
        *self
            .observed_fragment_next_headers
            .entry(view.fragment_next_header())
            .or_insert(0) += 1;

        if view.fragment_status().is_initial() && self.initial_fragment.is_none() {
            self.fragment_next_header = Some(view.fragment_next_header());
            self.initial_fragment = Some(Ipv6InitialFragment::from_record(record, view));
        }

        if view.reserved() != 0 || view.reserved_bits() != 0 {
            self.reserved_field_observations
                .push(Ipv6ReservedFieldObservation::from_view(view, input_order));
        }

        match self
            .ranges
            .insert(view.fragment_offset_bytes(), view.fragmentable_payload())
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
                .saturating_add(view.fragmentable_payload().len() as u32);
            match self.ranges.set_total_len(total_expected) {
                Ok(()) => self.total_expected_fragmentable_payload_len = Some(total_expected),
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

    fn byte_len(&self) -> usize {
        self.ranges.byte_len()
    }

    fn exceeds_max_bytes(&self, max_bytes: usize) -> bool {
        self.byte_len() > max_bytes
    }

    fn is_complete(&self) -> bool {
        self.initial_fragment.is_some() && self.ranges.is_complete()
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
        let initial_fragment = self.initial_fragment.as_ref().ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ip.defrag.ipv6.initial_fragment",
                "complete IPv6 defragmentation state requires an offset-zero fragment",
            )
        })?;
        let payload = self.ranges.contiguous_payload().ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ip.defrag.ipv6.payload",
                "complete IPv6 defragmentation state requires contiguous payload bytes",
            )
        })?;
        let (packet, emitted_len, total_len) = initial_fragment.reassembled_packet(&payload)?;
        let metadata = initial_fragment
            .input_metadata
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
        IpDefragMetadata::new(IpFragmentFamily::Ipv6, self.key.identification)
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
            "evicted incomplete IPv6 defrag state: reason={reason} key={} fragments={} bytes={}",
            self.key.summary(),
            self.fragment_count,
            self.byte_len()
        )
    }

    fn known_packet_total_len(&self) -> Option<u32> {
        let payload_len = self
            .total_expected_fragmentable_payload_len
            .or_else(|| self.ranges.total_len())?;
        let initial_fragment = self.initial_fragment.as_ref()?;
        let header_len = u32::try_from(initial_fragment.header.len()).ok()?;
        let unfragmentable_len =
            u32::try_from(initial_fragment.extension_chain.unfragmentable().len()).ok()?;
        header_len
            .checked_add(unfragmentable_len)?
            .checked_add(payload_len)
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
            return format!("ambiguous conflicting IPv6 overlap: policy={action}");
        };

        format!(
            "ambiguous conflicting IPv6 overlap: policy={action} reason={:?} offset={} incoming={:?} existing={:?} incoming_byte={:?} existing_byte={:?}",
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv6InitialFragment {
    header: Vec<u8>,
    wrapper: Ipv6FragmentWrapper,
    extension_chain: Ipv6FragmentExtensionContext,
    fragment_header: Vec<u8>,
    ipv6_next_header: u8,
    fragment_next_header: u8,
    fragment_status: Ipv6FragmentHeaderStatus,
    input_metadata: PacketMetadata,
}

impl Ipv6InitialFragment {
    fn from_record(record: &PacketRecord, view: &Ipv6FragmentView) -> Self {
        Self {
            header: view.header().to_vec(),
            wrapper: view.wrapper().clone(),
            extension_chain: view.extension_chain().clone(),
            fragment_header: view.fragment_header().to_vec(),
            ipv6_next_header: view.ipv6_next_header(),
            fragment_next_header: view.fragment_next_header(),
            fragment_status: view.fragment_status(),
            input_metadata: record.metadata().clone().clear_captured_bytes(),
        }
    }

    fn reassembled_packet(&self, fragmentable_payload: &[u8]) -> Result<(Packet, u32, u32)> {
        let l3_bytes = self.reassembled_l3_bytes(fragmentable_payload)?;
        let total_len = u32::try_from(l3_bytes.len()).map_err(|_| {
            CrafterError::invalid_field_value("ipv6.payload_length", "packet length exceeds u32")
        })?;
        let frame_bytes = self.wrapper.wrap_l3(&l3_bytes);
        let packet = self.wrapper.decode_packet(&frame_bytes)?;
        let emitted_len = u32::try_from(frame_bytes.len()).map_err(|_| {
            CrafterError::invalid_field_value("ip.defrag.output_len", "packet length exceeds u32")
        })?;

        Ok((packet, emitted_len, total_len))
    }

    fn reassembled_l3_bytes(&self, fragmentable_payload: &[u8]) -> Result<Vec<u8>> {
        if self.header.len() < IPV6_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "ipv6 header",
                IPV6_HEADER_LEN,
                self.header.len(),
            )
            .into());
        }

        let unfragmentable = self.extension_chain.unfragmentable();
        let payload_length = unfragmentable
            .len()
            .checked_add(fragmentable_payload.len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "ipv6.payload_length",
                    "IPv6 payload length overflow",
                )
            })?;
        let payload_length = u16::try_from(payload_length).map_err(|_| {
            CrafterError::invalid_field_value(
                "ipv6.payload_length",
                "IPv6 payload length exceeds 65535 bytes",
            )
        })?;

        let previous_next_header_offset = self.extension_chain.previous_next_header_offset();
        let unfragmentable_end = IPV6_HEADER_LEN + unfragmentable.len();
        if previous_next_header_offset >= unfragmentable_end {
            return Err(CrafterError::invalid_field_value(
                "ip.defrag.ipv6.extension_chain",
                "previous Next Header offset must be before the fragmentable payload",
            )
            .into());
        }

        let mut header = self.header.clone();
        header[4..6].copy_from_slice(&payload_length.to_be_bytes());

        let mut l3_bytes =
            Vec::with_capacity(IPV6_HEADER_LEN + unfragmentable.len() + fragmentable_payload.len());
        l3_bytes.extend_from_slice(&header);
        l3_bytes.extend_from_slice(unfragmentable);
        l3_bytes.extend_from_slice(fragmentable_payload);

        // Remove the Fragment Header by repairing the saved previous Next Header
        // byte to point at the original fragmentable payload protocol.
        l3_bytes[previous_next_header_offset] = self.fragment_next_header;

        Ok(l3_bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv6ReservedFieldObservation {
    fragment_offset_bytes: u32,
    reserved: u8,
    reserved_bits: u8,
    input_order: usize,
}

impl Ipv6ReservedFieldObservation {
    fn from_view(view: &Ipv6FragmentView, input_order: usize) -> Self {
        Self {
            fragment_offset_bytes: view.fragment_offset_bytes(),
            reserved: view.reserved(),
            reserved_bits: view.reserved_bits(),
            input_order,
        }
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

impl Ipv6FragmentWrapper {
    fn wrap_l3(&self, l3_bytes: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.prefix().len() + l3_bytes.len());
        bytes.extend_from_slice(self.prefix());
        bytes.extend_from_slice(l3_bytes);
        bytes
    }

    fn decode_packet(&self, bytes: &[u8]) -> Result<Packet> {
        let registry = ipv6_defrag_registry();
        match self.kind() {
            super::ipv6::Ipv6FragmentWrapperKind::L3 => Ok(Packet::decode_from_l3_with_registry(
                &registry,
                NetworkLayer::Ipv6,
                bytes,
            )?),
            super::ipv6::Ipv6FragmentWrapperKind::Ethernet
            | super::ipv6::Ipv6FragmentWrapperKind::EthernetVlan { .. } => Ok(
                Packet::decode_from_link_with_registry(&registry, LinkType::Ethernet, bytes)?,
            ),
            super::ipv6::Ipv6FragmentWrapperKind::LinuxSll => Ok(
                Packet::decode_from_link_with_registry(&registry, LinkType::LinuxSll, bytes)?,
            ),
            super::ipv6::Ipv6FragmentWrapperKind::NullLoopback => Ok(
                Packet::decode_from_link_with_registry(&registry, LinkType::NullLoopback, bytes)?,
            ),
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

fn ipv6_defrag_registry() -> ProtocolRegistry {
    let mut registry = ProtocolRegistry::empty();
    registry.bind_ethertype_with_registry(ETHERTYPE_IPV6, |registry, packet, payload| {
        append_ipv6_packet_with_registry(registry, packet, payload)
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

fn ipv6_fragment_record_len(view: &Ipv6FragmentView) -> Result<u32> {
    let len = view
        .wrapper()
        .prefix()
        .len()
        .checked_add(view.total_len())
        .and_then(|len| len.checked_add(view.wrapper().suffix().len()))
        .ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ip.defrag.ipv6.input_len",
                "IPv6 fragment record length overflow",
            )
        })?;
    u32::try_from(len).map_err(|_| {
        CrafterError::invalid_field_value(
            "ip.defrag.ipv6.input_len",
            "IPv6 fragment record length exceeds u32",
        )
        .into()
    })
}

fn ipv6_atomic_fragment_metadata(
    view: &Ipv6FragmentView,
    total_len: u32,
) -> Result<IpDefragMetadata> {
    let range_end = u32::try_from(view.fragmentable_payload().len()).map_err(|_| {
        CrafterError::invalid_field_value(
            "ip.defrag.ipv6.atomic_payload",
            "IPv6 atomic fragment payload length exceeds u32",
        )
    })?;

    Ok(
        IpDefragMetadata::new(IpFragmentFamily::Ipv6, view.identification())
            .with_datagram_key(Ipv6DefragKey::from_view(view).summary())
            .with_fragment_count(1)
            .with_duplicate_count(0)
            .with_byte_ranges([IpFragmentRange::new(0, range_end)])
            .with_total_len(total_len),
    )
}

#[cfg(test)]
mod public_api {
    use super::*;
    use crate::wire::record::PacketRecord;
    use crate::wire::sniffer::Sniffer;
    use crate::wire::source::VecPacketSource;
    use crate::Raw;

    const PROTOCOL_UDP: u8 = 17;
    const IDENTIFICATION: u16 = 0x1234;

    fn source() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn destination() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn fragment_record(fragment_offset: u16, more_fragments: bool, payload: &[u8]) -> PacketRecord {
        PacketRecord::new(
            Ipv4::with_addresses(source(), destination())
                .protocol(PROTOCOL_UDP)
                .identification(IDENTIFICATION)
                .more_fragments(more_fragments)
                .fragment_offset(fragment_offset)
                / Raw::from_bytes(payload),
        )
    }

    #[test]
    fn public_builders_forward_to_config() {
        let transform = IpDefrag::new()
            .pass_non_fragments(false)
            .max_datagrams(16)
            .max_bytes_per_datagram(4096)
            .max_age(Duration::from_secs(5))
            .overlap_policy(IpDefragOverlapPolicy::PassThroughConflicting)
            .ipv6_atomic_fragments(Ipv6AtomicFragmentPolicy::PassThrough)
            .trace_passthrough(true)
            .trace_evictions(true);

        assert!(!transform.config().emits_non_fragments());
        assert_eq!(transform.config().max_datagrams_limit(), 16);
        assert_eq!(transform.config().max_bytes_per_datagram_limit(), 4096);
        assert_eq!(transform.config().max_age_limit(), Duration::from_secs(5));
        assert_eq!(
            transform.config().configured_overlap_policy(),
            IpDefragOverlapPolicy::PassThroughConflicting
        );
        assert_eq!(
            transform.config().ipv6_atomic_fragment_policy(),
            Ipv6AtomicFragmentPolicy::PassThrough
        );
        assert!(transform.config().traces_passthrough());
        assert!(transform.config().traces_evictions());

        assert!(IpDefrag::new().try_max_datagrams(0).is_err());
        assert!(IpDefrag::new().try_max_bytes_per_datagram(0).is_err());
        assert!(IpDefrag::new().try_max_age(Duration::from_secs(0)).is_err());
        assert!(IpDefrag::try_from_config(IpDefragConfig::new().max_datagrams(0)).is_err());
        assert!(IpDefrag::from_config(IpDefragConfig::new())
            .try_with_config(IpDefragConfig::new())
            .is_ok());
    }

    #[test]
    fn sniffer_accepts_defrag_transform_and_exposes_metadata() {
        let source = VecPacketSource::new([
            fragment_record(1, false, b"ijkl"),
            fragment_record(0, true, b"abcdefgh"),
        ]);

        let records = Sniffer::new(source)
            .with(IpDefrag::new())
            .collect_records()
            .unwrap();

        assert_eq!(records.len(), 1);
        let metadata = &records[0].metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.identification(), IDENTIFICATION as u32);
        assert_eq!(metadata.fragment_count(), 2);
        assert_eq!(metadata.duplicate_count(), 0);
    }

    #[test]
    fn debug_output_uses_counts_not_buffer_contents() {
        let mut transform = IpDefrag::new();
        let output = transform
            .defrag_record(fragment_record(0, true, b"abcdefgh"))
            .unwrap();

        assert!(output.is_empty());
        assert_eq!(transform.pending_ipv4_datagram_count(), 1);
        assert_eq!(transform.pending_ipv6_datagram_count(), 0);
        assert_eq!(transform.pending_datagram_count(), 1);

        let debug = format!("{transform:?}");
        assert!(debug.contains("pending_ipv4_datagrams: 1"));
        assert!(debug.contains("pending_ipv6_datagrams: 0"));
        assert!(!debug.contains("Ipv4DatagramState"));
        assert!(!debug.contains("abcdefgh"));
    }
}

#[cfg(test)]
mod ipv4_pass_through {
    use super::*;
    use crate::wire::record::{BackendKind, PacketOrigin, PacketRecord};
    use crate::{Ethernet, Ipv4, Raw};

    fn ipv4_packet() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            .protocol(17)
            .identification(0x2468)
            / Raw::from_bytes(b"non-fragmented")
    }

    fn assert_record_unchanged(output: &TransformOutput, input: &PacketRecord) {
        assert_eq!(output.len(), 1);
        let record = &output.records()[0];
        assert_eq!(record.packet().summary(), input.packet().summary());
        assert_eq!(
            record.packet().compile().unwrap().as_bytes(),
            input.packet().compile().unwrap().as_bytes()
        );
        assert_eq!(record.metadata(), input.metadata());
    }

    #[test]
    fn l3_non_fragmented_ipv4_passes_through_unchanged() {
        let input = PacketRecord::new(ipv4_packet())
            .with_origin(PacketOrigin::Generated)
            .with_backend(BackendKind::Memory)
            .with_interface("lo");
        let mut transform = IpDefrag::new();

        let output = transform.defrag_record(input.clone()).unwrap();

        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        assert!(transform.ipv4_datagrams.is_empty());
        assert_record_unchanged(&output, &input);
    }

    #[test]
    fn ethernet_non_fragmented_ipv4_passes_through_unchanged() {
        let input = PacketRecord::new(Ethernet::new() / ipv4_packet())
            .with_origin(PacketOrigin::Generated)
            .with_backend(BackendKind::Memory)
            .with_interface("eth0");
        let mut transform = IpDefrag::new();

        let output = transform.defrag_record(input.clone()).unwrap();

        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        assert!(transform.ipv4_datagrams.is_empty());
        assert_record_unchanged(&output, &input);
    }

    #[test]
    fn trace_passthrough_marks_non_fragmented_ipv4_without_rewriting_packet() {
        let input = PacketRecord::new(ipv4_packet());
        let expected_bytes = input.packet().compile().unwrap().as_bytes().to_vec();
        let config = IpDefragConfig::new().trace_passthrough(true);
        let mut transform = IpDefrag::new().with_config(config);

        let output = transform.defrag_record(input).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let record = &output.records()[0];
        assert_eq!(
            record.packet().compile().unwrap().as_bytes(),
            expected_bytes.as_slice()
        );
        let traces = record.metadata().transforms();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].name(), "ip-defrag");
        assert_eq!(traces[0].note(), Some("passthrough"));
    }

    #[test]
    fn pass_non_fragments_false_drops_non_fragmented_ipv4() {
        let config = IpDefragConfig::new().pass_non_fragments(false);
        let mut transform = IpDefrag::new().with_config(config);

        let output = transform
            .defrag_record(PacketRecord::new(ipv4_packet()))
            .unwrap();

        assert!(output.is_empty());
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 0);
        assert!(transform.ipv4_datagrams.is_empty());
    }
}

#[cfg(test)]
mod ipv4_reassembles {
    use super::*;
    use crate::wire::backend::pcap::PcapTimestamp;
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

#[cfg(test)]
mod ipv6_reassembles {
    use super::*;
    use crate::wire::backend::pcap::PcapTimestamp;
    use crate::wire::ip::{IpDefragOverlapStatus, IpFragmentFamily, IpFragmentRange};
    use crate::wire::record::{BackendKind, PacketOrigin, PacketRecord};
    use crate::{
        Ipv6, Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Raw, IPPROTO_IPV6_DSTOPTS,
        IPPROTO_TCP, IPPROTO_UDP,
    };

    const IDENTIFICATION: u32 = 0x6def_ac18;

    fn source() -> Ipv6Addr {
        "2001:db8:18::1".parse().unwrap()
    }

    fn destination() -> Ipv6Addr {
        "2001:db8:18::2".parse().unwrap()
    }

    fn fragment_record(
        fragment_offset: u16,
        more_fragments: bool,
        payload: &[u8],
        timestamp: PcapTimestamp,
        interface: &str,
    ) -> PacketRecord {
        fragment_record_with_next_header(
            IPPROTO_UDP,
            fragment_offset,
            more_fragments,
            payload,
            timestamp,
            interface,
        )
    }

    fn fragment_record_with_next_header(
        fragment_next_header: u8,
        fragment_offset: u16,
        more_fragments: bool,
        payload: &[u8],
        timestamp: PcapTimestamp,
        interface: &str,
    ) -> PacketRecord {
        let packet = Ipv6::new().src(source()).dst(destination())
            / Ipv6FragmentHeader::new()
                .next_header(fragment_next_header)
                .identification(IDENTIFICATION)
                .fragment_offset(fragment_offset)
                .more_fragments(more_fragments)
            / Raw::from_bytes(payload);

        PacketRecord::new(packet)
            .with_origin(PacketOrigin::Captured)
            .with_timestamp(timestamp)
            .with_backend(BackendKind::PcapFile)
            .with_interface(interface)
    }

    fn destination_options_fragment_record(
        fragment_offset: u16,
        more_fragments: bool,
        payload: &[u8],
    ) -> PacketRecord {
        let packet = Ipv6::new().src(source()).dst(destination())
            / Ipv6DestinationOptionsHeader::new()
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(IDENTIFICATION)
                .fragment_offset(fragment_offset)
                .more_fragments(more_fragments)
            / Raw::from_bytes(payload);

        PacketRecord::new(packet)
    }

    #[test]
    fn ipv6_reassembles_complete_out_of_order_fragments() {
        let first_seen_timestamp = PcapTimestamp::micros(18, 200).unwrap();
        let initial_fragment_timestamp = PcapTimestamp::micros(18, 100).unwrap();
        let mut transform = IpDefrag::new();

        let final_output = transform
            .defrag_record(fragment_record_with_next_header(
                IPPROTO_TCP,
                1,
                false,
                b"ijkl",
                first_seen_timestamp,
                "wan0",
            ))
            .unwrap();
        let initial_output = transform
            .defrag_record(fragment_record(
                0,
                true,
                b"abcdefgh",
                initial_fragment_timestamp,
                "wan1",
            ))
            .unwrap();

        assert_eq!(final_output.len(), 0);
        assert_eq!(initial_output.len(), 1);
        assert_eq!(transform.input_count(), 2);
        assert_eq!(transform.emitted_count(), 1);
        assert!(!transform.ipv6_datagrams.contains_key(&Ipv6DefragKey::new(
            source(),
            destination(),
            IDENTIFICATION
        )));

        let record = &initial_output.records()[0];
        let ipv6 = record.packet().layer::<Ipv6>().unwrap();
        let raw = record.packet().layer::<Raw>().unwrap();
        assert_eq!(ipv6.source(), source());
        assert_eq!(ipv6.destination(), destination());
        assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);
        assert_eq!(ipv6.payload_length_value(), Some(12));
        assert!(record.packet().layer::<Ipv6FragmentHeader>().is_none());
        assert_eq!(raw.as_bytes(), b"abcdefghijkl");

        let compiled = record.packet().compile().unwrap();
        assert_eq!(
            u16::from_be_bytes([compiled.as_bytes()[4], compiled.as_bytes()[5]]),
            12
        );
        assert_eq!(compiled.as_bytes()[6], IPPROTO_UDP);
        assert_eq!(&compiled.as_bytes()[40..], b"abcdefghijkl");

        assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
        assert_eq!(record.metadata().backend(), &BackendKind::PcapFile);
        assert_eq!(record.metadata().interface(), Some("wan1"));
        assert_eq!(
            record.metadata().timestamp(),
            Some(initial_fragment_timestamp)
        );
        assert_eq!(record.metadata().original_len(), Some(52));
        assert_eq!(record.metadata().captured_len(), Some(52));
        assert_eq!(record.metadata().emitted_len(), Some(52));

        let metadata = &record.metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
        assert_eq!(metadata.identification(), IDENTIFICATION);
        assert_eq!(
            metadata.datagram_key(),
            Some("2001:db8:18::1>2001:db8:18::2 id=0x6defac18")
        );
        assert_eq!(metadata.fragment_count(), 2);
        assert_eq!(metadata.duplicate_count(), 0);
        assert_eq!(metadata.overlap_status(), IpDefragOverlapStatus::None);
        assert_eq!(
            metadata.byte_ranges(),
            &[IpFragmentRange::new(0, 8), IpFragmentRange::new(8, 12)]
        );
        assert_eq!(metadata.total_len(), Some(52));

        let trace = &record.metadata().transforms()[0];
        assert_eq!(trace.name(), "ip-defrag");
        assert_eq!(trace.note(), Some("reassembled"));
        assert_eq!(trace.output_len(), Some(52));
    }

    #[test]
    fn ipv6_reassembles_and_repairs_supported_extension_chain() {
        let mut transform = IpDefrag::new();

        assert!(transform
            .defrag_record(destination_options_fragment_record(0, true, b"abcdefgh"))
            .unwrap()
            .is_empty());
        let output = transform
            .defrag_record(destination_options_fragment_record(1, false, b"ijkl"))
            .unwrap();

        assert_eq!(output.len(), 1);
        let record = &output.records()[0];
        let ipv6 = record.packet().layer::<Ipv6>().unwrap();
        let destination_options = record
            .packet()
            .layer::<Ipv6DestinationOptionsHeader>()
            .unwrap();
        let raw = record.packet().layer::<Raw>().unwrap();

        assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_DSTOPTS);
        assert_eq!(ipv6.payload_length_value(), Some(20));
        assert_eq!(destination_options.next_header_value(), IPPROTO_UDP);
        assert!(record.packet().layer::<Ipv6FragmentHeader>().is_none());
        assert_eq!(raw.as_bytes(), b"abcdefghijkl");

        let compiled = record.packet().compile().unwrap();
        assert_eq!(
            u16::from_be_bytes([compiled.as_bytes()[4], compiled.as_bytes()[5]]),
            20
        );
        assert_eq!(compiled.as_bytes()[6], IPPROTO_IPV6_DSTOPTS);
        assert_eq!(compiled.as_bytes()[40], IPPROTO_UDP);
        assert_eq!(&compiled.as_bytes()[48..], b"abcdefghijkl");

        let metadata = &record.metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
        assert_eq!(metadata.total_len(), Some(60));
        assert_eq!(
            metadata.byte_ranges(),
            &[IpFragmentRange::new(0, 8), IpFragmentRange::new(8, 12)]
        );
    }
}

#[cfg(test)]
mod ipv6_overlap {
    use super::*;
    use crate::wire::ip::{
        IpDefragOverlapPolicy, IpDefragOverlapStatus, IpFragmentFamily, IpFragmentRange,
    };
    use crate::wire::record::{BackendKind, PacketRecord};
    use crate::wire::WireError;
    use crate::{Ipv6, Ipv6FragmentHeader, Raw, IPPROTO_UDP};

    const IDENTIFICATION: u32 = 0x6f1a_0020;

    fn source() -> Ipv6Addr {
        "2001:db8:20::1".parse().unwrap()
    }

    fn destination() -> Ipv6Addr {
        "2001:db8:20::2".parse().unwrap()
    }

    fn fragment_record(fragment_offset: u16, more_fragments: bool, payload: &[u8]) -> PacketRecord {
        let packet = Ipv6::new().src(source()).dst(destination())
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(IDENTIFICATION)
                .fragment_offset(fragment_offset)
                .more_fragments(more_fragments)
            / Raw::from_bytes(payload);

        PacketRecord::new(packet).with_backend(BackendKind::PcapFile)
    }

    fn key() -> Ipv6DefragKey {
        Ipv6DefragKey::new(source(), destination(), IDENTIFICATION)
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
        assert!(!transform.ipv6_datagrams.contains_key(&key()));

        let record = &output.records()[0];
        assert!(record.packet().layer::<Ipv6FragmentHeader>().is_none());
        let raw = record.packet().layer::<Raw>().unwrap();
        assert_eq!(raw.as_bytes(), b"abcdefghijkl");

        let metadata = &record.metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
        assert_eq!(metadata.fragment_count(), 2);
        assert_eq!(metadata.duplicate_count(), 1);
        assert_eq!(metadata.overlap_status(), IpDefragOverlapStatus::None);
        assert_eq!(
            metadata.byte_ranges(),
            &[IpFragmentRange::new(0, 8), IpFragmentRange::new(8, 12)]
        );
        assert_eq!(metadata.total_len(), Some(52));
    }

    #[test]
    fn default_rejects_conflicting_overlaps_as_ambiguous() {
        let mut transform = IpDefrag::new();
        let conflicting = start_conflict_sequence(&mut transform);

        let error = transform.defrag_record(conflicting).unwrap_err();

        match error {
            WireError::Packet(CrafterError::InvalidFieldValue { field, reason }) => {
                assert_eq!(field, "ip.defrag.ipv6.overlap");
                assert!(reason.contains("ambiguous"));
            }
            other => panic!("expected structured ambiguous overlap error, got {other:?}"),
        }
        assert!(!transform.ipv6_datagrams.contains_key(&key()));
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn drop_policy_discards_ambiguous_ipv6_datagram() {
        let config = IpDefragConfig::new().overlap_policy(IpDefragOverlapPolicy::DropConflicting);
        let mut transform = IpDefrag::new().with_config(config);
        let conflicting = start_conflict_sequence(&mut transform);

        let output = transform.defrag_record(conflicting).unwrap();

        assert!(output.is_empty());
        assert!(!transform.ipv6_datagrams.contains_key(&key()));
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
        assert!(!transform.ipv6_datagrams.contains_key(&key()));
        assert_eq!(transform.emitted_count(), 1);

        let record = &output.records()[0];
        let metadata = &record.metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
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
        assert_eq!(metadata.total_len(), Some(56));

        let trace = &record.metadata().transforms()[0];
        assert_eq!(trace.name(), "ip-defrag");
        let note = trace.note().unwrap();
        assert!(note.contains("ambiguous"));
        assert!(note.contains("ByteMismatch"));
        assert!(note.contains("offset=8"));
    }

    #[test]
    fn missing_final_fragment_stays_buffered_without_reassembly() {
        let mut transform = IpDefrag::new();

        let first = transform
            .defrag_record(fragment_record(0, true, b"abcdefgh"))
            .unwrap();
        let second = transform
            .defrag_record(fragment_record(1, true, b"ijklmnop"))
            .unwrap();

        assert!(first.is_empty());
        assert!(second.is_empty());
        assert_eq!(transform.emitted_count(), 0);
        let state = transform
            .ipv6_datagrams
            .get(&key())
            .expect("missing final fragment should leave IPv6 state buffered");
        assert_eq!(state.fragment_count, 2);
        assert!(state.initial_fragment.is_some());
        assert_eq!(state.total_expected_fragmentable_payload_len, None);
        assert!(!state.ranges.is_complete());
    }
}

#[cfg(test)]
mod ipv6_limits {
    use super::*;
    use std::time::Duration;

    use crate::wire::backend::pcap::PcapTimestamp;
    use crate::wire::ip::{IpFragmentFamily, IpFragmentRange};
    use crate::wire::record::{BackendKind, PacketRecord};
    use crate::{Ipv6, Ipv6FragmentHeader, Raw, IPPROTO_UDP};

    const IDENTIFICATION: u32 = 0x6f1a_1020;

    fn source_one() -> Ipv6Addr {
        "2001:db8:20::10".parse().unwrap()
    }

    fn source_two() -> Ipv6Addr {
        "2001:db8:20::11".parse().unwrap()
    }

    fn destination() -> Ipv6Addr {
        "2001:db8:20::20".parse().unwrap()
    }

    fn fragment_record(
        source: Ipv6Addr,
        fragment_offset: u16,
        more_fragments: bool,
        payload: &[u8],
        seconds: u64,
    ) -> PacketRecord {
        let packet = Ipv6::new().src(source).dst(destination())
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(IDENTIFICATION)
                .fragment_offset(fragment_offset)
                .more_fragments(more_fragments)
            / Raw::from_bytes(payload);

        PacketRecord::new(packet)
            .with_timestamp(PcapTimestamp::micros(seconds, 0).unwrap())
            .with_backend(BackendKind::PcapFile)
    }

    fn key_for(source: Ipv6Addr) -> Ipv6DefragKey {
        Ipv6DefragKey::new(source, destination(), IDENTIFICATION)
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
            .ipv6_datagrams
            .contains_key(&key_for(source_one())));
        assert_eq!(transform.eviction_count(), 1);
        assert_eq!(transform.byte_limit_eviction_count(), 1);
        assert_eq!(transform.datagram_limit_eviction_count(), 0);
        assert_eq!(transform.timeout_eviction_count(), 0);
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn max_datagrams_evicts_oldest_ipv6_state_deterministically() {
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
            .ipv6_datagrams
            .contains_key(&key_for(source_one())));
        assert!(transform
            .ipv6_datagrams
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
            .ipv6_datagrams
            .get(&key_for(source_one()))
            .expect("late final fragment should start new incomplete IPv6 state");
        assert_eq!(state.fragment_count, 1);
        assert!(state.initial_fragment.is_none());
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
        assert!(record.packet().layer::<Ipv6FragmentHeader>().is_some());

        let metadata = &record.metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
        assert_eq!(metadata.identification(), IDENTIFICATION);
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
        assert!(note.contains("evicted incomplete IPv6 defrag state"));
    }
}

#[cfg(test)]
mod ipv6_state {
    use super::super::ipv6::Ipv6FragmentWrapperKind;
    use super::*;
    use crate::wire::ip::{IpDefragOverlapStatus, IpFragmentFamily, IpFragmentRange};
    use crate::wire::record::PacketRecord;
    use crate::{
        Ipv6, Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Raw, IPPROTO_TCP, IPPROTO_UDP,
    };

    const IDENTIFICATION: u32 = 0xfeed_ba11;

    fn source() -> Ipv6Addr {
        "2001:db8::10".parse().unwrap()
    }

    fn other_source() -> Ipv6Addr {
        "2001:db8::11".parse().unwrap()
    }

    fn destination() -> Ipv6Addr {
        "2001:db8::20".parse().unwrap()
    }

    fn fragment_record(
        source: Ipv6Addr,
        fragment_next_header: u8,
        fragment_offset: u16,
        more_fragments: bool,
        payload: &[u8],
    ) -> PacketRecord {
        reserved_fragment_record(
            source,
            fragment_next_header,
            fragment_offset,
            more_fragments,
            payload,
            0,
            0,
        )
    }

    fn reserved_fragment_record(
        source: Ipv6Addr,
        fragment_next_header: u8,
        fragment_offset: u16,
        more_fragments: bool,
        payload: &[u8],
        reserved: u8,
        reserved_bits: u8,
    ) -> PacketRecord {
        let packet = Ipv6::new().src(source).dst(destination())
            / Ipv6FragmentHeader::new()
                .next_header(fragment_next_header)
                .identification(IDENTIFICATION)
                .fragment_offset(fragment_offset)
                .reserved(reserved)
                .res(reserved_bits)
                .more_fragments(more_fragments)
            / Raw::from_bytes(payload);

        PacketRecord::new(packet)
    }

    fn fragment_record_with_destination_options() -> PacketRecord {
        let packet = Ipv6::new().src(source()).dst(destination())
            / Ipv6DestinationOptionsHeader::new()
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(IDENTIFICATION)
                .more_fragments(true)
            / Raw::from_bytes(b"abcdefgh");

        PacketRecord::new(packet)
    }

    fn key_for(source: Ipv6Addr) -> Ipv6DefragKey {
        Ipv6DefragKey::new(source, destination(), IDENTIFICATION)
    }

    fn view(record: &PacketRecord) -> Ipv6FragmentView {
        match extract_ipv6_fragment(record).unwrap() {
            Ipv6FragmentExtract::View(view) => view,
            Ipv6FragmentExtract::PassThrough(pass_through) => {
                panic!(
                    "expected IPv6 fragment view, got {:?}",
                    pass_through.reason()
                )
            }
        }
    }

    #[test]
    fn ipv6_defrag_key_uses_fragment_identity_without_next_header() {
        let mut transform = IpDefrag::new();

        let first = transform
            .defrag_record(fragment_record(source(), IPPROTO_UDP, 0, true, b"abcdefgh"))
            .unwrap();
        let final_fragment = transform
            .defrag_record(fragment_record(source(), IPPROTO_TCP, 2, false, b"qrst"))
            .unwrap();

        assert!(first.is_empty());
        assert!(final_fragment.is_empty());
        assert_eq!(transform.emitted_count(), 0);
        assert_eq!(transform.ipv6_datagrams.len(), 1);
        assert!(transform.ipv6_datagrams.contains_key(&key_for(source())));
        assert!(!transform
            .ipv6_datagrams
            .contains_key(&key_for(other_source())));

        let state = transform.ipv6_datagrams.get(&key_for(source())).unwrap();
        assert_eq!(state.fragment_count, 2);
        assert_eq!(state.duplicate_count, 0);
        assert_eq!(state.total_expected_fragmentable_payload_len, Some(20));
        assert!(state.initial_fragment.is_some());
        assert!(!state.ranges.is_complete());
        assert_eq!(state.fragment_next_header, Some(IPPROTO_UDP));
        assert_eq!(
            state.observed_fragment_next_headers.get(&IPPROTO_UDP),
            Some(&1)
        );
        assert_eq!(
            state.observed_fragment_next_headers.get(&IPPROTO_TCP),
            Some(&1)
        );

        let metadata = state.metadata();
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
        assert_eq!(metadata.identification(), IDENTIFICATION);
        assert_eq!(
            metadata.datagram_key(),
            Some("2001:db8::10>2001:db8::20 id=0xfeedba11")
        );
        assert_eq!(metadata.fragment_count(), 2);
        assert_eq!(metadata.overlap_status(), IpDefragOverlapStatus::None);
        assert_eq!(
            metadata.byte_ranges(),
            &[IpFragmentRange::new(0, 8), IpFragmentRange::new(16, 20)]
        );
    }

    #[test]
    fn ipv6_datagram_state_tracks_duplicates_conflicts_and_reserved_fields() {
        let first = reserved_fragment_record(source(), IPPROTO_UDP, 0, true, b"abcdefgh", 0xab, 3);
        let duplicate = fragment_record(source(), IPPROTO_UDP, 0, true, b"abcdefgh");
        let conflict = fragment_record(source(), IPPROTO_UDP, 0, true, b"abcdWXYZ");
        let mut state = Ipv6DatagramState::new(key_for(source()), &first, 1, false);

        for (order, record) in [(1, &first), (2, &duplicate), (3, &conflict)] {
            let view = view(record);
            state.observe_fragment(record, &view, order, false);
        }

        assert_eq!(state.fragment_count, 1);
        assert_eq!(state.duplicate_count, 1);
        assert_eq!(state.conflict_count, 1);
        assert!(state.first_conflict.is_some());
        assert!(state.ranges.has_conflict());
        assert_eq!(state.reserved_field_observations.len(), 1);
        assert_eq!(
            state.reserved_field_observations[0],
            Ipv6ReservedFieldObservation {
                fragment_offset_bytes: 0,
                reserved: 0xab,
                reserved_bits: 3,
                input_order: 1,
            }
        );
    }

    #[test]
    fn initial_fragment_context_keeps_extension_chain_and_output_repair_metadata() {
        let record = fragment_record_with_destination_options();
        let view = view(&record);
        let mut state = Ipv6DatagramState::new(key_for(source()), &record, 1, false);

        state.observe_fragment(&record, &view, 1, false);

        let initial_fragment = state
            .initial_fragment
            .as_ref()
            .expect("offset-zero IPv6 fragment should store initial context");
        assert_eq!(initial_fragment.header.len(), 40);
        assert_eq!(initial_fragment.wrapper.kind(), Ipv6FragmentWrapperKind::L3);
        assert_eq!(
            initial_fragment.extension_chain.fragment_header_offset(),
            48
        );
        assert_eq!(
            initial_fragment
                .extension_chain
                .previous_next_header_offset(),
            40
        );
        assert_eq!(initial_fragment.extension_chain.unfragmentable().len(), 8);
        assert_eq!(initial_fragment.fragment_header.len(), 8);
        assert_eq!(
            initial_fragment.ipv6_next_header,
            crate::IPPROTO_IPV6_DSTOPTS
        );
        assert_eq!(initial_fragment.fragment_next_header, IPPROTO_UDP);
        assert_eq!(
            initial_fragment.fragment_status,
            Ipv6FragmentHeaderStatus::Initial
        );
        assert!(initial_fragment.input_metadata.captured_bytes().is_none());
    }

    #[test]
    fn atomic_ipv6_fragments_normalize_without_creating_state() {
        let mut transform = IpDefrag::new();

        let output = transform
            .defrag_record(fragment_record(source(), IPPROTO_UDP, 0, false, b"atomic"))
            .unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.emitted_count(), 1);
        assert!(transform.ipv6_datagrams.is_empty());
        assert!(output.records()[0]
            .packet()
            .layer::<Ipv6FragmentHeader>()
            .is_none());
    }
}

#[cfg(test)]
mod ipv6_atomic {
    use super::*;
    use crate::wire::backend::pcap::PcapTimestamp;
    use crate::wire::ip::{IpDefragOverlapStatus, IpFragmentFamily, IpFragmentRange};
    use crate::wire::record::{BackendKind, PacketOrigin, PacketRecord};
    use crate::{
        Ipv6, Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Raw, IPPROTO_IPV6_DSTOPTS,
        IPPROTO_UDP,
    };

    const IDENTIFICATION: u32 = 0x6946_0019;

    fn source() -> Ipv6Addr {
        "2001:db8:19::1".parse().unwrap()
    }

    fn destination() -> Ipv6Addr {
        "2001:db8:19::2".parse().unwrap()
    }

    fn atomic_record(payload: &[u8]) -> PacketRecord {
        let packet = Ipv6::new().src(source()).dst(destination())
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(IDENTIFICATION)
                .fragment_offset(0)
                .more_fragments(false)
            / Raw::from_bytes(payload);

        PacketRecord::new(packet)
            .with_origin(PacketOrigin::Captured)
            .with_timestamp(PcapTimestamp::micros(19, 46).unwrap())
            .with_backend(BackendKind::PcapFile)
            .with_interface("wan19")
    }

    fn atomic_record_with_destination_options(payload: &[u8]) -> PacketRecord {
        let packet = Ipv6::new().src(source()).dst(destination())
            / Ipv6DestinationOptionsHeader::new()
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(IDENTIFICATION)
                .fragment_offset(0)
                .more_fragments(false)
            / Raw::from_bytes(payload);

        PacketRecord::new(packet)
    }

    fn initial_fragment_record(payload: &[u8]) -> PacketRecord {
        let packet = Ipv6::new().src(source()).dst(destination())
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(IDENTIFICATION)
                .fragment_offset(0)
                .more_fragments(true)
            / Raw::from_bytes(payload);

        PacketRecord::new(packet)
    }

    #[test]
    fn default_normalizes_atomic_fragment_and_records_trace() {
        let mut transform = IpDefrag::new();

        let output = transform.defrag_record(atomic_record(b"atomic")).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        assert!(transform.ipv6_datagrams.is_empty());

        let record = &output.records()[0];
        let ipv6 = record.packet().layer::<Ipv6>().unwrap();
        let raw = record.packet().layer::<Raw>().unwrap();
        assert_eq!(ipv6.source(), source());
        assert_eq!(ipv6.destination(), destination());
        assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);
        assert_eq!(ipv6.payload_length_value(), Some(6));
        assert!(record.packet().layer::<Ipv6FragmentHeader>().is_none());
        assert_eq!(raw.as_bytes(), b"atomic");

        let compiled = record.packet().compile().unwrap();
        assert_eq!(
            u16::from_be_bytes([compiled.as_bytes()[4], compiled.as_bytes()[5]]),
            6
        );
        assert_eq!(compiled.as_bytes()[6], IPPROTO_UDP);
        assert_eq!(&compiled.as_bytes()[40..], b"atomic");

        assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
        assert_eq!(record.metadata().backend(), &BackendKind::PcapFile);
        assert_eq!(record.metadata().interface(), Some("wan19"));
        assert_eq!(
            record.metadata().timestamp(),
            Some(PcapTimestamp::micros(19, 46).unwrap())
        );
        assert_eq!(record.metadata().original_len(), Some(54));
        assert_eq!(record.metadata().captured_len(), Some(54));
        assert_eq!(record.metadata().emitted_len(), Some(46));

        let metadata = &record.metadata().ip_defrag_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
        assert_eq!(metadata.identification(), IDENTIFICATION);
        assert_eq!(
            metadata.datagram_key(),
            Some("2001:db8:19::1>2001:db8:19::2 id=0x69460019")
        );
        assert_eq!(metadata.fragment_count(), 1);
        assert_eq!(metadata.duplicate_count(), 0);
        assert_eq!(metadata.overlap_status(), IpDefragOverlapStatus::None);
        assert_eq!(metadata.byte_ranges(), &[IpFragmentRange::new(0, 6)]);
        assert_eq!(metadata.total_len(), Some(46));

        let trace = &record.metadata().transforms()[0];
        assert_eq!(trace.name(), "ip-defrag");
        assert_eq!(trace.note(), Some("atomic fragment normalized"));
        assert_eq!(trace.input_len(), Some(54));
        assert_eq!(trace.output_len(), Some(46));
    }

    #[test]
    fn default_normalizes_atomic_fragment_with_supported_extension_chain() {
        let mut transform = IpDefrag::new();

        let output = transform
            .defrag_record(atomic_record_with_destination_options(b"atomic"))
            .unwrap();

        assert_eq!(output.len(), 1);
        let record = &output.records()[0];
        let ipv6 = record.packet().layer::<Ipv6>().unwrap();
        let destination_options = record
            .packet()
            .layer::<Ipv6DestinationOptionsHeader>()
            .unwrap();
        let raw = record.packet().layer::<Raw>().unwrap();

        assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_DSTOPTS);
        assert_eq!(ipv6.payload_length_value(), Some(14));
        assert_eq!(destination_options.next_header_value(), IPPROTO_UDP);
        assert!(record.packet().layer::<Ipv6FragmentHeader>().is_none());
        assert_eq!(raw.as_bytes(), b"atomic");

        let compiled = record.packet().compile().unwrap();
        assert_eq!(
            u16::from_be_bytes([compiled.as_bytes()[4], compiled.as_bytes()[5]]),
            14
        );
        assert_eq!(compiled.as_bytes()[6], IPPROTO_IPV6_DSTOPTS);
        assert_eq!(compiled.as_bytes()[40], IPPROTO_UDP);
        assert_eq!(&compiled.as_bytes()[48..], b"atomic");
    }

    #[test]
    fn atomic_fragment_is_processed_in_isolation_from_existing_state() {
        let mut transform = IpDefrag::new();

        assert!(transform
            .defrag_record(initial_fragment_record(b"abcdefgh"))
            .unwrap()
            .is_empty());
        let output = transform.defrag_record(atomic_record(b"atomic")).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.emitted_count(), 1);
        assert_eq!(transform.ipv6_datagrams.len(), 1);
        let state = transform
            .ipv6_datagrams
            .get(&Ipv6DefragKey::new(source(), destination(), IDENTIFICATION))
            .expect("original non-atomic fragment state should remain queued");
        assert_eq!(state.fragment_count, 1);
        let ranges = state.ranges.ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start(), 0);
        assert_eq!(ranges[0].end(), 8);
        assert_eq!(
            output.records()[0].metadata().transforms()[0].note(),
            Some("atomic fragment normalized")
        );
    }

    #[test]
    fn configured_pass_through_keeps_atomic_fragment_header_with_trace() {
        let config =
            IpDefragConfig::new().ipv6_atomic_fragments(Ipv6AtomicFragmentPolicy::PassThrough);
        let mut transform = IpDefrag::new().with_config(config);
        let input = atomic_record(b"atomic");
        let input_bytes = input.packet().compile().unwrap().as_bytes().to_vec();

        let output = transform.defrag_record(input).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let record = &output.records()[0];
        assert_eq!(
            record.packet().compile().unwrap().as_bytes(),
            input_bytes.as_slice()
        );
        assert!(record.packet().layer::<Ipv6FragmentHeader>().is_some());
        assert!(transform.ipv6_datagrams.is_empty());
        let trace = &record.metadata().transforms()[0];
        assert_eq!(trace.name(), "ip-defrag");
        assert_eq!(trace.note(), Some("atomic fragment pass-through"));
    }

    #[test]
    fn configured_drop_suppresses_atomic_fragment_without_state() {
        let config = IpDefragConfig::new().ipv6_atomic_fragments(Ipv6AtomicFragmentPolicy::Drop);
        let mut transform = IpDefrag::new().with_config(config);

        let output = transform.defrag_record(atomic_record(b"atomic")).unwrap();

        assert!(output.is_empty());
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 0);
        assert!(transform.ipv6_datagrams.is_empty());
    }
}
