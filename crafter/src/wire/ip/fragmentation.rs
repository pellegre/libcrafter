//! Transmit-side IP fragmentation transform.

use super::fragment::ipv4_planner::{Ipv4FragmentPlan, Ipv4PlannedFragment};
use super::fragment::ipv6_identification::Ipv6IdentificationGenerator;
use super::fragment::ipv6_planner::{
    Ipv6FragmentHeaderContext, Ipv6FragmentPlan, Ipv6PlannedFragment,
};
use super::ipv4::{
    extract_ipv4_fragment, Ipv4FragmentExtract, Ipv4FragmentView, Ipv4FragmentWrapper,
    Ipv4FragmentWrapperKind,
};
use super::ipv6::{
    extract_ipv6_fragment, extract_ipv6_fragmentable, Ipv6FragmentExtract, Ipv6FragmentView,
    Ipv6FragmentWrapper, Ipv6FragmentWrapperKind, Ipv6FragmentableExtract, Ipv6FragmentableView,
};
use super::{
    IpFragmentConfig, IpFragmentFamily, IpFragmentMetadata, IpFragmentRange, IpFragmentReason,
    Ipv4DontFragmentPolicy, Ipv6FragmentIdentificationPolicy,
};
use crate::protocols::ipv4::{append_ipv4_packet_with_registry, IPV4_FLAG_MORE_FRAGMENTS};
use crate::protocols::ipv6::append_ipv6_packet_with_registry;
use crate::protocols::link::{append_vlan_packet_with_registry, ETHERTYPE_IPV4, ETHERTYPE_VLAN};
use crate::wire::record::{PacketRecord, TransformTrace};
use crate::wire::transform::{PacketTransform, TransformOutput};
use crate::wire::{Result, WireError};
use crate::{
    CrafterError, Ipv4, Ipv6, Ipv6FragmentHeader, LinkType, NetworkLayer, Packet, PacketOrigin,
    ProtocolRegistry, Raw, ETHERTYPE_IPV6, IPPROTO_IPV6_FRAGMENT,
};

pub(crate) const IPV4_DONT_FRAGMENT_ERROR_REASON: &str =
    "IPv4 Don't Fragment is set and packet exceeds configured MTU";
pub(crate) const IPV4_DONT_FRAGMENT_PASSTHROUGH_NOTE: &str = "ipv4 don't-fragment pass-through";
pub(crate) const IPV4_DONT_FRAGMENT_OVERRIDE_NOTE: &str = "ipv4 don't-fragment override";

/// Transmit-side IP fragmentation transform.
#[derive(Debug, Clone)]
pub struct IpFragment {
    config: IpFragmentConfig,
    ipv6_identification_generator: Ipv6IdentificationGenerator,
    input_count: usize,
    emitted_count: usize,
    pass_through_count: usize,
    fragments_observed: usize,
    completed_datagram_count: usize,
    error_count: usize,
}

/// Compact counters for an [`IpFragment`] transform.
///
/// These counters summarize source-side fragmentation activity without
/// retaining packet bytes or emitted records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpFragmentStats {
    input_count: usize,
    emitted_count: usize,
    pass_through_count: usize,
    fragments_observed: usize,
    completed_datagrams: usize,
    evicted_datagrams: usize,
    conflicts: usize,
    errors: usize,
}

impl IpFragmentStats {
    /// Number of input records seen.
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Number of records successfully emitted.
    pub const fn emitted_count(&self) -> usize {
        self.emitted_count
    }

    /// Number of records emitted without splitting into new fragments.
    pub const fn pass_through_count(&self) -> usize {
        self.pass_through_count
    }

    /// Number of fragment records emitted or accepted as pre-fragmented input.
    pub const fn fragments_observed(&self) -> usize {
        self.fragments_observed
    }

    /// Number of source datagrams split into multiple fragments.
    pub const fn completed_datagrams(&self) -> usize {
        self.completed_datagrams
    }

    /// Number of datagrams evicted by this transform.
    pub const fn evicted_datagrams(&self) -> usize {
        self.evicted_datagrams
    }

    /// Number of conflicting fragment datagrams observed by this transform.
    pub const fn conflicts(&self) -> usize {
        self.conflicts
    }

    /// Number of transform calls that returned an error.
    pub const fn errors(&self) -> usize {
        self.errors
    }
}

impl IpFragment {
    /// Create an IP fragmentation transform with an explicit MTU.
    pub const fn new(mtu: usize) -> Self {
        Self::with_config(IpFragmentConfig::new(mtu))
    }

    /// Create an IP fragmentation transform with a validated explicit MTU.
    pub fn try_new(mtu: usize) -> Result<Self> {
        Ok(Self::with_config(IpFragmentConfig::try_new(mtu)?))
    }

    /// Create an IP fragmentation transform from an explicit configuration.
    pub const fn with_config(config: IpFragmentConfig) -> Self {
        Self {
            config,
            ipv6_identification_generator: Ipv6IdentificationGenerator::new(),
            input_count: 0,
            emitted_count: 0,
            pass_through_count: 0,
            fragments_observed: 0,
            completed_datagram_count: 0,
            error_count: 0,
        }
    }

    /// Create an IP fragmentation transform from a validated explicit configuration.
    pub fn try_with_config(config: IpFragmentConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self::with_config(config))
    }

    /// Borrow the current configuration.
    pub const fn config(&self) -> &IpFragmentConfig {
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

    /// Number of records emitted without splitting into new fragments.
    pub const fn pass_through_count(&self) -> usize {
        self.pass_through_count
    }

    /// Number of fragment records emitted or accepted as pre-fragmented input.
    pub const fn fragments_observed(&self) -> usize {
        self.fragments_observed
    }

    /// Number of source datagrams split into multiple fragments.
    pub const fn completed_datagrams(&self) -> usize {
        self.completed_datagram_count
    }

    /// Number of datagrams evicted by this transform.
    pub const fn evicted_datagrams(&self) -> usize {
        0
    }

    /// Number of conflicting fragment datagrams observed by this transform.
    pub const fn conflicts(&self) -> usize {
        0
    }

    /// Number of transform calls that returned an error.
    pub const fn errors(&self) -> usize {
        self.error_count
    }

    /// Return a compact snapshot of transform counters.
    pub const fn stats(&self) -> IpFragmentStats {
        IpFragmentStats {
            input_count: self.input_count,
            emitted_count: self.emitted_count,
            pass_through_count: self.pass_through_count,
            fragments_observed: self.fragments_observed,
            completed_datagrams: self.completed_datagram_count,
            evicted_datagrams: 0,
            conflicts: 0,
            errors: self.error_count,
        }
    }

    /// Run the transform and collect emitted records into a small buffer.
    pub fn fragment_record(&mut self, record: PacketRecord) -> Result<TransformOutput> {
        self.transform_to_output(record)
    }
}

impl PacketTransform for IpFragment {
    fn name(&self) -> &'static str {
        "ip-fragment"
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

impl IpFragment {
    fn try_transform(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.config.validate()?;
        self.input_count += 1;

        match extract_ipv4_fragment(&record)? {
            Ipv4FragmentExtract::View(view) => {
                let plan = Ipv4FragmentPlan::from_view(&view, self.config.mtu())?;
                let decision = self.ipv4_fragment_decision(&view, &plan)?;

                if plan.fragment_count() > 1 && decision.reason == IpFragmentReason::Fragmented {
                    self.emit_ipv4_fragments(&record, &view, &plan, decision.trace_note, emit)?;
                    return Ok(());
                }

                if view.is_fragmented() {
                    self.fragments_observed += 1;
                }
                let mut record = record;
                record
                    .metadata_mut()
                    .push_ip_fragment_metadata(ipv4_fragment_metadata(
                        &view,
                        self.config.mtu(),
                        decision.reason,
                    ));
                self.emit_single(record, decision.trace_note, emit)?;
                return Ok(());
            }
            Ipv4FragmentExtract::PassThrough(_) => {}
        }

        self.handle_ipv6_or_pass_through(record, emit)?;
        Ok(())
    }
}

impl IpFragment {
    fn handle_ipv6_or_pass_through(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        match extract_ipv6_fragment(&record)? {
            Ipv6FragmentExtract::View(view) => {
                self.fragments_observed += 1;
                let mut record = record;
                record
                    .metadata_mut()
                    .push_ip_fragment_metadata(ipv6_fragment_metadata(&view, self.config.mtu()));
                return self.emit_single(record, None, emit);
            }
            Ipv6FragmentExtract::PassThrough(pass_through) => {
                if pass_through.reason().trace_note().is_some() {
                    return self.emit_single(record, pass_through.reason().trace_note(), emit);
                }
            }
        }

        match extract_ipv6_fragmentable(&record)? {
            Ipv6FragmentableExtract::View(view) if view.total_len() > self.config.mtu() => {
                let header =
                    Ipv6FragmentHeaderContext::from_extension_context(view.extension_chain());
                let plan = Ipv6FragmentPlan::new(
                    header,
                    view.fragmentable_payload().len(),
                    self.config.mtu(),
                )?;
                if plan.fragment_count() > 1 {
                    return self.emit_ipv6_fragments(&record, &view, &plan, emit);
                }
                self.emit_single(record, None, emit)
            }
            Ipv6FragmentableExtract::View(_) => self.emit_single(record, None, emit),
            Ipv6FragmentableExtract::PassThrough(pass_through) => {
                self.emit_single(record, pass_through.reason().trace_note(), emit)
            }
        }
    }

    pub(in crate::wire::ip) fn next_ipv6_fragment_identification(&mut self) -> u32 {
        match self.config.configured_ipv6_identification_policy() {
            Ipv6FragmentIdentificationPolicy::Generate => self
                .ipv6_identification_generator
                .next(self.config.configured_ipv6_identification_seed()),
            Ipv6FragmentIdentificationPolicy::Fixed(identification) => identification,
        }
    }

    fn ipv4_fragment_decision(
        &self,
        view: &Ipv4FragmentView,
        plan: &Ipv4FragmentPlan,
    ) -> Result<Ipv4FragmentDecision> {
        let fragmentation_required = plan.fragment_count() > 1;

        if view.is_dont_fragment() && fragmentation_required {
            return match self.config.configured_dont_fragment_policy() {
                Ipv4DontFragmentPolicy::Error => Err(WireError::transform(
                    self.name(),
                    IPV4_DONT_FRAGMENT_ERROR_REASON,
                )),
                Ipv4DontFragmentPolicy::PassThrough => Ok(Ipv4FragmentDecision {
                    reason: IpFragmentReason::DontFragment,
                    trace_note: Some(IPV4_DONT_FRAGMENT_PASSTHROUGH_NOTE),
                }),
                Ipv4DontFragmentPolicy::FragmentAnyway => Ok(Ipv4FragmentDecision {
                    reason: IpFragmentReason::Fragmented,
                    trace_note: Some(IPV4_DONT_FRAGMENT_OVERRIDE_NOTE),
                }),
            };
        }

        let reason = if fragmentation_required || view.is_fragmented() {
            IpFragmentReason::Fragmented
        } else {
            IpFragmentReason::AlreadyFits
        };

        Ok(Ipv4FragmentDecision {
            reason,
            trace_note: None,
        })
    }

    fn emit_single(
        &mut self,
        mut record: PacketRecord,
        trace_note: Option<&'static str>,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        if let Some(note) =
            trace_note.or_else(|| self.config.traces_passthrough().then_some("passthrough"))
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

    fn emit_ipv4_fragments(
        &mut self,
        record: &PacketRecord,
        view: &Ipv4FragmentView,
        plan: &Ipv4FragmentPlan,
        trace_note: Option<&'static str>,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        let input_len = ipv4_fragment_record_len(view)?;
        let original_len = saturated_u32(view.payload().len());

        for (index, fragment) in plan.fragments().iter().copied().enumerate() {
            let packet = ipv4_fragment_packet(view, fragment)?;
            let l3_bytes = packet.compile()?.as_bytes().to_vec();
            let frame_bytes = wrap_ipv4_l3(view.wrapper(), &l3_bytes);
            let emitted_len = saturated_u32(frame_bytes.len());
            let packet = decode_ipv4_fragment_packet(view.wrapper(), &frame_bytes)?;

            let mut metadata = record
                .metadata()
                .clone()
                .clear_captured_bytes()
                .with_origin(PacketOrigin::Transformed)
                .with_original_len(input_len)
                .with_captured_len(input_len)
                .with_emitted_len(emitted_len)
                .with_ip_fragment_metadata(
                    IpFragmentMetadata::new(
                        IpFragmentFamily::Ipv4,
                        self.config.mtu(),
                        u32::from(view.identification()),
                        fragment.fragment_offset(),
                        fragment.more_fragments(),
                        plan.fragment_count(),
                        index,
                        fragment.datagram_range(),
                    )
                    .with_original_len(original_len)
                    .with_reason(IpFragmentReason::Fragmented),
                );

            if let Some(note) = trace_note {
                metadata = metadata.with_transform_trace(
                    TransformTrace::new(self.name())
                        .with_note(note)
                        .with_input_len(input_len)
                        .with_output_len(emitted_len),
                );
            }

            emit(PacketRecord::from_packet_metadata(packet, metadata))?;
            self.emitted_count += 1;
            self.fragments_observed += 1;
        }

        self.completed_datagram_count += 1;
        Ok(())
    }

    fn emit_ipv6_fragments(
        &mut self,
        record: &PacketRecord,
        view: &Ipv6FragmentableView,
        plan: &Ipv6FragmentPlan,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        let input_len = ipv6_fragmentable_record_len(view)?;
        let original_len = saturated_u32(view.fragmentable_payload().len());
        let identification = self.next_ipv6_fragment_identification();

        for (index, fragment) in plan.fragments().iter().copied().enumerate() {
            let packet = ipv6_fragment_packet(view, fragment, identification)?;
            let l3_bytes = packet.compile()?.as_bytes().to_vec();
            let frame_bytes = wrap_ipv6_l3(view.wrapper(), &l3_bytes);
            let emitted_len = saturated_u32(frame_bytes.len());
            let packet = decode_ipv6_fragment_packet(view.wrapper(), &frame_bytes)?;

            let metadata = record
                .metadata()
                .clone()
                .clear_captured_bytes()
                .with_origin(PacketOrigin::Transformed)
                .with_original_len(input_len)
                .with_captured_len(input_len)
                .with_emitted_len(emitted_len)
                .with_ip_fragment_metadata(
                    IpFragmentMetadata::new(
                        IpFragmentFamily::Ipv6,
                        self.config.mtu(),
                        identification,
                        fragment.fragment_offset(),
                        fragment.more_fragments(),
                        plan.fragment_count(),
                        index,
                        fragment.fragmentable_range(),
                    )
                    .with_original_len(original_len)
                    .with_reason(IpFragmentReason::Fragmented),
                );

            emit(PacketRecord::from_packet_metadata(packet, metadata))?;
            self.emitted_count += 1;
            self.fragments_observed += 1;
        }

        self.completed_datagram_count += 1;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv4FragmentDecision {
    reason: IpFragmentReason,
    trace_note: Option<&'static str>,
}

fn ipv4_fragment_metadata(
    view: &Ipv4FragmentView,
    mtu: usize,
    reason: IpFragmentReason,
) -> IpFragmentMetadata {
    let start = view.fragment_offset_bytes();
    let payload_len = saturated_u32(view.payload().len());

    IpFragmentMetadata::new(
        IpFragmentFamily::Ipv4,
        mtu,
        u32::from(view.identification()),
        view.fragment_offset(),
        view.more_fragments(),
        1,
        0,
        IpFragmentRange::new(start, start.saturating_add(payload_len)),
    )
    .with_original_len(payload_len)
    .with_reason(reason)
}

fn ipv6_fragment_metadata(view: &Ipv6FragmentView, mtu: usize) -> IpFragmentMetadata {
    let start = view.fragment_offset_bytes();
    let payload_len = saturated_u32(view.fragmentable_payload().len());

    IpFragmentMetadata::new(
        IpFragmentFamily::Ipv6,
        mtu,
        view.identification(),
        view.fragment_offset(),
        view.more_fragments(),
        1,
        0,
        IpFragmentRange::new(start, start.saturating_add(payload_len)),
    )
    .with_original_len(payload_len)
    .with_reason(IpFragmentReason::Fragmented)
}

fn ipv4_fragment_packet(view: &Ipv4FragmentView, fragment: Ipv4PlannedFragment) -> Result<Packet> {
    let range = fragment.payload_range();
    let payload = payload_slice(view.payload(), range)?;
    let ipv4 = ipv4_layer_for_fragment(view, fragment)?;

    Ok(Packet::new().push(ipv4).push(Raw::from_bytes(payload)))
}

fn ipv4_layer_for_fragment(view: &Ipv4FragmentView, fragment: Ipv4PlannedFragment) -> Result<Ipv4> {
    let header = view.header();
    if header.len() < 20 {
        return Err(CrafterError::buffer_too_short("ipv4 header", 20, header.len()).into());
    }

    let options = if header.len() > 20 {
        header[20..].to_vec()
    } else {
        Vec::new()
    };
    let flags = ipv4_fragment_flags(view.flags(), fragment.more_fragments());

    Ok(Ipv4::new()
        .version(header[0] >> 4)
        .ihl(header[0] & 0x0f)
        .tos(header[1])
        .identification(view.identification())
        .flags(flags)
        .fragment_offset(fragment.fragment_offset())
        .ttl(header[8])
        .protocol(view.protocol())
        .src(view.source())
        .dst(view.destination())
        .options(options))
}

fn ipv6_fragment_packet(
    view: &Ipv6FragmentableView,
    fragment: Ipv6PlannedFragment,
    identification: u32,
) -> Result<Packet> {
    let range = fragment.fragmentable_range();
    let payload = fragmentable_slice(view.fragmentable_payload(), range)?;
    let ipv6 = ipv6_layer_for_fragment(view)?;
    let rest = ipv6_fragment_payload(view, fragment, identification, payload)?;

    Ok(Packet::new().push(ipv6).push(Raw::from_bytes(rest)))
}

fn ipv6_layer_for_fragment(view: &Ipv6FragmentableView) -> Result<Ipv6> {
    let header = view.header();
    if header.len() < 40 {
        return Err(CrafterError::buffer_too_short("ipv6 header", 40, header.len()).into());
    }

    let version = header[0] >> 4;
    let traffic_class = ((header[0] & 0x0f) << 4) | (header[1] >> 4);
    let flow_label =
        (u32::from(header[1] & 0x0f) << 16) | (u32::from(header[2]) << 8) | u32::from(header[3]);
    let next_header = if view.extension_chain().unfragmentable().is_empty() {
        IPPROTO_IPV6_FRAGMENT
    } else {
        view.ipv6_next_header()
    };

    Ok(Ipv6::new()
        .version(version)
        .traffic_class(traffic_class)
        .flow_label(flow_label)
        .next_header(next_header)
        .hop_limit(header[7])
        .src(view.source())
        .dst(view.destination()))
}

fn ipv6_fragment_payload(
    view: &Ipv6FragmentableView,
    fragment: Ipv6PlannedFragment,
    identification: u32,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut unfragmentable = view.extension_chain().unfragmentable().to_vec();
    let previous_next_header_offset = view.extension_chain().previous_next_header_offset();
    if previous_next_header_offset != 6 {
        let unfragmentable_offset =
            previous_next_header_offset.checked_sub(40).ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "ip.fragment.ipv6.extension_chain",
                    "previous Next Header offset must be in the IPv6 header or extension chain",
                )
            })?;
        let Some(next_header) = unfragmentable.get_mut(unfragmentable_offset) else {
            return Err(CrafterError::invalid_field_value(
                "ip.fragment.ipv6.extension_chain",
                "previous Next Header offset must be before the fragmentable payload",
            )
            .into());
        };
        *next_header = IPPROTO_IPV6_FRAGMENT;
    }

    let fragment_header = Ipv6FragmentHeader::new()
        .next_header(view.fragment_next_header())
        .identification(identification)
        .fragment_offset(fragment.fragment_offset())
        .more_fragments(fragment.more_fragments());

    let mut encoded_fragment_header = Vec::new();
    Packet::new()
        .push(fragment_header)
        .compile_into(&mut encoded_fragment_header)?;

    let mut rest =
        Vec::with_capacity(unfragmentable.len() + encoded_fragment_header.len() + payload.len());
    rest.extend_from_slice(&unfragmentable);
    rest.extend_from_slice(&encoded_fragment_header);
    rest.extend_from_slice(payload);
    Ok(rest)
}

fn ipv4_fragment_flags(input_flags: u8, more_fragments: bool) -> u8 {
    let mut flags = input_flags & !IPV4_FLAG_MORE_FRAGMENTS;
    if more_fragments {
        flags |= IPV4_FLAG_MORE_FRAGMENTS;
    }
    flags
}

fn payload_slice(payload: &[u8], range: IpFragmentRange) -> Result<&[u8]> {
    let start = usize::try_from(range.start()).map_err(|_| {
        CrafterError::invalid_field_value(
            "ipv4.payload_range",
            "fragment payload range start exceeds usize",
        )
    })?;
    let end = usize::try_from(range.end()).map_err(|_| {
        CrafterError::invalid_field_value(
            "ipv4.payload_range",
            "fragment payload range end exceeds usize",
        )
    })?;

    payload.get(start..end).ok_or_else(|| {
        CrafterError::invalid_field_value(
            "ipv4.payload_range",
            "fragment payload range must be within the IPv4 payload",
        )
        .into()
    })
}

fn fragmentable_slice(payload: &[u8], range: IpFragmentRange) -> Result<&[u8]> {
    let start = usize::try_from(range.start()).map_err(|_| {
        CrafterError::invalid_field_value(
            "ipv6.fragmentable_range",
            "fragmentable range start exceeds usize",
        )
    })?;
    let end = usize::try_from(range.end()).map_err(|_| {
        CrafterError::invalid_field_value(
            "ipv6.fragmentable_range",
            "fragmentable range end exceeds usize",
        )
    })?;

    payload.get(start..end).ok_or_else(|| {
        CrafterError::invalid_field_value(
            "ipv6.fragmentable_range",
            "fragmentable range must be within the IPv6 fragmentable payload",
        )
        .into()
    })
}

fn wrap_ipv4_l3(wrapper: &Ipv4FragmentWrapper, l3_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(wrapper.prefix().len() + l3_bytes.len());
    bytes.extend_from_slice(wrapper.prefix());
    bytes.extend_from_slice(l3_bytes);
    bytes
}

fn wrap_ipv6_l3(wrapper: &Ipv6FragmentWrapper, l3_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(wrapper.prefix().len() + l3_bytes.len());
    bytes.extend_from_slice(wrapper.prefix());
    bytes.extend_from_slice(l3_bytes);
    bytes
}

fn decode_ipv4_fragment_packet(wrapper: &Ipv4FragmentWrapper, bytes: &[u8]) -> Result<Packet> {
    let registry = ipv4_fragment_registry();
    match wrapper.kind() {
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

fn decode_ipv6_fragment_packet(wrapper: &Ipv6FragmentWrapper, bytes: &[u8]) -> Result<Packet> {
    let registry = ipv6_fragment_registry();
    match wrapper.kind() {
        Ipv6FragmentWrapperKind::L3 => Ok(Packet::decode_from_l3_with_registry(
            &registry,
            NetworkLayer::Ipv6,
            bytes,
        )?),
        Ipv6FragmentWrapperKind::Ethernet | Ipv6FragmentWrapperKind::EthernetVlan { .. } => Ok(
            Packet::decode_from_link_with_registry(&registry, LinkType::Ethernet, bytes)?,
        ),
        Ipv6FragmentWrapperKind::LinuxSll => Ok(Packet::decode_from_link_with_registry(
            &registry,
            LinkType::LinuxSll,
            bytes,
        )?),
        Ipv6FragmentWrapperKind::NullLoopback => Ok(Packet::decode_from_link_with_registry(
            &registry,
            LinkType::NullLoopback,
            bytes,
        )?),
    }
}

fn ipv4_fragment_registry() -> ProtocolRegistry {
    let mut registry = ProtocolRegistry::empty();
    registry.bind_ethertype_with_registry(ETHERTYPE_IPV4, |registry, packet, payload| {
        append_ipv4_packet_with_registry(registry, packet, payload)
    });
    registry.bind_ethertype_with_registry(ETHERTYPE_VLAN, |registry, packet, payload| {
        append_vlan_packet_with_registry(registry, packet, payload)
    });
    registry
}

fn ipv6_fragment_registry() -> ProtocolRegistry {
    let mut registry = ProtocolRegistry::empty();
    registry.bind_ethertype_with_registry(ETHERTYPE_IPV6, |registry, packet, payload| {
        append_ipv6_packet_with_registry(registry, packet, payload)
    });
    registry.bind_ethertype_with_registry(ETHERTYPE_VLAN, |registry, packet, payload| {
        append_vlan_packet_with_registry(registry, packet, payload)
    });
    registry
}

fn ipv4_fragment_record_len(view: &Ipv4FragmentView) -> Result<u32> {
    let len = view
        .wrapper()
        .prefix()
        .len()
        .checked_add(view.total_len())
        .and_then(|len| len.checked_add(view.wrapper().suffix().len()))
        .ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ip.fragment.ipv4.input_len",
                "IPv4 fragment record length overflow",
            )
        })?;

    u32::try_from(len).map_err(|_| {
        CrafterError::invalid_field_value(
            "ip.fragment.ipv4.input_len",
            "IPv4 fragment record length exceeds u32",
        )
        .into()
    })
}

fn ipv6_fragmentable_record_len(view: &Ipv6FragmentableView) -> Result<u32> {
    let len = view
        .wrapper()
        .prefix()
        .len()
        .checked_add(view.total_len())
        .and_then(|len| len.checked_add(view.wrapper().suffix().len()))
        .ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ip.fragment.ipv6.input_len",
                "IPv6 fragment record length overflow",
            )
        })?;

    u32::try_from(len).map_err(|_| {
        CrafterError::invalid_field_value(
            "ip.fragment.ipv6.input_len",
            "IPv6 fragment record length exceeds u32",
        )
        .into()
    })
}

fn saturated_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::super::config::IP_FRAGMENT_MIN_MTU;
    use super::super::ipv6::IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE;
    use super::*;
    use crate::wire::backend::pcap::PcapLinkType;
    use crate::wire::record::{BackendKind, PacketOrigin, PacketRecord};
    use crate::wire::WireError;
    use crate::{CrafterError, Ipv6, Raw, IPPROTO_IPV6_AH, IPPROTO_IPV6_FRAGMENT, IPPROTO_UDP};
    use std::net::Ipv6Addr;

    fn raw_record(payload: &'static str) -> PacketRecord {
        PacketRecord::new(Raw::from(payload))
            .with_origin(PacketOrigin::Generated)
            .with_backend(BackendKind::Memory)
            .with_interface("lo")
    }

    fn source() -> Ipv6Addr {
        "2001:db8:23::1".parse().unwrap()
    }

    fn destination() -> Ipv6Addr {
        "2001:db8:23::2".parse().unwrap()
    }

    fn unsupported_ipv6_extension_record() -> PacketRecord {
        let mut bytes = (Ipv6::new()
            .src(source())
            .dst(destination())
            .next_header(IPPROTO_IPV6_AH)
            / Raw::from_bytes([0u8; 8]))
        .compile()
        .unwrap()
        .as_bytes()
        .to_vec();
        bytes[40] = IPPROTO_IPV6_FRAGMENT;

        PacketRecord::new(Raw::from_bytes(&bytes))
            .with_pcap_link_type(PcapLinkType::RawIp)
            .with_captured_bytes(bytes)
    }

    #[test]
    fn non_ip_record_passes_through_unchanged_without_trace_by_default() {
        let input = raw_record("payload");
        let expected_summary = input.packet().summary();
        let expected_metadata = input.metadata().clone();
        let mut transform = IpFragment::new(1280);

        let output = transform.fragment_record(input).unwrap();

        assert_eq!(transform.name(), "ip-fragment");
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        assert_eq!(output.len(), 1);
        assert_eq!(output.records()[0].packet().summary(), expected_summary);
        assert_eq!(output.records()[0].metadata(), &expected_metadata);
    }

    #[test]
    fn trace_passthrough_marks_unchanged_records_when_configured() {
        let mut transform =
            IpFragment::with_config(IpFragmentConfig::new(1280).trace_passthrough(true));

        let output = transform.fragment_record(raw_record("payload")).unwrap();

        assert_eq!(output.len(), 1);
        let traces = output.records()[0].metadata().transforms();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].name(), "ip-fragment");
        assert_eq!(traces[0].note(), Some("passthrough"));
    }

    #[test]
    fn invalid_mtu_is_reported_when_transform_runs() {
        let mut transform = IpFragment::new(IP_FRAGMENT_MIN_MTU - 1);

        let error = transform
            .fragment_record(raw_record("payload"))
            .unwrap_err();

        match error {
            WireError::Packet(CrafterError::InvalidFieldValue { field, .. }) => {
                assert_eq!(field, "ip.fragment.mtu");
            }
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
        assert_eq!(transform.input_count(), 0);
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn unsupported_ipv6_extension_scope_passes_through_with_trace() {
        let mut transform = IpFragment::new(1280);

        let output = transform
            .fragment_record(unsupported_ipv6_extension_record())
            .unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let traces = output.records()[0].metadata().transforms();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].name(), "ip-fragment");
        assert_eq!(
            traces[0].note(),
            Some(IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE)
        );
    }

    #[test]
    fn unfragmented_ipv6_record_passes_through_unchanged() {
        let input = PacketRecord::new(
            Ipv6::new()
                .src(source())
                .dst(destination())
                .next_header(IPPROTO_UDP)
                / Raw::from_bytes(b"payload"),
        );
        let expected_summary = input.packet().summary();
        let expected_metadata = input.metadata().clone();
        let mut transform = IpFragment::new(1280);

        let output = transform.fragment_record(input).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(output.records()[0].packet().summary(), expected_summary);
        assert_eq!(output.records()[0].metadata(), &expected_metadata);
    }
}
