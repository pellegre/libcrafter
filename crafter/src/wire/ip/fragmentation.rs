//! Transmit-side IP fragmentation transform.

use super::ipv6::{extract_ipv6_fragment, Ipv6FragmentExtract};
use super::IpFragmentConfig;
use crate::wire::record::{PacketRecord, TransformTrace};
use crate::wire::transform::{PacketTransform, TransformOutput};
use crate::wire::Result;

/// Transmit-side IP fragmentation transform.
#[derive(Debug, Clone)]
pub struct IpFragment {
    config: IpFragmentConfig,
    input_count: usize,
    emitted_count: usize,
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
            input_count: 0,
            emitted_count: 0,
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
        self.config.validate()?;
        self.input_count += 1;

        let mut record = record;
        let trace_note = match extract_ipv6_fragment(&record)? {
            Ipv6FragmentExtract::PassThrough(pass_through) => pass_through.reason().trace_note(),
            Ipv6FragmentExtract::View(_) => None,
        };

        if let Some(note) =
            trace_note.or_else(|| self.config.traces_passthrough().then_some("passthrough"))
        {
            record
                .metadata_mut()
                .push_transform_trace(TransformTrace::new(self.name()).with_note(note));
        }

        emit(record)?;
        self.emitted_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::IP_FRAGMENT_MIN_MTU;
    use super::super::ipv6::IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE;
    use super::*;
    use crate::pcap::PcapLinkType;
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
