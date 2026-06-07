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
