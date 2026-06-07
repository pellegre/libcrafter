//! Shared configuration for IP wire transforms.

use core::time::Duration;

use crate::{CrafterError, Result};

/// Default maximum number of incomplete IP datagrams tracked by `IpDefrag`.
pub const IP_DEFRAG_DEFAULT_MAX_DATAGRAMS: usize = 1024;

/// Default maximum bytes retained for one incomplete IP datagram.
pub const IP_DEFRAG_DEFAULT_MAX_BYTES_PER_DATAGRAM: usize = 65_535;

/// Default maximum age for an incomplete IP datagram.
pub const IP_DEFRAG_DEFAULT_MAX_AGE: Duration = Duration::from_secs(60);

/// Smallest configured MTU that can make progress for IPv4 fragmentation.
pub const IP_FRAGMENT_MIN_MTU: usize = 28;

/// How `IpDefrag` handles conflicting overlapping fragment bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpDefragOverlapPolicy {
    /// Return a structured error instead of emitting an ambiguous datagram.
    RejectConflicting,
    /// Drop the ambiguous datagram state and keep processing later records.
    DropConflicting,
    /// Pass conflicting fragment records through with explicit trace metadata.
    PassThroughConflicting,
}

impl Default for IpDefragOverlapPolicy {
    fn default() -> Self {
        Self::RejectConflicting
    }
}

/// How `IpDefrag` handles IPv6 atomic fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ipv6AtomicFragmentPolicy {
    /// Emit atomic fragments unchanged, optionally with pass-through trace data.
    PassThrough,
    /// Normalize atomic fragments by removing the Fragment Header.
    Normalize,
    /// Drop atomic fragments without emitting an output record.
    Drop,
}

impl Default for Ipv6AtomicFragmentPolicy {
    fn default() -> Self {
        Self::Normalize
    }
}

/// How `IpFragment` handles IPv4 packets with Don't Fragment set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ipv4DontFragmentPolicy {
    /// Return a structured error when fragmentation would be required.
    Error,
    /// Emit the original record unchanged with explicit trace metadata.
    PassThrough,
    /// Ignore Don't Fragment and emit fragments anyway.
    FragmentAnyway,
}

impl Default for Ipv4DontFragmentPolicy {
    fn default() -> Self {
        Self::Error
    }
}

/// How `IpFragment` chooses an IPv4 Identification value when it emits fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ipv4FragmentIdentificationPolicy {
    /// Preserve an explicit packet ID, otherwise generate one.
    PreserveOrGenerate,
    /// Require the input packet to carry the ID that should be used.
    PreserveOnly,
    /// Use one fixed ID for every emitted IPv4 fragment set.
    Fixed(u16),
}

impl Default for Ipv4FragmentIdentificationPolicy {
    fn default() -> Self {
        Self::PreserveOrGenerate
    }
}

/// How `IpFragment` chooses an IPv6 Fragment Identification value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ipv6FragmentIdentificationPolicy {
    /// Generate an identification value for each emitted IPv6 fragment set.
    Generate,
    /// Use one fixed ID for every emitted IPv6 fragment set.
    Fixed(u32),
}

impl Default for Ipv6FragmentIdentificationPolicy {
    fn default() -> Self {
        Self::Generate
    }
}

/// Configuration for the receive-side IP defragmentation transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpDefragConfig {
    pass_non_fragments: bool,
    max_datagrams: usize,
    max_bytes_per_datagram: usize,
    max_age: Duration,
    overlap_policy: IpDefragOverlapPolicy,
    ipv6_atomic_fragment_policy: Ipv6AtomicFragmentPolicy,
    trace_passthrough: bool,
    trace_evictions: bool,
}

impl IpDefragConfig {
    /// Create the default IP defragmentation configuration.
    pub const fn new() -> Self {
        Self {
            pass_non_fragments: true,
            max_datagrams: IP_DEFRAG_DEFAULT_MAX_DATAGRAMS,
            max_bytes_per_datagram: IP_DEFRAG_DEFAULT_MAX_BYTES_PER_DATAGRAM,
            max_age: IP_DEFRAG_DEFAULT_MAX_AGE,
            overlap_policy: IpDefragOverlapPolicy::RejectConflicting,
            ipv6_atomic_fragment_policy: Ipv6AtomicFragmentPolicy::Normalize,
            trace_passthrough: false,
            trace_evictions: false,
        }
    }

    /// Configure whether records that are not handled as fragments pass through.
    pub const fn pass_non_fragments(mut self, pass_non_fragments: bool) -> Self {
        self.pass_non_fragments = pass_non_fragments;
        self
    }

    /// Whether non-fragment records are configured for pass-through.
    pub const fn emits_non_fragments(&self) -> bool {
        self.pass_non_fragments
    }

    /// Set the maximum number of incomplete datagrams retained at once.
    pub const fn max_datagrams(mut self, max_datagrams: usize) -> Self {
        self.max_datagrams = max_datagrams;
        self
    }

    /// Set the maximum number of incomplete datagrams retained at once.
    pub fn try_max_datagrams(self, max_datagrams: usize) -> Result<Self> {
        validate_nonzero("ip.defrag.max_datagrams", max_datagrams)?;
        Ok(self.max_datagrams(max_datagrams))
    }

    /// Maximum number of incomplete datagrams retained at once.
    pub const fn max_datagrams_limit(&self) -> usize {
        self.max_datagrams
    }

    /// Set the maximum bytes retained for one incomplete datagram.
    pub const fn max_bytes_per_datagram(mut self, max_bytes_per_datagram: usize) -> Self {
        self.max_bytes_per_datagram = max_bytes_per_datagram;
        self
    }

    /// Set the maximum bytes retained for one incomplete datagram.
    pub fn try_max_bytes_per_datagram(self, max_bytes_per_datagram: usize) -> Result<Self> {
        validate_nonzero("ip.defrag.max_bytes_per_datagram", max_bytes_per_datagram)?;
        Ok(self.max_bytes_per_datagram(max_bytes_per_datagram))
    }

    /// Maximum bytes retained for one incomplete datagram.
    pub const fn max_bytes_per_datagram_limit(&self) -> usize {
        self.max_bytes_per_datagram
    }

    /// Set the maximum age for an incomplete datagram.
    pub const fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Set the maximum age for an incomplete datagram.
    pub fn try_max_age(self, max_age: Duration) -> Result<Self> {
        validate_nonzero_duration("ip.defrag.max_age", max_age)?;
        Ok(self.max_age(max_age))
    }

    /// Maximum age for an incomplete datagram.
    pub const fn max_age_limit(&self) -> Duration {
        self.max_age
    }

    /// Set the conflicting-overlap handling policy.
    pub const fn overlap_policy(mut self, overlap_policy: IpDefragOverlapPolicy) -> Self {
        self.overlap_policy = overlap_policy;
        self
    }

    /// Conflicting-overlap handling policy.
    pub const fn configured_overlap_policy(&self) -> IpDefragOverlapPolicy {
        self.overlap_policy
    }

    /// Set the IPv6 atomic fragment handling policy.
    pub const fn ipv6_atomic_fragments(
        mut self,
        ipv6_atomic_fragment_policy: Ipv6AtomicFragmentPolicy,
    ) -> Self {
        self.ipv6_atomic_fragment_policy = ipv6_atomic_fragment_policy;
        self
    }

    /// IPv6 atomic fragment handling policy.
    pub const fn ipv6_atomic_fragment_policy(&self) -> Ipv6AtomicFragmentPolicy {
        self.ipv6_atomic_fragment_policy
    }

    /// Configure whether records emitted unchanged receive transform traces.
    pub const fn trace_passthrough(mut self, trace_passthrough: bool) -> Self {
        self.trace_passthrough = trace_passthrough;
        self
    }

    /// Whether records emitted unchanged receive transform traces.
    pub const fn traces_passthrough(&self) -> bool {
        self.trace_passthrough
    }

    /// Configure whether evictions emit representative trace records.
    pub const fn trace_evictions(mut self, trace_evictions: bool) -> Self {
        self.trace_evictions = trace_evictions;
        self
    }

    /// Whether evictions emit representative trace records.
    pub const fn traces_evictions(&self) -> bool {
        self.trace_evictions
    }

    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<()> {
        validate_nonzero("ip.defrag.max_datagrams", self.max_datagrams)?;
        validate_nonzero(
            "ip.defrag.max_bytes_per_datagram",
            self.max_bytes_per_datagram,
        )?;
        validate_nonzero_duration("ip.defrag.max_age", self.max_age)?;
        Ok(())
    }
}

impl Default for IpDefragConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for the transmit-side IP fragmentation transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpFragmentConfig {
    mtu: usize,
    dont_fragment_policy: Ipv4DontFragmentPolicy,
    ipv4_identification_policy: Ipv4FragmentIdentificationPolicy,
    ipv6_identification_policy: Ipv6FragmentIdentificationPolicy,
    trace_passthrough: bool,
}

impl IpFragmentConfig {
    /// Create an IP fragmentation configuration with an explicit MTU.
    pub const fn new(mtu: usize) -> Self {
        Self {
            mtu,
            dont_fragment_policy: Ipv4DontFragmentPolicy::Error,
            ipv4_identification_policy: Ipv4FragmentIdentificationPolicy::PreserveOrGenerate,
            ipv6_identification_policy: Ipv6FragmentIdentificationPolicy::Generate,
            trace_passthrough: false,
        }
    }

    /// Create an IP fragmentation configuration with a validated explicit MTU.
    pub fn try_new(mtu: usize) -> Result<Self> {
        validate_mtu(mtu)?;
        Ok(Self::new(mtu))
    }

    /// Configured MTU in octets.
    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    /// Replace the configured MTU in octets.
    pub const fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Replace the configured MTU in octets.
    pub fn try_mtu(self, mtu: usize) -> Result<Self> {
        validate_mtu(mtu)?;
        Ok(self.with_mtu(mtu))
    }

    /// Configure whether IPv4 Don't Fragment is honored.
    pub const fn honor_dont_fragment(mut self, honor_dont_fragment: bool) -> Self {
        self.dont_fragment_policy = if honor_dont_fragment {
            Ipv4DontFragmentPolicy::Error
        } else {
            Ipv4DontFragmentPolicy::FragmentAnyway
        };
        self
    }

    /// Whether IPv4 Don't Fragment is honored.
    pub const fn honors_dont_fragment(&self) -> bool {
        !matches!(
            self.dont_fragment_policy,
            Ipv4DontFragmentPolicy::FragmentAnyway
        )
    }

    /// Set the IPv4 Don't Fragment handling policy.
    pub const fn dont_fragment_policy(
        mut self,
        dont_fragment_policy: Ipv4DontFragmentPolicy,
    ) -> Self {
        self.dont_fragment_policy = dont_fragment_policy;
        self
    }

    /// IPv4 Don't Fragment handling policy.
    pub const fn configured_dont_fragment_policy(&self) -> Ipv4DontFragmentPolicy {
        self.dont_fragment_policy
    }

    /// Set the IPv4 Identification handling policy.
    pub const fn ipv4_identification_policy(
        mut self,
        ipv4_identification_policy: Ipv4FragmentIdentificationPolicy,
    ) -> Self {
        self.ipv4_identification_policy = ipv4_identification_policy;
        self
    }

    /// IPv4 Identification handling policy.
    pub const fn configured_ipv4_identification_policy(&self) -> Ipv4FragmentIdentificationPolicy {
        self.ipv4_identification_policy
    }

    /// Set the IPv6 Fragment Identification handling policy.
    pub const fn ipv6_identification_policy(
        mut self,
        ipv6_identification_policy: Ipv6FragmentIdentificationPolicy,
    ) -> Self {
        self.ipv6_identification_policy = ipv6_identification_policy;
        self
    }

    /// IPv6 Fragment Identification handling policy.
    pub const fn configured_ipv6_identification_policy(&self) -> Ipv6FragmentIdentificationPolicy {
        self.ipv6_identification_policy
    }

    /// Configure whether records emitted unchanged receive transform traces.
    pub const fn trace_passthrough(mut self, trace_passthrough: bool) -> Self {
        self.trace_passthrough = trace_passthrough;
        self
    }

    /// Whether records emitted unchanged receive transform traces.
    pub const fn traces_passthrough(&self) -> bool {
        self.trace_passthrough
    }

    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<()> {
        validate_mtu(self.mtu)
    }
}

fn validate_nonzero(field: &'static str, value: usize) -> Result<()> {
    if value == 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "must be greater than zero",
        ));
    }

    Ok(())
}

fn validate_nonzero_duration(field: &'static str, value: Duration) -> Result<()> {
    if value.is_zero() {
        return Err(CrafterError::invalid_field_value(
            field,
            "must be greater than zero",
        ));
    }

    Ok(())
}

fn validate_mtu(mtu: usize) -> Result<()> {
    if mtu < IP_FRAGMENT_MIN_MTU {
        return Err(CrafterError::invalid_field_value(
            "ip.fragment.mtu",
            "must fit the minimum IPv4 header and one 8-byte fragment unit",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ip::{IpDefrag, IpFragment};
    use crate::wire::record::{BackendKind, PacketOrigin, PacketRecord};
    use crate::Raw;

    fn assert_invalid_field(error: CrafterError, expected_field: &'static str) {
        match error {
            CrafterError::InvalidFieldValue { field, .. } => assert_eq!(field, expected_field),
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
    }

    fn record(payload: &'static str) -> PacketRecord {
        PacketRecord::new(Raw::from(payload))
            .with_origin(PacketOrigin::Generated)
            .with_backend(BackendKind::Memory)
    }

    #[test]
    fn ip_defrag_config_builders_expose_bounds_and_policies() {
        let config = IpDefragConfig::new()
            .pass_non_fragments(false)
            .max_datagrams(64)
            .max_bytes_per_datagram(8192)
            .max_age(Duration::from_secs(30))
            .overlap_policy(IpDefragOverlapPolicy::DropConflicting)
            .ipv6_atomic_fragments(Ipv6AtomicFragmentPolicy::Normalize)
            .trace_passthrough(true)
            .trace_evictions(true);

        assert!(!config.emits_non_fragments());
        assert_eq!(config.max_datagrams_limit(), 64);
        assert_eq!(config.max_bytes_per_datagram_limit(), 8192);
        assert_eq!(config.max_age_limit(), Duration::from_secs(30));
        assert_eq!(
            config.configured_overlap_policy(),
            IpDefragOverlapPolicy::DropConflicting
        );
        assert_eq!(
            config.ipv6_atomic_fragment_policy(),
            Ipv6AtomicFragmentPolicy::Normalize
        );
        assert!(config.traces_passthrough());
        assert!(config.traces_evictions());
        config.validate().unwrap();
    }

    #[test]
    fn ip_defrag_config_try_builders_reject_unbounded_settings() {
        let max_datagrams_error = IpDefragConfig::new().try_max_datagrams(0).unwrap_err();
        assert_invalid_field(max_datagrams_error, "ip.defrag.max_datagrams");

        let max_bytes_error = IpDefragConfig::new()
            .try_max_bytes_per_datagram(0)
            .unwrap_err();
        assert_invalid_field(max_bytes_error, "ip.defrag.max_bytes_per_datagram");

        let max_age_error = IpDefragConfig::new()
            .try_max_age(Duration::from_secs(0))
            .unwrap_err();
        assert_invalid_field(max_age_error, "ip.defrag.max_age");
    }

    #[test]
    fn ip_fragment_config_builders_expose_mtu_df_ids_and_trace() {
        let config = IpFragmentConfig::new(1500)
            .with_mtu(1280)
            .dont_fragment_policy(Ipv4DontFragmentPolicy::PassThrough)
            .ipv4_identification_policy(Ipv4FragmentIdentificationPolicy::Fixed(0x1234))
            .ipv6_identification_policy(Ipv6FragmentIdentificationPolicy::Fixed(0xfeed_beef))
            .trace_passthrough(true);

        assert_eq!(config.mtu(), 1280);
        assert!(config.honors_dont_fragment());
        assert_eq!(
            config.configured_dont_fragment_policy(),
            Ipv4DontFragmentPolicy::PassThrough
        );
        assert_eq!(
            config.configured_ipv4_identification_policy(),
            Ipv4FragmentIdentificationPolicy::Fixed(0x1234)
        );
        assert_eq!(
            config.configured_ipv6_identification_policy(),
            Ipv6FragmentIdentificationPolicy::Fixed(0xfeed_beef)
        );
        assert!(config.traces_passthrough());
        config.validate().unwrap();
    }

    #[test]
    fn ip_fragment_config_keeps_legacy_df_bool_builder() {
        let ignore_df = IpFragmentConfig::new(1500).honor_dont_fragment(false);
        assert!(!ignore_df.honors_dont_fragment());
        assert_eq!(
            ignore_df.configured_dont_fragment_policy(),
            Ipv4DontFragmentPolicy::FragmentAnyway
        );

        let honor_df = ignore_df.honor_dont_fragment(true);
        assert!(honor_df.honors_dont_fragment());
        assert_eq!(
            honor_df.configured_dont_fragment_policy(),
            Ipv4DontFragmentPolicy::Error
        );
    }

    #[test]
    fn ip_fragment_config_try_builders_reject_too_small_mtu() {
        let new_error = IpFragmentConfig::try_new(IP_FRAGMENT_MIN_MTU - 1).unwrap_err();
        assert_invalid_field(new_error, "ip.fragment.mtu");

        let mtu_error = IpFragmentConfig::new(1500)
            .try_mtu(IP_FRAGMENT_MIN_MTU - 1)
            .unwrap_err();
        assert_invalid_field(mtu_error, "ip.fragment.mtu");
    }

    #[test]
    fn trace_passthrough_adds_transform_trace_to_unchanged_records() {
        let mut defrag = IpDefrag::new().with_config(IpDefragConfig::new().trace_passthrough(true));
        let defrag_output = defrag.defrag_record(record("defrag")).unwrap();
        let defrag_traces = defrag_output.records()[0].metadata().transforms();
        assert_eq!(defrag_traces.len(), 1);
        assert_eq!(defrag_traces[0].name(), "ip-defrag");
        assert_eq!(defrag_traces[0].note(), Some("passthrough"));

        let mut fragment =
            IpFragment::with_config(IpFragmentConfig::new(1280).trace_passthrough(true));
        let fragment_output = fragment.fragment_record(record("fragment")).unwrap();
        let fragment_traces = fragment_output.records()[0].metadata().transforms();
        assert_eq!(fragment_traces.len(), 1);
        assert_eq!(fragment_traces[0].name(), "ip-fragment");
        assert_eq!(fragment_traces[0].note(), Some("passthrough"));
    }
}
