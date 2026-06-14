//! Inspectable metadata for IP fragmentation transforms.

/// IP version associated with fragment or defragmentation metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFragmentFamily {
    /// IPv4 fragmentation metadata.
    Ipv4,
    /// IPv6 fragmentation metadata.
    Ipv6,
}

impl IpFragmentFamily {
    /// Numeric IP version.
    pub const fn version(self) -> u8 {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 6,
        }
    }

    /// Stable lowercase family label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

/// Byte range from the fragmentable payload, using an exclusive end offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpFragmentRange {
    start: u32,
    end: u32,
}

impl IpFragmentRange {
    /// Create a byte range with an exclusive end offset.
    pub const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Start offset in bytes.
    pub const fn start(self) -> u32 {
        self.start
    }

    /// Exclusive end offset in bytes.
    pub const fn end(self) -> u32 {
        self.end
    }

    /// Length in bytes, saturating to zero for malformed ranges.
    pub const fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// Whether this range has no bytes.
    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// Why an IP fragment metadata record was attached.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpFragmentReason {
    /// The input packet exceeded the configured MTU and was split.
    Fragmented,
    /// The input already fit the configured MTU.
    AlreadyFits,
    /// IPv4 Don't Fragment policy prevented splitting.
    DontFragment,
    /// The packet family or header shape is not supported by the transform.
    Unsupported,
    /// Caller-defined reason.
    Other(String),
}

/// Metadata attached to one emitted IP fragment record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpFragmentMetadata {
    family: IpFragmentFamily,
    mtu: usize,
    identification: u32,
    fragment_offset: u16,
    more_fragments: bool,
    fragment_count: usize,
    emitted_index: usize,
    byte_range: IpFragmentRange,
    original_len: Option<u32>,
    reason: Option<IpFragmentReason>,
}

impl IpFragmentMetadata {
    /// Create metadata for one emitted fragment.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        family: IpFragmentFamily,
        mtu: usize,
        identification: u32,
        fragment_offset: u16,
        more_fragments: bool,
        fragment_count: usize,
        emitted_index: usize,
        byte_range: IpFragmentRange,
    ) -> Self {
        Self {
            family,
            mtu,
            identification,
            fragment_offset,
            more_fragments,
            fragment_count,
            emitted_index,
            byte_range,
            original_len: None,
            reason: None,
        }
    }

    /// IP version family.
    pub const fn family(&self) -> IpFragmentFamily {
        self.family
    }

    /// Configured MTU in bytes.
    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    /// IPv4 or IPv6 fragment identification value.
    pub const fn identification(&self) -> u32 {
        self.identification
    }

    /// Fragment offset in the protocol header's 8-octet units.
    pub const fn fragment_offset(&self) -> u16 {
        self.fragment_offset
    }

    /// Fragment offset converted to bytes.
    pub const fn fragment_offset_bytes(&self) -> u32 {
        (self.fragment_offset as u32) * 8
    }

    /// Whether the More Fragments flag is set.
    pub const fn more_fragments(&self) -> bool {
        self.more_fragments
    }

    /// Total number of fragments emitted for the source packet.
    pub const fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    /// Zero-based index of this emitted fragment.
    pub const fn emitted_index(&self) -> usize {
        self.emitted_index
    }

    /// Compatibility alias for the zero-based emitted fragment index.
    pub const fn fragment_index(&self) -> usize {
        self.emitted_index()
    }

    /// Byte range from the source packet's fragmentable payload.
    pub const fn byte_range(&self) -> IpFragmentRange {
        self.byte_range
    }

    /// Original packet length in bytes when known.
    pub const fn original_len(&self) -> Option<u32> {
        self.original_len
    }

    /// Reason this metadata was attached.
    pub const fn reason(&self) -> Option<&IpFragmentReason> {
        self.reason.as_ref()
    }

    /// Set the original packet length.
    pub const fn with_original_len(mut self, original_len: u32) -> Self {
        self.original_len = Some(original_len);
        self
    }

    /// Set the fragment metadata reason.
    pub fn with_reason(mut self, reason: IpFragmentReason) -> Self {
        self.reason = Some(reason);
        self
    }
}

/// Overlap status observed while defragmenting one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpDefragOverlapStatus {
    /// No overlapping byte ranges were observed.
    None,
    /// Overlapping byte ranges were observed and did not conflict.
    NonConflicting,
    /// At least one overlapping byte range carried conflicting bytes.
    Conflicting,
}

impl IpDefragOverlapStatus {
    /// Whether any overlap was observed.
    pub const fn has_overlap(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether any observed overlap had conflicting bytes.
    pub const fn has_conflict(self) -> bool {
        matches!(self, Self::Conflicting)
    }
}

/// Why defragmentation state was evicted before a complete packet was emitted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpDefragEvictionReason {
    /// The datagram exceeded the configured age bound.
    Timeout,
    /// The transform exceeded its datagram-count bound.
    DatagramLimit,
    /// The transform exceeded its byte-count bound.
    ByteLimit,
    /// Conflicting overlaps made the datagram ambiguous.
    Conflict,
    /// Caller-defined reason.
    Other(String),
}

/// Metadata attached to an IP defragmentation result or eviction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpDefragMetadata {
    family: IpFragmentFamily,
    identification: u32,
    datagram_key: Option<String>,
    fragment_count: usize,
    duplicate_count: usize,
    overlap_status: IpDefragOverlapStatus,
    byte_ranges: Vec<IpFragmentRange>,
    total_len: Option<u32>,
    eviction_reason: Option<IpDefragEvictionReason>,
}

impl IpDefragMetadata {
    /// Create metadata for one defragmentation result.
    pub const fn new(family: IpFragmentFamily, identification: u32) -> Self {
        Self {
            family,
            identification,
            datagram_key: None,
            fragment_count: 0,
            duplicate_count: 0,
            overlap_status: IpDefragOverlapStatus::None,
            byte_ranges: Vec::new(),
            total_len: None,
            eviction_reason: None,
        }
    }

    /// IP version family.
    pub const fn family(&self) -> IpFragmentFamily {
        self.family
    }

    /// IPv4 or IPv6 fragment identification value.
    pub const fn identification(&self) -> u32 {
        self.identification
    }

    /// Human-readable datagram key summary when available.
    pub fn datagram_key(&self) -> Option<&str> {
        self.datagram_key.as_deref()
    }

    /// Number of unique fragments accepted for this datagram.
    pub const fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    /// Number of exact duplicate fragments observed.
    pub const fn duplicate_count(&self) -> usize {
        self.duplicate_count
    }

    /// Overlap and conflict status observed for this datagram.
    pub const fn overlap_status(&self) -> IpDefragOverlapStatus {
        self.overlap_status
    }

    /// Whether any conflicting overlap was observed.
    pub const fn has_conflict(&self) -> bool {
        self.overlap_status.has_conflict()
    }

    /// Accepted byte ranges for this datagram.
    pub fn byte_ranges(&self) -> &[IpFragmentRange] {
        &self.byte_ranges
    }

    /// Reassembled packet length in bytes when known.
    pub const fn total_len(&self) -> Option<u32> {
        self.total_len
    }

    /// Eviction reason when state was discarded before completion.
    pub const fn eviction_reason(&self) -> Option<&IpDefragEvictionReason> {
        self.eviction_reason.as_ref()
    }

    /// Whether this metadata records a timeout eviction.
    pub const fn timed_out(&self) -> bool {
        matches!(self.eviction_reason, Some(IpDefragEvictionReason::Timeout))
    }

    /// Set a human-readable datagram key summary.
    pub fn with_datagram_key(mut self, datagram_key: impl Into<String>) -> Self {
        self.datagram_key = Some(datagram_key.into());
        self
    }

    /// Set the number of unique fragments accepted for this datagram.
    pub const fn with_fragment_count(mut self, fragment_count: usize) -> Self {
        self.fragment_count = fragment_count;
        self
    }

    /// Set the number of exact duplicate fragments observed.
    pub const fn with_duplicate_count(mut self, duplicate_count: usize) -> Self {
        self.duplicate_count = duplicate_count;
        self
    }

    /// Set the overlap and conflict status.
    pub const fn with_overlap_status(mut self, overlap_status: IpDefragOverlapStatus) -> Self {
        self.overlap_status = overlap_status;
        self
    }

    /// Append one accepted byte range.
    pub fn with_byte_range(mut self, byte_range: IpFragmentRange) -> Self {
        self.byte_ranges.push(byte_range);
        self
    }

    /// Replace accepted byte ranges.
    pub fn with_byte_ranges(
        mut self,
        byte_ranges: impl IntoIterator<Item = IpFragmentRange>,
    ) -> Self {
        self.byte_ranges = byte_ranges.into_iter().collect();
        self
    }

    /// Set the reassembled packet length.
    pub const fn with_total_len(mut self, total_len: u32) -> Self {
        self.total_len = Some(total_len);
        self
    }

    /// Set the state eviction reason.
    pub fn with_eviction_reason(mut self, eviction_reason: IpDefragEvictionReason) -> Self {
        self.eviction_reason = Some(eviction_reason);
        self
    }
}
