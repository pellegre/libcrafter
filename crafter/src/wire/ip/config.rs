//! Shared configuration for IP wire transforms.

/// Configuration for the receive-side IP defragmentation transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpDefragConfig {
    pass_non_fragments: bool,
}

impl IpDefragConfig {
    /// Create the default IP defragmentation configuration.
    pub const fn new() -> Self {
        Self {
            pass_non_fragments: true,
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
    honor_dont_fragment: bool,
}

impl IpFragmentConfig {
    /// Create an IP fragmentation configuration with an explicit MTU.
    pub const fn new(mtu: usize) -> Self {
        Self {
            mtu,
            honor_dont_fragment: true,
        }
    }

    /// Configured MTU in octets.
    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    /// Configure whether IPv4 Don't Fragment is honored.
    pub const fn honor_dont_fragment(mut self, honor_dont_fragment: bool) -> Self {
        self.honor_dont_fragment = honor_dont_fragment;
        self
    }

    /// Whether IPv4 Don't Fragment is honored.
    pub const fn honors_dont_fragment(&self) -> bool {
        self.honor_dont_fragment
    }
}
