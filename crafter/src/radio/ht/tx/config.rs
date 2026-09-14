//! Public HT20 transmit selections and resource bounds.

use crate::radio::{RadioError, WifiFcsPolicy};

/// One independent spatial-stream HT20 modulation and coding scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HtMcs {
    Mcs0,
    Mcs1,
    Mcs2,
    Mcs3,
    Mcs4,
    Mcs5,
    Mcs6,
    Mcs7,
}

impl HtMcs {
    pub const ALL: [Self; 8] = [
        Self::Mcs0,
        Self::Mcs1,
        Self::Mcs2,
        Self::Mcs3,
        Self::Mcs4,
        Self::Mcs5,
        Self::Mcs6,
        Self::Mcs7,
    ];

    pub const fn index(self) -> u8 {
        self as u8
    }

    pub const fn rate_bps(self, guard_interval: HtGuardInterval) -> u32 {
        let (_, data_bits) = self.parameters();
        data_bits as u32 * 20_000_000 / guard_interval.symbol_samples() as u32
    }

    pub(super) const fn parameters(self) -> (usize, usize) {
        [
            (1, 26),
            (2, 52),
            (2, 78),
            (4, 104),
            (4, 156),
            (6, 208),
            (6, 234),
            (6, 260),
        ][self as usize]
    }
}

impl TryFrom<u8> for HtMcs {
    type Error = RadioError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::ALL
            .get(value as usize)
            .copied()
            .ok_or(RadioError::Invalid {
                field: "mcs",
                reason: "single-stream HT20 transmission requires MCS 0 through 7",
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HtFormat {
    #[default]
    Mixed,
    Greenfield,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HtCoding {
    #[default]
    Bcc,
    Ldpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HtGuardInterval {
    Short,
    #[default]
    Long,
}

impl HtGuardInterval {
    pub const fn samples(self) -> usize {
        match self {
            Self::Short => 8,
            Self::Long => 16,
        }
    }

    const fn symbol_samples(self) -> usize {
        64 + self.samples()
    }
}

/// Bounded HT20 transmit configuration. Construction opens no device.
#[derive(Debug, Clone, PartialEq)]
pub struct HtTxConfig {
    pub mcs: HtMcs,
    pub fcs: WifiFcsPolicy,
    pub format: HtFormat,
    pub coding: HtCoding,
    pub guard_interval: HtGuardInterval,
    pub scrambler_seed: u8,
    pub leading_samples: usize,
    pub trailing_samples: usize,
    pub scale: f64,
    pub max_psdu_bytes: usize,
    pub max_samples: usize,
    pub ht_signal_override: Option<[u8; 48]>,
    pub legacy_signal_override: Option<[u8; 24]>,
}

impl HtTxConfig {
    pub fn new(mcs: HtMcs) -> Self {
        Self {
            mcs,
            fcs: WifiFcsPolicy::Auto,
            format: HtFormat::Mixed,
            coding: HtCoding::Bcc,
            guard_interval: HtGuardInterval::Long,
            scrambler_seed: 0x5d,
            leading_samples: 64,
            trailing_samples: 64,
            scale: 300.0,
            max_psdu_bytes: 4095,
            max_samples: 10_000_000,
            ht_signal_override: None,
            legacy_signal_override: None,
        }
    }

    pub fn with_format(mut self, format: HtFormat) -> Self {
        self.format = format;
        self
    }

    pub fn with_fcs(mut self, fcs: WifiFcsPolicy) -> Self {
        self.fcs = fcs;
        self
    }

    pub fn with_coding(mut self, coding: HtCoding) -> Self {
        self.coding = coding;
        self
    }

    pub fn with_guard_interval(mut self, guard_interval: HtGuardInterval) -> Self {
        self.guard_interval = guard_interval;
        self
    }
}
