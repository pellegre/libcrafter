//! HE20 SU / ER SU / MU / TB timing, IEEE802.11ax-2021 Equations27-119..122.
use super::SuSignal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Timing {
    pub ltf_symbols: usize,
    pub data_symbols: usize,
    pub midambles: usize,
    /// All offsets are from PPDU start at20Msps, excluding signal extension.
    pub data_start: usize,
    pub data_end: usize,
    pub packet_end: usize,
    pub signaled_end: usize,
    pub pe_samples: usize,
    symbol_samples: usize,
    training_samples: usize,
    midamble_period: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    Rate,
    Length,
    Format,
    Streams,
    Guard,
    Midamble,
    Duration,
    Stbc,
}

struct Layout {
    length: usize,
    m: usize,
    extra_preamble: usize,
    ltf_symbols: usize,
    training_samples: usize,
    symbol_samples: usize,
    period: Option<usize>,
    stbc: bool,
    pe_disambiguity: bool,
}

impl Timing {
    /// Header integrity must already be checked. Timing is not DATA admission.
    pub fn new(rate: u32, length: usize, a: &SuSignal) -> Result<Self, Error> {
        Self::for_format(rate, length, a, false)
    }

    /// Format must already be identified and its (possibly repeated) header checked.
    pub fn for_format(rate: u32, length: usize, a: &SuSignal, er: bool) -> Result<Self, Error> {
        if rate != 6_000_000 {
            return Err(Error::Rate);
        }
        if length > 4095 || length % 3 != 1 + usize::from(er) {
            return Err(Error::Length);
        }
        if a.bandwidth > u8::from(er) {
            return Err(Error::Format);
        }
        let sts = usize::from(a.space_time_streams);
        if !(1..=8).contains(&sts) || (a.stbc && (sts != 2 || a.dcm)) {
            return Err(Error::Streams);
        }
        if er && sts != 1 + usize::from(a.stbc) {
            return Err(Error::Streams);
        }
        let guard = match (a.ltf_size, a.guard_ns) {
            (1, 800) | (2, 800) | (4, 800) => 16,
            (2, 1600) => 32,
            (4, 3200) => 64,
            _ => return Err(Error::Guard),
        };
        if a.stbc && a.ltf_size == 4 && guard == 16 {
            return Err(Error::Guard);
        }
        let period = match a.midamble_period {
            None => None,
            Some(p @ (10 | 20)) if sts <= 4 => Some(usize::from(p)),
            _ => return Err(Error::Midamble),
        };
        let ltf_symbols = [1, 2, 4, 4, 6, 6, 8, 8][sts - 1];
        let training_samples = ltf_symbols * (64 * usize::from(a.ltf_size) + guard);
        let symbol_samples = 256 + guard;
        // L-SIG rounded duration excludes legacy20us. HE preamble here starts
        // at RL-SIG:4us + SIG-A8us + STF4us + LTF(s). SU uses m=2;
        // ER uses m=1 and repeats SIG-A, adding 8us (160 samples).
        let repeat_samples = 160 * usize::from(er);
        Self::resolve(Layout {
            length,
            m: if er { 1 } else { 2 },
            extra_preamble: repeat_samples,
            ltf_symbols,
            training_samples,
            symbol_samples,
            period,
            stbc: a.stbc,
            pe_disambiguity: a.pe_disambiguity,
        })
    }

    /// MU SIG-B duration is already resolved from checked signaling. Spatial
    /// consistency across RUs and DATA decoding are separate admission checks.
    pub fn for_mu(
        rate: u32,
        length: usize,
        a: &crate::radio::he::mu::MuSignal,
        sig_b_symbols: usize,
    ) -> Result<Self, Error> {
        if rate != 6_000_000 {
            return Err(Error::Rate);
        }
        if length > 4095 || length % 3 != 2 {
            return Err(Error::Length);
        }
        if a.bandwidth != 0 || !(1..=36).contains(&sig_b_symbols) {
            return Err(Error::Format);
        }
        let ltf_symbols = usize::from(a.ltf_symbols);
        if !matches!(ltf_symbols, 1 | 2 | 4 | 6 | 8) || (a.stbc && ltf_symbols == 1) {
            return Err(Error::Streams);
        }
        let guard = match (a.ltf_size, a.guard_ns) {
            (2, 800) | (4, 800) => 16,
            (2, 1600) => 32,
            (4, 3200) => 64,
            _ => return Err(Error::Guard),
        };
        let period = match a.midamble_period {
            None => None,
            Some(p @ (10 | 20)) if ltf_symbols <= 4 => Some(usize::from(p)),
            _ => return Err(Error::Midamble),
        };
        Self::resolve(Layout {
            length,
            m: 1,
            extra_preamble: 80 * sig_b_symbols,
            ltf_symbols,
            training_samples: ltf_symbols * (64 * usize::from(a.ltf_size) + guard),
            symbol_samples: 256 + guard,
            period,
            stbc: a.stbc,
            pe_disambiguity: a.pe_disambiguity,
        })
    }

    /// The caller establishes a matching Trigger exchange and checked TB
    /// signaling. Common Info supplies timing, not per-user DATA admission.
    pub fn for_tb(
        rate: u32,
        length: usize,
        common: &crate::Dot11TriggerCommonFields,
    ) -> Result<Self, Error> {
        if rate != 6_000_000 {
            return Err(Error::Rate);
        }
        if length > 4095 || length % 3 != 1 || length != usize::from(common.ul_length) {
            return Err(Error::Length);
        }
        // MU-RTS solicits CTS; NFRP solicits NDP feedback, not TB DATA.
        if common.bandwidth != 0 || !matches!(common.trigger_type, 0..=2 | 4..=6) {
            return Err(Error::Format);
        }
        let (size, guard) = match common.gi_ltf {
            0 => (1, 32),
            1 => (2, 32),
            2 => (4, 64),
            _ => return Err(Error::Guard),
        };
        let code = common.ltf_symbols_midamble;
        let (ltf_symbols, period) = if common.doppler {
            match code {
                0..=2 => ([1, 2, 4][usize::from(code)], Some(10)),
                4..=6 => ([1, 2, 4][usize::from(code - 4)], Some(20)),
                _ => return Err(Error::Midamble),
            }
        } else {
            let count = [1, 2, 4, 6, 8]
                .get(usize::from(code))
                .copied()
                .ok_or(Error::Streams)?;
            (count, None)
        };
        if common.stbc && ltf_symbols == 1 {
            return Err(Error::Streams);
        }
        Self::resolve(Layout {
            length,
            m: 2,
            // TB's STF is8us, four more than the base SU timeline. No SIG-B.
            extra_preamble: 80,
            ltf_symbols,
            training_samples: ltf_symbols * (64 * size + guard),
            symbol_samples: 256 + guard,
            period,
            stbc: common.stbc,
            pe_disambiguity: common.pe_disambiguity,
        })
    }

    fn resolve(layout: Layout) -> Result<Self, Error> {
        let Layout {
            length,
            m,
            extra_preamble: repeat_samples,
            ltf_symbols,
            training_samples,
            symbol_samples,
            period,
            stbc,
            pe_disambiguity,
        } = layout;
        let rounded = (length + m + 3) / 3 * 80;
        let available = rounded
            .checked_sub(320 + repeat_samples + training_samples)
            .ok_or(Error::Duration)?;
        let b = usize::from(pe_disambiguity);
        let midambles = period.map_or(0, |p| {
            available.saturating_sub((b + 2) * symbol_samples)
                / (p * symbol_samples + training_samples)
        });
        let remaining = available
            .checked_sub(midambles * training_samples)
            .ok_or(Error::Duration)?;
        let data_symbols = (remaining / symbol_samples)
            .checked_sub(b)
            .ok_or(Error::Duration)?;
        if data_symbols == 0 {
            return Err(Error::Duration);
        } // Sounding NDP is separate.
        if stbc && data_symbols % 2 != 0 {
            return Err(Error::Stbc);
        }
        if period.map_or(0, |p| data_symbols.saturating_sub(2) / p) != midambles {
            return Err(Error::Midamble);
        }
        let leftover = remaining - data_symbols * symbol_samples;
        let pe_samples = leftover / 80 * 80;
        if pe_samples > 320 {
            return Err(Error::Duration);
        }
        let data_start = 720 + repeat_samples + training_samples;
        let data_end = data_start + data_symbols * symbol_samples + midambles * training_samples;
        Ok(Self {
            ltf_symbols,
            data_symbols,
            midambles,
            data_start,
            data_end,
            packet_end: data_end + pe_samples,
            signaled_end: 400 + rounded,
            pe_samples,
            symbol_samples,
            training_samples,
            midamble_period: period,
        })
    }

    /// Beginning of DATA symbol CP, skipping inserted training periods.
    pub fn symbol_start(&self, symbol: usize) -> Option<usize> {
        if symbol >= self.data_symbols {
            return None;
        }
        let preceding = self
            .midamble_period
            .map_or(0, |p| (symbol / p).min(self.midambles));
        Some(self.data_start + symbol * self.symbol_samples + preceding * self.training_samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn radio_he_tb_timing_forward() {
        let rows = include_str!("../../../tests/fixtures/iq/he-tb-timing.tsv");
        assert_eq!(rows.lines().skip(1).count(), 3315);
        for row in rows.lines().skip(1) {
            let columns: Vec<_> = row.split('\t').collect();
            let c: Vec<usize> = columns[..14].iter().map(|s| s.parse().unwrap()).collect();
            let common = crate::Dot11TriggerCommonFields {
                gi_ltf: c[0] as u8,
                ltf_symbols_midamble: c[1] as u8,
                doppler: c[2] != 0,
                stbc: c[3] != 0,
                ul_length: c[6] as u16,
                pe_disambiguity: c[7] != 0,
                ..Default::default()
            };
            let t =
                Timing::for_tb(6_000_000, c[6], &common).unwrap_or_else(|e| panic!("{row}: {e:?}"));
            assert_eq!(
                [
                    t.ltf_symbols,
                    t.data_symbols,
                    t.pe_samples,
                    t.midambles,
                    t.data_start,
                    t.data_end,
                    t.packet_end,
                    t.signaled_end
                ],
                [c[8], c[4], c[5], c[9], c[10], c[11], c[12], c[13]],
                "{row}"
            );
            let mut hash = Sha256::new();
            for i in 0..t.data_symbols {
                hash.update((t.symbol_start(i).unwrap() as u32).to_le_bytes());
            }
            assert_eq!(format!("{:x}", hash.finalize()), columns[14], "{row}");
            assert!(t.symbol_start(t.data_symbols).is_none());
            assert!(t.symbol_start(usize::MAX).is_none());
        }
    }

    #[test]
    fn radio_he_tb_timing_rejects_inconsistent_or_reserved_context() {
        let mut common = crate::Dot11TriggerCommonFields::default();
        assert!(Timing::for_tb(6_000_000, 301, &common).is_ok());
        for rate in [0, 12_000_000, u32::MAX] {
            assert_eq!(Timing::for_tb(rate, 301, &common), Err(Error::Rate));
        }
        for length in [0, 1, 300, 302, 304, 4096, usize::MAX] {
            assert_eq!(
                Timing::for_tb(6_000_000, length, &common),
                Err(Error::Length)
            );
        }
        for variant in [3, 7, 8, 15, 255] {
            common.trigger_type = variant;
            assert_eq!(Timing::for_tb(6_000_000, 301, &common), Err(Error::Format));
        }
        common.trigger_type = 0;
        for bandwidth in [1, 2, 3, 255] {
            common.bandwidth = bandwidth;
            assert_eq!(Timing::for_tb(6_000_000, 301, &common), Err(Error::Format));
        }
        common.bandwidth = 0;
        for gi in [3, 4, 255] {
            common.gi_ltf = gi;
            assert_eq!(Timing::for_tb(6_000_000, 301, &common), Err(Error::Guard));
        }
        common.gi_ltf = 1;
        for code in [5, 6, 7, 255] {
            common.ltf_symbols_midamble = code;
            assert_eq!(Timing::for_tb(6_000_000, 301, &common), Err(Error::Streams));
        }
        common.doppler = true;
        for code in [3, 7, 8, 255] {
            common.ltf_symbols_midamble = code;
            assert_eq!(
                Timing::for_tb(6_000_000, 301, &common),
                Err(Error::Midamble)
            );
        }
        common.doppler = false;
        common.ltf_symbols_midamble = 0;
        common.stbc = true;
        assert_eq!(Timing::for_tb(6_000_000, 301, &common), Err(Error::Streams));
        common.ltf_symbols_midamble = 1;
        common.ul_length = 34;
        assert_eq!(Timing::for_tb(6_000_000, 34, &common), Err(Error::Stbc));
        common.stbc = false;
        common.ul_length = 1;
        assert_eq!(Timing::for_tb(6_000_000, 1, &common), Err(Error::Duration));
    }

    fn mu_header() -> crate::radio::he::mu::MuSignal {
        let row = include_str!("../../../tests/fixtures/iq/he-mu-signal-a-index.tsv")
            .lines()
            .nth(1)
            .unwrap();
        let bits: Vec<_> = row
            .split('\t')
            .next()
            .unwrap()
            .bytes()
            .map(|b| b - b'0')
            .collect();
        crate::radio::he::mu::MuSignal::decode(&bits).unwrap()
    }

    #[test]
    fn radio_he_mu_timing_forward() {
        let rows = include_str!("../../../tests/fixtures/iq/he-mu-timing.tsv");
        assert_eq!(rows.lines().skip(1).count(), 26529);
        for row in rows.lines().skip(1) {
            let columns: Vec<_> = row.split('\t').collect();
            let c: Vec<usize> = columns[..15].iter().map(|s| s.parse().unwrap()).collect();
            let mut a = mu_header();
            a.bandwidth = 0;
            a.ltf_symbols = c[0] as u8;
            a.ltf_size = c[1] as u8;
            a.guard_ns = c[2] as u16;
            a.midamble_period = (c[3] != 0).then_some(c[3] as u8);
            a.stbc = c[4] != 0;
            a.pe_disambiguity = c[9] != 0;
            let t = Timing::for_mu(6_000_000, c[8], &a, c[5])
                .unwrap_or_else(|e| panic!("{row}: {e:?}"));
            assert_eq!(
                [
                    t.ltf_symbols,
                    t.data_symbols,
                    t.pe_samples,
                    t.midambles,
                    t.data_start,
                    t.data_end,
                    t.packet_end,
                    t.signaled_end
                ],
                [c[0], c[6], c[7], c[10], c[11], c[12], c[13], c[14]],
                "{row}"
            );
            let mut hash = Sha256::new();
            for i in 0..t.data_symbols {
                hash.update((t.symbol_start(i).unwrap() as u32).to_le_bytes());
            }
            assert_eq!(format!("{:x}", hash.finalize()), columns[15], "{row}");
            assert!(t.symbol_start(t.data_symbols).is_none());
            assert!(t.symbol_start(usize::MAX).is_none());
        }
    }

    #[test]
    fn radio_he_mu_timing_bounds() {
        let mut a = mu_header();
        a.bandwidth = 0;
        a.ltf_symbols = 2;
        a.ltf_size = 4;
        a.guard_ns = 800;
        a.midamble_period = None;
        a.stbc = false;
        a.pe_disambiguity = false;
        for rate in [0, 12_000_000, u32::MAX] {
            assert_eq!(Timing::for_mu(rate, 302, &a, 1), Err(Error::Rate));
        }
        for length in [0, 1, 3, 301, 4095, 4096, usize::MAX] {
            assert_eq!(Timing::for_mu(6_000_000, length, &a, 1), Err(Error::Length));
        }
        for count in [0, 37, usize::MAX] {
            assert_eq!(
                Timing::for_mu(6_000_000, 302, &a, count),
                Err(Error::Format)
            );
        }
        a.bandwidth = 1;
        assert_eq!(Timing::for_mu(6_000_000, 302, &a, 1), Err(Error::Format));
        a.bandwidth = 0;
        for count in [0, 3, 5, 7, 9, 255] {
            a.ltf_symbols = count;
            assert_eq!(Timing::for_mu(6_000_000, 302, &a, 1), Err(Error::Streams));
        }
        a.ltf_symbols = 2;
        for (size, gi) in [(1, 800), (2, 3200), (4, 1600), (255, 800)] {
            a.ltf_size = size;
            a.guard_ns = gi;
            assert_eq!(Timing::for_mu(6_000_000, 302, &a, 1), Err(Error::Guard));
        }
        a.ltf_size = 4;
        a.guard_ns = 800;
        a.midamble_period = Some(11);
        assert_eq!(Timing::for_mu(6_000_000, 302, &a, 1), Err(Error::Midamble));
        a.midamble_period = Some(10);
        a.ltf_symbols = 6;
        assert_eq!(Timing::for_mu(6_000_000, 302, &a, 1), Err(Error::Midamble));
        a.midamble_period = None;
        a.ltf_symbols = 2;
        a.stbc = true;
        assert_eq!(Timing::for_mu(6_000_000, 44, &a, 1), Err(Error::Stbc));
        a.ltf_symbols = 1;
        assert_eq!(Timing::for_mu(6_000_000, 302, &a, 1), Err(Error::Streams));
        a.ltf_symbols = 2;
        a.stbc = false;
        assert_eq!(Timing::for_mu(6_000_000, 2, &a, 1), Err(Error::Duration));
    }
    fn header() -> SuSignal {
        SuSignal::decode(
            &b"1000000000000010000000000000000000100000100111000000"
                .iter()
                .map(|b| b - b'0')
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn radio_he_timing_independent_forward_timeline() {
        forward_timeline(
            include_str!("../../../tests/fixtures/iq/he-timing-index.tsv"),
            false,
            10252,
        );
    }

    #[test]
    fn radio_he_er_timing_independent_forward_timeline() {
        forward_timeline(
            include_str!("../../../tests/fixtures/iq/he-er-timing-index.tsv"),
            true,
            2479,
        );
    }

    fn forward_timeline(index: &str, er: bool, expected: usize) {
        let mut count = 0;
        for row in index.lines().skip(1) {
            let fields: Vec<_> = row.split('\t').collect();
            let c: Vec<usize> = fields[..15].iter().map(|v| v.parse().unwrap()).collect();
            let mut a = header();
            a.space_time_streams = c[0] as u8;
            a.ltf_size = c[1] as u8;
            a.guard_ns = c[2] as u16;
            a.midamble_period = (c[3] != 0).then_some(c[3] as u8);
            a.stbc = c[4] != 0;
            a.pe_disambiguity = c[8] != 0;
            let t = Timing::for_format(6_000_000, c[7], &a, er)
                .unwrap_or_else(|e| panic!("{row}: {e:?}"));
            if er {
                a.bandwidth = 1;
                assert_eq!(Timing::for_format(6_000_000, c[7], &a, true), Ok(t));
            }
            assert_eq!(
                [
                    t.data_symbols,
                    t.pe_samples,
                    t.ltf_symbols,
                    t.midambles,
                    t.data_start,
                    t.data_end,
                    t.packet_end,
                    t.signaled_end
                ],
                [c[5], c[6], c[9], c[10], c[11], c[12], c[13], c[14]],
                "{row}"
            );
            let mut digest = Sha256::new();
            for symbol in 0..t.data_symbols {
                digest.update((t.symbol_start(symbol).unwrap() as u32).to_le_bytes());
            }
            assert_eq!(format!("{:x}", digest.finalize()), fields[15], "{row}");
            assert!(t.symbol_start(t.data_symbols).is_none());
            assert!(t.symbol_start(usize::MAX).is_none());
            count += 1;
        }
        assert_eq!(count, expected);
    }

    #[test]
    fn radio_he_er_timing_invalid_fields_and_lengths() {
        let mut a = header();
        for rate in [0, 12_000_000, u32::MAX] {
            assert_eq!(Timing::for_format(rate, 302, &a, true), Err(Error::Rate));
        }
        for length in [0, 1, 3, 301, 4095, 4096, usize::MAX] {
            assert_eq!(
                Timing::for_format(6_000_000, length, &a, true),
                Err(Error::Length)
            );
        }
        for sts in [0, 2, 3, 8, 9, 255] {
            a.space_time_streams = sts;
            assert_eq!(
                Timing::for_format(6_000_000, 302, &a, true),
                Err(Error::Streams)
            );
        }
        a = header();
        for bandwidth in [2, 3, 255] {
            a.bandwidth = bandwidth;
            assert_eq!(
                Timing::for_format(6_000_000, 302, &a, true),
                Err(Error::Format)
            );
        }
        a = header();
        for length in 0..=4095 {
            for b in [false, true] {
                a.pe_disambiguity = b;
                if let Ok(t) = Timing::for_format(6_000_000, length, &a, true) {
                    assert_eq!((t.packet_end - 400).div_ceil(80) * 3 - 4, length);
                    assert_eq!(
                        t.pe_samples + t.signaled_end - t.packet_end >= t.symbol_samples,
                        b
                    );
                    assert_eq!(
                        t.symbol_start(t.data_symbols - 1).unwrap() + t.symbol_samples,
                        t.data_end
                    );
                }
            }
        }
    }

    #[test]
    fn radio_he_timing_invalid_fields_and_lengths() {
        let a = header();
        assert_eq!(Timing::new(12_000_000, 301, &a), Err(Error::Rate));
        for length in [0, 2, 3, 4095, 4096, usize::MAX] {
            assert_eq!(Timing::new(6_000_000, length, &a), Err(Error::Length));
        }
        for sts in [0, 9, 255] {
            let mut bad = a;
            bad.space_time_streams = sts;
            assert_eq!(Timing::new(6_000_000, 301, &bad), Err(Error::Streams));
        }
        for (size, guard) in [(0, 800), (1, 1600), (2, 3200), (3, 800), (4, 1600)] {
            let mut bad = a;
            bad.ltf_size = size;
            bad.guard_ns = guard;
            assert_eq!(Timing::new(6_000_000, 301, &bad), Err(Error::Guard));
        }
        let mut bad = a;
        bad.midamble_period = Some(11);
        assert_eq!(Timing::new(6_000_000, 301, &bad), Err(Error::Midamble));
        bad.midamble_period = Some(10);
        bad.space_time_streams = 5;
        assert_eq!(Timing::new(6_000_000, 301, &bad), Err(Error::Midamble));
        bad = a;
        bad.stbc = true;
        bad.space_time_streams = 4;
        assert_eq!(Timing::new(6_000_000, 301, &bad), Err(Error::Streams));
        bad.space_time_streams = 2;
        bad.dcm = true;
        assert_eq!(Timing::new(6_000_000, 301, &bad), Err(Error::Streams));
        bad = a;
        bad.bandwidth = 1;
        assert_eq!(Timing::new(6_000_000, 301, &bad), Err(Error::Format));
        assert_eq!(Timing::new(6_000_000, 1, &a), Err(Error::Duration));
        // Exhaustive L-SIG domain checks: accepted timelines reproduce its
        // rounded duration and PE disambiguity, without unsigned underflow.
        for length in 0..=4095 {
            for b in [false, true] {
                let mut a = a;
                a.pe_disambiguity = b;
                if let Ok(t) = Timing::new(6_000_000, length, &a) {
                    assert_eq!((t.packet_end - 400).div_ceil(80) * 3 - 5, length);
                    assert_eq!(
                        t.pe_samples + t.signaled_end - t.packet_end >= t.symbol_samples,
                        b
                    );
                    assert_eq!(
                        t.symbol_start(t.data_symbols - 1).unwrap() + t.symbol_samples,
                        t.data_end
                    );
                }
            }
        }
    }
}
