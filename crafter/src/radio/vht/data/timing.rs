//! VHT timing: Tables 21-5/12/13 and Equations 21-24/109/110 (802.11-2020).
#![allow(dead_code)] // Used by VHT streaming integration after independent tests.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Timing {
    pub ltf_symbols: usize,
    pub data_symbols: usize,
    /// Offsets from the PPDU start, at 20 Msps, not from L-SIG.
    pub data_start: usize,
    pub data_end: usize,
    /// L-SIG's rounded duration; not necessarily the last DATA sample.
    pub signaled_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Rate,
    Length,
    Streams,
    Duration,
    GuardInterval,
    StbcGrouping,
}

impl Timing {
    /// Input headers must already have passed their integrity checks. This
    /// checks timing consistency, not MCS/FEC admission or SIG-B/SERVICE.
    pub fn new(
        l_sig_rate_bps: u32,
        l_sig_length: usize,
        space_time_streams: u8,
        short_gi: bool,
        disambiguation: bool,
        stbc: bool,
    ) -> Result<Self, Error> {
        if l_sig_rate_bps != 6_000_000 {
            return Err(Error::Rate);
        }
        if l_sig_length > 4095 || l_sig_length % 3 != 0 {
            return Err(Error::Length);
        }
        if !(1..=8).contains(&space_time_streams) || (stbc && space_time_streams % 2 != 0) {
            return Err(Error::Streams);
        }
        let ltf_symbols = [1, 2, 4, 4, 6, 6, 8, 8][usize::from(space_time_streams - 1)];
        let legacy_units = l_sig_length / 3 + 1;
        let data_units = legacy_units
            .checked_sub(4 + ltf_symbols)
            .ok_or(Error::Duration)?;
        let data_symbols = if short_gi {
            let symbols = (10 * data_units / 9)
                .checked_sub(usize::from(disambiguation))
                .ok_or(Error::GuardInterval)?;
            if (symbols % 10 == 9) != disambiguation || (9 * symbols).div_ceil(10) != data_units {
                return Err(Error::GuardInterval);
            }
            symbols
        } else {
            if disambiguation {
                return Err(Error::GuardInterval);
            }
            data_units
        };
        if stbc && data_symbols % 2 != 0 {
            return Err(Error::StbcGrouping);
        }
        let data_start = 720 + 80 * ltf_symbols;
        let data_end = data_start + data_symbols * if short_gi { 72 } else { 80 };
        let signaled_end = 400 + 80 * legacy_units;
        Ok(Self {
            ltf_symbols,
            data_symbols,
            data_start,
            data_end,
            signaled_end,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_vht_timing_independent_forward_cases() {
        let rows: Vec<_> = include_str!("../../../../tests/fixtures/iq/vht-timing-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 1105);
        for row in rows {
            let c: Vec<usize> = row.split('\t').map(|v| v.parse().unwrap()).collect();
            let timing =
                Timing::new(6_000_000, c[4], c[0] as u8, c[1] != 0, c[5] != 0, c[2] != 0).unwrap();
            assert_eq!(
                timing,
                Timing {
                    ltf_symbols: c[6],
                    data_symbols: c[3],
                    data_start: c[7],
                    data_end: c[8],
                    signaled_end: c[9]
                }
            );
            assert!(timing.data_end <= timing.signaled_end);
            assert!(timing.signaled_end - timing.data_end < 80);
        }
    }
    #[test]
    fn radio_vht_timing_exhaustive_header_bounds() {
        for streams in 0..=255u8 {
            for stbc in [false, true] {
                let result = Timing::new(6_000_000, 300, streams, false, false, stbc);
                assert_eq!(
                    matches!(result, Err(Error::Streams)),
                    !(1..=8).contains(&streams) || (stbc && streams % 2 != 0)
                );
            }
        }
        // Two training fields: length 300 leaves 95 DATA symbols, which
        // cannot form STBC pairs; length 303 leaves 96 and is valid.
        assert_eq!(
            Timing::new(6_000_000, 300, 2, false, false, true),
            Err(Error::StbcGrouping)
        );
        assert_eq!(
            Timing::new(6_000_000, 303, 2, false, false, true)
                .unwrap()
                .data_symbols,
            96
        );
        for length in [4096, 4097, usize::MAX] {
            assert_eq!(
                Timing::new(6_000_000, length, 1, false, false, false),
                Err(Error::Length)
            );
        }
        for rate in [0, 1, 12_000_000, u32::MAX] {
            assert_eq!(
                Timing::new(rate, 12, 1, false, false, false),
                Err(Error::Rate)
            );
        }
        for length in 0..=4095 {
            for short in [false, true] {
                for disambiguation in [false, true] {
                    let result = Timing::new(6_000_000, length, 1, short, disambiguation, false);
                    if length % 3 != 0 {
                        assert_eq!(result, Err(Error::Length));
                        continue;
                    }
                    if length < 12 {
                        assert_eq!(result, Err(Error::Duration));
                        continue;
                    }
                    let units = length / 3 - 4;
                    // Enumerate forward-valid candidates, not the inverse formula.
                    let candidates: Vec<_> = (0..=1512usize)
                        .filter(|n| {
                            let duration = if short { (72 * n).div_ceil(80) } else { *n };
                            duration == units && (short && n % 10 == 9) == disambiguation
                        })
                        .collect();
                    assert!(candidates.len() <= 1);
                    assert_eq!(
                        result.ok().map(|t| t.data_symbols),
                        candidates.first().copied(),
                        "len={length} short={short} dis={disambiguation}"
                    );
                }
            }
        }
    }
}
