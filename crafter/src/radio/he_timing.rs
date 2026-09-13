//! HE20 SU timing, IEEE802.11ax-2021 Equations27-119..122.
use super::he::SuSignal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Timing {
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
pub(super) enum Error {
    Rate,
    Length,
    Format,
    Streams,
    Guard,
    Midamble,
    Duration,
    Stbc,
}

impl Timing {
    /// Header integrity must already be checked. Timing is not DATA admission.
    pub fn new(rate: u32, length: usize, a: &SuSignal) -> Result<Self, Error> {
        if rate != 6_000_000 {
            return Err(Error::Rate);
        }
        if length > 4095 || length % 3 != 1 {
            return Err(Error::Length);
        }
        if a.bandwidth != 0 {
            return Err(Error::Format);
        }
        let sts = usize::from(a.space_time_streams);
        if !(1..=8).contains(&sts) || (a.stbc && (sts != 2 || a.dcm)) {
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
        // at RL-SIG:4us + SIG-A8us + STF4us + LTF(s). SU uses m=2.
        let rounded = (length + 5) / 3 * 80;
        let available = rounded
            .checked_sub(320 + training_samples)
            .ok_or(Error::Duration)?;
        let b = usize::from(a.pe_disambiguity);
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
        if a.stbc && data_symbols % 2 != 0 {
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
        let data_start = 720 + training_samples;
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
        let mut count = 0;
        for row in include_str!("../../tests/fixtures/iq/he-timing-index.tsv")
            .lines()
            .skip(1)
        {
            let fields: Vec<_> = row.split('\t').collect();
            let c: Vec<usize> = fields[..15].iter().map(|v| v.parse().unwrap()).collect();
            let mut a = header();
            a.space_time_streams = c[0] as u8;
            a.ltf_size = c[1] as u8;
            a.guard_ns = c[2] as u16;
            a.midamble_period = (c[3] != 0).then_some(c[3] as u8);
            a.stbc = c[4] != 0;
            a.pe_disambiguity = c[8] != 0;
            let t = Timing::new(6_000_000, c[7], &a).unwrap_or_else(|e| panic!("{row}: {e:?}"));
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
        assert_eq!(count, 10252);
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
