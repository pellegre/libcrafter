//! Legacy SIGNAL: IEEE 802.11-2007 17.3.4–17.3.5; evidence in docs/radio.md.
#![allow(dead_code)] // Wired to the streaming DATA receiver in the next increment.
use super::{
    sync::{fft64, Acquisition},
    ComplexSample,
};

/// A validated legacy header is only a candidate: later PHYs share L-SIGNAL.
/// Frame publication still requires DATA decoding and MAC integrity validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalInfo {
    pub rate_bps: u32,
    pub coded_bits_per_symbol: usize,
    pub data_bits_per_symbol: usize,
    pub psdu_bytes: usize,
    pub data_symbols: usize,
    pub data_start: u64,
    /// Exclusive end, excluding ERP's optional signal extension.
    pub end_sample_index: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignalError {
    Truncated { required: usize, available: usize },
    UnsupportedRate,
    Reserved,
    Parity,
    Tail,
    Length,
    SampleOverflow,
    UnusableChannel,
}
impl SignalInfo {
    /// Check an exclusive sample end at EOF; never use chunk size as frame size.
    pub(super) fn check_end(&self, available_end: u64) -> Result<(), SignalError> {
        if available_end < self.end_sample_index {
            Err(SignalError::Truncated {
                required: (self.data_symbols * 80),
                available: available_end
                    .saturating_sub(self.data_start)
                    .min(usize::MAX as u64) as usize,
            })
        } else {
            Ok(())
        }
    }
}

pub(super) fn parse_bits(
    bits: &[u8; 24],
    max_bytes: usize,
    signal_start: u64,
) -> Result<SignalInfo, SignalError> {
    if bits.iter().any(|b| *b > 1) {
        return Err(SignalError::Parity);
    }
    if bits[4] != 0 {
        return Err(SignalError::Reserved);
    }
    if bits[..18].iter().fold(0, |p, b| p ^ b) != 0 {
        return Err(SignalError::Parity);
    }
    if bits[18..].iter().any(|b| *b != 0) {
        return Err(SignalError::Tail);
    }
    // Table 17-5, R1 first; numeric key below is little endian.
    let rate = bits[..4]
        .iter()
        .enumerate()
        .fold(0, |v, (i, b)| v | (*b << i));
    let (mbps, coded, data) = match rate {
        11 => (6, 48, 24),
        15 => (9, 48, 36),
        10 => (12, 96, 48),
        14 => (18, 96, 72),
        9 => (24, 192, 96),
        13 => (36, 192, 144),
        8 => (48, 288, 192),
        12 => (54, 288, 216),
        _ => return Err(SignalError::UnsupportedRate),
    };
    let length = bits[5..17]
        .iter()
        .enumerate()
        .fold(0usize, |v, (i, b)| v | ((*b as usize) << i));
    // No PSDU without a complete integrity trailer is eligible for this receiver.
    if length < 4 || length > max_bytes {
        return Err(SignalError::Length);
    }
    let symbols = (16 + length * 8 + 6usize).div_ceil(data);
    let data_start = signal_start
        .checked_add(80)
        .ok_or(SignalError::SampleOverflow)?;
    let end = data_start
        .checked_add((symbols * 80) as u64)
        .ok_or(SignalError::SampleOverflow)?;
    Ok(SignalInfo {
        rate_bps: mbps * 1_000_000,
        coded_bits_per_symbol: coded,
        data_bits_per_symbol: data,
        psdu_bytes: length,
        data_symbols: symbols,
        data_start,
        end_sample_index: end,
    })
}

/// Soft Viterbi, zero initial memory, unconstrained final state so a corrupt tail
/// is observable rather than silently forced to zero. Fixed 24x64 traceback.
fn viterbi(coded: &[f32; 48]) -> [u8; 24] {
    let mut metric = [f32::INFINITY; 64];
    metric[0] = 0.;
    let mut history = [[0u8; 64]; 24];
    for t in 0..24 {
        let mut next = [f32::INFINITY; 64];
        for (state, cost) in metric.iter().enumerate() {
            for bit in 0..2 {
                let register = (state << 1) | bit;
                // Figure 17-8 generators 133/171, reversed for newest-bit LSB.
                let a = (register & 0o155).count_ones() & 1;
                let b = (register & 0o117).count_ones() & 1;
                let score = cost
                    - coded[2 * t] * (2. * a as f32 - 1.)
                    - coded[2 * t + 1] * (2. * b as f32 - 1.);
                let dest = register & 63;
                if score < next[dest] {
                    next[dest] = score;
                    history[t][dest] = state as u8;
                }
            }
        }
        metric = next;
    }
    let mut state = (0..64)
        .min_by(|a, b| metric[*a].total_cmp(&metric[*b]))
        .unwrap();
    let mut bits = [0; 24];
    for t in (0..24).rev() {
        bits[t] = (state & 1) as u8;
        state = history[t][state] as usize;
    }
    bits
}

pub(super) fn decode_signal(
    samples: &[ComplexSample],
    acquisition: &Acquisition,
    max_bytes: usize,
) -> Result<SignalInfo, SignalError> {
    if samples.len() < 80 {
        return Err(SignalError::Truncated {
            required: 80,
            available: samples.len(),
        });
    }
    let mut time = [ComplexSample::ZERO; 64];
    for n in 0..64 {
        let index = acquisition
            .signal_start
            .checked_add(16 + n as u64)
            .ok_or(SignalError::SampleOverflow)?;
        let elapsed = index
            .checked_sub(acquisition.phase_origin)
            .ok_or(SignalError::SampleOverflow)?;
        time[n] = samples[16 + n].mul(ComplexSample::rotation(
            -acquisition.frequency_rad * elapsed as f32,
        ));
    }
    let bins = fft64(time);
    // SIGNAL pilot polarity index zero: +,+,+,-, ascending signed carrier.
    let mut pilot = ComplexSample::ZERO;
    for (k, sign) in [(43, 1.), (57, 1.), (7, 1.), (21, -1.)] {
        pilot = pilot.add(bins[k].mul(acquisition.channel[k].conj()).scale(sign));
    }
    if !pilot.power().is_finite() || pilot.power() < 1e-12 {
        return Err(SignalError::UnusableChannel);
    }
    let rotation = ComplexSample::rotation(-pilot.phase());
    let mut interleaved = [0.; 48];
    for (j, k) in (-26i32..=26)
        .filter(|k| ![-21, -7, 0, 7, 21].contains(k))
        .enumerate()
    {
        let k = k.rem_euclid(64) as usize;
        // Matched channel weighting avoids amplifying deep fades.
        let value = bins[k].mul(acquisition.channel[k].conj()).mul(rotation).i;
        if !value.is_finite() {
            return Err(SignalError::UnusableChannel);
        }
        interleaved[j] = value;
    }
    // Equations 17-15/16 with NCBPS=48, s=1 (second permutation identity).
    let coded = std::array::from_fn(|k| interleaved[3 * (k % 16) + k / 16]);
    parse_bits(&viterbi(&coded), max_bytes, acquisition.signal_start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radio::sync::{SyncEvent, Synchronizer};
    fn fixture(name: &str) -> (Vec<ComplexSample>, Acquisition) {
        let bytes = std::fs::read(format!(
            "{}/tests/fixtures/iq/ofdm-{name}.cs8",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let samples: Vec<_> = bytes
            .chunks_exact(2)
            .map(|b| ComplexSample {
                i: b[0] as i8 as f32 / 128.,
                q: b[1] as i8 as f32 / 128.,
            })
            .collect();
        let mut sync = Synchronizer::default();
        for (i, s) in samples.iter().enumerate() {
            if let Some(SyncEvent::Acquired(a)) = sync.push(*s, i as u64) {
                return (samples, a);
            }
        }
        panic!("fixture did not acquire")
    }
    #[test]
    fn radio_signal_independent_all_rates_and_impairments() {
        for (ordinal, (rate, ndbps)) in [
            (6, 24),
            (9, 36),
            (12, 48),
            (18, 72),
            (24, 96),
            (36, 144),
            (48, 192),
            (54, 216),
        ]
        .into_iter()
        .enumerate()
        {
            let expected_length = 59 + ordinal;
            let (samples, a) = fixture(&format!("{rate}-clean"));
            let info = decode_signal(&samples[a.signal_start as usize..], &a, 4095).unwrap();
            assert_eq!(info.rate_bps, rate * 1_000_000);
            assert_eq!(info.psdu_bytes, expected_length);
            assert_eq!(info.data_bits_per_symbol, ndbps);
            assert_eq!(
                info.data_symbols,
                (16 + expected_length * 8 + 6usize).div_ceil(ndbps)
            );
            assert_eq!(info.data_start, 437);
            info.check_end(samples.len() as u64).unwrap();
            assert!(info.check_end(info.end_sample_index - 1).is_err());
            assert_eq!(
                decode_signal(&samples[a.signal_start as usize..], &a, 58),
                Err(SignalError::Length)
            );
        }
        for name in ["6-noisy", "6-offset", "6-bad_fcs", "6-truncated"] {
            let (samples, a) = fixture(name);
            let info = decode_signal(&samples[a.signal_start as usize..], &a, 4095).unwrap();
            assert_eq!(info.psdu_bytes, 59);
            if name.ends_with("truncated") {
                assert!(info.check_end(samples.len() as u64).is_err());
            }
        }
        let (samples, a) = fixture("6-invalid_signal");
        assert_eq!(
            decode_signal(&samples[a.signal_start as usize..], &a, 4095),
            Err(SignalError::Parity)
        );
    }
    fn bits() -> [u8; 24] {
        [
            1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }
    #[test]
    fn radio_signal_rejects_header_fields_and_bounds() {
        for i in 18..24 {
            let mut b = bits();
            b[i] = 1;
            assert_eq!(parse_bits(&b, 4095, 0), Err(SignalError::Tail));
        }
        let mut b = bits();
        b[17] ^= 1;
        assert_eq!(parse_bits(&b, 4095, 0), Err(SignalError::Parity));
        let mut b = bits();
        b[4] = 1;
        assert_eq!(parse_bits(&b, 4095, 0), Err(SignalError::Reserved));
        let mut b = bits();
        b[0] = 0;
        b[1] = 0;
        b[3] = 0;
        b[17] = 1;
        assert_eq!(parse_bits(&b, 4095, 0), Err(SignalError::UnsupportedRate));
        for length in [0usize, 1, 3, 4095] {
            let mut b = bits();
            for i in 0..12 {
                b[5 + i] = ((length >> i) & 1) as u8;
            }
            b[17] = b[..17].iter().fold(0, |p, b| p ^ b);
            assert_eq!(parse_bits(&b, 4094, 0), Err(SignalError::Length));
        }
        assert_eq!(
            parse_bits(&bits(), 4095, u64::MAX - 80),
            Err(SignalError::SampleOverflow)
        );
        let (samples, a) = fixture("6-clean");
        for n in [0, 1, 16, 63, 79] {
            assert_eq!(
                decode_signal(&samples[..n], &a, 4095),
                Err(SignalError::Truncated {
                    required: 80,
                    available: n
                })
            );
        }
        assert_eq!(
            decode_signal(&[ComplexSample::ZERO; 80], &a, 4095),
            Err(SignalError::UnusableChannel)
        );
    }
    #[test]
    fn radio_signal_independent_coded_bits_and_error_correction() {
        let published = "111010111010000101101100110101011100000000000000";
        let coded: [f32; 48] = std::array::from_fn(|i| {
            if published.as_bytes()[i] == b'1' {
                1.
            } else {
                -1.
            }
        });
        assert_eq!(viterbi(&coded), bits());
        for i in 0..48 {
            let mut damaged = coded;
            damaged[i] *= -1.;
            assert_eq!(viterbi(&damaged), bits());
        }
        // An unconstrained traceback preserves a nonzero final tail bit.
        let mut invalid = bits();
        invalid[23] = 1;
        let mut state = 0usize;
        let mut coded = [0.; 48];
        for (i, bit) in invalid.iter().enumerate() {
            state = ((state << 1) | *bit as usize) & 127;
            for (j, mask) in [0o155, 0o117].iter().enumerate() {
                coded[2 * i + j] = if (state & mask).count_ones() % 2 == 1 {
                    1.
                } else {
                    -1.
                };
            }
        }
        assert_eq!(
            parse_bits(&viterbi(&coded), 4095, 0),
            Err(SignalError::Tail)
        );
    }
}
