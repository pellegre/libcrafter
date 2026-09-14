//! Deterministic single-stream HT20 transmission (IEEE 802.11-2020 clause 19).

use super::HtSignalFields;
use crate::radio::{
    ofdm_tx::{self as ofdm, Complex},
    RadioError, RadioResult, WifiFcsPolicy,
};
use std::f64::consts::PI;

const DATA_CARRIERS: [i32; 52] = [
    -28, -27, -26, -25, -24, -23, -22, -20, -19, -18, -17, -16, -15, -14, -13, -12, -11, -10, -9,
    -8, -6, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    22, 23, 24, 25, 26, 27, 28,
];

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

    const fn parameters(self) -> (usize, usize) {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtSignalBits {
    pub transmitted: [u8; 48],
    pub derived: [u8; 48],
    pub explicit: bool,
}

/// Inspectable owned output for one MAC-frame-to-HT20-IQ conversion.
#[derive(Debug, Clone, PartialEq)]
pub struct HtTransmission {
    pub mac_bytes: Vec<u8>,
    pub psdu_bytes: Vec<u8>,
    pub cs8: Vec<i8>,
    pub mcs: HtMcs,
    pub format: HtFormat,
    pub coding: HtCoding,
    pub guard_interval: HtGuardInterval,
    pub ht_signal: HtSignalBits,
    pub legacy_signal: Option<ofdm::OfdmSignalFields>,
    pub data_symbols: usize,
    pub scrambler_seed: u8,
    pub sample_rate_hz: u32,
    pub leading_samples: usize,
    pub preamble_samples: usize,
    pub signal_samples: usize,
    pub data_samples: usize,
    pub trailing_samples: usize,
    pub scale: f64,
    pub explicit_fcs: bool,
}

impl HtTransmission {
    /// Encode MAC bytes without an FCS. An explicit four-byte FCS is emitted verbatim.
    pub fn encode(
        mac_bytes: &[u8],
        explicit_fcs: Option<[u8; 4]>,
        config: &HtTxConfig,
    ) -> RadioResult<Self> {
        validate_config(config)?;
        let psdu_len = mac_bytes.len().checked_add(4).ok_or(RadioError::Overflow {
            context: "HT PSDU length",
        })?;
        if psdu_len > config.max_psdu_bytes || psdu_len > 4095 {
            return Err(RadioError::Limit {
                context: "HT PSDU bytes",
                limit: config.max_psdu_bytes.min(4095) as u64,
                actual: psdu_len as u64,
            });
        }
        let mut psdu = Vec::with_capacity(psdu_len);
        psdu.extend_from_slice(mac_bytes);
        psdu.extend_from_slice(
            &explicit_fcs.unwrap_or_else(|| ofdm::crc32(mac_bytes).to_le_bytes()),
        );

        let (bits_per_subcarrier, data_bits_per_symbol) = config.mcs.parameters();
        let payload_bits = psdu_len
            .checked_mul(8)
            .and_then(|value| value.checked_add(22))
            .ok_or(RadioError::Overflow {
                context: "HT DATA bits",
            })?;
        let symbols = payload_bits.div_ceil(data_bits_per_symbol);
        let data_bits_len =
            symbols
                .checked_mul(data_bits_per_symbol)
                .ok_or(RadioError::Overflow {
                    context: "HT padded DATA bits",
                })?;
        let guard = config.guard_interval.samples();
        let data_samples = symbols
            .checked_mul(64 + guard)
            .ok_or(RadioError::Overflow {
                context: "HT DATA samples",
            })?;

        if config.coding == HtCoding::Ldpc {
            return Err(RadioError::Invalid {
                field: "coding",
                reason: "HT LDPC transmission is not available",
            });
        }
        let mut data = vec![0; 16];
        ofdm::append_lsb_bits(&mut data, &psdu);
        data.resize(data_bits_len, 0);
        let mut scrambled = ofdm::scramble(&data, config.scrambler_seed);
        let tail_start = 16 + psdu_len * 8;
        scrambled[tail_start..tail_start + 6].fill(0);
        let coded = puncture(&ofdm::convolutional_encode(&scrambled), config.mcs);

        let derived_fields = HtSignalFields {
            mcs: config.mcs.index(),
            channel_width_40_mhz: false,
            psdu_bytes: psdu_len as u16,
            smoothing: true,
            not_sounding: true,
            aggregation: false,
            stbc: 0,
            ldpc: false,
            short_guard_interval: config.guard_interval == HtGuardInterval::Short,
            extension_spatial_streams: 0,
        };
        let derived_ht_signal = derived_fields.encode();
        let transmitted_ht_signal = config.ht_signal_override.unwrap_or(derived_ht_signal);
        validate_bits("ht_signal_override", &transmitted_ht_signal)?;
        let header = ofdm::convolutional_encode(&transmitted_ht_signal);

        let legacy_length = 3 * (4 + (symbols * (64 + guard)).div_ceil(80)) - 3;
        let derived_legacy_signal = ofdm::signal_bits([1, 1, 0, 1], legacy_length);
        let transmitted_legacy_signal = config
            .legacy_signal_override
            .unwrap_or(derived_legacy_signal);
        validate_bits("legacy_signal_override", &transmitted_legacy_signal)?;

        let preamble_samples = match config.format {
            HtFormat::Mixed => 560,
            HtFormat::Greenfield => 320,
        };
        let signal_samples = 160;
        let sample_count = config
            .leading_samples
            .checked_add(preamble_samples)
            .and_then(|value| value.checked_add(signal_samples))
            .and_then(|value| value.checked_add(data_samples))
            .and_then(|value| value.checked_add(config.trailing_samples))
            .ok_or(RadioError::Overflow {
                context: "HT waveform samples",
            })?;
        if sample_count > config.max_samples {
            return Err(RadioError::Limit {
                context: "HT waveform samples",
                limit: config.max_samples as u64,
                actual: sample_count as u64,
            });
        }
        sample_count.checked_mul(2).ok_or(RadioError::Overflow {
            context: "HT CS8 bytes",
        })?;

        let training = ht_training();
        let mut wave = Vec::with_capacity(sample_count);
        wave.resize(config.leading_samples, Complex::ZERO);
        match config.format {
            HtFormat::Mixed => {
                wave.extend(ofdm::preamble());
                let legacy =
                    ofdm::interleave(&ofdm::convolutional_encode(&transmitted_legacy_signal), 1);
                wave.extend(ofdm::ofdm_symbol(&legacy, 1, 1));
            }
            HtFormat::Greenfield => {
                wave.extend_from_slice(&ofdm::preamble()[..160]);
                wave.extend_from_slice(&training[32..]);
                wave.extend_from_slice(&training);
                wave.extend_from_slice(&training);
            }
        }
        for symbol in 0..2 {
            let bits = ofdm::interleave(&header[symbol * 48..(symbol + 1) * 48], 1);
            wave.extend(ht_signal_symbol(&bits));
        }
        if config.format == HtFormat::Mixed {
            wave.extend_from_slice(&ofdm::preamble()[..80]);
            wave.extend_from_slice(&training[48..]);
            wave.extend_from_slice(&training);
        }

        let pilot_offset = match config.format {
            HtFormat::Mixed => 3,
            HtFormat::Greenfield => 2,
        };
        let polarities: Vec<i8> = ofdm::scramble(&vec![0; symbols + pilot_offset], 127)
            .into_iter()
            .map(|bit| 1 - 2 * bit as i8)
            .collect();
        let coded_bits_per_symbol = 52 * bits_per_subcarrier;
        for (symbol, coded_symbol) in coded.chunks_exact(coded_bits_per_symbol).enumerate() {
            let interleaved = ht_interleave(coded_symbol, bits_per_subcarrier);
            wave.extend(ht_data_symbol(
                &interleaved,
                bits_per_subcarrier,
                polarities[symbol + pilot_offset],
                symbol,
                guard,
            ));
        }
        wave.resize(sample_count, Complex::ZERO);

        Ok(Self {
            mac_bytes: mac_bytes.to_vec(),
            psdu_bytes: psdu,
            cs8: ofdm::quantize(&wave, config.scale),
            mcs: config.mcs,
            format: config.format,
            coding: config.coding,
            guard_interval: config.guard_interval,
            ht_signal: HtSignalBits {
                transmitted: transmitted_ht_signal,
                derived: derived_ht_signal,
                explicit: config.ht_signal_override.is_some(),
            },
            legacy_signal: (config.format == HtFormat::Mixed).then_some(ofdm::OfdmSignalFields {
                transmitted: transmitted_legacy_signal,
                derived: derived_legacy_signal,
                explicit: config.legacy_signal_override.is_some(),
            }),
            data_symbols: symbols,
            scrambler_seed: config.scrambler_seed,
            sample_rate_hz: ofdm::SAMPLE_RATE_HZ,
            leading_samples: config.leading_samples,
            preamble_samples,
            signal_samples,
            data_samples,
            trailing_samples: config.trailing_samples,
            scale: config.scale,
            explicit_fcs: explicit_fcs.is_some(),
        })
    }

    pub fn sample_count(&self) -> usize {
        self.cs8.len() / 2
    }
}

fn validate_config(config: &HtTxConfig) -> RadioResult<()> {
    if config.scrambler_seed == 0 || config.scrambler_seed > 127 {
        return Err(RadioError::Invalid {
            field: "scrambler_seed",
            reason: "must be a nonzero seven-bit value",
        });
    }
    if config.max_psdu_bytes == 0 || config.max_samples == 0 {
        return Err(RadioError::Invalid {
            field: "transmit bounds",
            reason: "PSDU and sample bounds must be nonzero",
        });
    }
    if !config.scale.is_finite() || config.scale <= 0.0 {
        return Err(RadioError::Invalid {
            field: "scale",
            reason: "must be finite and positive",
        });
    }
    if config.format == HtFormat::Greenfield && config.guard_interval == HtGuardInterval::Short {
        return Err(RadioError::Invalid {
            field: "guard_interval",
            reason:
                "greenfield HT20 DATA immediately after HT-SIG requires the long guard interval",
        });
    }
    if config.format == HtFormat::Greenfield && config.legacy_signal_override.is_some() {
        return Err(RadioError::Invalid {
            field: "legacy_signal_override",
            reason: "greenfield format does not transmit L-SIG",
        });
    }
    Ok(())
}

fn validate_bits<const N: usize>(field: &'static str, bits: &[u8; N]) -> RadioResult<()> {
    if bits.iter().any(|bit| *bit > 1) {
        return Err(RadioError::Invalid {
            field,
            reason: "bits must be zero or one",
        });
    }
    Ok(())
}

fn puncture(coded: &[u8], mcs: HtMcs) -> Vec<u8> {
    let pattern: &[u8] = match mcs {
        HtMcs::Mcs0 | HtMcs::Mcs1 | HtMcs::Mcs3 => &[1, 1],
        HtMcs::Mcs5 => &[1, 1, 1, 0],
        HtMcs::Mcs2 | HtMcs::Mcs4 | HtMcs::Mcs6 => &[1, 1, 1, 0, 0, 1],
        HtMcs::Mcs7 => &[1, 1, 1, 0, 0, 1, 1, 0, 0, 1],
    };
    coded
        .iter()
        .enumerate()
        .filter_map(|(index, bit)| (pattern[index % pattern.len()] != 0).then_some(*bit))
        .collect()
}

fn ht_interleave(bits: &[u8], bits_per_subcarrier: usize) -> Vec<u8> {
    let rows = 4 * bits_per_subcarrier;
    let columns = 13;
    let mut first = vec![0; bits.len()];
    for row in 0..rows {
        for column in 0..columns {
            first[column * rows + row] = bits[row * columns + column];
        }
    }
    let s = (bits_per_subcarrier / 2).max(1);
    let mut result = vec![0; bits.len()];
    for (index, bit) in first.into_iter().enumerate() {
        let target = s * (index / s) + (index + bits.len() - (columns * index) / bits.len()) % s;
        result[target] = bit;
    }
    result
}

fn ifft57(frequency: &[Complex; 57]) -> [Complex; 64] {
    std::array::from_fn(|time| {
        let mut output = Complex::ZERO;
        for (index, value) in frequency.iter().enumerate() {
            let carrier = index as i32 - 28;
            let angle = 2.0 * PI * carrier as f64 * time as f64 / 64.0;
            let (sin, cos) = angle.sin_cos();
            let rotation = Complex {
                re: cos / 64.0,
                im: sin / 64.0,
            };
            output.re += value.re * rotation.re - value.im * rotation.im;
            output.im += value.re * rotation.im + value.im * rotation.re;
        }
        output
    })
}

fn ht_training() -> [Complex; 64] {
    let mut frequency = [Complex::ZERO; 57];
    frequency[0].re = 1.0;
    frequency[1].re = 1.0;
    for (destination, value) in frequency[2..55].iter_mut().zip(ofdm::LONG_TRAINING) {
        destination.re = value as f64;
    }
    frequency[55].re = -1.0;
    frequency[56].re = -1.0;
    ifft57(&frequency)
}

fn ht_signal_symbol(bits: &[u8]) -> Vec<Complex> {
    let mut frequency = [Complex::ZERO; 53];
    for (index, carrier) in DATA_CARRIERS[2..50].iter().enumerate() {
        frequency[(*carrier + 26) as usize].im = (2 * bits[index] as i32 - 1) as f64;
    }
    for (carrier, value) in [(-21, 1.0), (-7, 1.0), (7, 1.0), (21, -1.0)] {
        frequency[(carrier + 26) as usize].re = value;
    }
    let time = ofdm::ifft(&frequency);
    let mut output = Vec::with_capacity(80);
    output.extend_from_slice(&time[48..]);
    output.extend_from_slice(&time);
    output
}

fn ht_data_symbol(
    bits: &[u8],
    bits_per_subcarrier: usize,
    polarity: i8,
    symbol: usize,
    guard: usize,
) -> Vec<Complex> {
    let mut frequency = [Complex::ZERO; 57];
    for (index, carrier) in DATA_CARRIERS.iter().enumerate() {
        frequency[(*carrier + 28) as usize] = ofdm::constellation(
            &bits[index * bits_per_subcarrier..(index + 1) * bits_per_subcarrier],
        );
    }
    for (pilot, carrier) in [-21, -7, 7, 21].into_iter().enumerate() {
        let sign = [1, 1, 1, -1][(symbol + pilot) % 4];
        frequency[(carrier + 28) as usize].re = (sign * polarity) as f64;
    }
    let time = ifft57(&frequency);
    let mut output = Vec::with_capacity(64 + guard);
    output.extend_from_slice(&time[64 - guard..]);
    output.extend_from_slice(&time);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn assert_iq(case: &str, actual: &[i8]) {
        let expected = std::fs::read(format!(
            "{}/tests/fixtures/iq/{case}.cs8",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        assert_eq!(actual.len(), expected.len(), "{case}");
        for (index, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
            let delta = (*actual as i16 - *expected as i8 as i16).abs();
            assert!(
                delta <= 1,
                "{case} differs at byte {index}: actual={actual}, expected={}",
                *expected as i8
            );
        }
    }

    #[test]
    fn radio_ht_tx_matches_independent_bcc_waveforms() {
        let index = include_str!("../../../tests/fixtures/iq/ht-bcc-index.tsv");
        let mut cases = 0;
        for row in index.lines().skip(1).filter(|row| row.contains("-clean")) {
            let columns: Vec<_> = row.split('\t').collect();
            let psdu = bytes(columns[4]);
            let mut config =
                HtTxConfig::new(HtMcs::try_from(columns[1].parse::<u8>().unwrap()).unwrap());
            config.guard_interval = match columns[2] {
                "8" => HtGuardInterval::Short,
                "16" => HtGuardInterval::Long,
                _ => panic!(),
            };
            config.leading_samples = 37;
            config.trailing_samples = 64;
            let tx = HtTransmission::encode(
                &psdu[..psdu.len() - 4],
                Some(psdu[psdu.len() - 4..].try_into().unwrap()),
                &config,
            )
            .unwrap();
            assert_eq!(
                tx.data_symbols,
                columns[3].parse::<usize>().unwrap(),
                "{}",
                columns[0]
            );
            assert_iq(columns[0], &tx.cs8);
            cases += 1;
        }
        assert_eq!(cases, 32);
    }

    #[test]
    fn radio_ht_tx_matches_independent_greenfield_waveforms() {
        let index = include_str!("../../../tests/fixtures/iq/ht-greenfield-index.tsv");
        let mut cases = 0;
        for row in index
            .lines()
            .skip(1)
            .filter(|row| row.contains("-bcc-") && row.contains("-clean"))
        {
            let columns: Vec<_> = row.split('\t').collect();
            let psdu = bytes(columns[4]);
            let mut config =
                HtTxConfig::new(HtMcs::try_from(columns[1].parse::<u8>().unwrap()).unwrap())
                    .with_format(HtFormat::Greenfield);
            config.leading_samples = 37;
            config.trailing_samples = 64;
            let tx = HtTransmission::encode(
                &psdu[..psdu.len() - 4],
                Some(psdu[psdu.len() - 4..].try_into().unwrap()),
                &config,
            )
            .unwrap();
            assert_eq!(tx.data_symbols, columns[3].parse::<usize>().unwrap());
            assert_iq(columns[0], &tx.cs8);
            cases += 1;
        }
        assert_eq!(cases, 16);
    }

    #[test]
    fn radio_ht_tx_bounds_overrides_and_formats() {
        let mac = b"wifi four";
        let config = HtTxConfig::new(HtMcs::Mcs7);
        let first = HtTransmission::encode(mac, None, &config).unwrap();
        assert_eq!(first, HtTransmission::encode(mac, None, &config).unwrap());
        assert_eq!(&first.psdu_bytes[..mac.len()], mac);
        assert_eq!(
            &first.psdu_bytes[mac.len()..],
            &ofdm::crc32(mac).to_le_bytes()
        );
        assert_eq!(first.sample_rate_hz, 20_000_000);

        let greenfield =
            HtTransmission::encode(mac, None, &config.clone().with_format(HtFormat::Greenfield))
                .unwrap();
        assert_eq!(greenfield.format, HtFormat::Greenfield);
        assert!(greenfield.legacy_signal.is_none());

        let mut explicit = config.clone();
        let mut malformed = first.ht_signal.derived;
        malformed[34] ^= 1;
        explicit.ht_signal_override = Some(malformed);
        explicit.legacy_signal_override = first.legacy_signal.map(|signal| signal.derived);
        let tx = HtTransmission::encode(mac, Some([0; 4]), &explicit).unwrap();
        assert_eq!(tx.ht_signal.transmitted, malformed);
        assert!(tx.ht_signal.explicit && tx.explicit_fcs);

        let mut bounded = config.clone();
        bounded.max_samples = first.sample_count() - 1;
        assert!(matches!(
            HtTransmission::encode(mac, None, &bounded),
            Err(RadioError::Limit {
                context: "HT waveform samples",
                ..
            })
        ));
        bounded.max_samples = usize::MAX;
        bounded.max_psdu_bytes = 4;
        assert!(matches!(
            HtTransmission::encode(mac, None, &bounded),
            Err(RadioError::Limit {
                context: "HT PSDU bytes",
                ..
            })
        ));
        assert!(
            HtTransmission::encode(mac, None, &config.clone().with_coding(HtCoding::Ldpc)).is_err()
        );
        assert!(HtTransmission::encode(
            mac,
            None,
            &config
                .clone()
                .with_format(HtFormat::Greenfield)
                .with_guard_interval(HtGuardInterval::Short)
        )
        .is_err());
    }
}
