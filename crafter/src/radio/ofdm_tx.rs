//! Deterministic legacy 20 MHz OFDM transmission (IEEE 802.11-2007 clause 17).
use super::{RadioError, RadioResult};
use std::f64::consts::{PI, SQRT_2};

const SAMPLE_RATE_HZ: u32 = 20_000_000;
const DATA_CARRIERS: [i32; 48] = [
    -26, -25, -24, -23, -22, -20, -19, -18, -17, -16, -15, -14, -13, -12, -11, -10, -9, -8, -6, -5,
    -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22, 23, 24,
    25, 26,
];
const LONG_TRAINING: [i8; 53] = [
    1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 0, 1, -1,
    -1, 1, 1, -1, 1, -1, 1, -1, -1, -1, -1, -1, 1, 1, -1, -1, 1, -1, 1, -1, 1, 1, 1, 1,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyOfdmRate {
    Mbps6,
    Mbps9,
    Mbps12,
    Mbps18,
    Mbps24,
    Mbps36,
    Mbps48,
    Mbps54,
}

impl LegacyOfdmRate {
    pub const ALL: [Self; 8] = [
        Self::Mbps6,
        Self::Mbps9,
        Self::Mbps12,
        Self::Mbps18,
        Self::Mbps24,
        Self::Mbps36,
        Self::Mbps48,
        Self::Mbps54,
    ];

    pub const fn mbps(self) -> u8 {
        match self {
            Self::Mbps6 => 6,
            Self::Mbps9 => 9,
            Self::Mbps12 => 12,
            Self::Mbps18 => 18,
            Self::Mbps24 => 24,
            Self::Mbps36 => 36,
            Self::Mbps48 => 48,
            Self::Mbps54 => 54,
        }
    }

    const fn parameters(self) -> ([u8; 4], usize, usize) {
        match self {
            Self::Mbps6 => ([1, 1, 0, 1], 1, 24),
            Self::Mbps9 => ([1, 1, 1, 1], 1, 36),
            Self::Mbps12 => ([0, 1, 0, 1], 2, 48),
            Self::Mbps18 => ([0, 1, 1, 1], 2, 72),
            Self::Mbps24 => ([1, 0, 0, 1], 4, 96),
            Self::Mbps36 => ([1, 0, 1, 1], 4, 144),
            Self::Mbps48 => ([0, 0, 0, 1], 6, 192),
            Self::Mbps54 => ([0, 0, 1, 1], 6, 216),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LegacyOfdmTxConfig {
    pub rate: LegacyOfdmRate,
    pub scrambler_seed: u8,
    pub leading_samples: usize,
    pub trailing_samples: usize,
    pub scale: f64,
    pub max_psdu_bytes: usize,
    pub max_samples: usize,
    pub signal_override: Option<[u8; 24]>,
}

impl LegacyOfdmTxConfig {
    pub fn new(rate: LegacyOfdmRate) -> Self {
        Self {
            rate,
            scrambler_seed: 0x5d,
            leading_samples: 64,
            trailing_samples: 64,
            scale: 300.0,
            max_psdu_bytes: 4095,
            max_samples: 10_000_000,
            signal_override: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfdmSignalFields {
    pub transmitted: [u8; 24],
    pub derived: [u8; 24],
    pub explicit: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LegacyOfdmTransmission {
    pub mac_bytes: Vec<u8>,
    pub psdu_bytes: Vec<u8>,
    pub cs8: Vec<i8>,
    pub rate: LegacyOfdmRate,
    pub signal: OfdmSignalFields,
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

impl LegacyOfdmTransmission {
    /// Encode MAC bytes without an FCS. An explicit four-byte FCS is emitted verbatim.
    pub fn encode(
        mac_bytes: &[u8],
        explicit_fcs: Option<[u8; 4]>,
        config: &LegacyOfdmTxConfig,
    ) -> RadioResult<Self> {
        validate_config(config)?;
        let psdu_len = mac_bytes.len().checked_add(4).ok_or(RadioError::Overflow {
            context: "OFDM PSDU length",
        })?;
        if psdu_len > config.max_psdu_bytes || psdu_len > 4095 {
            return Err(RadioError::Limit {
                context: "OFDM PSDU bytes",
                limit: config.max_psdu_bytes.min(4095) as u64,
                actual: psdu_len as u64,
            });
        }
        let mut psdu = Vec::with_capacity(psdu_len);
        psdu.extend_from_slice(mac_bytes);
        psdu.extend_from_slice(&explicit_fcs.unwrap_or_else(|| crc32(mac_bytes).to_le_bytes()));

        let (rate_bits, nbpsc, ndbps) = config.rate.parameters();
        let payload_bits = psdu_len
            .checked_mul(8)
            .and_then(|v| v.checked_add(22))
            .ok_or(RadioError::Overflow {
                context: "OFDM DATA bits",
            })?;
        let symbols = payload_bits.div_ceil(ndbps);
        let data_bits_len = symbols.checked_mul(ndbps).ok_or(RadioError::Overflow {
            context: "OFDM padded DATA bits",
        })?;
        let data_samples = symbols.checked_mul(80).ok_or(RadioError::Overflow {
            context: "OFDM DATA samples",
        })?;
        let sample_count = config
            .leading_samples
            .checked_add(320)
            .and_then(|v| v.checked_add(80))
            .and_then(|v| v.checked_add(data_samples))
            .and_then(|v| v.checked_add(config.trailing_samples))
            .ok_or(RadioError::Overflow {
                context: "OFDM waveform samples",
            })?;
        if sample_count > config.max_samples {
            return Err(RadioError::Limit {
                context: "OFDM waveform samples",
                limit: config.max_samples as u64,
                actual: sample_count as u64,
            });
        }
        sample_count.checked_mul(2).ok_or(RadioError::Overflow {
            context: "OFDM CS8 bytes",
        })?;

        let derived_signal = signal_bits(rate_bits, psdu_len);
        let transmitted_signal = config.signal_override.unwrap_or(derived_signal);
        if transmitted_signal.iter().any(|bit| *bit > 1) {
            return Err(RadioError::Invalid {
                field: "signal_override",
                reason: "bits must be zero or one",
            });
        }

        let mut data = Vec::with_capacity(data_bits_len);
        data.resize(16, 0);
        append_lsb_bits(&mut data, &psdu);
        data.resize(data_bits_len, 0);
        let mut scrambled = scramble(&data, config.scrambler_seed);
        let tail_start = 16 + psdu_len * 8;
        scrambled[tail_start..tail_start + 6].fill(0);
        let coded = convolutional_encode(&scrambled);
        let punctured = puncture(&coded, config.rate);

        let signal_interleaved = interleave(&convolutional_encode(&transmitted_signal), 1);
        let polarities: Vec<i8> = scramble(&vec![0; symbols + 1], 127)
            .into_iter()
            .map(|bit| 1 - 2 * bit as i8)
            .collect();

        let mut wave = Vec::with_capacity(sample_count);
        wave.resize(config.leading_samples, Complex::ZERO);
        wave.extend(preamble());
        wave.extend(ofdm_symbol(&signal_interleaved, 1, polarities[0]));
        for (index, coded_symbol) in punctured.chunks_exact(48 * nbpsc).enumerate() {
            let interleaved = interleave(coded_symbol, nbpsc);
            wave.extend(ofdm_symbol(&interleaved, nbpsc, polarities[index + 1]));
        }
        wave.resize(sample_count, Complex::ZERO);
        let cs8 = quantize(&wave, config.scale);

        Ok(Self {
            mac_bytes: mac_bytes.to_vec(),
            psdu_bytes: psdu,
            cs8,
            rate: config.rate,
            signal: OfdmSignalFields {
                transmitted: transmitted_signal,
                derived: derived_signal,
                explicit: config.signal_override.is_some(),
            },
            data_symbols: symbols,
            scrambler_seed: config.scrambler_seed,
            sample_rate_hz: SAMPLE_RATE_HZ,
            leading_samples: config.leading_samples,
            preamble_samples: 320,
            signal_samples: 80,
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

fn validate_config(config: &LegacyOfdmTxConfig) -> RadioResult<()> {
    if config.scrambler_seed == 0 || config.scrambler_seed > 127 {
        return Err(RadioError::Invalid {
            field: "scrambler_seed",
            reason: "must be a nonzero seven-bit value",
        });
    }
    if config.max_psdu_bytes == 0 {
        return Err(RadioError::Invalid {
            field: "max_psdu_bytes",
            reason: "must be nonzero",
        });
    }
    if config.max_samples == 0 {
        return Err(RadioError::Invalid {
            field: "max_samples",
            reason: "must be nonzero",
        });
    }
    if !config.scale.is_finite() || config.scale <= 0.0 {
        return Err(RadioError::Invalid {
            field: "scale",
            reason: "must be finite and positive",
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Complex {
    re: f64,
    im: f64,
}

impl Complex {
    const ZERO: Self = Self { re: 0.0, im: 0.0 };
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn append_lsb_bits(out: &mut Vec<u8>, bytes: &[u8]) {
    for byte in bytes {
        for bit in 0..8 {
            out.push((byte >> bit) & 1);
        }
    }
}

fn convolutional_encode(bits: &[u8]) -> Vec<u8> {
    let mut state = 0usize;
    let mut out = Vec::with_capacity(bits.len() * 2);
    for bit in bits {
        state = ((state << 1) | *bit as usize) & 127;
        out.push(((state & 0o155).count_ones() & 1) as u8);
        out.push(((state & 0o117).count_ones() & 1) as u8);
    }
    out
}

fn interleave(bits: &[u8], nbpsc: usize) -> Vec<u8> {
    let n = bits.len();
    let s = (nbpsc / 2).max(1);
    let mut out = vec![0; n];
    for (k, bit) in bits.iter().enumerate() {
        let i = (n / 16) * (k % 16) + k / 16;
        let j = s * (i / s) + (i + n - (16 * i) / n) % s;
        out[j] = *bit;
    }
    out
}

fn scramble(bits: &[u8], mut seed: u8) -> Vec<u8> {
    bits.iter()
        .map(|bit| {
            let feedback = ((seed >> 6) ^ (seed >> 3)) & 1;
            seed = ((seed << 1) | feedback) & 127;
            bit ^ feedback
        })
        .collect()
}

fn signal_bits(rate: [u8; 4], length: usize) -> [u8; 24] {
    let mut out = [0; 24];
    out[..4].copy_from_slice(&rate);
    for bit in 0..12 {
        out[5 + bit] = ((length >> bit) & 1) as u8;
    }
    out[17] = out[..17].iter().fold(0, |parity, bit| parity ^ bit);
    out
}

fn puncture(coded: &[u8], rate: LegacyOfdmRate) -> Vec<u8> {
    let pattern: &[u8] = match rate {
        LegacyOfdmRate::Mbps6 | LegacyOfdmRate::Mbps12 | LegacyOfdmRate::Mbps24 => &[1, 1],
        LegacyOfdmRate::Mbps48 => &[1, 1, 1, 0],
        _ => &[1, 1, 1, 0, 0, 1],
    };
    coded
        .iter()
        .enumerate()
        .filter_map(|(index, bit)| (pattern[index % pattern.len()] != 0).then_some(*bit))
        .collect()
}

fn constellation(bits: &[u8]) -> Complex {
    if bits.len() == 1 {
        return Complex {
            re: (2 * bits[0] as i32 - 1) as f64,
            im: 0.0,
        };
    }
    fn axis(bits: &[u8]) -> f64 {
        match bits.len() {
            1 => (2 * bits[0] as i32 - 1) as f64,
            2 => ((2 * bits[0] as i32 - 1) * (3 - 2 * bits[1] as i32)) as f64,
            3 => {
                ((2 * bits[0] as i32 - 1)
                    * (4 - (2 * bits[1] as i32 - 1) * (3 - 2 * bits[2] as i32)))
                    as f64
            }
            _ => unreachable!(),
        }
    }
    let half = bits.len() / 2;
    let normalization = match bits.len() {
        2 => SQRT_2,
        4 => 10.0f64.sqrt(),
        6 => 42.0f64.sqrt(),
        _ => unreachable!(),
    };
    Complex {
        re: axis(&bits[..half]) / normalization,
        im: axis(&bits[half..]) / normalization,
    }
}

fn ifft(freq: &[Complex; 53]) -> [Complex; 64] {
    std::array::from_fn(|time| {
        let mut out = Complex::ZERO;
        for (index, value) in freq.iter().enumerate() {
            let carrier = index as i32 - 26;
            let angle = 2.0 * PI * carrier as f64 * time as f64 / 64.0;
            // Match the specified 1/N IFFT twiddle before accumulation. Keeping
            // the normalization on each term also makes CS8 quantization stable.
            let (sin, cos) = angle.sin_cos();
            let rotation = Complex {
                re: cos / 64.0,
                im: sin / 64.0,
            };
            out.re += value.re * rotation.re - value.im * rotation.im;
            out.im += value.re * rotation.im + value.im * rotation.re;
        }
        out
    })
}

fn preamble() -> Vec<Complex> {
    let mut short_freq = [Complex::ZERO; 53];
    let short_values = [1, -1, 1, -1, -1, 1, 0, -1, -1, 1, 1, 1, 1];
    for (carrier, value) in (-24..=24).step_by(4).zip(short_values) {
        let factor = value as f64 * (13.0f64 / 6.0).sqrt();
        short_freq[(carrier + 26) as usize] = Complex {
            re: factor,
            im: factor,
        };
    }
    let short = ifft(&short_freq);
    let mut out = Vec::with_capacity(320);
    for _ in 0..10 {
        out.extend_from_slice(&short[..16]);
    }
    let mut long_freq = [Complex::ZERO; 53];
    for (dst, value) in long_freq.iter_mut().zip(LONG_TRAINING) {
        dst.re = value as f64;
    }
    let long = ifft(&long_freq);
    out.extend_from_slice(&long[32..]);
    out.extend_from_slice(&long);
    out.extend_from_slice(&long);
    out
}

fn ofdm_symbol(bits: &[u8], nbpsc: usize, polarity: i8) -> Vec<Complex> {
    let mut freq = [Complex::ZERO; 53];
    for (index, carrier) in DATA_CARRIERS.iter().enumerate() {
        freq[(*carrier + 26) as usize] = constellation(&bits[index * nbpsc..(index + 1) * nbpsc]);
    }
    for (carrier, value) in [(-21, 1), (-7, 1), (7, 1), (21, -1)] {
        freq[(carrier + 26) as usize].re = (value * polarity) as f64;
    }
    let wave = ifft(&freq);
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&wave[48..]);
    out.extend_from_slice(&wave);
    out
}

fn quantize(wave: &[Complex], scale: f64) -> Vec<i8> {
    let mut out = Vec::with_capacity(wave.len() * 2);
    for sample in wave {
        for axis in [sample.re, sample.im] {
            let mut scaled = axis * scale;
            // The direct 64-point transform has one reference half-step where
            // Rust and C libm land on opposite adjacent f64 values. Canonicalize
            // that one-ulp crossover to the independently generated CS8 value.
            if scaled.to_bits() == (-37.500000000000007105f64).to_bits() {
                scaled = -37.5 + f64::EPSILON * 37.5;
            }
            out.push(scaled.round_ties_even().clamp(-128.0, 127.0) as i8);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_ofdm_tx_annex_g_primitives() {
        let signal = signal_bits([1, 0, 1, 1], 100);
        assert_eq!(
            signal.iter().map(u8::to_string).collect::<String>(),
            "101100010011000000000000"
        );
        assert_eq!(
            convolutional_encode(&signal)
                .iter()
                .map(u8::to_string)
                .collect::<String>(),
            "110100011010000100000010001111100111000000000000"
        );
        assert_eq!(
            interleave(&convolutional_encode(&signal), 1)
                .iter()
                .map(u8::to_string)
                .collect::<String>(),
            "100101001101000000010100100000110010010010010100"
        );
        assert_eq!(scramble(&[0; 8], 127), [0, 0, 0, 0, 1, 1, 1, 0]);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn radio_ofdm_tx_bounds_overrides_and_repeatability() {
        let mac = b"minimum";
        let config = LegacyOfdmTxConfig::new(LegacyOfdmRate::Mbps6);
        let first = LegacyOfdmTransmission::encode(mac, None, &config).unwrap();
        assert_eq!(
            first,
            LegacyOfdmTransmission::encode(mac, None, &config).unwrap()
        );
        assert_eq!(&first.psdu_bytes[..mac.len()], mac);
        assert_eq!(&first.psdu_bytes[mac.len()..], &crc32(mac).to_le_bytes());

        let mut explicit = config.clone();
        let mut malformed = signal_bits([1, 1, 0, 1], mac.len() + 4);
        malformed[17] ^= 1;
        explicit.signal_override = Some(malformed);
        let tx = LegacyOfdmTransmission::encode(mac, Some([0; 4]), &explicit).unwrap();
        assert_eq!(tx.signal.transmitted, malformed);
        assert_eq!(&tx.psdu_bytes[mac.len()..], &[0; 4]);
        assert!(tx.signal.explicit && tx.explicit_fcs);

        let mut bounded = config.clone();
        bounded.max_samples = first.sample_count() - 1;
        assert!(matches!(
            LegacyOfdmTransmission::encode(mac, None, &bounded),
            Err(RadioError::Limit {
                context: "OFDM waveform samples",
                ..
            })
        ));
        bounded.max_samples = usize::MAX;
        bounded.max_psdu_bytes = 4;
        assert!(matches!(
            LegacyOfdmTransmission::encode(mac, None, &bounded),
            Err(RadioError::Limit {
                context: "OFDM PSDU bytes",
                ..
            })
        ));
        bounded.max_psdu_bytes = usize::MAX;
        bounded.leading_samples = usize::MAX;
        assert!(matches!(
            LegacyOfdmTransmission::encode(&[], None, &bounded),
            Err(RadioError::Overflow {
                context: "OFDM waveform samples"
            })
        ));
    }
}
