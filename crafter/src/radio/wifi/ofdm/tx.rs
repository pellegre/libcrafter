//! Deterministic legacy 20 MHz OFDM transmission (IEEE 802.11-2007 clause 17).
use super::waveform::{
    append_lsb_bits, convolutional_encode, crc32, interleave, ofdm_symbol, preamble, quantize,
    scramble, signal_bits, Complex, SAMPLE_RATE_HZ,
};
use crate::radio::{RadioError, RadioResult};

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
