//! MAC-frame to single-stream HT20 waveform encoding.

use super::{
    waveform::{ht_data_symbol, ht_interleave, ht_signal_symbol, ht_training, puncture},
    HtCoding, HtFormat, HtGuardInterval, HtMcs, HtTxConfig,
};
use crate::radio::ht::HtSignalFields;
use crate::radio::wifi::ofdm::waveform::Complex;
use crate::radio::{
    ldpc,
    wifi::ofdm::{waveform as ofdm, OfdmSignalFields},
    RadioError, RadioResult,
};

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
    pub legacy_signal: Option<OfdmSignalFields>,
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
        let (symbols, coded) = match config.coding {
            HtCoding::Bcc => {
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
                let mut data = vec![0; 16];
                ofdm::append_lsb_bits(&mut data, &psdu);
                data.resize(data_bits_len, 0);
                let mut scrambled = ofdm::scramble(&data, config.scrambler_seed);
                let tail_start = 16 + psdu_len * 8;
                scrambled[tail_start..tail_start + 6].fill(0);
                (
                    symbols,
                    puncture(&ofdm::convolutional_encode(&scrambled), config.mcs),
                )
            }
            HtCoding::Ldpc => {
                use ldpc::Rate::*;
                let rate = [
                    Half,
                    Half,
                    ThreeQuarters,
                    Half,
                    ThreeQuarters,
                    TwoThirds,
                    ThreeQuarters,
                    FiveSixths,
                ][config.mcs.index() as usize];
                let layout = ldpc::rate::Layout::new(
                    psdu_len as u16,
                    (52 * bits_per_subcarrier) as u16,
                    rate,
                    false,
                )
                .map_err(|error| RadioError::Source(format!("HT LDPC rate matching: {error:?}")))?;
                let mut data = vec![0; 16];
                ofdm::append_lsb_bits(&mut data, &psdu);
                let scrambled = ofdm::scramble(&data, config.scrambler_seed);
                let coded = layout
                    .encode(&scrambled)
                    .map_err(|error| RadioError::Source(format!("HT LDPC encoding: {error:?}")))?;
                (layout.symbols, coded)
            }
        };
        let guard = config.guard_interval.samples();
        let data_samples = symbols
            .checked_mul(64 + guard)
            .ok_or(RadioError::Overflow {
                context: "HT DATA samples",
            })?;

        let derived_fields = HtSignalFields {
            mcs: config.mcs.index(),
            channel_width_40_mhz: false,
            psdu_bytes: psdu_len as u16,
            smoothing: true,
            not_sounding: true,
            aggregation: false,
            stbc: 0,
            ldpc: config.coding == HtCoding::Ldpc,
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
            let interleaved = (config.coding == HtCoding::Bcc)
                .then(|| ht_interleave(coded_symbol, bits_per_subcarrier));
            let mapped = interleaved.as_deref().unwrap_or(coded_symbol);
            wave.extend(ht_data_symbol(
                mapped,
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
            legacy_signal: (config.format == HtFormat::Mixed).then_some(OfdmSignalFields {
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
