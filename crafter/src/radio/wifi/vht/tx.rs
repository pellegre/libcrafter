//! Packet-shaped VHT20 SU transmission, IEEE 802.11-2020 10.12.6 and 21.3.
use super::{
    layout, VhtCoding, VhtGuardInterval, VhtMcs, VhtSignalAFields, VhtSignalAUsers,
    VhtSignalB20Content, VhtSignalB20Fields, VhtTxConfig,
};
use crate::radio::wifi::{
    ht::{crc, tx::waveform as ht},
    ofdm::waveform::{self as ofdm, Complex},
};
use crate::radio::{OfdmSignalFields, RadioError, RadioResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhtSignalBits<const N: usize> {
    pub derived: [u8; N],
    pub transmitted: [u8; N],
    pub explicit: bool,
}

/// Retains the MAC, FCS-bearing MPDU, padded PSDU, signaling and sample geometry.
#[derive(Debug, Clone, PartialEq)]
pub struct VhtTransmission {
    pub mac_bytes: Vec<u8>,
    pub mpdu_bytes: Vec<u8>,
    pub psdu_bytes: Vec<u8>,
    pub cs8: Vec<i8>,
    pub mcs: VhtMcs,
    pub coding: VhtCoding,
    pub guard_interval: VhtGuardInterval,
    pub signal_a: VhtSignalBits<48>,
    pub signal_b: VhtSignalBits<26>,
    pub legacy_signal: OfdmSignalFields,
    pub apep_bytes: usize,
    pub data_symbols: usize,
    pub sample_rate_hz: u32,
    pub leading_samples: usize,
    pub data_start: usize,
    pub data_samples: usize,
    pub trailing_samples: usize,
    pub scrambler_seed: u8,
    pub scale: f64,
    pub explicit_fcs: bool,
}

fn invalid(field: &'static str, reason: &'static str) -> RadioError {
    RadioError::Invalid { field, reason }
}
fn delimiter(length: usize, eof: bool) -> [u8; 4] {
    let header = ((length & 4095) << 4) | ((length >> 12) << 2) | usize::from(eof);
    let a = header as u8;
    let b = (header >> 8) as u8;
    let bits = std::array::from_fn::<_, 16, _>(|i| ([a, b][i / 8] >> (i % 8)) & 1);
    [a, b, crc(&bits).reverse_bits(), 0x4e]
}
fn pad_psdu(bytes: &mut Vec<u8>, length: usize) {
    while bytes.len() < length && bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    while bytes.len() + 4 <= length {
        bytes.extend_from_slice(&delimiter(0, true));
    }
    bytes.resize(length, 0);
}
fn puncture(bits: &[u8], mcs: VhtMcs) -> Vec<u8> {
    let p: &[u8] = match mcs {
        VhtMcs::Mcs0 | VhtMcs::Mcs1 | VhtMcs::Mcs3 => &[1, 1],
        VhtMcs::Mcs5 => &[1, 1, 1, 0],
        VhtMcs::Mcs7 => &[1, 1, 1, 0, 0, 1, 1, 0, 0, 1],
        _ => &[1, 1, 1, 0, 0, 1],
    };
    bits.iter()
        .enumerate()
        .filter_map(|(i, b)| (p[i % p.len()] != 0).then_some(*b))
        .collect()
}
impl VhtTransmission {
    pub fn encode(mac: &[u8], fcs: Option<[u8; 4]>, config: &VhtTxConfig) -> RadioResult<Self> {
        if config.scrambler_seed == 0 || config.scrambler_seed > 127 {
            return Err(invalid(
                "scrambler_seed",
                "must be a nonzero seven-bit value",
            ));
        }
        if !config.scale.is_finite() || config.scale <= 0. {
            return Err(invalid("scale", "must be finite and positive"));
        }
        let mpdu_len = mac.len().checked_add(4).ok_or(RadioError::Overflow {
            context: "VHT MPDU length",
        })?;
        if mpdu_len > 16383 {
            return Err(RadioError::Limit {
                context: "VHT MPDU bytes",
                limit: 16383,
                actual: mpdu_len as u64,
            });
        }
        let apep = mpdu_len + 4;
        let (nbpsc, ndbps) = config.mcs.parameters();
        let ldpc =
            (config.coding == VhtCoding::Ldpc).then(|| layout::ldpc_encode(apep, config.mcs));
        let symbols = ldpc.map_or_else(|| (16 + 8 * apep + 6).div_ceil(ndbps), |l| l.symbols);
        let psdu_len =
            ldpc.map_or_else(|| (symbols * ndbps - 22) / 8, |l| (l.payload_bits - 16) / 8);
        if psdu_len > config.max_psdu_bytes {
            return Err(RadioError::Limit {
                context: "VHT PSDU bytes",
                limit: config.max_psdu_bytes as u64,
                actual: psdu_len as u64,
            });
        }
        let length =
            layout::Timing::legacy_length(symbols, config.guard_interval).ok_or(invalid(
                "duration",
                "VHT PPDU duration exceeds the legacy SIGNAL representation",
            ))?;
        let data_samples = symbols * config.guard_interval.symbol_samples();
        let sample_count = config
            .leading_samples
            .checked_add(800)
            .and_then(|n| n.checked_add(data_samples))
            .and_then(|n| n.checked_add(config.trailing_samples))
            .ok_or(RadioError::Overflow {
                context: "VHT waveform samples",
            })?;
        if sample_count > config.max_samples {
            return Err(RadioError::Limit {
                context: "VHT waveform samples",
                limit: config.max_samples as u64,
                actual: sample_count as u64,
            });
        }
        sample_count
            .checked_mul(std::mem::size_of::<Complex>())
            .ok_or(RadioError::Overflow {
                context: "VHT waveform allocation bytes",
            })?;
        sample_count.checked_mul(2).ok_or(RadioError::Overflow {
            context: "VHT CS8 bytes",
        })?;
        let derived_a = VhtSignalAFields {
            bandwidth_code: 0,
            group_id: 63,
            stbc: false,
            short_guard_interval: config.guard_interval == VhtGuardInterval::Short,
            short_gi_disambiguation: config.guard_interval == VhtGuardInterval::Short
                && symbols % 10 == 9,
            ldpc_extra_symbol: ldpc.is_some_and(|l| l.extra_symbol_group),
            txop_ps_not_allowed: true,
            users: VhtSignalAUsers::Single {
                space_time_streams: 1,
                partial_aid: 0,
                mcs: config.mcs.index(),
                ldpc: config.coding == VhtCoding::Ldpc,
                beamformed: false,
            },
        }
        .encode();
        let derived_b = VhtSignalB20Fields::encode(VhtSignalB20Content::SingleUser {
            length_units: apep.div_ceil(4) as u32,
        });
        let derived_l = ofdm::signal_bits([1, 1, 0, 1], length);
        let a = config.signal_a_override.unwrap_or(derived_a);
        let b = config.signal_b_override.unwrap_or(derived_b);
        let l = config.legacy_signal_override.unwrap_or(derived_l);
        for (name, bits) in [
            ("signal_a", a.as_slice()),
            ("signal_b", b.as_slice()),
            ("legacy_signal", l.as_slice()),
        ] {
            if bits.iter().any(|v| *v > 1) {
                return Err(invalid(name, "bits must be zero or one"));
            }
        }
        let mut mpdu = mac.to_vec();
        mpdu.extend_from_slice(&fcs.unwrap_or_else(|| ofdm::crc32(mac).to_le_bytes()));
        let mut psdu = delimiter(mpdu.len(), true).to_vec();
        psdu.extend_from_slice(&mpdu);
        pad_psdu(&mut psdu, psdu_len);
        let mut data = vec![0; 16];
        let check = crc(&b[..20]);
        for i in 0..8 {
            data[8 + i] = (check >> (7 - i)) & 1;
        }
        ofdm::append_lsb_bits(&mut data, &psdu);
        let coded = if let Some(layout) = ldpc {
            data.resize(layout.payload_bits, 0);
            layout
                .encode(&ofdm::scramble(&data, config.scrambler_seed))
                .map_err(|e| RadioError::Source(format!("VHT LDPC encoding: {e:?}")))?
        } else {
            data.resize(symbols * ndbps - 6, 0);
            let mut scrambled = ofdm::scramble(&data, config.scrambler_seed);
            scrambled.extend_from_slice(&[0; 6]);
            puncture(&ofdm::convolutional_encode(&scrambled), config.mcs)
        };
        let mut wave = vec![Complex::ZERO; config.leading_samples];
        wave.extend(ofdm::preamble());
        wave.extend(ofdm::ofdm_symbol(
            &ofdm::interleave(&ofdm::convolutional_encode(&l), 1),
            1,
            1,
        ));
        let coded_a = ofdm::convolutional_encode(&a);
        wave.extend(ofdm::ofdm_symbol(
            &ofdm::interleave(&coded_a[..48], 1),
            1,
            1,
        ));
        wave.extend(ht::ht_signal_symbol(&ofdm::interleave(&coded_a[48..], 1)));
        wave.extend_from_slice(&ofdm::preamble()[..80]);
        let vht_start = wave.len();
        let training = ht::ht_training();
        wave.extend_from_slice(&training[48..]);
        wave.extend_from_slice(&training);
        let signs: Vec<_> = ofdm::scramble(&vec![0; symbols + 4], 127)
            .iter()
            .map(|b| 1 - 2 * (*b as i8))
            .collect();
        wave.extend(ht::ht_data_symbol(
            &ht::ht_interleave(&ofdm::convolutional_encode(&b), 1),
            1,
            signs[3],
            0,
            16,
        ));
        for (i, symbol) in coded.chunks_exact(52 * nbpsc).enumerate() {
            let mapped = if ldpc.is_some() {
                let mut mapped = vec![0; 52 * nbpsc];
                for k in 0..52 {
                    let dest = 4 * (k % 13) + k / 13;
                    mapped[dest * nbpsc..(dest + 1) * nbpsc]
                        .copy_from_slice(&symbol[k * nbpsc..(k + 1) * nbpsc]);
                }
                mapped
            } else {
                ht::ht_interleave(symbol, nbpsc)
            };
            wave.extend(ht::ht_data_symbol(
                &mapped,
                nbpsc,
                signs[i + 4],
                i,
                config.guard_interval.samples(),
            ));
        }
        // IEEE 21.3.8/10: equal mean power across the 52- and 56-tone fields.
        let ratio = (52f64 / 56.).sqrt();
        for sample in &mut wave[vht_start..] {
            sample.re *= ratio;
            sample.im *= ratio;
        }
        wave.resize(sample_count, Complex::ZERO);
        Ok(Self {
            mac_bytes: mac.to_vec(),
            mpdu_bytes: mpdu,
            psdu_bytes: psdu,
            cs8: ofdm::quantize(&wave, config.scale),
            mcs: config.mcs,
            coding: config.coding,
            guard_interval: config.guard_interval,
            signal_a: VhtSignalBits {
                derived: derived_a,
                transmitted: a,
                explicit: config.signal_a_override.is_some(),
            },
            signal_b: VhtSignalBits {
                derived: derived_b,
                transmitted: b,
                explicit: config.signal_b_override.is_some(),
            },
            legacy_signal: OfdmSignalFields {
                derived: derived_l,
                transmitted: l,
                explicit: config.legacy_signal_override.is_some(),
            },
            apep_bytes: apep,
            data_symbols: symbols,
            sample_rate_hz: 20_000_000,
            leading_samples: config.leading_samples,
            data_start: config.leading_samples + 800,
            data_samples,
            trailing_samples: config.trailing_samples,
            scrambler_seed: config.scrambler_seed,
            scale: config.scale,
            explicit_fcs: fcs.is_some(),
        })
    }
    pub fn sample_count(&self) -> usize {
        self.cs8.len() / 2
    }
}
