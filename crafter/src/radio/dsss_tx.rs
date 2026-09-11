//! Deterministic legacy DSSS/CCK transmission (IEEE 802.11-2007 clauses 15 and 18).

use super::{RadioError, RadioResult};
use std::f64::consts::PI;

const SAMPLE_RATE_HZ: u32 = 20_000_000;
const CHIP_RATE_HZ: u32 = 11_000_000;
const BARKER: [i8; 11] = [1, -1, 1, 1, -1, 1, 1, 1, -1, -1, -1];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyDsssCckRate {
    Mbps1,
    Mbps2,
    Mbps5_5,
    Mbps11,
}

impl LegacyDsssCckRate {
    pub const ALL: [Self; 4] = [Self::Mbps1, Self::Mbps2, Self::Mbps5_5, Self::Mbps11];

    pub const fn bps(self) -> u32 {
        match self {
            Self::Mbps1 => 1_000_000,
            Self::Mbps2 => 2_000_000,
            Self::Mbps5_5 => 5_500_000,
            Self::Mbps11 => 11_000_000,
        }
    }

    const fn signal(self) -> u8 {
        match self {
            Self::Mbps1 => 10,
            Self::Mbps2 => 20,
            Self::Mbps5_5 => 55,
            Self::Mbps11 => 110,
        }
    }

    const fn payload_chips_per_octet(self) -> usize {
        match self {
            Self::Mbps1 => 88,
            Self::Mbps2 => 44,
            Self::Mbps5_5 => 16,
            Self::Mbps11 => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsssPreamble {
    Long,
    Short,
}

impl DsssPreamble {
    pub const fn is_short(self) -> bool {
        matches!(self, Self::Short)
    }

    const fn sync_bits(self) -> usize {
        if self.is_short() {
            56
        } else {
            128
        }
    }

    const fn scrambler_seed(self) -> [u8; 7] {
        if self.is_short() {
            [0, 0, 1, 1, 0, 1, 1]
        } else {
            [1, 1, 0, 1, 1, 0, 0]
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LegacyDsssCckTxConfig {
    pub rate: LegacyDsssCckRate,
    pub preamble: DsssPreamble,
    pub sample_rate_hz: u32,
    pub scrambler_seed_override: Option<[u8; 7]>,
    pub leading_samples: usize,
    pub trailing_samples: usize,
    pub gain: f64,
    pub max_psdu_bytes: usize,
    pub max_samples: usize,
    pub plcp_override: Option<[u8; 6]>,
}

impl LegacyDsssCckTxConfig {
    pub fn new(rate: LegacyDsssCckRate, preamble: DsssPreamble) -> Self {
        Self {
            rate,
            preamble,
            sample_rate_hz: SAMPLE_RATE_HZ,
            scrambler_seed_override: None,
            leading_samples: 64,
            trailing_samples: 64,
            gain: 0.48,
            max_psdu_bytes: 4095,
            max_samples: 10_000_000,
            plcp_override: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DsssPlcpFields {
    pub transmitted: [u8; 6],
    pub derived: [u8; 6],
    pub length_us: u16,
    pub length_extension: bool,
    pub explicit: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LegacyDsssCckTransmission {
    pub mac_bytes: Vec<u8>,
    pub psdu_bytes: Vec<u8>,
    pub cs8: Vec<i8>,
    pub rate: LegacyDsssCckRate,
    pub preamble: DsssPreamble,
    pub plcp: DsssPlcpFields,
    pub scrambler_seed: [u8; 7],
    pub sample_rate_hz: u32,
    pub chip_rate_hz: u32,
    pub leading_samples: usize,
    pub payload_start_sample: f64,
    pub frame_end_sample: f64,
    pub trailing_samples: usize,
    pub chip_count: usize,
    pub cck_symbols: usize,
    pub gain: f64,
    pub explicit_fcs: bool,
    pub explicit_scrambler_seed: bool,
}

impl LegacyDsssCckTransmission {
    /// Encode MAC bytes without an FCS. An explicit four-byte FCS is emitted verbatim.
    pub fn encode(
        mac_bytes: &[u8],
        explicit_fcs: Option<[u8; 4]>,
        config: &LegacyDsssCckTxConfig,
    ) -> RadioResult<Self> {
        validate_config(config)?;
        let psdu_len = mac_bytes.len().checked_add(4).ok_or(RadioError::Overflow {
            context: "DSSS PSDU length",
        })?;
        if psdu_len > config.max_psdu_bytes {
            return Err(RadioError::Limit {
                context: "DSSS PSDU bytes",
                limit: config.max_psdu_bytes as u64,
                actual: psdu_len as u64,
            });
        }

        let payload_chips = psdu_len
            .checked_mul(config.rate.payload_chips_per_octet())
            .ok_or(RadioError::Overflow {
                context: "DSSS payload chips",
            })?;
        let header_chips = if config.preamble.is_short() {
            1056usize
        } else {
            2112usize
        };
        let chip_count = header_chips
            .checked_add(payload_chips)
            .ok_or(RadioError::Overflow {
                context: "DSSS waveform chips",
            })?;
        let shaped_samples = chip_count
            .checked_mul(20)
            .and_then(|value| value.checked_add(10))
            .map(|value| value / 11)
            .ok_or(RadioError::Overflow {
                context: "DSSS resampled waveform",
            })?;
        let sample_count = config
            .leading_samples
            .checked_add(shaped_samples)
            .and_then(|value| value.checked_add(config.trailing_samples))
            .ok_or(RadioError::Overflow {
                context: "DSSS waveform samples",
            })?;
        if sample_count > config.max_samples {
            return Err(RadioError::Limit {
                context: "DSSS waveform samples",
                limit: config.max_samples as u64,
                actual: sample_count as u64,
            });
        }
        sample_count.checked_mul(2).ok_or(RadioError::Overflow {
            context: "DSSS CS8 bytes",
        })?;

        let mut psdu = Vec::with_capacity(psdu_len);
        psdu.extend_from_slice(mac_bytes);
        psdu.extend_from_slice(&explicit_fcs.unwrap_or_else(|| crc32(mac_bytes).to_le_bytes()));

        let (length_us, length_extension) = length_fields(psdu_len, config.rate)?;
        let mut derived_header = [0u8; 6];
        derived_header[0] = config.rate.signal();
        derived_header[1] = u8::from(length_extension) << 7;
        derived_header[2..4].copy_from_slice(&length_us.to_le_bytes());
        let header_crc = crc16(&derived_header[..4]);
        derived_header[4..].copy_from_slice(&header_crc.to_le_bytes());
        let transmitted_header = config.plcp_override.unwrap_or(derived_header);

        let seed = config
            .scrambler_seed_override
            .unwrap_or_else(|| config.preamble.scrambler_seed());
        let raw_bits_len = config
            .preamble
            .sync_bits()
            .checked_add(16 + 48)
            .and_then(|value| value.checked_add(psdu_len.checked_mul(8)?))
            .ok_or(RadioError::Overflow {
                context: "DSSS serialized bits",
            })?;
        let mut raw = Vec::with_capacity(raw_bits_len);
        raw.resize(
            config.preamble.sync_bits(),
            u8::from(!config.preamble.is_short()),
        );
        append_lsb_bits(
            &mut raw,
            &(if config.preamble.is_short() {
                0x05cfu16
            } else {
                0xf3a0u16
            })
            .to_le_bytes(),
        );
        append_lsb_bits(&mut raw, &transmitted_header);
        append_lsb_bits(&mut raw, &psdu);
        let serial = scramble(&raw, seed);

        let preamble_bits = config.preamble.sync_bits() + 16;
        let mut chips = Vec::with_capacity(chip_count);
        let mut common = 0u8;
        append_barker(&mut chips, &serial[..preamble_bits], 1, &mut common);
        append_barker(
            &mut chips,
            &serial[preamble_bits..preamble_bits + 48],
            if config.preamble.is_short() { 2 } else { 1 },
            &mut common,
        );
        debug_assert_eq!(chips.len(), header_chips);
        let payload = &serial[preamble_bits + 48..];
        let cck_symbols = match config.rate {
            LegacyDsssCckRate::Mbps1 => {
                append_barker(&mut chips, payload, 1, &mut common);
                0
            }
            LegacyDsssCckRate::Mbps2 => {
                append_barker(&mut chips, payload, 2, &mut common);
                0
            }
            LegacyDsssCckRate::Mbps5_5 | LegacyDsssCckRate::Mbps11 => {
                let width = if config.rate == LegacyDsssCckRate::Mbps5_5 {
                    4
                } else {
                    8
                };
                for (number, word) in payload.chunks_exact(width).enumerate() {
                    common = (common + differential(&word[..2]) + 2 * (number as u8 % 2)) % 4;
                    chips.extend_from_slice(&cck_codeword(word, common));
                }
                payload.len() / width
            }
        };
        debug_assert_eq!(chips.len(), chip_count);

        let cs8 = quantize(&chips, sample_count, config);
        let payload_start_sample =
            config.leading_samples as f64 + header_chips as f64 * 20.0 / 11.0;
        let frame_end_sample = config.leading_samples as f64 + chip_count as f64 * 20.0 / 11.0;
        Ok(Self {
            mac_bytes: mac_bytes.to_vec(),
            psdu_bytes: psdu,
            cs8,
            rate: config.rate,
            preamble: config.preamble,
            plcp: DsssPlcpFields {
                transmitted: transmitted_header,
                derived: derived_header,
                length_us,
                length_extension,
                explicit: config.plcp_override.is_some(),
            },
            scrambler_seed: seed,
            sample_rate_hz: SAMPLE_RATE_HZ,
            chip_rate_hz: CHIP_RATE_HZ,
            leading_samples: config.leading_samples,
            payload_start_sample,
            frame_end_sample,
            trailing_samples: config.trailing_samples,
            chip_count,
            cck_symbols,
            gain: config.gain,
            explicit_fcs: explicit_fcs.is_some(),
            explicit_scrambler_seed: config.scrambler_seed_override.is_some(),
        })
    }

    pub fn sample_count(&self) -> usize {
        self.cs8.len() / 2
    }
}

fn validate_config(config: &LegacyDsssCckTxConfig) -> RadioResult<()> {
    if config.preamble.is_short() && config.rate == LegacyDsssCckRate::Mbps1 {
        return Err(RadioError::Invalid {
            field: "preamble",
            reason: "short preamble is unsupported at 1 Mb/s",
        });
    }
    if config.sample_rate_hz != SAMPLE_RATE_HZ {
        return Err(RadioError::Invalid {
            field: "sample_rate_hz",
            reason: "DSSS/CCK transmission requires 20 Msps",
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
    if !config.gain.is_finite() || config.gain <= 0.0 {
        return Err(RadioError::Invalid {
            field: "gain",
            reason: "must be finite and positive",
        });
    }
    if let Some(seed) = config.scrambler_seed_override {
        if seed.iter().any(|bit| *bit > 1) || seed.iter().all(|bit| *bit == 0) {
            return Err(RadioError::Invalid {
                field: "scrambler_seed_override",
                reason: "must contain seven binary bits and be nonzero",
            });
        }
    }
    Ok(())
}

fn length_fields(octets: usize, rate: LegacyDsssCckRate) -> RadioResult<(u16, bool)> {
    let rate_units = usize::from(rate.signal());
    let numerator = octets
        .checked_mul(80)
        .and_then(|value| value.checked_add(rate_units - 1))
        .ok_or(RadioError::Overflow {
            context: "DSSS PLCP length",
        })?;
    let length = numerator / rate_units;
    let length_us = u16::try_from(length).map_err(|_| RadioError::Limit {
        context: "DSSS PLCP length microseconds",
        limit: u16::MAX as u64,
        actual: length as u64,
    })?;
    let extension = rate == LegacyDsssCckRate::Mbps11
        && length
            .checked_mul(11)
            .and_then(|value| value.checked_sub(octets * 8))
            .is_some_and(|remainder| remainder >= 8);
    Ok((length_us, extension))
}

fn append_lsb_bits(out: &mut Vec<u8>, bytes: &[u8]) {
    for byte in bytes {
        for bit in 0..8 {
            out.push((byte >> bit) & 1);
        }
    }
}

fn scramble(bits: &[u8], seed: [u8; 7]) -> Vec<u8> {
    let mut history = seed;
    let mut out = Vec::with_capacity(bits.len());
    for bit in bits {
        let value = bit ^ history[3] ^ history[6];
        out.push(value);
        history.copy_within(..6, 1);
        history[0] = value;
    }
    out
}

fn differential(bits: &[u8]) -> u8 {
    match (bits[0], bits[1]) {
        (0, 0) => 0,
        (0, 1) => 1,
        (1, 1) => 2,
        (1, 0) => 3,
        _ => unreachable!(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Complex {
    re: f64,
    im: f64,
}

impl Complex {
    const PHASES: [Self; 4] = [
        Self { re: 1.0, im: 0.0 },
        Self { re: 0.0, im: 1.0 },
        Self { re: -1.0, im: 0.0 },
        Self { re: 0.0, im: -1.0 },
    ];

    fn scale(self, value: f64) -> Self {
        Self {
            re: self.re * value,
            im: self.im * value,
        }
    }
}

fn append_barker(out: &mut Vec<Complex>, bits: &[u8], width: usize, common: &mut u8) {
    for serial in bits.chunks_exact(width) {
        *common = (*common
            + if width == 1 {
                2 * serial[0]
            } else {
                differential(serial)
            })
            % 4;
        let phase = Complex::PHASES[*common as usize];
        out.extend(BARKER.into_iter().map(|chip| phase.scale(f64::from(chip))));
    }
}

fn cck_codeword(serial: &[u8], common: u8) -> [Complex; 8] {
    let (b, c, d) = if serial.len() == 4 {
        (2 * serial[2] + 1, 0, 2 * serial[3])
    } else {
        (
            2 * serial[2] + serial[3],
            2 * serial[4] + serial[5],
            2 * serial[6] + serial[7],
        )
    };
    let phases = [b + c + d, c + d, b + d, d, b + c, c, b, 0];
    std::array::from_fn(|index| {
        let sign = if index == 3 || index == 6 { -1.0 } else { 1.0 };
        Complex::PHASES[((common + phases[index]) % 4) as usize].scale(sign)
    })
}

fn pulse(time: f64) -> f64 {
    const BETA: f64 = 0.35;
    if time.abs() >= 8.0 {
        return 0.0;
    }
    if time.abs() < 1e-12 {
        return 1.0;
    }
    if ((2.0 * BETA * time).abs() - 1.0).abs() < 1e-10 {
        return PI / 4.0 * (PI * time).sin() / (PI * time);
    }
    (PI * time).sin() / (PI * time) * (PI * BETA * time).cos() / (1.0 - (2.0 * BETA * time).powi(2))
}

fn quantize(chips: &[Complex], sample_count: usize, config: &LegacyDsssCckTxConfig) -> Vec<i8> {
    let mut out = Vec::with_capacity(sample_count * 2);
    for sample in 0..sample_count {
        let position = (sample as f64 - config.leading_samples as f64) * 11.0 / 20.0;
        let center = position.floor() as isize;
        let start = (center - 8).max(0) as usize;
        let end = (center + 9).max(0) as usize;
        let mut value = Complex { re: 0.0, im: 0.0 };
        for (index, chip) in chips
            .iter()
            .enumerate()
            .take(end.min(chips.len()))
            .skip(start)
        {
            let weight = pulse(position - index as f64 - 0.5);
            value.re += chip.re * weight;
            value.im += chip.im * weight;
        }
        for axis in [value.re, value.im] {
            out.push(
                (axis * config.gain * 127.0)
                    .round_ties_even()
                    .clamp(-128.0, 127.0) as i8,
            );
        }
    }
    out
}

fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for byte in bytes {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x8408 & 0u16.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_dsss_tx_clause_primitives_and_length_extension() {
        assert_eq!(crc16(&[0x0a, 0x00, 0xc0, 0x00]), 0xeada);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(differential(&[1, 0]), 3);
        assert_eq!(
            scramble(&[1; 16], DsssPreamble::Long.scrambler_seed()),
            [0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0]
        );
        assert_eq!(
            scramble(&[0; 16], DsssPreamble::Short.scrambler_seed()),
            [0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1]
        );
        assert_eq!(
            cck_codeword(&[0, 0, 0, 0], 0),
            [
                Complex::PHASES[1],
                Complex::PHASES[0],
                Complex::PHASES[1],
                Complex::PHASES[2],
                Complex::PHASES[1],
                Complex::PHASES[0],
                Complex::PHASES[3],
                Complex::PHASES[0],
            ]
        );
        assert_eq!(
            [1023, 1024, 1025, 1026].map(|n| length_fields(n, LegacyDsssCckRate::Mbps11).unwrap()),
            [(744, false), (745, false), (746, false), (747, true)]
        );
    }

    #[test]
    fn radio_dsss_tx_bounds_overrides_and_repeatability() {
        let mac = b"minimum";
        let config = LegacyDsssCckTxConfig::new(LegacyDsssCckRate::Mbps11, DsssPreamble::Long);
        let first = LegacyDsssCckTransmission::encode(mac, None, &config).unwrap();
        assert_eq!(
            first,
            LegacyDsssCckTransmission::encode(mac, None, &config).unwrap()
        );
        assert_eq!(&first.psdu_bytes[..mac.len()], mac);
        assert_eq!(&first.psdu_bytes[mac.len()..], &crc32(mac).to_le_bytes());

        let mut explicit = config.clone();
        explicit.plcp_override = Some([110, 0x84, 0, 0, 0, 0]);
        explicit.scrambler_seed_override = Some([1, 0, 1, 0, 1, 1, 1]);
        let tx = LegacyDsssCckTransmission::encode(mac, Some([0; 4]), &explicit).unwrap();
        assert_eq!(tx.plcp.transmitted, [110, 0x84, 0, 0, 0, 0]);
        assert_eq!(tx.scrambler_seed, [1, 0, 1, 0, 1, 1, 1]);
        assert_eq!(&tx.psdu_bytes[mac.len()..], &[0; 4]);
        assert!(tx.plcp.explicit && tx.explicit_fcs && tx.explicit_scrambler_seed);

        let invalid = LegacyDsssCckTxConfig::new(LegacyDsssCckRate::Mbps1, DsssPreamble::Short);
        assert!(matches!(
            LegacyDsssCckTransmission::encode(mac, None, &invalid),
            Err(RadioError::Invalid {
                field: "preamble",
                ..
            })
        ));
        let mut wrong_sample_rate = config.clone();
        wrong_sample_rate.sample_rate_hz = 11_000_000;
        assert!(matches!(
            LegacyDsssCckTransmission::encode(mac, None, &wrong_sample_rate),
            Err(RadioError::Invalid {
                field: "sample_rate_hz",
                ..
            })
        ));
        let mut bounded = config.clone();
        bounded.max_samples = first.sample_count() - 1;
        assert!(matches!(
            LegacyDsssCckTransmission::encode(mac, None, &bounded),
            Err(RadioError::Limit {
                context: "DSSS waveform samples",
                ..
            })
        ));
        let mut unrepresentable =
            LegacyDsssCckTxConfig::new(LegacyDsssCckRate::Mbps1, DsssPreamble::Long);
        unrepresentable.max_psdu_bytes = 8192;
        assert!(matches!(
            LegacyDsssCckTransmission::encode(&vec![0; 8188], None, &unrepresentable),
            Err(RadioError::Limit {
                context: "DSSS PLCP length microseconds",
                ..
            })
        ));
        bounded.max_samples = usize::MAX;
        bounded.max_psdu_bytes = 4;
        assert!(matches!(
            LegacyDsssCckTransmission::encode(mac, None, &bounded),
            Err(RadioError::Limit {
                context: "DSSS PSDU bytes",
                ..
            })
        ));
        bounded.max_psdu_bytes = usize::MAX;
        bounded.leading_samples = usize::MAX;
        assert!(matches!(
            LegacyDsssCckTransmission::encode(&[], None, &bounded),
            Err(RadioError::Overflow {
                context: "DSSS waveform samples"
            })
        ));
    }
}
