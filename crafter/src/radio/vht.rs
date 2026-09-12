//! VHT-SIG-A interpretation, IEEE 802.11-2020 21.3.8.3.3 Table 21-12.
//! Edition caveats and source inventory: docs/wifi-phy-evidence.json.

/// Group-dependent fields. Absent MU users have no observed coding mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhtSignalAUsers {
    Single {
        space_time_streams: u8,
        partial_aid: u16,
        /// Signaled value; DATA admission must reject unsupported MCS values.
        mcs: u8,
        ldpc: bool,
        beamformed: bool,
    },
    Multi {
        space_time_streams: [u8; 4],
        ldpc: [Option<bool>; 4],
    },
}

/// Integrity-checked header fields, not an assertion of DATA decodability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhtSignalAFields {
    /// 0: 20 MHz, 1: 40 MHz, 2: 80 MHz, 3: 160 MHz or 80+80 MHz.
    pub bandwidth_code: u8,
    pub group_id: u8,
    pub stbc: bool,
    pub short_guard_interval: bool,
    pub short_gi_disambiguation: bool,
    pub ldpc_extra_symbol: bool,
    pub txop_ps_not_allowed: bool,
    pub users: VhtSignalAUsers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhtSignalAError {
    BitCount { required: usize, available: usize },
    NonBinary { index: usize, value: u8 },
    MetricCount { required: usize, available: usize },
    NonFiniteMetric { index: usize },
    UnusableMetrics,
    Crc { expected: u8, received: u8 },
    ReservedBit { index: usize },
    TailBit { index: usize },
    ReservedMuStreams { user: usize, value: u8 },
}

impl std::fmt::Display for VhtSignalAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VHT-SIG-A: {self:?}")
    }
}
impl std::error::Error for VhtSignalAError {}

impl VhtSignalAFields {
    /// Decode two sets of 48 interleaved data-tone soft metrics. Positive
    /// favors bit one. The caller must have equalized and demapped BPSK on
    /// the first symbol and QBPSK on the second, keeping pilots unrotated.
    pub fn decode_interleaved(metrics: &[f32]) -> Result<Self, VhtSignalAError> {
        if metrics.len() != 96 {
            return Err(VhtSignalAError::MetricCount {
                required: 96,
                available: metrics.len(),
            });
        }
        if let Some(index) = metrics.iter().position(|v| !v.is_finite()) {
            return Err(VhtSignalAError::NonFiniteMetric { index });
        }
        let scale = metrics.iter().map(|v| v.abs()).fold(0f32, f32::max);
        if scale == 0. {
            return Err(VhtSignalAError::UnusableMetrics);
        }
        let deinterleaved: [f32; 96] = std::array::from_fn(|k| {
            let bit = k % 48;
            metrics[(k / 48) * 48 + 3 * (bit % 16) + bit / 16] / scale
        });
        let pairs =
            std::array::from_fn::<_, 48, _>(|i| [deinterleaved[2 * i], deinterleaved[2 * i + 1]]);
        Self::decode(&super::signal::decode_bcc(&pairs))
    }

    /// Decode exactly 48 binary bits in transmission order, without allocation
    /// or device access. Unsupported DATA modes remain signaled metadata.
    pub fn decode(bits: &[u8]) -> Result<Self, VhtSignalAError> {
        if bits.len() != 48 {
            return Err(VhtSignalAError::BitCount {
                required: 48,
                available: bits.len(),
            });
        }
        if let Some((index, &value)) = bits.iter().enumerate().find(|(_, v)| **v > 1) {
            return Err(VhtSignalAError::NonBinary { index, value });
        }
        let expected = super::ht::crc(&bits[..34]);
        let received = bits[34..42].iter().fold(0u8, |v, b| (v << 1) | b);
        if received != expected {
            return Err(VhtSignalAError::Crc { expected, received });
        }
        if let Some(index) = (42..48).find(|i| bits[*i] != 0) {
            return Err(VhtSignalAError::TailBit { index });
        }
        for index in [2, 23, 33] {
            if bits[index] != 1 {
                return Err(VhtSignalAError::ReservedBit { index });
            }
        }
        let field = |start: usize, count: usize| {
            bits[start..start + count]
                .iter()
                .enumerate()
                .fold(0u16, |v, (i, b)| v | (u16::from(*b) << i))
        };
        let group_id = field(4, 6) as u8;
        let users = if group_id == 0 || group_id == 63 {
            VhtSignalAUsers::Single {
                space_time_streams: field(10, 3) as u8 + 1,
                partial_aid: field(13, 9),
                mcs: field(28, 4) as u8,
                ldpc: bits[26] != 0,
                beamformed: bits[32] != 0,
            }
        } else {
            for (index, value) in [(3, 0), (31, 1), (32, 1)] {
                if bits[index] != value {
                    return Err(VhtSignalAError::ReservedBit { index });
                }
            }
            let space_time_streams = std::array::from_fn(|user| field(10 + 3 * user, 3) as u8);
            let mut ldpc = [None; 4];
            for user in 0..4 {
                let value = space_time_streams[user];
                if value > 4 {
                    return Err(VhtSignalAError::ReservedMuStreams { user, value });
                }
                let index = [26, 28, 29, 30][user];
                if value == 0 {
                    if bits[index] != 1 {
                        return Err(VhtSignalAError::ReservedBit { index });
                    }
                } else {
                    ldpc[user] = Some(bits[index] != 0);
                }
            }
            VhtSignalAUsers::Multi {
                space_time_streams,
                ldpc,
            }
        };
        Ok(Self {
            bandwidth_code: field(0, 2) as u8,
            group_id,
            stbc: bits[3] != 0,
            short_guard_interval: bits[24] != 0,
            short_gi_disambiguation: bits[25] != 0,
            ldpc_extra_symbol: bits[27] != 0,
            txop_ps_not_allowed: bits[22] != 0,
            users,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(text: &str) -> Vec<u8> {
        text.bytes().map(|b| b - b'0').collect()
    }
    fn repair_crc(bits: &mut [u8]) {
        let crc = crate::radio::ht::crc(&bits[..34]);
        for i in 0..8 {
            bits[34 + i] = (crc >> (7 - i)) & 1;
        }
    }

    #[test]
    fn radio_vht_signal_a_independent_fields_and_soft_recovery() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/vht-signal-a-index.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 1880);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            let number = |i: usize| c[i].parse::<u16>().unwrap();
            let input = bits(c[0]);
            let f = VhtSignalAFields::decode(&input).unwrap();
            assert_eq!(f.bandwidth_code, number(1) as u8);
            assert_eq!(f.group_id, number(2) as u8);
            assert_eq!(f.stbc, number(3) != 0);
            assert_eq!(f.short_guard_interval, number(5) != 0);
            assert_eq!(f.short_gi_disambiguation, number(6) != 0);
            assert_eq!(f.ldpc_extra_symbol, number(7) != 0);
            assert_eq!(f.txop_ps_not_allowed, number(8) != 0);
            if f.group_id == 0 || f.group_id == 63 {
                assert_eq!(
                    f.users,
                    VhtSignalAUsers::Single {
                        space_time_streams: (number(4) & 7) as u8 + 1,
                        partial_aid: number(4) >> 3,
                        mcs: number(10) as u8,
                        ldpc: number(9) != 0,
                        beamformed: number(11) != 0,
                    }
                );
            } else {
                let counts = std::array::from_fn(|i| ((number(4) >> (3 * i)) & 7) as u8);
                let coding = std::array::from_fn(|i| {
                    (counts[i] != 0).then_some(if i == 0 {
                        number(9) != 0
                    } else {
                        number(10) & (1 << (i - 1)) != 0
                    })
                });
                assert_eq!(
                    f.users,
                    VhtSignalAUsers::Multi {
                        space_time_streams: counts,
                        ldpc: coding
                    }
                );
            }
            let metrics: Vec<_> = bits(c[12])
                .iter()
                .map(|b| if *b == 1 { 1. } else { -1. })
                .collect();
            assert_eq!(VhtSignalAFields::decode_interleaved(&metrics), Ok(f));
            for i in 0..48 {
                let mut changed = input.clone();
                changed[i] ^= 1;
                assert!(VhtSignalAFields::decode(&changed).is_err(), "bit={i}");
            }
        }
    }

    #[test]
    fn radio_vht_signal_a_input_and_reserved_bounds() {
        let rows: Vec<_> = include_str!("../../tests/fixtures/iq/vht-signal-a-index.tsv")
            .lines()
            .skip(1)
            .collect();
        let su: Vec<_> = rows[0].split('\t').collect();
        let good = bits(su[0]);
        // Integrity parsing retains a signaled MCS even when a DATA receiver
        // cannot admit it. It must not silently relabel it as a supported MCS.
        for mcs in 10..16u8 {
            let mut changed = good.clone();
            for i in 0..4 {
                changed[28 + i] = (mcs >> i) & 1;
            }
            repair_crc(&mut changed);
            assert!(matches!(VhtSignalAFields::decode(&changed).unwrap().users,
                VhtSignalAUsers::Single { mcs: observed, .. } if observed == mcs));
        }
        for size in [0, 1, 47, 49, 96] {
            assert_eq!(
                VhtSignalAFields::decode(&vec![0; size]),
                Err(VhtSignalAError::BitCount {
                    required: 48,
                    available: size
                })
            );
        }
        for i in 0..48 {
            let mut changed = good.clone();
            changed[i] = 2;
            assert_eq!(
                VhtSignalAFields::decode(&changed),
                Err(VhtSignalAError::NonBinary { index: i, value: 2 })
            );
        }
        for i in [2, 23, 33] {
            let mut changed = good.clone();
            changed[i] = 0;
            repair_crc(&mut changed);
            assert_eq!(
                VhtSignalAFields::decode(&changed),
                Err(VhtSignalAError::ReservedBit { index: i })
            );
        }
        let mu = bits(rows[640].split('\t').next().unwrap());
        for i in [3, 31, 32, 28, 29, 30] {
            let mut changed = mu.clone();
            changed[i] ^= 1;
            repair_crc(&mut changed);
            assert_eq!(
                VhtSignalAFields::decode(&changed),
                Err(VhtSignalAError::ReservedBit { index: i })
            );
        }
        for user in 0..4 {
            for value in 5..8u8 {
                let mut changed = mu.clone();
                for i in 0..3 {
                    changed[10 + 3 * user + i] = (value >> i) & 1;
                }
                repair_crc(&mut changed);
                assert_eq!(
                    VhtSignalAFields::decode(&changed),
                    Err(VhtSignalAError::ReservedMuStreams { user, value })
                );
            }
        }
        for size in [0, 1, 95, 97] {
            assert_eq!(
                VhtSignalAFields::decode_interleaved(&vec![0.; size]),
                Err(VhtSignalAError::MetricCount {
                    required: 96,
                    available: size
                })
            );
        }
        assert_eq!(
            VhtSignalAFields::decode_interleaved(&[0.; 96]),
            Err(VhtSignalAError::UnusableMetrics)
        );
        let metrics: Vec<f32> = bits(su[12])
            .iter()
            .map(|b| if *b == 1 { 1. } else { -1. })
            .collect();
        for i in 0..96 {
            for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                let mut changed = metrics.clone();
                changed[i] = value;
                assert_eq!(
                    VhtSignalAFields::decode_interleaved(&changed),
                    Err(VhtSignalAError::NonFiniteMetric { index: i })
                );
            }
        }
        for scale in [f32::MIN_POSITIVE, 1e-20, 1., 1e20, f32::MAX] {
            let scaled: Vec<_> = metrics.iter().map(|m| m * scale).collect();
            assert_eq!(
                VhtSignalAFields::decode_interleaved(&scaled),
                VhtSignalAFields::decode(&good)
            );
        }
    }
}
