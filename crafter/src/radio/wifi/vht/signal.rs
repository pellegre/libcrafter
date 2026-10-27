//! VHT signaling, IEEE 802.11-2020 21.3.8.3.3/6 and 21.3.10.2/3.
use crate::radio::wifi::{ht::crc, ofdm::signal::decode_bcc};

/// SU and MU fields remain distinct; absent MU users have no coding observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhtSignalAUsers {
    Single {
        space_time_streams: u8,
        partial_aid: u16,
        mcs: u8,
        ldpc: bool,
        beamformed: bool,
    },
    Multi {
        space_time_streams: [u8; 4],
        ldpc: [Option<bool>; 4],
    },
}

/// Integrity-checked signaling. DATA admission separately checks PHY support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhtSignalAFields {
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
pub enum VhtSignalError {
    BitCount {
        context: &'static str,
        required: usize,
        available: usize,
    },
    NonBinary {
        context: &'static str,
        index: usize,
        value: u8,
    },
    MetricCount {
        required: usize,
        available: usize,
    },
    NonFiniteMetric {
        index: usize,
    },
    UnusableMetrics,
    Crc {
        expected: u8,
        received: u8,
    },
    ReservedBit {
        index: usize,
    },
    TailBit {
        index: usize,
    },
    ReservedStreams {
        user: usize,
        value: u8,
    },
    NoServiceForNdp,
    ServicePrefix {
        index: usize,
    },
}
impl std::fmt::Display for VhtSignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VHT signaling: {self:?}")
    }
}
impl std::error::Error for VhtSignalError {}

fn binary(bits: &[u8], n: usize, context: &'static str) -> Result<(), VhtSignalError> {
    if bits.len() != n {
        return Err(VhtSignalError::BitCount {
            context,
            required: n,
            available: bits.len(),
        });
    }
    if let Some((index, &value)) = bits.iter().enumerate().find(|(_, b)| **b > 1) {
        return Err(VhtSignalError::NonBinary {
            context,
            index,
            value,
        });
    }
    Ok(())
}
fn get(bits: &[u8], start: usize, count: usize) -> u32 {
    bits[start..start + count]
        .iter()
        .enumerate()
        .fold(0, |v, (i, b)| v | (u32::from(*b) << i))
}
fn put(bits: &mut [u8], start: usize, count: usize, value: u32) {
    for i in 0..count {
        bits[start + i] = ((value >> i) & 1) as u8;
    }
}
fn soft<const N: usize>(metrics: &[f32], columns: usize) -> Result<[u8; N], VhtSignalError> {
    let n = 2 * N;
    if metrics.len() != n {
        return Err(VhtSignalError::MetricCount {
            required: n,
            available: metrics.len(),
        });
    }
    if let Some(index) = metrics.iter().position(|v| !v.is_finite()) {
        return Err(VhtSignalError::NonFiniteMetric { index });
    }
    let scale = metrics.iter().map(|v| v.abs()).fold(0f32, f32::max);
    if scale == 0. {
        return Err(VhtSignalError::UnusableMetrics);
    }
    let block = if n == 96 { 48 } else { 52 };
    let deinterleaved: Vec<_> = (0..n)
        .map(|k| {
            let bit = k % block;
            metrics[k / block * block + (block / columns) * (bit % columns) + bit / columns] / scale
        })
        .collect();
    let pairs =
        std::array::from_fn::<_, N, _>(|i| [deinterleaved[2 * i], deinterleaved[2 * i + 1]]);
    Ok(decode_bcc(&pairs))
}

impl VhtSignalAFields {
    pub fn encode(self) -> [u8; 48] {
        let mut bits = [0; 48];
        put(&mut bits, 0, 2, u32::from(self.bandwidth_code));
        for i in [2, 23, 33] {
            bits[i] = 1;
        }
        bits[3] = u8::from(self.stbc);
        put(&mut bits, 4, 6, u32::from(self.group_id));
        bits[22] = u8::from(self.txop_ps_not_allowed);
        bits[24] = u8::from(self.short_guard_interval);
        bits[25] = u8::from(self.short_gi_disambiguation);
        bits[27] = u8::from(self.ldpc_extra_symbol);
        match self.users {
            VhtSignalAUsers::Single {
                space_time_streams,
                partial_aid,
                mcs,
                ldpc,
                beamformed,
            } => {
                put(
                    &mut bits,
                    10,
                    3,
                    u32::from(space_time_streams.saturating_sub(1)),
                );
                put(&mut bits, 13, 9, u32::from(partial_aid));
                put(&mut bits, 28, 4, u32::from(mcs));
                bits[26] = u8::from(ldpc);
                bits[32] = u8::from(beamformed);
            }
            VhtSignalAUsers::Multi {
                space_time_streams,
                ldpc,
            } => {
                bits[31] = 1;
                bits[32] = 1;
                for user in 0..4 {
                    put(
                        &mut bits,
                        10 + 3 * user,
                        3,
                        u32::from(space_time_streams[user]),
                    );
                    bits[[26, 28, 29, 30][user]] = u8::from(ldpc[user].unwrap_or(true));
                }
            }
        }
        let check = crc(&bits[..34]);
        for i in 0..8 {
            bits[34 + i] = (check >> (7 - i)) & 1;
        }
        bits
    }
    pub fn decode_interleaved(metrics: &[f32]) -> Result<Self, VhtSignalError> {
        Self::decode(&soft::<48>(metrics, 16)?)
    }
    pub fn decode(bits: &[u8]) -> Result<Self, VhtSignalError> {
        binary(bits, 48, "SIG-A")?;
        let expected = crc(&bits[..34]);
        let received = bits[34..42].iter().fold(0, |v, b| (v << 1) | b);
        if expected != received {
            return Err(VhtSignalError::Crc { expected, received });
        }
        for i in [2, 23, 33] {
            if bits[i] != 1 {
                return Err(VhtSignalError::ReservedBit { index: i });
            }
        }
        if let Some(index) = (42..48).find(|i| bits[*i] != 0) {
            return Err(VhtSignalError::TailBit { index });
        }
        let group_id = get(bits, 4, 6) as u8;
        let users = if group_id == 0 || group_id == 63 {
            VhtSignalAUsers::Single {
                space_time_streams: get(bits, 10, 3) as u8 + 1,
                partial_aid: get(bits, 13, 9) as u16,
                mcs: get(bits, 28, 4) as u8,
                ldpc: bits[26] != 0,
                beamformed: bits[32] != 0,
            }
        } else {
            for (i, value) in [(3, 0), (31, 1), (32, 1)] {
                if bits[i] != value {
                    return Err(VhtSignalError::ReservedBit { index: i });
                }
            }
            let space_time_streams = std::array::from_fn(|u| get(bits, 10 + 3 * u, 3) as u8);
            let mut ldpc = [None; 4];
            for user in 0..4 {
                let value = space_time_streams[user];
                if value > 4 {
                    return Err(VhtSignalError::ReservedStreams { user, value });
                }
                let i = [26, 28, 29, 30][user];
                if value == 0 && bits[i] != 1 {
                    return Err(VhtSignalError::ReservedBit { index: i });
                }
                if value != 0 {
                    ldpc[user] = Some(bits[i] != 0);
                }
            }
            VhtSignalAUsers::Multi {
                space_time_streams,
                ldpc,
            }
        };
        Ok(Self {
            bandwidth_code: get(bits, 0, 2) as u8,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhtSignalB20Content {
    Ndp,
    SingleUser { length_units: u32 },
    MultiUser { length_units: u32, mcs: u8 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhtSignalB20Fields {
    content: VhtSignalB20Content,
    service_crc: Option<u8>,
}
impl VhtSignalB20Fields {
    pub fn content(self) -> VhtSignalB20Content {
        self.content
    }
    pub fn encode(content: VhtSignalB20Content) -> [u8; 26] {
        let mut bits = [0; 26];
        match content {
            VhtSignalB20Content::Ndp => {
                bits[..20].copy_from_slice(&b"00000111010001000010".map(|b| b - b'0'))
            }
            VhtSignalB20Content::SingleUser { length_units } => {
                put(&mut bits, 0, 17, length_units);
                bits[17..20].fill(1);
            }
            VhtSignalB20Content::MultiUser { length_units, mcs } => {
                put(&mut bits, 0, 16, length_units);
                put(&mut bits, 16, 4, u32::from(mcs));
            }
        }
        bits
    }
    pub fn decode_interleaved(metrics: &[f32], multi_user: bool) -> Result<Self, VhtSignalError> {
        Self::decode(&soft::<26>(metrics, 13)?, multi_user)
    }
    pub fn decode(bits: &[u8], multi_user: bool) -> Result<Self, VhtSignalError> {
        binary(bits, 26, "SIG-B")?;
        if let Some(index) = (20..26).find(|i| bits[*i] != 0) {
            return Err(VhtSignalError::TailBit { index });
        }
        if !multi_user && bits[..20] == Self::encode(VhtSignalB20Content::Ndp)[..20] {
            return Ok(Self {
                content: VhtSignalB20Content::Ndp,
                service_crc: None,
            });
        }
        let content = if multi_user {
            VhtSignalB20Content::MultiUser {
                length_units: get(bits, 0, 16),
                mcs: get(bits, 16, 4) as u8,
            }
        } else {
            if let Some(index) = (17..20).find(|i| bits[*i] != 1) {
                return Err(VhtSignalError::ReservedBit { index });
            }
            VhtSignalB20Content::SingleUser {
                length_units: get(bits, 0, 17),
            }
        };
        Ok(Self {
            content,
            service_crc: Some(crc(&bits[..20])),
        })
    }
    pub fn apep_length_bounds(self) -> Option<(u32, u32)> {
        let n = match self.content {
            VhtSignalB20Content::Ndp => return None,
            VhtSignalB20Content::SingleUser { length_units }
            | VhtSignalB20Content::MultiUser { length_units, .. } => length_units,
        };
        Some((if n == 0 { 0 } else { 4 * (n - 1) + 1 }, 4 * n))
    }
    pub fn expected_service_crc(self) -> Option<u8> {
        self.service_crc
    }
    pub fn verify_service(self, bits: &[u8]) -> Result<(), VhtSignalError> {
        binary(bits, 16, "SERVICE")?;
        let expected = self.service_crc.ok_or(VhtSignalError::NoServiceForNdp)?;
        if let Some(index) = (0..8).find(|i| bits[*i] != 0) {
            return Err(VhtSignalError::ServicePrefix { index });
        }
        let received = bits[8..].iter().fold(0, |v, b| (v << 1) | b);
        if expected != received {
            return Err(VhtSignalError::Crc { expected, received });
        }
        Ok(())
    }
}
