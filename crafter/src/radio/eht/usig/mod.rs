//! Universal SIGNAL interpretation for EHT MU and EHT TB PPDUs.

#[cfg(test)]
mod tests;

/// EHT-SIG modulation selected by the MU U-SIG field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtSigMcs {
    Mcs0,
    Mcs1,
    Mcs3,
    Mcs0Dcm,
}

/// EHT MU PPDU interpretation selected by UL/DL and PPDU type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtMuPpduType {
    DownlinkOfdma,
    SingleUser,
    DownlinkMuMimo,
}

/// Version-dependent U-SIG fields carried by an EHT MU PPDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtMuUsigFields {
    pub ppdu_type: EhtMuPpduType,
    pub punctured_channel_information: u8,
    pub eht_sig_mcs: EhtSigMcs,
    pub eht_sig_symbols: u8,
}

/// Version-dependent U-SIG fields carried by an EHT TB PPDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtTbUsigFields {
    pub spatial_reuse: [u8; 2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtUsigFormat {
    Mu(EhtMuUsigFields),
    TriggerBased(EhtTbUsigFields),
}

/// Integrity-checked EHT U-SIG fields. DATA admission remains a separate step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtUsigFields {
    /// 0=20, 1=40, 2=80, 3=160, 4/5=the two 320 MHz placements.
    pub bandwidth_code: u8,
    pub uplink: bool,
    pub bss_color: u8,
    pub txop: u8,
    pub format: EhtUsigFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtUsigError {
    BitCount { required: usize, available: usize },
    NonBinary { index: usize, value: u8 },
    MetricCount { required: usize, available: usize },
    NonFiniteMetric { index: usize },
    UnusableMetrics,
    Crc { expected: u8, received: u8 },
    TailBit { index: usize },
    PhyVersion(u8),
    Bandwidth(u8),
    ValidateBit { index: usize },
    PpduType { uplink: bool, value: u8 },
    PuncturedChannelInformation(u8),
}

impl std::fmt::Display for EhtUsigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EHT U-SIG: {self:?}")
    }
}

impl std::error::Error for EhtUsigError {}

impl EhtUsigFields {
    /// Recover U-SIG from two symbols of 52 interleaved soft metrics each.
    /// Positive values favor bit one. The continuous rate-half BCC state spans
    /// both symbols; the caller supplies equalized data tones in ascending order.
    pub fn decode_interleaved(metrics: &[f32]) -> Result<Self, EhtUsigError> {
        if metrics.len() != 104 {
            return Err(EhtUsigError::MetricCount {
                required: 104,
                available: metrics.len(),
            });
        }
        if let Some(index) = metrics.iter().position(|value| !value.is_finite()) {
            return Err(EhtUsigError::NonFiniteMetric { index });
        }
        let scale = metrics.iter().map(|value| value.abs()).fold(0f32, f32::max);
        if scale == 0. {
            return Err(EhtUsigError::UnusableMetrics);
        }
        let coded: [f32; 104] = std::array::from_fn(|index| {
            let bit = index % 52;
            metrics[(index / 52) * 52 + 4 * (bit % 13) + bit / 13] / scale
        });
        let pairs =
            std::array::from_fn::<_, 52, _>(|index| [coded[2 * index], coded[2 * index + 1]]);
        Self::decode(&super::super::signal::decode_bcc(&pairs))
    }

    /// Decode the 52 U-SIG information bits in transmission order.
    pub fn decode(bits: &[u8]) -> Result<Self, EhtUsigError> {
        validate_integrity(bits)?;
        let field = |start: usize, count: usize| {
            bits[start..start + count]
                .iter()
                .enumerate()
                .fold(0u8, |value, (index, bit)| value | (bit << index))
        };
        let version = field(0, 3);
        if version != 0 {
            return Err(EhtUsigError::PhyVersion(version));
        }
        let bandwidth_code = field(3, 3);
        if bandwidth_code > 5 {
            return Err(EhtUsigError::Bandwidth(bandwidth_code));
        }
        let uplink = bits[6] != 0;
        let ppdu_type = field(26, 2);
        let format = match (uplink, ppdu_type) {
            (true, 0) => EhtUsigFormat::TriggerBased(EhtTbUsigFields {
                spatial_reuse: [field(29, 4), field(33, 4)],
            }),
            (_, 1) | (false, 0 | 2) => {
                for index in [25, 28, 34] {
                    if bits[index] != 1 {
                        return Err(EhtUsigError::ValidateBit { index });
                    }
                }
                let punctured_channel_information = field(29, 5);
                // For 20 and 40 MHz, the four channel-presence bits are one.
                // B7 is Disregard, so it is deliberately not constrained.
                if bandwidth_code <= 1 && punctured_channel_information & 0x0f != 0x0f {
                    return Err(EhtUsigError::PuncturedChannelInformation(
                        punctured_channel_information,
                    ));
                }
                let ppdu_type = match ppdu_type {
                    0 => EhtMuPpduType::DownlinkOfdma,
                    1 => EhtMuPpduType::SingleUser,
                    2 => EhtMuPpduType::DownlinkMuMimo,
                    _ => unreachable!(),
                };
                let eht_sig_mcs = match field(35, 2) {
                    0 => EhtSigMcs::Mcs0,
                    1 => EhtSigMcs::Mcs1,
                    2 => EhtSigMcs::Mcs3,
                    3 => EhtSigMcs::Mcs0Dcm,
                    _ => unreachable!(),
                };
                EhtUsigFormat::Mu(EhtMuUsigFields {
                    ppdu_type,
                    punctured_channel_information,
                    eht_sig_mcs,
                    eht_sig_symbols: field(37, 5) + 1,
                })
            }
            _ => {
                return Err(EhtUsigError::PpduType {
                    uplink,
                    value: ppdu_type,
                })
            }
        };
        if matches!(format, EhtUsigFormat::TriggerBased(_)) && bits[28] != 1 {
            return Err(EhtUsigError::ValidateBit { index: 28 });
        }
        Ok(Self {
            bandwidth_code,
            uplink,
            bss_color: field(7, 6),
            txop: field(13, 7),
            format,
        })
    }
}

fn validate_integrity(bits: &[u8]) -> Result<(), EhtUsigError> {
    if bits.len() != 52 {
        return Err(EhtUsigError::BitCount {
            required: 52,
            available: bits.len(),
        });
    }
    if let Some((index, &value)) = bits.iter().enumerate().find(|(_, value)| **value > 1) {
        return Err(EhtUsigError::NonBinary { index, value });
    }
    let expected = super::super::ht::crc(&bits[..42]) >> 4;
    let received = bits[42..46]
        .iter()
        .fold(0u8, |value, bit| (value << 1) | bit);
    if expected != received {
        return Err(EhtUsigError::Crc { expected, received });
    }
    if let Some(index) = (46..52).find(|index| bits[*index] != 0) {
        return Err(EhtUsigError::TailBit { index });
    }
    Ok(())
}
