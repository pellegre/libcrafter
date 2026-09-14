//! VHT20 SIG-B and SERVICE, IEEE 802.11-2020 21.3.8.3.6 and 21.3.10.2-3.
//! Source facts and edition caveats: docs/wifi-phy-evidence.json.

/// Context-dependent SIG-B interpretation. MCS admission is a separate step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhtSignalB20Content {
    Ndp,
    SingleUser { length_units: u32 },
    MultiUser { length_units: u32, mcs: u8 },
}

/// Parsed SIG-B, not integrity-verified until `verify_service` succeeds.
/// Private fields keep the expected CRC bound to the decoded header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhtSignalB20Fields {
    content: VhtSignalB20Content,
    service_crc: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhtSignalB20Error {
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
    ReservedBit {
        index: usize,
    },
    TailBit {
        index: usize,
    },
    NoServiceForNdp,
    ServicePrefixBit {
        index: usize,
    },
    ServiceCrc {
        expected: u8,
        received: u8,
    },
}
impl std::fmt::Display for VhtSignalB20Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VHT20 SIG-B: {self:?}")
    }
}
impl std::error::Error for VhtSignalB20Error {}

fn binary(bits: &[u8], required: usize, context: &'static str) -> Result<(), VhtSignalB20Error> {
    if bits.len() != required {
        return Err(VhtSignalB20Error::BitCount {
            context,
            required,
            available: bits.len(),
        });
    }
    if let Some((index, &value)) = bits.iter().enumerate().find(|(_, b)| **b > 1) {
        return Err(VhtSignalB20Error::NonBinary {
            context,
            index,
            value,
        });
    }
    Ok(())
}

impl VhtSignalB20Fields {
    /// Recover 26 input bits from 52 equalized, interleaved BPSK soft metrics.
    /// Positive favors bit one. `multi_user` comes from VHT-SIG-A, not SIG-B.
    /// Channel estimation, pilot correction and DATA admission are external.
    pub fn decode_interleaved(
        metrics: &[f32],
        multi_user: bool,
    ) -> Result<Self, VhtSignalB20Error> {
        if metrics.len() != 52 {
            return Err(VhtSignalB20Error::MetricCount {
                required: 52,
                available: metrics.len(),
            });
        }
        if let Some(index) = metrics.iter().position(|v| !v.is_finite()) {
            return Err(VhtSignalB20Error::NonFiniteMetric { index });
        }
        let scale = metrics.iter().map(|v| v.abs()).fold(0f32, f32::max);
        if scale == 0. {
            return Err(VhtSignalB20Error::UnusableMetrics);
        }
        let deinterleaved: [f32; 52] =
            std::array::from_fn(|k| metrics[4 * (k % 13) + k / 13] / scale);
        let pairs =
            std::array::from_fn::<_, 26, _>(|i| [deinterleaved[2 * i], deinterleaved[2 * i + 1]]);
        Self::decode(&crate::radio::signal::decode_bcc(&pairs), multi_user)
    }

    /// Interpret exactly 26 binary bits. This cannot verify the header's CRC:
    /// that CRC is carried later in the descrambled DATA SERVICE field.
    pub fn decode(bits: &[u8], multi_user: bool) -> Result<Self, VhtSignalB20Error> {
        binary(bits, 26, "SIG-B")?;
        if let Some(index) = (20..26).find(|i| bits[*i] != 0) {
            return Err(VhtSignalB20Error::TailBit { index });
        }
        const NDP: &[u8; 20] = b"00000111010001000010";
        if !multi_user && bits[..20].iter().zip(NDP).all(|(a, b)| *a == *b - b'0') {
            return Ok(Self {
                content: VhtSignalB20Content::Ndp,
                service_crc: None,
            });
        }
        let field = |start: usize, count: usize| {
            bits[start..start + count]
                .iter()
                .enumerate()
                .fold(0u32, |v, (i, b)| v | (u32::from(*b) << i))
        };
        let content = if multi_user {
            VhtSignalB20Content::MultiUser {
                length_units: field(0, 16),
                mcs: field(16, 4) as u8,
            }
        } else {
            if let Some(index) = (17..20).find(|i| bits[*i] != 1) {
                return Err(VhtSignalB20Error::ReservedBit { index });
            }
            VhtSignalB20Content::SingleUser {
                length_units: field(0, 17),
            }
        };
        Ok(Self {
            content,
            service_crc: Some(crate::radio::ht::crc(&bits[..20])),
        })
    }

    pub fn content(&self) -> VhtSignalB20Content {
        self.content
    }

    /// Inclusive bounds implied by ceil(APEP_LENGTH/4), not an exact PSDU
    /// length. NDP has no DATA; zero length units encode bounds (0, 0).
    pub fn apep_length_bounds(&self) -> Option<(u32, u32)> {
        let units = match self.content {
            VhtSignalB20Content::Ndp => return None,
            VhtSignalB20Content::SingleUser { length_units }
            | VhtSignalB20Content::MultiUser { length_units, .. } => length_units,
        };
        Some((if units == 0 { 0 } else { 4 * (units - 1) + 1 }, 4 * units))
    }

    /// Expected CRC byte, c7 in its most significant bit. No CRC for NDP.
    pub fn expected_service_crc(&self) -> Option<u8> {
        self.service_crc
    }

    /// Check exactly 16 already-descrambled SERVICE bits in transmission
    /// order. This verifies SIG-B linkage, not any MPDU's FCS or DATA mode.
    pub fn verify_service(&self, bits: &[u8]) -> Result<(), VhtSignalB20Error> {
        let expected = self.service_crc.ok_or(VhtSignalB20Error::NoServiceForNdp)?;
        binary(bits, 16, "SERVICE")?;
        if let Some(index) = (0..8).find(|i| bits[*i] != 0) {
            return Err(VhtSignalB20Error::ServicePrefixBit { index });
        }
        let received = bits[8..].iter().fold(0u8, |v, b| (v << 1) | b);
        if expected != received {
            return Err(VhtSignalB20Error::ServiceCrc { expected, received });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
