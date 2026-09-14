use super::Error;
use crate::protocols::link::{Dot11EhtTriggerCommonFields, Dot11EhtTriggerUserFields};
use crate::radio::eht::{
    sig::iq::SignalFields, EhtNonMuUser, EhtNonOfdmaUsers, EhtOfdmaCommon, EhtResourceUnit,
    EhtRuSize,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Modulation {
    bits_per_tone: usize,
    rate_num: usize,
    rate_den: usize,
    dcm: bool,
}

impl Modulation {
    fn new(mcs: u8) -> Result<Self, Error> {
        let (bits_per_tone, rate_num, rate_den, dcm) = match mcs {
            0 => (1, 1, 2, false),
            1 => (2, 1, 2, false),
            2 => (2, 3, 4, false),
            3 => (4, 1, 2, false),
            4 => (4, 3, 4, false),
            5 => (6, 2, 3, false),
            6 => (6, 3, 4, false),
            7 => (6, 5, 6, false),
            8 => (8, 3, 4, false),
            9 => (8, 5, 6, false),
            10 => (10, 3, 4, false),
            11 => (10, 5, 6, false),
            12 => (12, 3, 4, false),
            13 => (12, 5, 6, false),
            15 => (1, 1, 2, true),
            value => return Err(Error::Modulation(value)),
        };
        Ok(Self {
            bits_per_tone,
            rate_num,
            rate_den,
            dcm,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    data_tones: usize,
    short_tones: usize,
}

impl Geometry {
    fn full_band(dcm: bool) -> Self {
        Self {
            data_tones: if dcm { 117 } else { 234 },
            short_tones: if dcm { 30 } else { 60 },
        }
    }

    fn for_resource(resource: EhtResourceUnit, dcm: bool) -> Result<Self, Error> {
        let mut result = Self {
            data_tones: 0,
            short_tones: 0,
        };
        for component in resource.components() {
            let (data, short) = match (component.size(), dcm) {
                (EhtRuSize::Ru26, false) => (24, 6),
                (EhtRuSize::Ru26, true) => (12, 2),
                (EhtRuSize::Ru52, false) => (48, 12),
                (EhtRuSize::Ru52, true) => (24, 6),
                (EhtRuSize::Ru106, false) => (102, 24),
                (EhtRuSize::Ru106, true) => (51, 12),
                (EhtRuSize::Ru242, false) => (234, 60),
                (EhtRuSize::Ru242, true) => (117, 30),
            };
            result.data_tones = result.data_tones.checked_add(data).ok_or(Error::Overflow)?;
            result.short_tones = result
                .short_tones
                .checked_add(short)
                .ok_or(Error::Overflow)?;
        }
        Ok(result)
    }
}

/// One-stream EHT20 payload and post-FEC padding geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) struct Capacity {
    pub mcs: u8,
    pub bits_per_tone: usize,
    pub rate_num: usize,
    pub rate_den: usize,
    pub dcm: bool,
    pub ldpc: bool,
    pub coded_per_symbol: usize,
    pub coded_short: usize,
    pub data_per_symbol: usize,
    pub coded_last: usize,
    pub coded_bits: usize,
    pub data_bits: usize,
    pub psdu_bytes: usize,
    pub phy_pad_bits: usize,
    pub tail_bits: usize,
    pub bcc_dcm_filler: bool,
}

impl Capacity {
    /// Construct the one-user non-OFDMA DATA geometry.
    pub fn new(fields: &crate::radio::eht::sig::iq::Fields, symbols: usize) -> Result<Self, Error> {
        let SignalFields::NonOfdma(signal) = &fields.signal else {
            return Err(Error::UnsupportedFormat);
        };
        let EhtNonOfdmaUsers::Single(user) = &signal.users else {
            return Err(Error::UnsupportedFormat);
        };
        if user.space_time_streams != 1 {
            return Err(Error::UnsupportedFormat);
        }
        let modulation = Modulation::new(user.mcs)?;
        Self::for_user(
            user,
            modulation,
            Geometry::full_band(modulation.dcm),
            signal.common.pre_fec_padding_factor,
            signal.common.ldpc_extra_symbol,
            symbols,
        )
    }

    /// Construct one independently decodable OFDMA user's RU or MRU geometry.
    /// Header integrity, allocation ownership and channel training remain the
    /// receiver's responsibility.
    pub fn for_ofdma(
        common: &EhtOfdmaCommon,
        user: &EhtNonMuUser,
        resource: EhtResourceUnit,
        symbols: usize,
    ) -> Result<Self, Error> {
        if resource.user_count() != 1 || user.space_time_streams != 1 {
            return Err(Error::UnsupportedFormat);
        }
        let modulation = Modulation::new(user.mcs)?;
        Self::for_user(
            user,
            modulation,
            Geometry::for_resource(resource, modulation.dcm)?,
            common.pre_fec_padding_factor,
            common.ldpc_extra_symbol,
            symbols,
        )
    }

    /// Construct one independently decodable EHT-TB user's RU or MRU geometry.
    pub fn for_tb(
        common: &Dot11EhtTriggerCommonFields,
        fields: &Dot11EhtTriggerUserFields,
        resource: EhtResourceUnit,
        symbols: usize,
    ) -> Result<Self, Error> {
        let stream_start = fields.spatial_allocation & 7;
        let stream_count = (fields.spatial_allocation >> 3) + 1;
        if resource.user_count() != 1
            || stream_start != 0
            || stream_count != 1
            || fields.reserved
            || fields.ps160
        {
            return Err(Error::UnsupportedFormat);
        }
        let user = EhtNonMuUser {
            sta_id: fields.aid12,
            mcs: fields.mcs,
            reserved: fields.reserved,
            space_time_streams: stream_count,
            beamformed: false,
            ldpc: fields.ldpc,
        };
        let modulation = Modulation::new(user.mcs)?;
        let padding = match common.pre_fec_padding_raw {
            0 => 4,
            value => value,
        };
        Self::for_user(
            &user,
            modulation,
            Geometry::for_resource(resource, modulation.dcm)?,
            padding,
            common.ldpc_extra_segment,
            symbols,
        )
    }

    fn for_user(
        user: &EhtNonMuUser,
        modulation: Modulation,
        geometry: Geometry,
        pre_fec_padding_factor: u8,
        ldpc_extra_symbol: bool,
        symbols: usize,
    ) -> Result<Self, Error> {
        if !user.ldpc && user.mcs > 9 && user.mcs != 15 {
            return Err(Error::Coding);
        }
        if symbols == 0 {
            return Err(Error::Duration);
        }
        let padding = usize::from(pre_fec_padding_factor);
        if !(1..=4).contains(&padding) {
            return Err(Error::Padding);
        }
        let coded_per_symbol = geometry
            .data_tones
            .checked_mul(modulation.bits_per_tone)
            .ok_or(Error::Overflow)?;
        let coded_short = geometry
            .short_tones
            .checked_mul(modulation.bits_per_tone)
            .ok_or(Error::Overflow)?;
        let data_per_symbol = coded_per_symbol * modulation.rate_num / modulation.rate_den;
        let data_short = coded_short * modulation.rate_num / modulation.rate_den;
        let extra = user.ldpc && ldpc_extra_symbol;
        let (payload_symbols, payload_padding) = if extra {
            if padding == 1 {
                (symbols.checked_sub(1).ok_or(Error::Duration)?, 4)
            } else {
                (symbols, padding - 1)
            }
        } else {
            (symbols, padding)
        };
        let data_last = if payload_padding == 4 {
            data_per_symbol
        } else {
            payload_padding * data_short
        };
        let full_symbols = payload_symbols.checked_sub(1).ok_or(Error::Duration)?;
        let data_bits = full_symbols
            .checked_mul(data_per_symbol)
            .and_then(|bits| bits.checked_add(data_last))
            .ok_or(Error::Overflow)?;
        let tail_bits = if user.ldpc { 0 } else { 6 };
        let payload_bits = data_bits
            .checked_sub(16 + tail_bits)
            .ok_or(Error::Duration)?;
        let coded_last = if padding == 4 {
            coded_per_symbol
        } else {
            padding * coded_short
        };
        let coded_bits = (symbols - 1)
            .checked_mul(coded_per_symbol)
            .and_then(|bits| bits.checked_add(coded_last))
            .ok_or(Error::Overflow)?;
        Ok(Self {
            mcs: user.mcs,
            bits_per_tone: modulation.bits_per_tone,
            rate_num: modulation.rate_num,
            rate_den: modulation.rate_den,
            dcm: modulation.dcm,
            ldpc: user.ldpc,
            coded_per_symbol,
            coded_short,
            data_per_symbol,
            coded_last,
            coded_bits,
            data_bits,
            psdu_bytes: payload_bits / 8,
            phy_pad_bits: payload_bits % 8,
            tail_bits,
            bcc_dcm_filler: !user.ldpc && user.mcs == 15 && coded_per_symbol % 2 != 0,
        })
    }
}
