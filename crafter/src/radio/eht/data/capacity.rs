use super::Error;
use crate::radio::eht::{sig::iq::SignalFields, EhtNonOfdmaUsers};

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
        if !user.ldpc && user.mcs > 9 && user.mcs != 15 {
            return Err(Error::Coding);
        }
        if symbols == 0 {
            return Err(Error::Duration);
        }
        let padding = usize::from(signal.common.pre_fec_padding_factor);
        if !(1..=4).contains(&padding) {
            return Err(Error::Padding);
        }
        let data_tones = if modulation.dcm { 117 } else { 234 };
        let short_tones = if modulation.dcm { 30 } else { 60 };
        let coded_per_symbol = data_tones * modulation.bits_per_tone;
        let coded_short = short_tones * modulation.bits_per_tone;
        let data_per_symbol = coded_per_symbol * modulation.rate_num / modulation.rate_den;
        let data_short = coded_short * modulation.rate_num / modulation.rate_den;
        let extra = user.ldpc && signal.common.ldpc_extra_symbol;
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
            bcc_dcm_filler: !user.ldpc && user.mcs == 15,
        })
    }
}
