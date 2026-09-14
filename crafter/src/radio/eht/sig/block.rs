use super::EhtSigError;

pub(super) struct EncodingBlock<'a> {
    bits: &'a [u8],
}

impl<'a> EncodingBlock<'a> {
    pub(super) fn new(
        bits: &'a [u8],
        protected: usize,
        block: usize,
        base: usize,
    ) -> Result<Self, EhtSigError> {
        let required = protected + 10;
        if bits.len() != required {
            return Err(EhtSigError::BitCount {
                required,
                available: bits.len(),
            });
        }
        if let Some((index, &value)) = bits.iter().enumerate().find(|(_, value)| **value > 1) {
            return Err(EhtSigError::NonBinary {
                index: base + index,
                value,
            });
        }
        let expected = crate::radio::ht::crc(&bits[..protected]) >> 4;
        let received = bits[protected..protected + 4]
            .iter()
            .fold(0u8, |value, bit| (value << 1) | bit);
        if expected != received {
            return Err(EhtSigError::Crc {
                block,
                expected,
                received,
            });
        }
        if let Some(index) = (protected + 4..required).find(|index| bits[*index] != 0) {
            return Err(EhtSigError::TailBit {
                block,
                index: base + index,
            });
        }
        Ok(Self { bits })
    }

    pub(super) fn bit(&self, index: usize) -> bool {
        self.bits[index] != 0
    }

    pub(super) fn field(&self, start: usize, count: usize) -> u16 {
        self.bits[start..start + count]
            .iter()
            .enumerate()
            .fold(0u16, |value, (index, bit)| {
                value | (u16::from(*bit) << index)
            })
    }
}
