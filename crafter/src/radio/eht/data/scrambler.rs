use super::Error;

/// EHT's 11-stage DATA scrambler, including SERVICE-based seed recovery.
pub(super) struct Descrambler;

impl Descrambler {
    pub fn recover(mut bits: Vec<u8>, psdu_bytes: usize) -> Result<Vec<u8>, Error> {
        let payload_end = psdu_bytes
            .checked_mul(8)
            .and_then(|bits| bits.checked_add(16))
            .ok_or(Error::Overflow)?;
        if bits.len() < payload_end || bits.len() < 16 || bits.iter().any(|bit| *bit > 1) {
            return Err(Error::Service);
        }
        let seed = bits[..11]
            .iter()
            .fold(0u16, |state, bit| (state << 1) | u16::from(*bit));
        if seed == 0 {
            return Err(Error::Service);
        }
        let mut state = seed;
        for bit in &mut bits {
            *bit ^= Self::next(&mut state);
        }
        if bits[..16].iter().any(|bit| *bit != 0) {
            return Err(Error::Service);
        }
        Ok(bits[16..payload_end]
            .chunks_exact(8)
            .map(|octet| {
                octet
                    .iter()
                    .enumerate()
                    .fold(0, |value, (index, bit)| value | (bit << index))
            })
            .collect())
    }

    fn next(state: &mut u16) -> u8 {
        let output = (*state >> 10) as u8;
        let feedback = ((*state >> 10) ^ (*state >> 8)) & 1;
        *state = ((*state << 1) | feedback) & 0x07ff;
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_eht_data_scrambler_published_sequence() {
        let expected = b"111111111110000000001100000001111000001100110001111111101100000010111000";
        let mut state = 0x07ff;
        let actual: Vec<_> = (0..expected.len())
            .map(|_| b'0' + Descrambler::next(&mut state))
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(state, 0x0259);
    }

    #[test]
    fn radio_eht_data_descrambler_bounds_service_and_payload() {
        let payload = [0x00, 0xa5, 0xff, 0x42];
        for seed in [1, 2, 93, 1024, 2047] {
            let mut state = seed;
            let mut bits: Vec<u8> = [0; 16]
                .into_iter()
                .chain(
                    payload
                        .into_iter()
                        .flat_map(|octet| (0..8).map(move |bit| (octet >> bit) & 1)),
                )
                .collect();
            for bit in &mut bits {
                *bit ^= Descrambler::next(&mut state);
            }
            assert_eq!(
                Descrambler::recover(bits, payload.len()),
                Ok(payload.to_vec())
            );
        }
        assert_eq!(Descrambler::recover(vec![0; 48], 4), Err(Error::Service));
        assert_eq!(Descrambler::recover(vec![1; 47], 4), Err(Error::Service));
        let mut nonbinary = vec![1; 48];
        nonbinary[20] = 2;
        assert_eq!(Descrambler::recover(nonbinary, 4), Err(Error::Service));
        assert_eq!(
            Descrambler::recover(vec![1; 48], usize::MAX),
            Err(Error::Overflow)
        );
    }
}
