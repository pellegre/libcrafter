//! HE20 SIG-B IQ, IEEE802.11ax-2021 27.3.11.8. No MU DATA admission.
use super::{
    he_iq::{bins_polarity, decode_mu_prefix},
    he_mu::MuSignal,
    he_sig_b::{HeSigBCommon20Fields, HeSigBUserContext, HeSigBUserFields},
    he_sig_b_coded::{Blocks, Error as BlockError},
    he_sig_b_modulation::Modulation,
    sync::Acquisition,
    ComplexSample,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Prefix,
    Layout,
    Samples,
    Overflow,
    Truncated { required: usize, available: usize },
    Common(BlockError),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Fields {
    pub signal: MuSignal,
    pub common: Option<HeSigBCommon20Fields>,
    pub users: Vec<Result<HeSigBUserFields, BlockError>>,
    pub symbols: usize,
    pub end_sample: u64,
}

/// Input begins at L-SIG. Only complete SIG-B fields are returned; successful
/// headers establish neither training/DATA admissibility nor MAC integrity.
pub(super) fn recover(samples: &[ComplexSample], a: &Acquisition) -> Result<Fields, Error> {
    let signal = decode_mu_prefix(samples, a).ok_or(Error::Prefix)?;
    let mode = Modulation::new(signal.sig_b_mcs, signal.sig_b_dcm).ok_or(Error::Layout)?;
    let dbps = [26usize, 52, 78, 104, 156, 208][signal.sig_b_mcs as usize]
        / (1 + usize::from(signal.sig_b_dcm));
    let common = if signal.sig_b_compression {
        None
    } else {
        let metrics = demodulate(samples, a, 18usize.div_ceil(dbps), mode)?;
        Some(
            Blocks::new(&metrics, signal.sig_b_mcs)
                .map_err(Error::Common)?
                .common()
                .map_err(Error::Common)?,
        )
    };
    let mut contexts = Vec::with_capacity(17);
    if let Some(common) = &common {
        for ru in common.rus() {
            add_contexts(&mut contexts, ru.users)?;
        }
    } else {
        add_contexts(&mut contexts, signal.sig_b_symbols_or_users + 1)?;
    }
    let users = contexts.len();
    let bits = 18 * usize::from(common.is_some()) + (users / 2) * 52 + (users % 2) * 31;
    let minimum = bits.div_ceil(dbps);
    let symbols = if signal.sig_b_compression {
        minimum
    } else if signal.sig_b_symbols_or_users == 15 {
        minimum.max(16)
    } else {
        usize::from(signal.sig_b_symbols_or_users) + 1
    };
    if symbols < minimum || symbols == 0 || symbols > 36 {
        return Err(Error::Layout);
    }
    let metrics = demodulate(samples, a, symbols, mode)?;
    let mut blocks = Blocks::new(&metrics, signal.sig_b_mcs).map_err(Error::Common)?;
    if common.is_some() {
        blocks.common().map_err(Error::Common)?;
    }
    let mut users = Vec::with_capacity(contexts.len());
    for pair in contexts.chunks(2) {
        match blocks.users(pair) {
            Ok(block) => users.extend(
                block
                    .users()
                    .iter()
                    .map(|user| user.map_err(BlockError::Header)),
            ),
            Err(error) => users.extend(std::iter::repeat(Err(error)).take(pair.len())),
        }
    }
    let end_sample = a
        .signal_start
        .checked_add((320 + 80 * symbols) as u64)
        .ok_or(Error::Overflow)?;
    Ok(Fields {
        signal,
        common,
        users,
        symbols,
        end_sample,
    })
}

fn add_contexts(contexts: &mut Vec<HeSigBUserContext>, users: u8) -> Result<(), Error> {
    if users > 8 {
        return Err(Error::Layout);
    }
    for position in 0..users {
        contexts.push(if users == 1 {
            HeSigBUserContext::NonMu
        } else {
            HeSigBUserContext::MuMimo { users, position }
        });
    }
    Ok(())
}

fn demodulate(
    samples: &[ComplexSample],
    a: &Acquisition,
    symbols: usize,
    mode: Modulation,
) -> Result<Vec<f32>, Error> {
    if symbols == 0 || symbols > 36 {
        return Err(Error::Layout);
    }
    let required = 320 + 80 * symbols;
    a.signal_start
        .checked_add(required as u64)
        .ok_or(Error::Overflow)?;
    let input = samples.get(..required).ok_or(Error::Truncated {
        required,
        available: samples.len(),
    })?;
    if input.iter().any(|v| !v.power().is_finite()) {
        return Err(Error::Samples);
    }
    let lsig = bins_polarity(&input[..80], a.signal_start, a, 1.).ok_or(Error::Samples)?;
    let repeated =
        bins_polarity(&input[80..160], a.signal_start + 80, a, 1.).ok_or(Error::Samples)?;
    let mut channel = a.channel;
    // L-SIG and RL-SIG provide the four tones outside ordinary L-LTF coverage.
    for (k, sign) in [(36, -1.), (37, -1.), (27, -1.), (28, 1.)] {
        channel[k] = lsig[k].add(repeated[k]).scale(0.5 * sign);
    }
    if channel.iter().any(|v| !v.power().is_finite()) {
        return Err(Error::Samples);
    }
    let mut state = 127;
    for _ in 0..4 {
        super::data::feedback(&mut state);
    }
    let mut metrics = Vec::with_capacity(symbols * mode.coded_per_symbol());
    for symbol in 0..symbols {
        let offset = 320 + symbol * 80;
        let polarity = 1. - 2. * f32::from(super::data::feedback(&mut state));
        if let Some(bins) = bins_polarity(
            &input[offset..offset + 80],
            a.signal_start + offset as u64,
            a,
            polarity,
        ) {
            let tones: Vec<_> = (-28i32..=28)
                .filter(|k| ![-21, -7, 0, 7, 21].contains(k))
                .map(|k| {
                    let k = k.rem_euclid(64) as usize;
                    let weight = channel[k].power();
                    if weight > 1e-12 {
                        (bins[k].mul(channel[k].conj()).scale(1. / weight), weight)
                    } else {
                        (ComplexSample::ZERO, 0.)
                    }
                })
                .collect();
            metrics.extend(mode.decode(&tones).ok_or(Error::Samples)?);
        } else {
            metrics.extend(std::iter::repeat(0.).take(mode.coded_per_symbol()));
        }
    }
    Ok(metrics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radio::{
        sync::{SyncEvent, Synchronizer},
        HeSigBError, HeSigBUserEncoding,
    };

    fn fixture(name: &str) -> (Vec<ComplexSample>, Acquisition) {
        let bytes = std::fs::read(format!(
            "{}/tests/fixtures/iq/{name}.cs8",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let samples: Vec<_> = bytes
            .chunks_exact(2)
            .map(|b| ComplexSample {
                i: b[0] as i8 as f32 / 128.,
                q: b[1] as i8 as f32 / 128.,
            })
            .collect();
        let mut sync = Synchronizer::default();
        let acquired = samples
            .iter()
            .enumerate()
            .find_map(|(n, s)| match sync.push(*s, n as u64) {
                Some(SyncEvent::Acquired(a)) => Some(a),
                _ => None,
            })
            .unwrap();
        (samples, acquired)
    }

    #[test]
    fn radio_he_sig_b_iq_independent() {
        let rows = include_str!("../../tests/fixtures/iq/he-sigb-iq-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 172);
        let mut long = false;
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let (samples, a) = fixture(c[0]);
            let input = &samples[a.signal_start as usize..];
            let result = recover(input, &a);
            if matches!(c[5], "short-count" | "too-many") {
                assert_eq!(result, Err(Error::Layout), "{}", c[0]);
                continue;
            }
            if c[5] == "common-crc" {
                assert!(
                    matches!(
                        result,
                        Err(Error::Common(BlockError::Header(HeSigBError::Crc { .. })))
                    ),
                    "{}: {result:?}",
                    c[0]
                );
                continue;
            }
            let fields = result.unwrap_or_else(|e| panic!("{}: {e:?}", c[0]));
            let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
            assert_eq!(fields.signal, MuSignal::decode(&bits).unwrap());
            assert_eq!(fields.symbols, c[4].parse::<usize>().unwrap(), "{}", c[0]);
            assert_eq!(fields.end_sample, samples.len() as u64);
            assert_eq!(fields.users.len(), c[3].parse::<usize>().unwrap());
            let code: i32 = c[2].parse().unwrap();
            assert_eq!(
                fields
                    .common
                    .as_ref()
                    .map(|v| i32::from(v.allocation_code())),
                (code >= 0).then_some(code)
            );
            if fields.symbols > 16 {
                long = true;
                assert_eq!(fields.signal.sig_b_symbols_or_users, 15);
            }
            for (i, user) in fields.users.iter().enumerate() {
                if c[5] == "user-crc" && i < 2 {
                    assert!(
                        matches!(user, Err(BlockError::Header(HeSigBError::Crc { .. }))),
                        "{}: {user:?}",
                        c[0]
                    );
                    continue;
                }
                let user = user.unwrap_or_else(|e| panic!("{} user{i}: {e:?}", c[0]));
                assert_eq!(user.sta_id, 37 + i as u16);
                let mu =
                    code == 199 || (code == 191 && i != 8) || (code < 0 && fields.users.len() > 1);
                let expected = if mu {
                    let position = if code == 191 && i > 8 { i - 9 } else { i };
                    HeSigBUserEncoding::MuMimo {
                        spatial_configuration: 0,
                        streams: 1,
                        start_stream: position as u8,
                        total_streams: if code < 0 {
                            fields.users.len() as u8
                        } else {
                            8
                        },
                        mcs: (i % 12) as u8,
                        ldpc: i % 2 != 0,
                    }
                } else {
                    HeSigBUserEncoding::NonMu {
                        space_time_streams: 1,
                        beamformed: false,
                        mcs: (i % 12) as u8,
                        dcm: false,
                        ldpc: i % 2 != 0,
                    }
                };
                assert_eq!(user.encoding, expected, "{} user{i}", c[0]);
            }
            for end in [0, 319, input.len() - 1] {
                assert!(recover(&input[..end], &a).is_err(), "{} end{end}", c[0]);
            }
        }
        assert!(long);
    }

    #[test]
    fn radio_he_sig_b_iq_damage_and_bounds() {
        let (samples, a) = fixture("he-sigb-iq-m0-d0-a0-u0-i0-none-e0");
        let input = &samples[a.signal_start as usize..];
        let mut erased = input.to_vec();
        erased[400..480].fill(ComplexSample::ZERO);
        let fields = recover(&erased, &a).unwrap();
        assert!(fields.users[..2].iter().all(Result::is_err));
        assert!(fields.users[2..].iter().all(Result::is_ok));
        for index in [320, 399, input.len() - 1] {
            for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
                let mut bad = input.to_vec();
                bad[index].i = value;
                assert!(recover(&bad, &a).is_err());
            }
        }
        let mut overflow = a.clone();
        overflow.signal_start = u64::MAX - 319;
        assert!(recover(input, &overflow).is_err());
        let mode = Modulation::new(0, false).unwrap();
        for symbols in [0, 37, usize::MAX] {
            assert_eq!(demodulate(input, &a, symbols, mode), Err(Error::Layout));
        }
        for users in [9, 16, 255] {
            assert_eq!(add_contexts(&mut Vec::new(), users), Err(Error::Layout));
        }
    }
}
