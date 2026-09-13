//! HE20 MU single-stream RUs, ax-2021 27.3.11.8/10 and 27.3.12.
//! Returned PSDUs are not MAC/FCS qualified. No spatial separation is inferred.
use super::{
    he_capacity::Capacity, he_sig_b::HeSigBUserEncoding, he_sig_b_iq::Fields, he_timing::Timing,
    sync::Acquisition, ComplexSample,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Header,
    Timing,
    Layout,
    Unsupported,
    Unused,
    Limit,
    Samples,
    Training,
    Metrics,
    Allocation,
    Bcc(super::he_bcc::Error),
    Ldpc(super::he_mu_ldpc::Error),
}

#[derive(Debug)]
pub(super) struct Payload {
    pub psdu: Vec<u8>,
    pub failed_codewords: usize,
    pub first_failure: Option<super::ldpc_rate::Error>,
}

#[derive(Debug)]
pub(super) struct Recovered {
    pub fields: Fields,
    pub timing: Timing,
    /// Original SIG-B order, including unused users and failed headers.
    pub users: Vec<Result<Payload, Error>>,
}

/// Checked SIG-B to bounded DATA retention. No payload or MAC integrity is
/// established here; at least one RU must have a supported user layout.
pub(super) fn admit(
    samples: &[ComplexSample],
    a: &Acquisition,
    fields: &Fields,
    max_samples: usize,
) -> Result<Timing, Error> {
    if a.signal_start.checked_sub(a.preamble_start) != Some(320) {
        return Err(Error::Layout);
    }
    let length = super::he_iq::repeated_er_signal(samples, a).ok_or(Error::Header)?;
    let timing = Timing::for_mu(6_000_000, length, &fields.signal, fields.symbols)
        .map_err(|_| Error::Timing)?;
    let needed = timing.data_end.checked_sub(320).ok_or(Error::Timing)?;
    a.preamble_start
        .checked_add(timing.data_end as u64)
        .ok_or(Error::Timing)?;
    if needed > max_samples || timing.data_symbols > 400 {
        return Err(Error::Limit);
    }
    let layout = fields.layout().map_err(|_| Error::Layout)?;
    let supported = !fields.signal.stbc
        && (layout.len() != 1 || timing.ltf_symbols == 1)
        && layout.iter().any(|ru| {
            ru.users.len() == 1
                && ru.users.clone().any(|i| {
                    fields.users[i].is_ok_and(|user| {
                        matches!(
                            user.encoding,
                            HeSigBUserEncoding::NonMu {
                                space_time_streams: 1,
                                ..
                            }
                        ) && Capacity::for_mu(
                            &fields.signal,
                            &user,
                            (ru.tones.count() + ru.tones.pilots().len()) as u16,
                            timing.data_symbols,
                        )
                        .is_ok()
                    })
                })
        });
    if !supported {
        return Err(Error::Unsupported);
    }
    Ok(timing)
}

/// Input begins at L-SIG, not at the legacy preamble. Bounds cover the entire
/// DATA region before per-user allocation. Header recovery does not emit frames.
pub(super) fn recover(
    samples: &[ComplexSample],
    a: &Acquisition,
    max_psdu: usize,
    max_samples: usize,
    partial: bool,
) -> Result<Recovered, Error> {
    if a.signal_start.checked_sub(a.preamble_start) != Some(320) {
        return Err(Error::Layout);
    }
    let fields = super::he_sig_b_iq::recover(samples, a).map_err(|_| Error::Header)?;
    let timing = admit(samples, a, &fields, max_samples)?;
    let needed = timing.data_end.checked_sub(320).ok_or(Error::Timing)?;
    if needed > max_samples || timing.data_symbols > 400 {
        return Err(Error::Limit);
    }
    if samples.len() < needed {
        return Err(Error::Samples);
    }
    let layout = fields.layout().map_err(|_| Error::Layout)?;
    let mut users = Vec::with_capacity(fields.users.len());
    for ru in &layout {
        for index in ru.users.clone() {
            let result = (|| {
                let user = fields.users[index].map_err(|_| Error::Header)?;
                let (dcm, ldpc) = match user.encoding {
                    HeSigBUserEncoding::Unused { .. } => return Err(Error::Unused),
                    HeSigBUserEncoding::NonMu {
                        space_time_streams: 1,
                        dcm,
                        ldpc,
                        ..
                    } if !fields.signal.stbc && ru.users.len() == 1 => (dcm, ldpc),
                    _ => return Err(Error::Unsupported),
                };
                // 27.3.11.10: a single RU's LTF count is determined by its
                // streams; a multi-RU PPDU may signal extra training symbols.
                if layout.len() == 1 && timing.ltf_symbols != 1 {
                    return Err(Error::Layout);
                }
                let size = (ru.tones.count() + ru.tones.pilots().len()) as u16;
                let c = Capacity::for_mu(&fields.signal, &user, size, timing.data_symbols)
                    .map_err(|_| Error::Layout)?;
                if c.psdu_bytes > max_psdu {
                    return Err(Error::Limit);
                }
                if ldpc {
                    super::ldpc_rate::Layout::he_mu(
                        &fields.signal,
                        &user,
                        size,
                        timing.data_symbols as u16,
                    )
                    .map_err(|_| Error::Layout)?;
                }
                let guard = usize::from(fields.signal.guard_ns) / 50;
                let training =
                    timing.ltf_symbols * (64 * usize::from(fields.signal.ltf_size) + guard);
                let train = |cp| {
                    super::he_training::train_ru_field(
                        samples,
                        a,
                        ru.tones,
                        fields.signal.ltf_size,
                        fields.signal.guard_ns,
                        cp,
                    )
                    .ok_or(Error::Training)
                };
                let cp = usize::try_from(
                    fields
                        .end_sample
                        .checked_sub(a.signal_start)
                        .ok_or(Error::Timing)?,
                )
                .map_err(|_| Error::Timing)?
                .checked_add(80)
                .ok_or(Error::Timing)?;
                // For one stream, the first column of P4/P6/P8 and the
                // single-stream pilot matrix has coefficient +1. Other LTF
                // symbols may improve estimation later; no stream is omitted.
                let mut channel = train(cp)?;
                let mut demod =
                    super::he_ru_symbol::Demodulator::new(ru.tones, c.bits_per_tone, ldpc, dcm)
                        .ok_or(Error::Unsupported)?;
                let mut metrics = Vec::new();
                metrics
                    .try_reserve_exact(
                        timing
                            .data_symbols
                            .checked_mul(c.coded_per_symbol)
                            .ok_or(Error::Limit)?,
                    )
                    .map_err(|_| Error::Allocation)?;
                let mut pilot = 127;
                // Equation27-108: L-SIG + RL-SIG + two SIG-A + SIG-B.
                for _ in 0..4 + fields.symbols {
                    super::data::feedback(&mut pilot);
                }
                for symbol in 0..timing.data_symbols {
                    let offset = timing.symbol_start(symbol).ok_or(Error::Timing)?;
                    if let Some(period) = fields.signal.midamble_period.map(usize::from) {
                        if symbol > 0 && symbol % period == 0 && symbol / period <= timing.midambles
                        {
                            channel =
                                train(offset.checked_sub(training + 320).ok_or(Error::Timing)?)?;
                            demod.reset();
                        }
                    }
                    let start = offset
                        .checked_add(guard)
                        .and_then(|n| n.checked_sub(320))
                        .ok_or(Error::Timing)?;
                    let elapsed = a
                        .signal_start
                        .checked_add(start as u64)
                        .and_then(|n| n.checked_sub(a.phase_origin))
                        .ok_or(Error::Timing)?;
                    let polarity = 1. - 2. * super::data::feedback(&mut pilot) as f32;
                    let block = demod
                        .recover(
                            samples.get(start..start + 256).ok_or(Error::Samples)?,
                            &channel,
                            a.frequency_rad,
                            elapsed,
                            symbol,
                            polarity,
                        )
                        .ok_or(Error::Metrics)?;
                    metrics.extend(block);
                }
                if ldpc {
                    let r = super::he_mu_ldpc::recover(
                        &fields.signal,
                        &user,
                        size,
                        timing.data_symbols,
                        &metrics,
                        max_psdu,
                        partial,
                    )
                    .map_err(Error::Ldpc)?;
                    Ok(Payload {
                        psdu: r.psdu,
                        failed_codewords: r.failed_codewords,
                        first_failure: r.first_failure,
                    })
                } else {
                    let psdu = super::he_bcc::recover_mu(
                        &fields.signal,
                        &user,
                        size,
                        timing.data_symbols,
                        &metrics,
                        max_psdu,
                    )
                    .map_err(Error::Bcc)?;
                    Ok(Payload {
                        psdu,
                        failed_codewords: 0,
                        first_failure: None,
                    })
                }
            })();
            users.push(result);
        }
    }
    Ok(Recovered {
        fields,
        timing,
        users,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_he_mu_complete_psdu_waveforms() {
        let rows = include_str!("../../tests/fixtures/iq/he-mu-data-iq-index.tsv");
        assert_eq!(rows.lines().skip(1).count(), 252);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/iq")
                    .join(format!("{}.cs8", c[0])),
            )
            .unwrap();
            let samples: Vec<_> = bytes
                .chunks_exact(2)
                .map(|b| ComplexSample {
                    i: b[0] as i8 as f32 / 128.,
                    q: b[1] as i8 as f32 / 128.,
                })
                .collect();
            let mut sync = super::super::sync::Synchronizer::default();
            let a = samples
                .iter()
                .enumerate()
                .find_map(|(n, &s)| match sync.push(s, n as u64) {
                    Some(super::super::sync::SyncEvent::Acquired(a)) => Some(a),
                    _ => None,
                })
                .unwrap();
            let input = &samples[a.signal_start as usize..];
            let result = recover(input, &a, 65535, input.len(), false)
                .unwrap_or_else(|e| panic!("{}: {e:?}", c[0]));
            let expected: Vec<_> = c[11].split(',').collect();
            assert_eq!(result.users.len(), expected.len(), "{}", c[0]);
            assert_eq!(result.fields.users.len(), expected.len());
            assert_eq!(result.timing.data_symbols, c[10].parse().unwrap());
            if c[1] == "192" && c[3] == "1" {
                let partial = recover(input, &a, 65535, input.len(), true).unwrap();
                for (strict, partial) in result.users.iter().zip(&partial.users) {
                    let strict = strict.as_ref().unwrap();
                    let partial = partial.as_ref().unwrap();
                    assert_eq!(partial.psdu, strict.psdu);
                    assert_eq!(partial.failed_codewords, 0);
                    assert_eq!(partial.first_failure, None);
                }
            }
            for (i, (user, expected)) in result.users.iter().zip(expected).enumerate() {
                if c[9] == "user-crc" && i < 2 {
                    assert!(matches!(user, Err(Error::Header)), "{}: {user:?}", c[0]);
                    continue;
                }
                if c[9] == "service" && i == 0 {
                    assert!(
                        matches!(
                            user,
                            Err(Error::Bcc(super::super::he_bcc::Error::Service)
                                | Error::Ldpc(super::super::he_mu_ldpc::Error::Service))
                        ),
                        "{}: {user:?}",
                        c[0]
                    );
                    continue;
                }
                let payload = user
                    .as_ref()
                    .unwrap_or_else(|e| panic!("{} user{i}: {e:?}", c[0]));
                let bytes: Vec<_> = expected
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                    .collect();
                assert_eq!(payload.psdu, bytes, "{} user{i}", c[0]);
                assert_eq!(payload.failed_codewords, 0);
                assert_eq!(payload.first_failure, None);
            }
            assert!(matches!(
                recover(&input[..input.len() - 1], &a, 65535, input.len(), false),
                Err(Error::Samples)
            ));
            assert!(matches!(
                recover(input, &a, 65535, input.len() - 1, false),
                Err(Error::Limit)
            ));
            if c[9] == "none" {
                let limited = recover(input, &a, 0, input.len(), false).unwrap();
                for (limited, original) in limited.users.iter().zip(&result.users) {
                    if original.as_ref().unwrap().psdu.is_empty() {
                        assert!(limited.as_ref().unwrap().psdu.is_empty());
                    } else {
                        assert!(matches!(limited, Err(Error::Limit)));
                    }
                }
            }
        }
    }
}
