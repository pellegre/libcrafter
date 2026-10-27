//! Bounded VHT20 SU IQ recovery over shared legacy acquisition and OFDM kernels.
use super::{
    layout, VhtGuardInterval, VhtMcs, VhtSignalAFields, VhtSignalAUsers, VhtSignalB20Fields,
};
use crate::radio::wifi::{
    ht,
    ofdm::{
        demod,
        sync::{fft64, Acquisition},
    },
    recovery::{self, DecodeAttempt, Profile},
};
use crate::radio::{ComplexSample, IqPosition, PhyDiagnostic, RxConfig, SignalInfo};

fn bins(samples: &[ComplexSample], start: u64, a: &Acquisition) -> Option<[ComplexSample; 64]> {
    if samples.len() != 80 {
        return None;
    }
    let elapsed = start.checked_add(16)?.checked_sub(a.phase_origin)?;
    let fft = fft64(std::array::from_fn(|n| {
        samples[16 + n].mul(ComplexSample::rotation(
            -a.frequency_rad * (elapsed as f32 + n as f32),
        ))
    }));
    let mut pilots = ComplexSample::ZERO;
    for (k, sign) in [(43, 1.), (57, 1.), (7, 1.), (21, -1.)] {
        pilots = pilots.add(fft[k].mul(a.channel[k].conj()).scale(sign));
    }
    if !pilots.power().is_finite() || pilots.power() < 1e-12 {
        return None;
    }
    let phase = ComplexSample::rotation(-pilots.phase());
    let out: [_; 64] = std::array::from_fn(|k| fft[k].mul(a.channel[k].conj()).mul(phase));
    out.iter().all(|v| v.power().is_finite()).then_some(out)
}

fn signal_a(samples: &[ComplexSample], a: &Acquisition) -> Option<VhtSignalAFields> {
    if samples.len() != 160 {
        return None;
    }
    let mut metrics = [0.; 96];
    for symbol in 0..2 {
        let corrected = bins(
            &samples[symbol * 80..symbol * 80 + 80],
            a.signal_start.checked_add(80 + 80 * symbol as u64)?,
            a,
        )?;
        let (mut desired, mut other) = (0., 0.);
        for (i, k) in (-26i32..=26)
            .filter(|k| ![-21, -7, 0, 7, 21].contains(k))
            .enumerate()
        {
            let v = corrected[k.rem_euclid(64) as usize];
            let (x, y) = if symbol == 0 { (v.i, v.q) } else { (v.q, v.i) };
            metrics[symbol * 48 + i] = x;
            desired += x * x;
            other += y * y;
        }
        if desired < 1e-12 || desired <= 4. * other {
            return None;
        }
    }
    VhtSignalAFields::decode_interleaved(&metrics).ok()
}

pub(in crate::radio) enum HeaderOutcome {
    NotVht,
    Unsupported(VhtSignalAFields),
    Supported {
        candidate: Candidate,
        info: SignalInfo,
    },
}

#[derive(Clone, Copy)]
pub(in crate::radio) struct Candidate {
    pub fields: VhtSignalAFields,
    mcs: VhtMcs,
    guard: VhtGuardInterval,
    ldpc: Option<ht::ldpc::rate::Layout>,
}
impl Candidate {
    pub fn recognize(
        samples: &mut Vec<ComplexSample>,
        a: &Acquisition,
        config: &RxConfig,
        reserved: usize,
    ) -> HeaderOutcome {
        let Some(fields) = samples.get(80..240).and_then(|s| signal_a(s, a)) else {
            return HeaderOutcome::NotVht;
        };
        match Self::configure(fields, samples, a, config, reserved) {
            Some((candidate, info)) => HeaderOutcome::Supported { candidate, info },
            None => HeaderOutcome::Unsupported(fields),
        }
    }
    fn configure(
        fields: VhtSignalAFields,
        samples: &mut Vec<ComplexSample>,
        a: &Acquisition,
        config: &RxConfig,
        reserved: usize,
    ) -> Option<(Self, SignalInfo)> {
        let VhtSignalAUsers::Single {
            space_time_streams: 1,
            mcs,
            ldpc,
            ..
        } = fields.users
        else {
            return None;
        };
        if fields.bandwidth_code != 0 || fields.stbc || (!ldpc && fields.ldpc_extra_symbol) {
            return None;
        }
        let mcs = VhtMcs::try_from(mcs).ok()?;
        let guard = if fields.short_guard_interval {
            VhtGuardInterval::Short
        } else {
            VhtGuardInterval::Long
        };
        let legacy = super::super::ofdm::signal::decode_signal(samples.get(..80)?, a, 4095).ok()?;
        if legacy.rate_bps != 6_000_000 {
            return None;
        }
        let timing =
            layout::Timing::receive(legacy.psdu_bytes, guard, fields.short_gi_disambiguation)?;
        if timing.end_offset.saturating_sub(samples.capacity())
            > config.max_buffer_samples.saturating_sub(reserved)
        {
            return None;
        }
        let (nbpsc, ndbps) = mcs.parameters();
        let ldpc = if ldpc {
            Some(layout::ldpc_receive(
                timing.symbols,
                mcs,
                fields.ldpc_extra_symbol,
            )?)
        } else {
            None
        };
        let psdu_bytes = if let Some(l) = ldpc {
            (l.payload_bits.checked_sub(16)?) / 8
        } else {
            (timing.symbols.checked_mul(ndbps)?.checked_sub(22)?) / 8
        };
        let info = SignalInfo {
            rate_bps: mcs.rate_bps(guard),
            coded_bits_per_symbol: 52 * nbpsc,
            data_bits_per_symbol: ndbps,
            psdu_bytes,
            data_symbols: timing.symbols,
            data_start: a.signal_start.checked_add(timing.data_offset as u64)?,
            end_sample_index: a.signal_start.checked_add(timing.end_offset as u64)?,
        };
        samples.reserve_exact(timing.end_offset.saturating_sub(samples.len()));
        Some((
            Self {
                fields,
                mcs,
                guard,
                ldpc,
            },
            info,
        ))
    }
    pub fn decode(
        self,
        samples: &[ComplexSample],
        a: &Acquisition,
        info: SignalInfo,
        start: &IqPosition,
    ) -> DecodeAttempt {
        recovery::recover_vht(|profile| self.decode_profile(samples, a, info, start, profile))
    }
    fn decode_profile(
        self,
        samples: &[ComplexSample],
        a: &Acquisition,
        info: SignalInfo,
        start: &IqPosition,
        profile: Profile,
    ) -> DecodeAttempt {
        let mut diagnostics = vec![PhyDiagnostic::VhtSignal {
            fields: self.fields,
            preamble_sample_index: start.sample_index,
        }];
        let mut failures = Vec::new();
        let result = (|| {
            let trained = ht::train_single_stream(
                samples.get(320..400).ok_or(())?,
                a.signal_start.checked_add(320).ok_or(())?,
                a,
            )
            .ok_or(())?;
            let sigb = bins(
                samples.get(400..480).ok_or(())?,
                a.signal_start.checked_add(400).ok_or(())?,
                &trained,
            )
            .ok_or(())?;
            let metrics: Vec<_> = (-28i32..=28)
                .filter(|k| ![-21, -7, 0, 7, 21].contains(k))
                .map(|k| sigb[k.rem_euclid(64) as usize].i)
                .collect();
            let signal_b =
                VhtSignalB20Fields::decode_interleaved(&metrics, false).map_err(|_| ())?;
            if signal_b.apep_length_bounds().ok_or(())?.0 as usize > info.psdu_bytes {
                return Err(());
            }
            let offset = usize::try_from(info.data_start.checked_sub(a.signal_start).ok_or(())?)
                .map_err(|_| ())?;
            let end = usize::try_from(
                info.end_sample_index
                    .checked_sub(a.signal_start)
                    .ok_or(())?,
            )
            .map_err(|_| ())?;
            let (coded, tracking) = demod::demodulate_vht_data_profile(
                samples.get(offset..end).ok_or(())?,
                &trained,
                info,
                self.guard.samples(),
                self.ldpc.is_none(),
                profile,
            )?;
            let bits = if let Some(layout) = self.ldpc {
                let nbpsc = self.mcs.parameters().0;
                let mut unpermuted = Vec::with_capacity(coded.len());
                for symbol in coded.chunks_exact(52 * nbpsc) {
                    for k in 0..52 {
                        let source = 4 * (k % 13) + k / 13;
                        unpermuted.extend_from_slice(&symbol[source * nbpsc..(source + 1) * nbpsc]);
                    }
                }
                let recovered = layout.recover_partial(&unpermuted, 64).map_err(|_| ())?;
                diagnostics.push(PhyDiagnostic::Ldpc {
                    codewords: layout.codewords,
                    iterations: recovered.iterations,
                });
                if recovered.failed_codewords != 0 {
                    diagnostics.push(PhyDiagnostic::LdpcPartial {
                        failed_codewords: recovered.failed_codewords,
                    });
                    if let Some(ht::ldpc::rate::Error::Codeword {
                        index,
                        error:
                            ht::ldpc::Error::Nonconvergence {
                                iterations,
                                failed_checks,
                            },
                    }) = recovered.first_failure
                    {
                        failures.push(PhyDiagnostic::LdpcNonconvergence {
                            codeword: index,
                            iterations,
                            failed_checks,
                        });
                    }
                }
                recovered.bits
            } else {
                demod::recover_vht_bcc(&coded, info)?
            };
            let bytes = descramble(bits, info.psdu_bytes, signal_b)?;
            diagnostics.push(PhyDiagnostic::VhtSignalB {
                fields: signal_b,
                preamble_sample_index: start.sample_index,
            });
            Ok((bytes, tracking))
        })();
        let mut attempt = DecodeAttempt::plain(result);
        attempt.frame_diagnostics = diagnostics;
        attempt.failure_diagnostics = failures;
        attempt
    }
}

fn descramble(bits: Vec<u8>, psdu: usize, signal_b: VhtSignalB20Fields) -> Result<Vec<u8>, ()> {
    let required = 16 + 8 * psdu;
    if bits.len() < required {
        return Err(());
    }
    let mut seed = (1..128u8)
        .find(|s| super::super::ofdm::waveform::scramble(&[0; 7], *s) == bits[..7])
        .ok_or(())?;
    let mut plain = bits;
    for bit in &mut plain {
        let feedback = ((seed >> 6) ^ (seed >> 3)) & 1;
        seed = ((seed << 1) | feedback) & 127;
        *bit ^= feedback;
    }
    signal_b.verify_service(&plain[..16]).map_err(|_| ())?;
    Ok(plain[16..required]
        .chunks_exact(8)
        .map(|octet| octet.iter().enumerate().fold(0, |v, (i, b)| v | (b << i)))
        .collect())
}
