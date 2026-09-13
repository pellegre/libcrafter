//! Combined receive-only legacy and opt-in modern PHY dispatch.
use super::*;

/// Combined legacy, HT20/VHT20 BCC/LDPC and HE20 receiver.
///
/// HT MCS 0–7, BCC and LDPC, valid long/short guard intervals, mixed and
/// greenfield formats, nonaggregated PSDUs, A-MPDUs, one-data-stream STBC and
/// extension training are supported. `max_frame_bytes` bounds each MPDU;
/// `max_pending_frames` must accommodate the returned MPDUs plus two reserved
/// child slots. Overflow is an explicit error, never a truncated aggregate.
/// VHT supports SU MCS 0–8, both guard intervals, one-DATA-stream STBC,
/// S-MPDU and A-MPDU framing.
/// HE20 SU/ER supports BCC/LDPC, DCM, one-DATA-stream STBC and midambles
/// for admitted layouts; detailed coverage is in `docs/modern-wifi-iq.md`.
/// HE MU recovers FCS-checked aggregates for one non-STBC stream per RU.
/// Other HE layouts, VHT MU,
/// additional independent DATA streams, wider channels and EHT are not yet decoded.
/// This implements the same `PhyDecoder` packet-source interface
/// and shares the bounds and output ordering of `LegacyWifiDecoder`.
pub struct WifiDecoder {
    inner: LegacyWifiDecoder,
}
impl Default for WifiDecoder {
    fn default() -> Self {
        Self {
            inner: LegacyWifiDecoder {
                ofdm: LegacyOfdmDecoder::with_ht(),
                ..LegacyWifiDecoder::default()
            },
        }
    }
}
impl WifiDecoder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn ofdm_stats(&self) -> DecoderStats {
        self.inner.ofdm_stats()
    }
    pub fn dsss_stats(&self) -> DecoderStats {
        self.inner.dsss_stats()
    }
}
impl PhyDecoder for WifiDecoder {
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        self.inner.reset(reason)
    }
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        self.inner.consume(event)
    }
}

/// OFDM and DSSS/CCK reception from the same 20 Msps sample stream.
///
/// Samples are dispatched in at most 128-sample slices. Within each slice,
/// completed frames are ordered by end coordinate, start coordinate, then rate.
/// This is completion order, not a promise to order overlapping transmissions
/// by their preamble starts. Each child gets one transient output slot; the
/// returned output plus those slots share `max_pending_frames` (minimum three).
/// The DSSS sample ring reserves 128 samples from the aggregate buffer bound.
/// An output overflow fails explicitly rather than silently losing packets.
/// Frame sample coordinates, epoch and acquisition configuration retain their
/// source meaning; `start.sequence` identifies the internal dispatch slice,
/// since one source chunk can be dispatched as multiple decoder chunks.
#[derive(Default)]
pub struct LegacyWifiDecoder {
    ofdm: LegacyOfdmDecoder,
    dsss: DsssCckDecoder,
    continuity: IqContinuity,
    sequence: u64,
    terminal: bool,
}
impl LegacyWifiDecoder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn ofdm_stats(&self) -> DecoderStats {
        self.ofdm.stats()
    }
    pub fn dsss_stats(&self) -> DecoderStats {
        self.dsss.stats()
    }
}
impl PhyDecoder for LegacyWifiDecoder {
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        self.continuity.reset();
        self.sequence = 0;
        self.terminal = matches!(reason, ResetReason::End(_));
        let mut out = self.ofdm.reset(reason);
        out.diagnostics.extend(self.dsss.reset(reason).diagnostics);
        out
    }
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        if self.terminal {
            return Ok(DecodeOutput::default());
        }
        let chunk = match event {
            IqEvent::End(end) => return Ok(self.reset(ResetReason::End(end))),
            IqEvent::Chunk(c) => c,
        };
        let config = chunk.config();
        if config.sample_rate_hz != 20_000_000
            || config.max_buffer_samples < 512
            || config.max_pending_frames < 3
        {
            self.reset(ResetReason::Explicit);
            return Err(RadioError::Invalid {
                field: "config",
                reason: "combined Wi-Fi requires 20 Msps, 512 buffer samples and 3 output slots",
            });
        }
        let mut out = DecodeOutput::default();
        if let Some(gap) = self.continuity.observe(&chunk) {
            out = self.reset(ResetReason::Gap(gap));
            self.continuity.observe(&chunk);
        }
        let mut ofdm_config = config.clone();
        ofdm_config.max_buffer_samples -= 128;
        ofdm_config.max_chunk_samples = 128;
        ofdm_config.max_pending_frames = if self.ofdm.ht_enabled() {
            config.max_pending_frames - 2
        } else {
            1
        };
        let mut dsss_config = ofdm_config.clone();
        dsss_config.max_buffer_samples = 128;
        dsss_config.max_pending_frames = 1;
        for (index, samples) in chunk.cs8().chunks(256).enumerate() {
            if self.ofdm.ht_enabled() {
                self.ofdm.set_output_allowance(
                    (config.max_pending_frames - 2).saturating_sub(out.frames.len()),
                );
            }
            let mut position = chunk.position().clone();
            position.sample_index += (index * 128) as u64;
            position.sequence = self.sequence;
            position.discontinuity = None;
            self.sequence = self.sequence.checked_add(1).ok_or(RadioError::Overflow {
                context: "combined decoder sequence",
            })?;
            let first = self.ofdm.consume(IqEvent::Chunk(IqChunk::new(
                ofdm_config.clone(),
                position.clone(),
                samples.to_vec(),
            )?));
            let second = self.dsss.consume(IqEvent::Chunk(IqChunk::new(
                dsss_config.clone(),
                position,
                samples.to_vec(),
            )?));
            let (first, second) = match (first, second) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => {
                    self.reset(ResetReason::Explicit);
                    return Err(e);
                }
            };
            let mut completed = first.frames;
            completed.extend(second.frames);
            completed.sort_by_key(|f| (f.end_sample_index, f.start.sample_index, f.rate_bps));
            for mut frame in completed {
                // Only identical full intervals and bytes are duplicate evidence.
                // Equal packets at different source positions remain occurrences.
                if out.frames.iter().any(|old| same_occurrence(old, &frame)) {
                    continue;
                }
                if out.frames.len() == config.max_pending_frames - 2 {
                    self.reset(ResetReason::Explicit);
                    return Err(RadioError::Limit {
                        context: "combined pending frames (two child slots reserved)",
                        limit: (config.max_pending_frames - 2) as u64,
                        actual: (out.frames.len() + 1) as u64,
                    });
                }
                frame.config = config.clone();
                out.frames.push(frame);
            }
            for diagnostic in first.diagnostics.into_iter().chain(second.diagnostics) {
                if out.diagnostics.len() < config.max_pending_frames {
                    out.diagnostics.push(diagnostic);
                }
            }
        }
        Ok(out)
    }
}
pub(super) fn same_occurrence(a: &RecoveredFrame, b: &RecoveredFrame) -> bool {
    a.start.epoch == b.start.epoch
        && a.start.sample_index == b.start.sample_index
        && a.end_sample_index == b.end_sample_index
        && aggregate_offset(a) == aggregate_offset(b)
        && mu_user(a) == mu_user(b)
        && a.bytes == b.bytes
}
fn mu_user(frame: &RecoveredFrame) -> Option<usize> {
    frame.diagnostics.iter().find_map(|d| match d {
        PhyDiagnostic::HeMuUser { user_index, .. } => Some(*user_index),
        _ => None,
    })
}
fn aggregate_offset(frame: &RecoveredFrame) -> Option<usize> {
    frame.diagnostics.iter().find_map(|d| match d {
        PhyDiagnostic::Ampdu {
            delimiter_offset, ..
        } => Some(*delimiter_offset),
        _ => None,
    })
}
