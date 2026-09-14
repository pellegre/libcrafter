//! Coarse-grained parallel Wi-Fi decoding over bounded overlapping time windows.
use super::*;
use std::{
    collections::BTreeMap,
    sync::{mpsc, Arc, Mutex},
    thread::JoinHandle,
};

const LEGACY_CORE_SAMPLES: usize = 2_000_000;
const WIFI4_CORE_SAMPLES: usize = 1_600_000;
const LEGACY_MARGIN_SAMPLES: usize = 3_840 + 4_095 * 8 * 20 + 64;
// One-stream HT20 MCS 0 with STBC has the longest supported Wi-Fi 4 PSDU.
// The margin includes its maximum 65,535-byte aggregate and ample preamble room.
const WIFI4_MARGIN_SAMPLES: usize = 3_840 + ((16 + 8 * 65_535 + 6 + 51) / 52) * 160;

#[derive(Clone, Copy)]
enum WindowProfile {
    Legacy,
    Wifi4,
}
impl WindowProfile {
    fn core_samples(self) -> usize {
        match self {
            Self::Legacy => LEGACY_CORE_SAMPLES,
            Self::Wifi4 => WIFI4_CORE_SAMPLES,
        }
    }
    fn margin_samples(self) -> usize {
        match self {
            Self::Legacy => LEGACY_MARGIN_SAMPLES,
            Self::Wifi4 => WIFI4_MARGIN_SAMPLES,
        }
    }
}

enum WindowDecoder {
    Legacy(LegacyWifiDecoder),
    Wifi4(WifiDecoder),
}
impl WindowDecoder {
    fn new(profile: WindowProfile) -> Self {
        match profile {
            WindowProfile::Legacy => Self::Legacy(LegacyWifiDecoder::new()),
            WindowProfile::Wifi4 => Self::Wifi4(WifiDecoder::new()),
        }
    }
    fn ofdm_stats(&self) -> DecoderStats {
        match self {
            Self::Legacy(decoder) => decoder.ofdm_stats(),
            Self::Wifi4(decoder) => decoder.ofdm_stats(),
        }
    }
    fn dsss_stats(&self) -> DecoderStats {
        match self {
            Self::Legacy(decoder) => decoder.dsss_stats(),
            Self::Wifi4(decoder) => decoder.dsss_stats(),
        }
    }
}
impl PhyDecoder for WindowDecoder {
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        match self {
            Self::Legacy(decoder) => decoder.reset(reason),
            Self::Wifi4(decoder) => decoder.reset(reason),
        }
    }
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        match self {
            Self::Legacy(decoder) => decoder.consume(event),
            Self::Wifi4(decoder) => decoder.consume(event),
        }
    }
}

struct Job {
    ordinal: u64,
    core_start: u64,
    core_end: u64,
    config: RxConfig,
    position: IqPosition,
    cs8: Vec<i8>,
    boundary: Option<ResetReason>,
}
struct Reply {
    worker: usize,
    ordinal: u64,
    result: RadioResult<DecodeOutput>,
    ofdm: DecoderStats,
    dsss: DecoderStats,
}

fn run_worker(
    worker: usize,
    profile: WindowProfile,
    jobs: Arc<Mutex<mpsc::Receiver<Job>>>,
    replies: mpsc::Sender<Reply>,
) {
    let mut ofdm = DecoderStats::default();
    let mut dsss = DecoderStats::default();
    loop {
        let job = match jobs.lock().unwrap_or_else(|e| e.into_inner()).recv() {
            Ok(job) => job,
            Err(_) => break,
        };
        // Window boundaries are implementation details, not stream loss. A
        // fresh decoder prevents an abandoned overlap candidate's reset from
        // leaking a synthetic truncation into the following job's counters.
        let mut decoder = WindowDecoder::new(profile);
        let mut decoded = DecodeOutput::default();
        let mut failure = None;
        for (index, bytes) in job.cs8.chunks(job.config.max_chunk_samples * 2).enumerate() {
            let offset = index * job.config.max_chunk_samples;
            let mut position = job.position.clone();
            position.sample_index += offset as u64;
            position.sequence = index as u64;
            position.discontinuity = None;
            match IqChunk::new(job.config.clone(), position, bytes.to_vec())
                .and_then(|chunk| decoder.consume(IqEvent::Chunk(chunk)))
            {
                Ok(output) => {
                    decoded
                        .frames
                        .extend(output.frames.into_iter().filter(|frame| {
                            frame.start.sample_index >= job.core_start
                                && frame.start.sample_index < job.core_end
                        }));
                    decoded.diagnostics.extend(output.diagnostics);
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        if failure.is_none() {
            if let Some(reason) = job.boundary {
                // Only a real segment end (EOF or gap) truncates candidates.
                // The outer decoder publishes the boundary itself once.
                decoded.diagnostics.extend(
                    decoder
                        .reset(reason)
                        .diagnostics
                        .into_iter()
                        .filter(|d| !matches!(d, PhyDiagnostic::Reset(_))),
                );
            }
        }
        ofdm = sum_stats(&[ofdm, decoder.ofdm_stats()]);
        dsss = sum_stats(&[dsss, decoder.dsss_stats()]);
        let result = failure.map_or(Ok(decoded), Err);
        if replies
            .send(Reply {
                worker,
                ordinal: job.ordinal,
                result,
                ofdm,
                dsss,
            })
            .is_err()
        {
            break;
        }
    }
}

/// Parallel legacy OFDM/DSSS/CCK decoder using bounded overlapping time windows.
pub struct WindowedLegacyWifiDecoder {
    jobs: Option<mpsc::SyncSender<Job>>,
    replies: mpsc::Receiver<Reply>,
    threads: Vec<JoinHandle<()>>,
    continuity: IqContinuity,
    config: Option<RxConfig>,
    position: Option<IqPosition>,
    bytes: Vec<i8>,
    byte_start: usize,
    sample_start: u64,
    next_job: u64,
    next_output: u64,
    in_flight: usize,
    ready: BTreeMap<u64, Reply>,
    terminal: bool,
    failed: bool,
    ofdm: DecoderStats,
    dsss: DecoderStats,
    worker_ofdm: Vec<DecoderStats>,
    worker_dsss: Vec<DecoderStats>,
    workers: usize,
    profile: WindowProfile,
}

impl WindowedLegacyWifiDecoder {
    pub fn new(workers: usize) -> RadioResult<Self> {
        Self::configured(workers, WindowProfile::Legacy)
    }
    fn configured(workers: usize, profile: WindowProfile) -> RadioResult<Self> {
        if !(1..=32).contains(&workers) {
            return Err(RadioError::Invalid {
                field: "workers",
                reason: "windowed Wi-Fi requires 1..=32 workers",
            });
        }
        // Rendezvous with an available worker so completed windows cannot build
        // a second hidden input queue behind the decoder's bounded output.
        let (jobs, receiver) = mpsc::sync_channel(0);
        let receiver = Arc::new(Mutex::new(receiver));
        let (sender, replies) = mpsc::channel();
        let mut threads = Vec::with_capacity(workers);
        for index in 0..workers {
            let receiver = Arc::clone(&receiver);
            let sender = sender.clone();
            threads.push(
                std::thread::Builder::new()
                    .name(format!("crafter-wifi-window-{index}"))
                    .spawn(move || run_worker(index, profile, receiver, sender))
                    .map_err(|e| RadioError::Source(format!("Wi-Fi worker creation: {e}")))?,
            );
        }
        drop(sender);
        Ok(Self {
            jobs: Some(jobs),
            replies,
            threads,
            continuity: IqContinuity::default(),
            config: None,
            position: None,
            bytes: Vec::new(),
            byte_start: 0,
            sample_start: 0,
            next_job: 0,
            next_output: 0,
            in_flight: 0,
            ready: BTreeMap::new(),
            terminal: false,
            failed: false,
            ofdm: DecoderStats::default(),
            dsss: DecoderStats::default(),
            worker_ofdm: vec![DecoderStats::default(); workers],
            worker_dsss: vec![DecoderStats::default(); workers],
            workers,
            profile,
        })
    }
    pub fn ofdm_stats(&self) -> DecoderStats {
        self.ofdm
    }
    pub fn dsss_stats(&self) -> DecoderStats {
        self.dsss
    }
    fn available(&self) -> usize {
        (self.bytes.len() - self.byte_start) / 2
    }
    fn compact(&mut self) {
        if self.byte_start >= self.bytes.len() / 2 {
            self.bytes.drain(..self.byte_start);
            self.byte_start = 0;
        }
    }
    fn submit(
        &mut self,
        core: usize,
        window: usize,
        boundary: Option<ResetReason>,
    ) -> RadioResult<()> {
        let config = self
            .config
            .clone()
            .ok_or_else(|| RadioError::Source("windowed decoder has no configuration".into()))?;
        let mut position = self
            .position
            .clone()
            .ok_or_else(|| RadioError::Source("windowed decoder has no position".into()))?;
        position.sample_index = self.sample_start;
        position.sequence = 0;
        position.discontinuity = None;
        let end = self.byte_start + window * 2;
        self.jobs
            .as_ref()
            .ok_or_else(|| RadioError::Source("windowed workers are closed".into()))?
            .send(Job {
                ordinal: self.next_job,
                core_start: self.sample_start,
                core_end: self.sample_start + core as u64,
                config,
                position,
                cs8: self.bytes[self.byte_start..end].to_vec(),
                boundary,
            })
            .map_err(|_| RadioError::Source("windowed worker queue closed".into()))?;
        self.next_job += 1;
        self.in_flight += 1;
        self.byte_start += core * 2;
        self.sample_start += core as u64;
        self.compact();
        Ok(())
    }
    fn accept(&mut self, reply: Reply) {
        self.in_flight -= 1;
        self.ready.insert(reply.ordinal, reply);
    }
    fn collect(&mut self, wait: bool, limit: usize) -> RadioResult<DecodeOutput> {
        if wait {
            while self.in_flight != 0 {
                let reply = self
                    .replies
                    .recv()
                    .map_err(|_| RadioError::Source("windowed result queue closed".into()))?;
                self.accept(reply);
            }
        } else {
            while let Ok(reply) = self.replies.try_recv() {
                self.accept(reply);
            }
        }
        let mut output = DecodeOutput::default();
        while let Some(reply) = self.ready.remove(&self.next_output) {
            if !wait
                && reply
                    .result
                    .as_ref()
                    .is_ok_and(|decoded| output.frames.len() + decoded.frames.len() > limit)
            {
                self.ready.insert(self.next_output, reply);
                break;
            }
            let decoded = reply.result?;
            if output.frames.len() + decoded.frames.len() > limit {
                self.failed = true;
                return Err(RadioError::Limit {
                    context: "windowed pending frames",
                    limit: limit as u64,
                    actual: (output.frames.len() + decoded.frames.len()) as u64,
                });
            }
            let unique_ofdm = self.ofdm.valid_frames;
            let unique_dsss = self.dsss.valid_frames;
            self.worker_ofdm[reply.worker] = reply.ofdm;
            self.worker_dsss[reply.worker] = reply.dsss;
            self.ofdm = sum_stats(&self.worker_ofdm);
            self.dsss = sum_stats(&self.worker_dsss);
            // Worker counters include valid frames in the trailing overlap.
            // Report only the core-owned frames that this decoder emits.
            self.ofdm.valid_frames = unique_ofdm;
            self.dsss.valid_frames = unique_dsss;
            for frame in &decoded.frames {
                if matches!(
                    frame.rate_bps,
                    1_000_000 | 2_000_000 | 5_500_000 | 11_000_000
                ) {
                    self.dsss.valid_frames = self.dsss.valid_frames.saturating_add(1);
                } else {
                    self.ofdm.valid_frames = self.ofdm.valid_frames.saturating_add(1);
                }
            }
            output.frames.extend(decoded.frames);
            output.diagnostics.extend(decoded.diagnostics);
            self.next_output += 1;
        }
        output.frames.sort_by_key(|frame| {
            (
                frame.end_sample_index,
                frame.start.sample_index,
                frame.rate_bps,
            )
        });
        output.diagnostics.truncate(limit);
        Ok(output)
    }
    fn clear_stream(&mut self) {
        self.bytes.clear();
        self.byte_start = 0;
        self.config = None;
        self.position = None;
        self.continuity.reset();
    }
    fn finish_segment(&mut self, limit: usize, reason: ResetReason) -> RadioResult<DecodeOutput> {
        while self.available() != 0 {
            let core = self.available().min(self.profile.core_samples());
            let window = self.available();
            self.submit(core, window, Some(reason))?;
        }
        self.collect(true, limit)
    }
    fn discard_workers(&mut self) {
        while self.in_flight != 0 {
            match self.replies.recv() {
                Ok(reply) => self.accept(reply),
                Err(_) => {
                    self.failed = true;
                    break;
                }
            }
        }
        self.ready.clear();
        self.next_output = self.next_job;
    }
}

fn sum_stats(stats: &[DecoderStats]) -> DecoderStats {
    stats
        .iter()
        .fold(DecoderStats::default(), |a, b| DecoderStats {
            valid_frames: a.valid_frames.saturating_add(b.valid_frames),
            invalid_fcs: a.invalid_fcs.saturating_add(b.invalid_fcs),
            rejected_frames: a.rejected_frames.saturating_add(b.rejected_frames),
            truncated_frames: a.truncated_frames.saturating_add(b.truncated_frames),
            dropped_frames: a.dropped_frames.saturating_add(b.dropped_frames),
        })
}

impl Drop for WindowedLegacyWifiDecoder {
    fn drop(&mut self) {
        self.jobs.take();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl PhyDecoder for WindowedLegacyWifiDecoder {
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        self.discard_workers();
        self.clear_stream();
        self.terminal = matches!(reason, ResetReason::End(_));
        DecodeOutput {
            frames: Vec::new(),
            diagnostics: vec![PhyDiagnostic::Reset(reason)],
        }
    }
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        if self.failed {
            return Err(RadioError::Source(
                "windowed Wi-Fi worker failed; create a new decoder".into(),
            ));
        }
        if self.terminal {
            return Ok(DecodeOutput::default());
        }
        let chunk = match event {
            IqEvent::End(end) => {
                let limit = self.config.as_ref().map_or(64, |c| c.max_pending_frames);
                let mut output = self.finish_segment(limit, ResetReason::End(end))?;
                self.clear_stream();
                self.terminal = true;
                output
                    .diagnostics
                    .push(PhyDiagnostic::Reset(ResetReason::End(end)));
                return Ok(output);
            }
            IqEvent::Chunk(chunk) => chunk,
        };
        let config = chunk.config();
        let core_samples = self.profile.core_samples();
        let margin_samples = self.profile.margin_samples();
        let required_buffer = (self.workers + 1)
            .checked_mul(core_samples + margin_samples)
            .ok_or(RadioError::Overflow {
                context: "windowed sample buffer bound",
            })?;
        if config.sample_rate_hz != 20_000_000
            || config.max_buffer_samples < required_buffer
            || config.max_pending_frames < 3
        {
            self.reset(ResetReason::Explicit);
            return Err(RadioError::Invalid {
                field: "config",
                reason: "windowed Wi-Fi requires 20 Msps, bounded assembly and worker windows, and 3 output slots",
            });
        }
        let mut output = DecodeOutput::default();
        if let Some(gap) = self.continuity.observe(&chunk) {
            output = self.finish_segment(config.max_pending_frames, ResetReason::Gap(gap))?;
            self.clear_stream();
            output
                .diagnostics
                .push(PhyDiagnostic::Reset(ResetReason::Gap(gap)));
            self.continuity.observe(&chunk);
        }
        if self.config.is_none() {
            self.config = Some(config.clone());
            self.position = Some(chunk.position().clone());
            self.sample_start = chunk.position().sample_index;
        }
        self.bytes.extend_from_slice(chunk.cs8());
        while self.available() >= core_samples + margin_samples {
            self.submit(core_samples, core_samples + margin_samples, None)?;
        }
        let mut completed = self.collect(false, config.max_pending_frames)?;
        output.frames.append(&mut completed.frames);
        output.diagnostics.append(&mut completed.diagnostics);
        output.diagnostics.truncate(config.max_pending_frames);
        Ok(output)
    }
}

/// Parallel Wi-Fi 4 and legacy decoding over bounded overlapping time windows.
///
/// Each worker runs an independent [`WifiDecoder`]. Windows overlap far enough
/// to finish the longest supported HT20 aggregate; only the worker whose core
/// owns a preamble emits that occurrence.
pub struct WindowedWifiDecoder {
    inner: WindowedLegacyWifiDecoder,
}
impl WindowedWifiDecoder {
    pub fn new(workers: usize) -> RadioResult<Self> {
        Ok(Self {
            inner: WindowedLegacyWifiDecoder::configured(workers, WindowProfile::Wifi4)?,
        })
    }
    pub fn ofdm_stats(&self) -> DecoderStats {
        self.inner.ofdm_stats()
    }
    pub fn dsss_stats(&self) -> DecoderStats {
        self.inner.dsss_stats()
    }
}
impl PhyDecoder for WindowedWifiDecoder {
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        self.inner.reset(reason)
    }
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        self.inner.consume(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn worker_overlap_reset_does_not_invent_stream_truncation() {
        let (jobs, receiver) = mpsc::channel();
        let (replies, outputs) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            run_worker(
                0,
                WindowProfile::Legacy,
                Arc::new(Mutex::new(receiver)),
                replies,
            )
        });
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_437_000_000,
            max_chunk_samples: 4096,
            max_buffer_samples: 120_000,
            max_frame_bytes: 4095,
            max_pending_frames: 64,
            max_capture_samples: 20_000_000,
            max_duration: Duration::from_secs(1),
        };
        for (ordinal, cs8, boundary) in [
            (
                0,
                include_bytes!("../../tests/fixtures/iq/ofdm-6-truncated.cs8")
                    .iter()
                    .map(|b| *b as i8)
                    .collect::<Vec<_>>(),
                None,
            ),
            (1, vec![0; 1024], Some(ResetReason::End(StreamEnd::Eof))),
        ] {
            jobs.send(Job {
                ordinal,
                core_start: 0,
                core_end: cs8.len() as u64 / 2,
                config: config.clone(),
                position: IqPosition {
                    epoch: 0,
                    sequence: 0,
                    sample_index: 0,
                    time_anchor: None,
                    discontinuity: None,
                },
                cs8,
                boundary,
            })
            .unwrap();
            let reply = outputs.recv().unwrap();
            let output = reply.result.unwrap();
            assert!(output.frames.is_empty());
            assert!(!output
                .diagnostics
                .iter()
                .any(|d| matches!(d, PhyDiagnostic::TruncatedFrame)));
            assert_eq!(reply.ofdm.truncated_frames, 0);
        }
        drop(jobs);
        worker.join().unwrap();
    }
}
