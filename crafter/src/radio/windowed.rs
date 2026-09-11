//! Coarse-grained parallel legacy Wi-Fi decoding over overlapping time windows.
use super::*;
use std::{
    collections::BTreeMap,
    sync::{mpsc, Arc, Mutex},
    thread::JoinHandle,
};

const CORE_SAMPLES: usize = 2_000_000;
const MARGIN_SAMPLES: usize = 3_840 + 4_095 * 8 * 20 + 64;

struct Job {
    ordinal: u64,
    core_start: u64,
    core_end: u64,
    config: RxConfig,
    position: IqPosition,
    cs8: Vec<i8>,
}
struct Reply {
    worker: usize,
    ordinal: u64,
    result: RadioResult<DecodeOutput>,
    ofdm: DecoderStats,
    dsss: DecoderStats,
}

fn run_worker(worker: usize, jobs: Arc<Mutex<mpsc::Receiver<Job>>>, replies: mpsc::Sender<Reply>) {
    let mut decoder = LegacyWifiDecoder::new();
    loop {
        let job = match jobs.lock().unwrap_or_else(|e| e.into_inner()).recv() {
            Ok(job) => job,
            Err(_) => break,
        };
        decoder.reset(ResetReason::Explicit);
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
        let result = failure.map_or(Ok(decoded), Err);
        if replies
            .send(Reply {
                worker,
                ordinal: job.ordinal,
                result,
                ofdm: decoder.ofdm_stats(),
                dsss: decoder.dsss_stats(),
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
}

impl WindowedLegacyWifiDecoder {
    pub fn new(workers: usize) -> RadioResult<Self> {
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
                    .spawn(move || run_worker(index, receiver, sender))
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
    fn submit(&mut self, core: usize, window: usize) -> RadioResult<()> {
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
            self.worker_ofdm[reply.worker] = reply.ofdm;
            self.worker_dsss[reply.worker] = reply.dsss;
            self.ofdm = sum_stats(&self.worker_ofdm);
            self.dsss = sum_stats(&self.worker_dsss);
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
    fn finish_segment(&mut self, limit: usize) -> RadioResult<DecodeOutput> {
        while self.available() != 0 {
            let core = self.available().min(CORE_SAMPLES);
            let window = self.available();
            self.submit(core, window)?;
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
                let mut output = self.finish_segment(limit)?;
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
        let required_buffer = (self.workers + 1)
            .checked_mul(CORE_SAMPLES + MARGIN_SAMPLES)
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
            output = self.finish_segment(config.max_pending_frames)?;
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
        while self.available() >= CORE_SAMPLES + MARGIN_SAMPLES {
            self.submit(CORE_SAMPLES, CORE_SAMPLES + MARGIN_SAMPLES)?;
        }
        let mut completed = self.collect(false, config.max_pending_frames)?;
        output.frames.append(&mut completed.frames);
        output.diagnostics.append(&mut completed.diagnostics);
        output.diagnostics.truncate(config.max_pending_frames);
        Ok(output)
    }
}
