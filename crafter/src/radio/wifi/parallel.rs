//! Bounded parallel Wi-Fi PHY dispatch; sources and packet parsing stay unchanged.
use super::{
    dsss::DsssCckDecoder,
    ofdm::{DecoderStats, LegacyOfdmDecoder},
    same_occurrence,
};
use crate::radio::{
    codec::{DecodeOutput, PhyDecoder, PhyDiagnostic, RecoveredFrame, ResetReason},
    error::{RadioError, RadioResult},
    transport::{IqChunk, IqContinuity, IqEvent, RxConfig},
};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;

struct Job {
    chunk: IqChunk,
    dsss_workers: usize,
    ofdm_output_slots: usize,
    worker_chunk_samples: usize,
    output: Mutex<Collector>,
}
struct Collector {
    frames: Vec<(usize, RecoveredFrame)>,
    diagnostics: Vec<((usize, u8, usize), PhyDiagnostic)>,
    limit: usize,
    diagnostic_limit: usize,
    split: bool,
    recent: Vec<RecoveredFrame>,
}
fn same_split_frame(a: &RecoveredFrame, b: &RecoveredFrame) -> bool {
    a.start.epoch == b.start.epoch
        && a.rate_bps == b.rate_bps
        // Independent phase tracks can lock one symbol apart. Identical
        // payloads occupying overlapping intervals denote one reception;
        // nonoverlapping retransmissions remain separate occurrences.
        && a.start.sample_index.max(b.start.sample_index)
            < a.end_sample_index.min(b.end_sample_index)
        && a.bytes == b.bytes
}
impl Collector {
    fn append(
        &mut self,
        slice: usize,
        family: u8,
        output: DecodeOutput,
        config: &RxConfig,
    ) -> RadioResult<()> {
        for mut frame in output.frames {
            if self.split
                && family != 0
                && self.recent.iter().any(|old| same_split_frame(old, &frame))
            {
                continue;
            }
            if let Some((old_slice, old)) = self.frames.iter_mut().find(|(_, old)| {
                (self.split && family != 0 && same_split_frame(old, &frame))
                    || same_occurrence(old, &frame)
            }) {
                if (
                    slice,
                    frame.end_sample_index,
                    frame.start.sample_index,
                    frame.rate_bps,
                ) < (
                    *old_slice,
                    old.end_sample_index,
                    old.start.sample_index,
                    old.rate_bps,
                ) {
                    frame.config = config.clone();
                    *old_slice = slice;
                    *old = frame;
                }
                continue;
            }
            let reserved = if self.split { 5 } else { 2 };
            if self.frames.len() == self.limit - reserved {
                return Err(RadioError::Limit {
                    context: if self.split {
                        "combined pending frames (worker and history slots reserved)"
                    } else {
                        "combined pending frames (two child slots reserved)"
                    },
                    limit: (self.limit - reserved) as u64,
                    actual: (self.frames.len() + 1) as u64,
                });
            }
            frame.config = config.clone();
            self.frames.push((slice, frame));
        }
        for (index, diagnostic) in output.diagnostics.into_iter().enumerate() {
            let key = (slice, family, index);
            let position = self.diagnostics.partition_point(|(old, _)| *old <= key);
            if position < self.diagnostic_limit {
                if self.diagnostics.len() == self.diagnostic_limit {
                    self.diagnostics.pop();
                }
                self.diagnostics.insert(position, (key, diagnostic));
            }
        }
        Ok(())
    }
    fn finish(mut self) -> (DecodeOutput, Vec<RecoveredFrame>) {
        self.frames.sort_by_key(|(slice, f)| {
            (*slice, f.end_sample_index, f.start.sample_index, f.rate_bps)
        });
        if self.split {
            for (_, frame) in &self.frames {
                if matches!(
                    frame.rate_bps,
                    1_000_000 | 2_000_000 | 5_500_000 | 11_000_000
                ) {
                    if self.recent.len() == 2 {
                        self.recent.remove(0);
                    }
                    self.recent.push(frame.clone());
                }
            }
        }
        (
            DecodeOutput {
                frames: self.frames.into_iter().map(|(_, f)| f).collect(),
                diagnostics: self.diagnostics.into_iter().map(|(_, d)| d).collect(),
            },
            self.recent,
        )
    }
}
enum Command {
    Process(Arc<Job>),
    Reset(ResetReason),
}
struct Reply {
    result: RadioResult<DecodeOutput>,
    stats: DecoderStats,
}
struct Worker {
    commands: Option<mpsc::SyncSender<Command>>,
    replies: Option<mpsc::Receiver<Reply>>,
    thread: Option<JoinHandle<()>>,
}
impl Worker {
    fn new<D: PhyDecoder + Send + 'static>(
        mut decoder: D,
        stats: fn(&D) -> DecoderStats,
        family: u8,
    ) -> RadioResult<Self> {
        let (commands, receive) = mpsc::sync_channel(1);
        let (send, replies) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name(
                if family == 0 {
                    "crafter-ofdm"
                } else {
                    "crafter-dsss"
                }
                .into(),
            )
            .spawn(move || {
                let mut worker_sequence = 0u64;
                while let Ok(command) = receive.recv() {
                    let result = match command {
                        Command::Reset(reason) => {
                            worker_sequence = 0;
                            Ok(decoder.reset(reason))
                        }
                        Command::Process(job) => {
                            process(&mut decoder, &job, family, &mut worker_sequence)
                                .map(|()| DecodeOutput::default())
                        }
                    };
                    if send
                        .send(Reply {
                            result,
                            stats: stats(&decoder),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .map_err(|e| RadioError::Source(format!("PHY worker creation: {e}")))?;
        Ok(Self {
            commands: Some(commands),
            replies: Some(replies),
            thread: Some(thread),
        })
    }
    fn send(&self, command: Command) -> RadioResult<()> {
        self.commands
            .as_ref()
            .unwrap()
            .send(command)
            .map_err(|_| RadioError::Source("PHY worker command channel closed".into()))
    }
    fn receive(&self) -> RadioResult<Reply> {
        self.replies
            .as_ref()
            .unwrap()
            .recv()
            .map_err(|_| RadioError::Source("PHY worker reply channel closed".into()))
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Close both directions before joining, including partially failed exchanges.
        self.commands.take();
        self.replies.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn process(
    decoder: &mut impl PhyDecoder,
    job: &Job,
    family: u8,
    worker_sequence: &mut u64,
) -> RadioResult<()> {
    let chunk_samples = if family != 0 && job.dsss_workers == 2 {
        job.worker_chunk_samples
    } else {
        128
    };
    let mut config = job.chunk.config().clone();
    config.max_buffer_samples = if family == 0 {
        config.max_buffer_samples - 128 * job.dsss_workers
    } else {
        chunk_samples
    };
    config.max_chunk_samples = chunk_samples;
    config.max_pending_frames = if family == 0 {
        job.ofdm_output_slots
    } else if job.dsss_workers == 2 {
        job.chunk.config().max_pending_frames
    } else {
        1
    };
    for (index, samples) in job.chunk.cs8().chunks(chunk_samples * 2).enumerate() {
        let sample_offset = index * chunk_samples;
        let mut position = job.chunk.position().clone();
        position.sample_index += sample_offset as u64;
        position.sequence = *worker_sequence;
        position.discontinuity = None;
        let output = decoder.consume(IqEvent::Chunk(IqChunk::new(
            config.clone(),
            position,
            samples.to_vec(),
        )?))?;
        *worker_sequence = worker_sequence.checked_add(1).ok_or(RadioError::Overflow {
            context: "parallel decoder worker sequence",
        })?;
        if !output.frames.is_empty() || !output.diagnostics.is_empty() {
            let slice = if chunk_samples == 128 {
                index
            } else {
                sample_offset / 128
            };
            job.output
                .lock()
                .map_err(|_| RadioError::Source("PHY output lock poisoned".into()))?
                .append(slice, family, output, job.chunk.config())?;
        }
    }
    Ok(())
}

/// Persistent PHY workers sharing one owned input chunk and one output budget.
///
/// Implements the same [`PhyDecoder`] boundary as [`crate::radio::LegacyWifiDecoder`]. No device
/// is opened. Dispatch retains 128-sample slice coordinates and completion order.
/// Each call waits for all workers, so no input backlog is hidden in the decoder.
/// A failed worker channel is terminal; construct a new decoder to recover it.
/// On a failed chunk, worker statistics can include later work than serial dispatch.
pub struct ParallelLegacyWifiDecoder {
    workers: Vec<Worker>,
    stats: Vec<DecoderStats>,
    recent: Vec<RecoveredFrame>,
    continuity: IqContinuity,
    sequence: u64,
    terminal: bool,
    failed: bool,
}
impl ParallelLegacyWifiDecoder {
    fn configured(ofdm: LegacyOfdmDecoder, split_dsss: bool) -> RadioResult<Self> {
        let mut workers = vec![Worker::new(ofdm, LegacyOfdmDecoder::stats, 0)?];
        if split_dsss {
            workers.push(Worker::new(
                DsssCckDecoder::phase_worker(0),
                DsssCckDecoder::stats,
                1,
            )?);
            workers.push(Worker::new(
                DsssCckDecoder::phase_worker(1),
                DsssCckDecoder::stats,
                2,
            )?);
        } else {
            workers.push(Worker::new(
                DsssCckDecoder::new(),
                DsssCckDecoder::stats,
                1,
            )?);
        }
        let worker_count = workers.len();
        Ok(Self {
            workers,
            stats: vec![DecoderStats::default(); worker_count],
            recent: Vec::new(),
            continuity: IqContinuity::default(),
            sequence: 0,
            terminal: false,
            failed: false,
        })
    }
    pub fn new() -> RadioResult<Self> {
        Self::configured(LegacyOfdmDecoder::new(), false)
    }
    /// Use separate workers for the two DSSS acquisition phases.
    /// Requires 640 buffer samples and six frame slots. DSSS statistics count
    /// worker detections before duplicate suppression.
    pub fn with_parallel_dsss() -> RadioResult<Self> {
        Self::configured(LegacyOfdmDecoder::new(), true)
    }
    pub fn ofdm_stats(&self) -> DecoderStats {
        self.stats[0]
    }
    pub fn dsss_stats(&self) -> DecoderStats {
        self.stats[1..]
            .iter()
            .fold(DecoderStats::default(), |a, b| DecoderStats {
                valid_frames: a.valid_frames.saturating_add(b.valid_frames),
                invalid_fcs: a.invalid_fcs.saturating_add(b.invalid_fcs),
                rejected_frames: a.rejected_frames.saturating_add(b.rejected_frames),
                truncated_frames: a.truncated_frames.saturating_add(b.truncated_frames),
                dropped_frames: a.dropped_frames.saturating_add(b.dropped_frames),
            })
    }
    fn collect(&mut self) -> RadioResult<DecodeOutput> {
        // Always drain all replies, even when a decoder reports an error.
        let replies: Vec<_> = self.workers.iter().map(Worker::receive).collect();
        let mut output = DecodeOutput::default();
        let mut error = None;
        for (i, reply) in replies.into_iter().enumerate() {
            match reply {
                Ok(reply) => {
                    self.stats[i] = reply.stats;
                    match reply.result {
                        Ok(decoded) => output.diagnostics.extend(decoded.diagnostics),
                        Err(e) => {
                            error.get_or_insert(e);
                        }
                    }
                }
                Err(e) => {
                    self.failed = true;
                    error.get_or_insert(e);
                }
            }
        }
        error.map_or(Ok(output), Err)
    }
    fn send_both(&mut self, command: impl Fn() -> Command) -> RadioResult<()> {
        for worker in &self.workers {
            if let Err(e) = worker.send(command()) {
                self.failed = true;
                return Err(e);
            }
        }
        Ok(())
    }
}
impl PhyDecoder for ParallelLegacyWifiDecoder {
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        self.recent.clear();
        self.continuity.reset();
        self.sequence = 0;
        self.terminal = matches!(reason, ResetReason::End(_));
        if self.failed || self.send_both(|| Command::Reset(reason)).is_err() {
            return DecodeOutput {
                frames: Vec::new(),
                diagnostics: vec![PhyDiagnostic::Reset(reason)],
            };
        }
        self.collect().unwrap_or_default()
    }
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        if self.failed {
            return Err(RadioError::Source(
                "PHY worker failed; create a new decoder".into(),
            ));
        }
        if self.terminal {
            return Ok(DecodeOutput::default());
        }
        let chunk = match event {
            IqEvent::End(end) => {
                let output = self.reset(ResetReason::End(end));
                if self.failed {
                    return Err(RadioError::Source(
                        "PHY worker failed during end-of-stream reset".into(),
                    ));
                }
                return Ok(output);
            }
            IqEvent::Chunk(chunk) => chunk,
        };
        let config = chunk.config();
        let split = self.workers.len() == 3;
        if config.sample_rate_hz != 20_000_000
            || config.max_buffer_samples < if split { 640 } else { 512 }
            || config.max_pending_frames < if split { 6 } else { 3 }
        {
            self.reset(ResetReason::Explicit);
            return Err(RadioError::Invalid {
                field: "config",
                reason: if split {
                    "split Wi-Fi requires 20 Msps, 640 buffer samples and 6 output slots"
                } else {
                    "combined Wi-Fi requires 20 Msps, 512 buffer samples and 3 output slots"
                },
            });
        }
        let mut output = DecodeOutput::default();
        if let Some(gap) = self.continuity.observe(&chunk) {
            output = self.reset(ResetReason::Gap(gap));
            self.continuity.observe(&chunk);
        }
        let slices = chunk.len().div_ceil(128) as u64;
        let next = self
            .sequence
            .checked_add(slices)
            .ok_or(RadioError::Overflow {
                context: "combined decoder sequence",
            })?;
        let ofdm_output_slots = config.max_pending_frames - if split { 5 } else { 2 };
        // Bound each split-DSSS batch by the caller's input and memory limits.
        // OFDM and the unsplit decoder retain their exact 128-sample dispatch.
        let worker_chunk_samples = config
            .max_chunk_samples
            .max(128)
            .min(16_384)
            .min((config.max_buffer_samples - 384) / (self.workers.len() - 1))
            .max(1);
        let job = Arc::new(Job {
            output: Mutex::new(Collector {
                frames: Vec::new(),
                split,
                recent: std::mem::take(&mut self.recent),
                diagnostics: Vec::new(),
                limit: config.max_pending_frames,
                diagnostic_limit: config
                    .max_pending_frames
                    .saturating_sub(output.diagnostics.len()),
            }),
            chunk,
            dsss_workers: self.workers.len() - 1,
            ofdm_output_slots,
            worker_chunk_samples,
        });
        self.send_both(|| Command::Process(job.clone()))?;
        if let Err(e) = self.collect() {
            self.reset(ResetReason::Explicit);
            return Err(e);
        }
        self.sequence = next;
        // Workers release their Arc before replying, so only the caller remains.
        let job = Arc::try_unwrap(job)
            .map_err(|_| RadioError::Source("PHY worker retained completed input".into()))?;
        let (decoded, recent) = job
            .output
            .into_inner()
            .map_err(|_| RadioError::Source("PHY output lock poisoned".into()))?
            .finish();
        self.recent = recent;
        output.frames = decoded.frames;
        output.diagnostics.extend(decoded.diagnostics);
        Ok(output)
    }
}

/// Persistent parallel Wi-Fi 4 and legacy PHY workers.
///
/// The OFDM worker enables HT20 decoding while the independent DSSS/CCK worker
/// retains reception of legacy 2.4 GHz traffic. `with_parallel_dsss` assigns
/// each DSSS acquisition phase to its own worker. Both constructors preserve
/// the same bounded [`PhyDecoder`] contract as [`crate::radio::WifiDecoder`].
pub struct ParallelWifiDecoder {
    inner: ParallelLegacyWifiDecoder,
}

impl ParallelWifiDecoder {
    pub fn new() -> RadioResult<Self> {
        Ok(Self {
            inner: ParallelLegacyWifiDecoder::configured(LegacyOfdmDecoder::with_ht(), false)?,
        })
    }

    pub fn with_parallel_dsss() -> RadioResult<Self> {
        Ok(Self {
            inner: ParallelLegacyWifiDecoder::configured(LegacyOfdmDecoder::with_ht(), true)?,
        })
    }

    pub fn ofdm_stats(&self) -> DecoderStats {
        self.inner.ofdm_stats()
    }

    pub fn dsss_stats(&self) -> DecoderStats {
        self.inner.dsss_stats()
    }
}

impl PhyDecoder for ParallelWifiDecoder {
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        self.inner.reset(reason)
    }

    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        self.inner.consume(event)
    }
}

#[cfg(all(test, not(crafter_packaged)))]
mod tests {
    use super::*;
    use crate::radio::transport::{IqPosition, StreamEnd};
    struct FailedReset;
    impl PhyDecoder for FailedReset {
        fn consume(&mut self, _: IqEvent) -> RadioResult<DecodeOutput> {
            Ok(DecodeOutput::default())
        }
        fn reset(&mut self, _: ResetReason) -> DecodeOutput {
            panic!("simulated worker failure")
        }
    }
    #[test]
    fn split_collector_coalesces_overlapping_phase_locks_across_chunks() {
        let bytes = include_bytes!("../../../tests/fixtures/iq/dsss-20-short-clean-48.cs8");
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_437_000_000,
            max_chunk_samples: bytes.len() / 2,
            max_buffer_samples: bytes.len(),
            max_frame_bytes: 4095,
            max_pending_frames: 8,
            max_capture_samples: bytes.len() as u64,
            max_duration: std::time::Duration::from_secs(1),
        };
        let position = IqPosition {
            epoch: 0,
            sequence: 0,
            sample_index: 0,
            time_anchor: None,
            discontinuity: None,
        };
        let chunk = IqChunk::new(
            config.clone(),
            position,
            bytes.iter().map(|b| *b as i8).collect(),
        )
        .unwrap();
        let frame = DsssCckDecoder::new()
            .consume(IqEvent::Chunk(chunk))
            .unwrap()
            .frames
            .remove(0);
        let mut late = frame.clone();
        late.start.sample_index += 18;
        late.end_sample_index += 17;
        let mut collector = Collector {
            frames: Vec::new(),
            diagnostics: Vec::new(),
            limit: 8,
            diagnostic_limit: 8,
            split: true,
            recent: Vec::new(),
        };
        let output = |frame| DecodeOutput {
            frames: vec![frame],
            diagnostics: Vec::new(),
        };
        collector
            .append(0, 1, output(frame.clone()), &config)
            .unwrap();
        let (first, recent) = collector.finish();
        assert_eq!(first.frames.len(), 1);
        let mut collector = Collector {
            frames: Vec::new(),
            diagnostics: Vec::new(),
            limit: 8,
            diagnostic_limit: 8,
            split: true,
            recent,
        };
        collector.append(0, 2, output(late), &config).unwrap();
        assert!(collector.frames.is_empty());
        let mut repeat = frame.clone();
        let shift = frame.end_sample_index - frame.start.sample_index + 100;
        repeat.start.sample_index += shift;
        repeat.end_sample_index += shift;
        collector.append(1, 1, output(repeat), &config).unwrap();
        assert_eq!(collector.finish().0.frames.len(), 1);
    }
    #[test]
    fn third_worker_failure_at_eof_is_not_successful_completion() {
        let mut decoder = ParallelLegacyWifiDecoder::with_parallel_dsss().unwrap();
        decoder.workers[2] = Worker::new(FailedReset, |_| DecoderStats::default(), 2).unwrap();
        assert!(matches!(
            decoder.consume(IqEvent::End(StreamEnd::Eof)),
            Err(RadioError::Source(_))
        ));
        assert!(matches!(
            decoder.consume(IqEvent::End(StreamEnd::Eof)),
            Err(RadioError::Source(_))
        ));
        drop(decoder);
    }
    #[test]
    fn worker_failure_at_eof_is_not_successful_completion() {
        let mut decoder = ParallelLegacyWifiDecoder {
            workers: vec![
                Worker::new(FailedReset, |_| DecoderStats::default(), 0).unwrap(),
                Worker::new(DsssCckDecoder::new(), DsssCckDecoder::stats, 1).unwrap(),
            ],
            stats: vec![DecoderStats::default(); 2],
            recent: Vec::new(),
            continuity: IqContinuity::default(),
            sequence: 0,
            terminal: false,
            failed: false,
        };
        assert!(matches!(
            decoder.consume(IqEvent::End(StreamEnd::Eof)),
            Err(RadioError::Source(_))
        ));
        assert!(matches!(
            decoder.consume(IqEvent::End(StreamEnd::Eof)),
            Err(RadioError::Source(_))
        ));
        // Drop must close both channels before joining the surviving worker.
        drop(decoder);
    }
}
