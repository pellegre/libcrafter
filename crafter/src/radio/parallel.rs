//! Bounded parallel legacy PHY dispatch; sources and packet parsing stay unchanged.
use super::*;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;

struct Job {
    chunk: IqChunk,
    sequence: u64,
    output: Mutex<Collector>,
}
struct Collector {
    frames: Vec<(usize, RecoveredFrame)>,
    diagnostics: Vec<((usize, u8, usize), PhyDiagnostic)>,
    limit: usize,
    diagnostic_limit: usize,
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
            if let Some((old_slice, old)) = self.frames.iter_mut().find(|(_, old)| {
                old.start.epoch == frame.start.epoch
                    && old.start.sample_index == frame.start.sample_index
                    && old.end_sample_index == frame.end_sample_index
                    && old.bytes == frame.bytes
            }) {
                if (slice, frame.rate_bps) < (*old_slice, old.rate_bps) {
                    frame.config = config.clone();
                    *old_slice = slice;
                    *old = frame;
                }
                continue;
            }
            if self.frames.len() == self.limit - 2 {
                return Err(RadioError::Limit {
                    context: "combined pending frames (two child slots reserved)",
                    limit: (self.limit - 2) as u64,
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
    fn finish(mut self) -> DecodeOutput {
        self.frames.sort_by_key(|(slice, f)| {
            (*slice, f.end_sample_index, f.start.sample_index, f.rate_bps)
        });
        DecodeOutput {
            frames: self.frames.into_iter().map(|(_, f)| f).collect(),
            diagnostics: self.diagnostics.into_iter().map(|(_, d)| d).collect(),
        }
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
                while let Ok(command) = receive.recv() {
                    let result = match command {
                        Command::Reset(reason) => Ok(decoder.reset(reason)),
                        Command::Process(job) => {
                            process(&mut decoder, &job, family).map(|()| DecodeOutput::default())
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
fn process(decoder: &mut impl PhyDecoder, job: &Job, family: u8) -> RadioResult<()> {
    let mut config = job.chunk.config().clone();
    config.max_buffer_samples = if family == 0 {
        config.max_buffer_samples - 128
    } else {
        128
    };
    config.max_chunk_samples = 128;
    config.max_pending_frames = 1;
    for (index, samples) in job.chunk.cs8().chunks(256).enumerate() {
        let mut position = job.chunk.position().clone();
        position.sample_index += (index * 128) as u64;
        position.sequence = job.sequence + index as u64;
        position.discontinuity = None;
        let output = decoder.consume(IqEvent::Chunk(IqChunk::new(
            config.clone(),
            position,
            samples.to_vec(),
        )?))?;
        if !output.frames.is_empty() || !output.diagnostics.is_empty() {
            job.output
                .lock()
                .map_err(|_| RadioError::Source("PHY output lock poisoned".into()))?
                .append(index, family, output, job.chunk.config())?;
        }
    }
    Ok(())
}

/// Two persistent PHY workers sharing one owned input chunk and one output budget.
///
/// Implements the same [`PhyDecoder`] boundary as [`LegacyWifiDecoder`]. No device
/// is opened. Dispatch retains 128-sample slice coordinates and completion order.
/// Each call waits for both workers, so no input backlog is hidden in the decoder.
/// A failed worker channel is terminal; construct a new decoder to recover it.
/// On a failed chunk, worker statistics can include later work than serial dispatch.
pub struct ParallelLegacyWifiDecoder {
    workers: [Worker; 2],
    stats: [DecoderStats; 2],
    continuity: IqContinuity,
    sequence: u64,
    terminal: bool,
    failed: bool,
}
impl ParallelLegacyWifiDecoder {
    pub fn new() -> RadioResult<Self> {
        Ok(Self {
            workers: [
                Worker::new(LegacyOfdmDecoder::new(), LegacyOfdmDecoder::stats, 0)?,
                Worker::new(DsssCckDecoder::new(), DsssCckDecoder::stats, 1)?,
            ],
            stats: [DecoderStats::default(); 2],
            continuity: IqContinuity::default(),
            sequence: 0,
            terminal: false,
            failed: false,
        })
    }
    pub fn ofdm_stats(&self) -> DecoderStats {
        self.stats[0]
    }
    pub fn dsss_stats(&self) -> DecoderStats {
        self.stats[1]
    }
    fn collect(&mut self) -> RadioResult<DecodeOutput> {
        // Always drain both replies, even when a decoder reports an error.
        let replies = [self.workers[0].receive(), self.workers[1].receive()];
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
        let job = Arc::new(Job {
            output: Mutex::new(Collector {
                frames: Vec::new(),
                diagnostics: Vec::new(),
                limit: config.max_pending_frames,
                diagnostic_limit: config
                    .max_pending_frames
                    .saturating_sub(output.diagnostics.len()),
            }),
            chunk,
            sequence: self.sequence,
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
        let decoded = job
            .output
            .into_inner()
            .map_err(|_| RadioError::Source("PHY output lock poisoned".into()))?
            .finish();
        output.frames = decoded.frames;
        output.diagnostics.extend(decoded.diagnostics);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn worker_failure_at_eof_is_not_successful_completion() {
        let mut decoder = ParallelLegacyWifiDecoder {
            workers: [
                Worker::new(FailedReset, |_| DecoderStats::default(), 0).unwrap(),
                Worker::new(DsssCckDecoder::new(), DsssCckDecoder::stats, 1).unwrap(),
            ],
            stats: [DecoderStats::default(); 2],
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
