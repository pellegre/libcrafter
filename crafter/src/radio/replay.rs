//! Incremental offline cs8 replay. Timing comes only from supplied metadata.
use super::*;
use std::io::{Cursor, Read};

/// Offline source over any blocking reader. A short read is not EOF. After an
/// error the source repeats that error until cancellation; partial data from a
/// failed read is never presented as a continuous chunk.
///
/// Duration bounds apply to sample time, not host replay speed. Gaps do not
/// consume the received-sample budget. No filesystem timestamps are consulted.
pub struct ReaderIqSource<R> {
    reader: R,
    config: RxConfig,
    position: IqPosition,
    remaining: u64,
    terminal: Option<StreamEnd>,
    error: Option<RadioError>,
    sequence_exhausted: bool,
}

/// In-memory replay has exactly the same validation and chunking as file replay.
pub type MemoryIqSource = ReaderIqSource<Cursor<Vec<u8>>>;

impl MemoryIqSource {
    pub fn from_cs8(samples: Vec<i8>, config: RxConfig, position: IqPosition) -> RadioResult<Self> {
        Self::new(
            Cursor::new(samples.into_iter().map(|v| v as u8).collect()),
            config,
            position,
        )
    }
}

impl<R: Read> ReaderIqSource<R> {
    pub fn new(reader: R, config: RxConfig, position: IqPosition) -> RadioResult<Self> {
        config.validate()?;
        // u128 safely holds Duration's maximum nanoseconds times a u32 rate.
        let duration_samples =
            config.max_duration.as_nanos() * u128::from(config.sample_rate_hz) / 1_000_000_000;
        let remaining = u128::from(config.max_capture_samples).min(duration_samples) as u64;
        Ok(Self {
            reader,
            config,
            position,
            remaining,
            terminal: None,
            error: None,
            sequence_exhausted: false,
        })
    }

    /// Mark a gap before the next chunk. Known losses advance the absolute sample
    /// index; unknown loss begins a new epoch at zero and clears the time anchor.
    /// Multiple pending gaps are rejected instead of silently overwriting one.
    pub fn mark_gap(&mut self, gap: Discontinuity) -> RadioResult<()> {
        if self.terminal.is_some() || self.error.is_some() || self.position.discontinuity.is_some()
        {
            return Err(RadioError::Invalid {
                field: "discontinuity",
                reason: "source ended, failed, or already has a pending gap",
            });
        }
        match gap.loss {
            SampleLoss::Known(count) => {
                self.position.sample_index =
                    self.position
                        .sample_index
                        .checked_add(count)
                        .ok_or(RadioError::Overflow {
                            context: "gap sample position",
                        })?;
            }
            SampleLoss::Unknown => {
                self.position.epoch =
                    self.position
                        .epoch
                        .checked_add(1)
                        .ok_or(RadioError::Overflow {
                            context: "gap epoch",
                        })?;
                self.position.sample_index = 0;
                self.position.time_anchor = None;
            }
        }
        self.position.discontinuity = Some(gap);
        Ok(())
    }

    fn read_event(&mut self) -> RadioResult<IqEvent> {
        if self.remaining == 0 {
            self.terminal = Some(StreamEnd::LimitReached);
            return Ok(IqEvent::End(StreamEnd::LimitReached));
        }
        let count = self.remaining.min(self.config.max_chunk_samples as u64) as usize;
        let mut bytes = vec![0u8; count * 2];
        let mut used = 0;
        while used < bytes.len() {
            match self.reader.read(&mut bytes[used..]) {
                Ok(0) => break,
                Ok(n) => used += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(RadioError::Source(e.to_string())),
            }
        }
        if used % 2 != 0 {
            return Err(RadioError::Invalid {
                field: "cs8",
                reason: "EOF within an I/Q pair",
            });
        }
        if used == 0 {
            self.terminal = Some(StreamEnd::Eof);
            return Ok(IqEvent::End(StreamEnd::Eof));
        }
        if self.sequence_exhausted {
            return Err(RadioError::Overflow {
                context: "replay sequence",
            });
        }
        bytes.truncate(used);
        let chunk = IqChunk::new(
            self.config.clone(),
            self.position.clone(),
            bytes.into_iter().map(|b| b as i8).collect(),
        )?;
        self.position.sample_index += chunk.len() as u64; // checked by IqChunk
        if let Some(next) = self.position.sequence.checked_add(1) {
            self.position.sequence = next;
        } else {
            self.sequence_exhausted = true;
        }
        self.position.discontinuity = None;
        self.remaining -= chunk.len() as u64;
        Ok(IqEvent::Chunk(chunk))
    }
}
impl<R: Read> IqSource for ReaderIqSource<R> {
    fn next_event(&mut self) -> RadioResult<IqEvent> {
        if let Some(end) = self.terminal {
            return Ok(IqEvent::End(end));
        }
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        let result = self.read_event();
        if let Err(error) = &result {
            self.error = Some(error.clone());
        }
        result
    }
    fn cancel(&mut self) {
        if self.terminal.is_none() {
            self.terminal = Some(StreamEnd::Cancelled);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(size: usize) -> RxConfig {
        RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: size,
            max_buffer_samples: 64,
            max_frame_bytes: 4096,
            max_pending_frames: 4,
            max_capture_samples: 100,
            max_duration: Duration::from_secs(1),
        }
    }
    fn position() -> IqPosition {
        IqPosition {
            epoch: 2,
            sequence: 0,
            sample_index: 10,
            time_anchor: None,
            discontinuity: None,
        }
    }
    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/iq/ramp.cs8");
    struct Short {
        inner: Cursor<Vec<u8>>,
        interrupted: bool,
    }
    impl Read for Short {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.inner.read(&mut out[..1])
        }
    }
    #[test]
    fn radio_replay_arbitrary_chunks_short_reads_and_eof() {
        for size in 1..=32 {
            let mut source = ReaderIqSource::new(
                Short {
                    inner: Cursor::new(FIXTURE.to_vec()),
                    interrupted: false,
                },
                config(size),
                position(),
            )
            .unwrap();
            let mut bytes = Vec::new();
            let mut sequence = 0;
            loop {
                match source.next_event().unwrap() {
                    IqEvent::Chunk(chunk) => {
                        assert_eq!(chunk.position().sample_index, 10 + bytes.len() as u64 / 2);
                        assert_eq!(chunk.position().sequence, sequence);
                        assert_eq!(chunk.position().time_anchor, None);
                        assert!(chunk.len() <= size);
                        bytes.extend(chunk.cs8().iter().map(|b| *b as u8));
                        sequence += 1;
                    }
                    IqEvent::End(end) => {
                        assert_eq!(end, StreamEnd::Eof);
                        break;
                    }
                }
            }
            assert_eq!(bytes, FIXTURE);
            assert!(matches!(
                source.next_event().unwrap(),
                IqEvent::End(StreamEnd::Eof)
            ));
        }
    }
    #[test]
    fn radio_replay_truncation_errors_and_empty() {
        let mut empty = ReaderIqSource::new(Cursor::new(vec![]), config(2), position()).unwrap();
        assert!(matches!(
            empty.next_event().unwrap(),
            IqEvent::End(StreamEnd::Eof)
        ));
        let mut odd = MemoryIqSource::from_cs8(vec![1, 2, 3], config(2), position()).unwrap();
        let error = odd.next_event().unwrap_err();
        assert!(matches!(error, RadioError::Invalid { field: "cs8", .. }));
        assert_eq!(odd.next_event().unwrap_err(), error);
        struct Broken(bool);
        impl Read for Broken {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    out[0] = 1;
                    return Ok(1);
                }
                Err(std::io::Error::other("fixture read failure"))
            }
        }
        let mut broken = ReaderIqSource::new(Broken(false), config(2), position()).unwrap();
        assert_eq!(
            broken.next_event().unwrap_err(),
            RadioError::Source("fixture read failure".into())
        );
        assert!(broken.next_event().is_err());
        broken.cancel();
        assert!(matches!(
            broken.next_event().unwrap(),
            IqEvent::End(StreamEnd::Cancelled)
        ));
        let mut invalid = config(1);
        invalid.sample_rate_hz = 0;
        assert!(MemoryIqSource::from_cs8(vec![], invalid, position()).is_err());
    }
    #[test]
    fn radio_replay_limits_cancel_and_overflow() {
        for duration in [false, true] {
            let mut c = config(8);
            if duration {
                c.max_duration = Duration::from_nanos(150);
            } else {
                c.max_capture_samples = 3;
            }
            let mut s = ReaderIqSource::new(Cursor::new(FIXTURE), c, position()).unwrap();
            assert!(matches!(s.next_event().unwrap(), IqEvent::Chunk(c) if c.len() == 3));
            for _ in 0..2 {
                assert!(matches!(
                    s.next_event().unwrap(),
                    IqEvent::End(StreamEnd::LimitReached)
                ));
            }
        }
        let mut p = position();
        p.sample_index = u64::MAX;
        let mut s = MemoryIqSource::from_cs8(vec![0, 0], config(1), p).unwrap();
        assert!(matches!(
            s.next_event(),
            Err(RadioError::Overflow {
                context: "sample end"
            })
        ));
        let mut p = position();
        p.sequence = u64::MAX;
        let mut s = MemoryIqSource::from_cs8(vec![0; 4], config(1), p).unwrap();
        assert!(matches!(s.next_event().unwrap(), IqEvent::Chunk(_)));
        assert!(matches!(
            s.next_event(),
            Err(RadioError::Overflow {
                context: "replay sequence"
            })
        ));
        let mut s = ReaderIqSource::new(Cursor::new(FIXTURE), config(1), position()).unwrap();
        s.cancel();
        for _ in 0..2 {
            assert!(matches!(
                s.next_event().unwrap(),
                IqEvent::End(StreamEnd::Cancelled)
            ));
        }
    }
    #[test]
    fn radio_replay_gaps_and_explicit_time() {
        let mut p = position();
        p.time_anchor = Some(TimeAnchor {
            sample_index: 10,
            time: SystemTime::UNIX_EPOCH,
            uncertainty: Duration::from_micros(1),
        });
        let mut s = ReaderIqSource::new(Cursor::new(FIXTURE), config(1), p.clone()).unwrap();
        let mut continuity = IqContinuity::default();
        let IqEvent::Chunk(first) = s.next_event().unwrap() else {
            panic!()
        };
        assert_eq!(first.position(), &p);
        assert_eq!(continuity.observe(&first), None);
        for loss in [SampleLoss::Known(7), SampleLoss::Unknown] {
            let gap = Discontinuity {
                reason: GapReason::SourceLoss,
                loss,
            };
            s.mark_gap(gap).unwrap();
            assert!(s.mark_gap(gap).is_err());
            let IqEvent::Chunk(chunk) = s.next_event().unwrap() else {
                panic!()
            };
            assert_eq!(continuity.observe(&chunk), Some(gap));
            match loss {
                SampleLoss::Known(_) => {
                    assert_eq!(chunk.position().sample_index, 18);
                    assert_eq!(chunk.position().time_anchor, p.time_anchor);
                }
                SampleLoss::Unknown => {
                    assert_eq!(chunk.position().sample_index, 0);
                    assert_eq!(chunk.position().epoch, 3);
                    assert_eq!(chunk.position().time_anchor, None);
                }
            }
        }
    }
}
