//! Bounded receive supervisor; native calls are isolated in `native`.
use super::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread::{self, JoinHandle},
    time::Instant,
};
#[cfg(feature = "radio-hackrf")]
#[allow(unsafe_code)]
mod native;

/// All live settings must be supplied. Construction of this value opens nothing.
#[derive(Clone, Debug)]
pub struct HackRfConfig {
    pub rx: RxConfig,
    pub serial: String,
    pub baseband_filter_hz: u32,
    pub lna_gain_db: u32,
    pub vga_gain_db: u32,
    pub amplifier_enabled: bool,
    pub antenna_power_enabled: bool,
}
impl HackRfConfig {
    fn validate(&self) -> RadioResult<()> {
        self.rx.validate()?;
        if self.serial.is_empty() || self.serial.as_bytes().contains(&0) {
            return Err(RadioError::Invalid {
                field: "serial",
                reason: "explicit nonempty device serial required",
            });
        }
        if self.lna_gain_db > 40
            || self.lna_gain_db % 8 != 0
            || self.vga_gain_db > 62
            || self.vga_gain_db % 2 != 0
        {
            return Err(RadioError::Invalid {
                field: "gain",
                reason: "LNA requires 0..40 in steps of 8; VGA 0..62 in steps of 2",
            });
        }
        if !(2_000_000..=20_000_000).contains(&self.rx.sample_rate_hz)
            || self.baseband_filter_hz == 0
        {
            return Err(RadioError::Invalid {
                field: "RF configuration",
                reason: "requires 2..20 Msps and explicit native-supported filter",
            });
        }
        Ok(())
    }
}
/// Aggregate diagnostics remain available even if no following chunk can carry a gap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HackRfStats {
    /// Samples currently retained in the pending-verification and ready queues.
    pub queued_samples: usize,
    /// Largest retained queue size, excluding samples rejected on overflow.
    pub peak_queued_samples: usize,
    pub received_samples: u64,
    pub verified_samples: u64,
    pub discarded_samples: u64,
    pub queue_overflows: u64,
    pub unknown_loss_intervals: u64,
    pub counter_queries: u64,
    pub last_gap: Option<Discontinuity>,
}
struct State {
    pending: VecDeque<IqChunk>,
    ready: VecDeque<IqChunk>,
    buffered: usize,
    sequence: u64,
    stop: bool,
    cancelled: bool,
    terminal: Option<RadioResult<StreamEnd>>,
    fault: Option<RadioError>,
    stats: HackRfStats,
}
struct Shared {
    config: RxConfig,
    start: Instant,
    state: Mutex<State>,
    wake: Condvar,
}
impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn gap(s: &mut State, reason: GapReason) {
        s.stats.unknown_loss_intervals += 1;
        s.stats.last_gap = Some(Discontinuity {
            reason,
            loss: SampleLoss::Unknown,
        });
    }
    /// Callback copies all accepted bytes before returning. No native calls here.
    fn receive(&self, bytes: &[i8]) -> bool {
        let mut s = self.lock();
        if s.stop || s.cancelled {
            return false;
        }
        if self.start.elapsed() >= self.config.max_duration {
            return true;
        }
        if bytes.len() % 2 != 0 {
            s.fault = Some(RadioError::Source(
                "HackRF returned incomplete IQ pair".into(),
            ));
            Self::gap(&mut s, GapReason::SourceLoss);
            s.stop = true;
            return false;
        }
        let count = ((bytes.len() / 2) as u64)
            .min(self.config.max_capture_samples - s.stats.received_samples)
            as usize;
        if count > self.config.max_buffer_samples - s.buffered {
            let pending: usize = s.pending.iter().map(IqChunk::len).sum();
            let ready = s.buffered - pending;
            s.stats.queue_overflows += 1;
            s.stats.received_samples += count as u64;
            s.stats.discarded_samples += count as u64;
            Self::gap(&mut s, GapReason::QueueOverflow);
            s.fault = Some(RadioError::Source(format!(
                "HackRF receive queue overflow (pending_samples={pending}, ready_samples={ready}, incoming_samples={count}, limit_samples={})",
                self.config.max_buffer_samples
            )));
            s.stop = true;
            self.wake.notify_all();
            return false;
        }
        for part in bytes[..count * 2].chunks(self.config.max_chunk_samples * 2) {
            let position = IqPosition {
                epoch: 0,
                sequence: s.sequence,
                sample_index: s.stats.received_samples,
                time_anchor: None,
                discontinuity: None,
            };
            match IqChunk::new(self.config.clone(), position, part.to_vec()) {
                Ok(chunk) => {
                    s.sequence += 1;
                    s.buffered += chunk.len();
                    s.stats.peak_queued_samples = s.stats.peak_queued_samples.max(s.buffered);
                    s.stats.received_samples += chunk.len() as u64;
                    s.pending.push_back(chunk);
                }
                Err(e) => {
                    s.fault = Some(e);
                    s.stop = true;
                    return false;
                }
            }
        }
        // Supervisor, rather than this callback, stops at the sample bound. This
        // permits a final running-state query covering this received high water.
        self.wake.notify_all();
        true
    }
    fn discard_pending(s: &mut State) {
        while let Some(chunk) = s.pending.pop_front() {
            s.buffered -= chunk.len();
            s.stats.discarded_samples += chunk.len() as u64;
        }
    }
    fn verify(&self, high_water: u64, counter: RadioResult<(u32, u32)>) {
        let mut s = self.lock();
        s.stats.counter_queries += 1;
        match counter {
            Ok((0, 0)) => {
                if s.fault.is_none() && !s.cancelled {
                    while s
                        .pending
                        .front()
                        .is_some_and(|c| c.position().sample_index + c.len() as u64 <= high_water)
                    {
                        let chunk = s.pending.pop_front().unwrap();
                        s.stats.verified_samples += chunk.len() as u64;
                        s.ready.push_back(chunk);
                    }
                } else {
                    // A callback fault or cancellation during the query does
                    // not make successful hardware counters a second loss.
                    Self::discard_pending(&mut s);
                    s.stop = true;
                }
            }
            failure => {
                Self::discard_pending(&mut s);
                Self::gap(&mut s, GapReason::SourceLoss);
                if s.fault.is_none() {
                    s.fault = Some(match failure {
                        Ok((shortfalls, longest)) => RadioError::Source(format!(
                            "HackRF continuity counters changed (shortfalls={shortfalls}, longest_shortfall={longest})"
                        )),
                        Err(error) => error,
                    });
                }
                s.stop = true;
            }
        }
        self.wake.notify_all();
    }
}
// Created and used entirely on the supervisor thread; raw native handles never
// need a Send implementation. stop must quiesce callbacks before releasing ctx.
trait Driver {
    fn start(&mut self, shared: Arc<Shared>) -> RadioResult<()>;
    fn counters(&mut self) -> RadioResult<(u32, u32)>;
    fn streaming(&mut self) -> bool;
    fn stop(&mut self) -> RadioResult<()>;
}

/// Explicit live opt-in is `open_live`. A supervisor enforces the wall-clock
/// deadline even when the consumer stalls. Any loss terminates capture; verified
/// prefixes remain readable, then a sticky structured error reports the gap.
pub struct HackRfSource {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}
impl HackRfSource {
    #[cfg(feature = "radio-hackrf")]
    pub fn open_live(config: HackRfConfig) -> RadioResult<Self> {
        config.validate()?;
        let rx = config.rx.clone();
        Self::spawn(rx, move || native::Native::open(config))
    }
    fn spawn<D: Driver + 'static>(
        config: RxConfig,
        open: impl FnOnce() -> RadioResult<D> + Send + 'static,
    ) -> RadioResult<Self> {
        config.validate()?;
        let shared = Arc::new(Shared {
            config,
            start: Instant::now(),
            wake: Condvar::new(),
            state: Mutex::new(State {
                pending: VecDeque::new(),
                ready: VecDeque::new(),
                buffered: 0,
                sequence: 0,
                stop: false,
                cancelled: false,
                terminal: None,
                fault: None,
                stats: HackRfStats::default(),
            }),
        });
        let worker_shared = shared.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("crafter-hackrf-rx".into())
            .spawn(move || {
                let mut driver = match open() {
                    Ok(d) => d,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                };
                if let Err(e) = driver.start(worker_shared.clone()) {
                    let _ = driver.stop();
                    let _ = tx.send(Err(e));
                    return;
                }
                let _ = tx.send(Ok(()));
                supervise(&worker_shared, &mut driver);
            })
            .map_err(|e| RadioError::Source(e.to_string()))?;
        match rx.recv() {
            Ok(Ok(())) => Ok(Self {
                shared,
                worker: Some(worker),
            }),
            result => {
                let _ = worker.join();
                Err(match result {
                    Ok(Err(e)) => e,
                    _ => RadioError::Source("HackRF supervisor startup failed".into()),
                })
            }
        }
    }
    pub fn stats(&self) -> HackRfStats {
        let state = self.shared.lock();
        let mut stats = state.stats.clone();
        stats.queued_samples = state.buffered;
        stats
    }
    fn join(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn supervise(shared: &Shared, driver: &mut impl Driver) {
    loop {
        let (stop, high_water) = {
            let s = shared.lock();
            (s.stop || s.cancelled, s.stats.received_samples)
        };
        if stop {
            break;
        }
        if !driver.streaming() {
            let mut s = shared.lock();
            Shared::gap(&mut s, GapReason::SourceLoss);
            s.fault = Some(RadioError::Source(
                "HackRF disconnected or stopped unexpectedly".into(),
            ));
            break;
        }
        // Query is after receipt of high_water; samples arriving during the query
        // stay pending for the NEXT query. Never qualify using post-stop counters.
        shared.verify(high_water, driver.counters());
        let s = shared.lock();
        if s.stop
            || s.cancelled
            || high_water >= shared.config.max_capture_samples
            || shared.start.elapsed() >= shared.config.max_duration
        {
            break;
        }
        // Batch continuity checks instead of issuing a synchronous USB control
        // transfer on every callback wakeup. Unverified samples remain pending.
        // Bound both the delay and pending share of the configured queue; stop,
        // cancellation and the capture sample bound still wake immediately.
        let batch_samples = (shared.config.max_buffer_samples / 4)
            .max(1)
            .min((shared.config.sample_rate_hz as usize / 50).max(1))
            as u64;
        let delay = Duration::from_millis(20).min(
            shared
                .config
                .max_duration
                .saturating_sub(shared.start.elapsed()),
        );
        let _ = shared.wake.wait_timeout_while(s, delay, |s| {
            !s.stop
                && !s.cancelled
                && s.stats.received_samples < shared.config.max_capture_samples
                && s.stats
                    .received_samples
                    .saturating_sub(s.stats.verified_samples + s.stats.discarded_samples)
                    < batch_samples
        });
    }
    {
        shared.lock().stop = true;
    }
    let stopped = driver.stop(); // callbacks cease before terminal notification
    let mut s = shared.lock();
    Shared::discard_pending(&mut s);
    if s.cancelled {
        s.stats.discarded_samples += s.ready.iter().map(|c| c.len() as u64).sum::<u64>();
        s.ready.clear();
        s.buffered = 0;
        s.terminal = Some(Ok(StreamEnd::Cancelled));
    } else {
        if let Err(e) = stopped {
            s.fault = Some(e);
        }
        s.terminal = Some(match s.fault.take() {
            Some(e) => Err(e),
            None => Ok(StreamEnd::LimitReached),
        });
    }
    shared.wake.notify_all();
}
impl IqSource for HackRfSource {
    fn next_event(&mut self) -> RadioResult<IqEvent> {
        let mut s = self.shared.lock();
        loop {
            if let Some(chunk) = s.ready.pop_front() {
                s.buffered -= chunk.len();
                return Ok(IqEvent::Chunk(chunk));
            }
            if let Some(end) = &s.terminal {
                return end.clone().map(IqEvent::End);
            }
            s = self.shared.wake.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }
    fn cancel(&mut self) {
        {
            let mut s = self.shared.lock();
            s.cancelled = true;
            s.stop = true;
        }
        self.shared.wake.notify_all();
        self.join();
        let mut s = self.shared.lock();
        Shared::discard_pending(&mut s);
        s.stats.discarded_samples += s.ready.iter().map(|c| c.len() as u64).sum::<u64>();
        s.ready.clear();
        s.buffered = 0;
        s.terminal = Some(Ok(StreamEnd::Cancelled));
    }
}
impl Drop for HackRfSource {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn config() -> RxConfig {
        RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 4,
            max_buffer_samples: 32,
            max_frame_bytes: 4096,
            max_pending_frames: 4,
            max_capture_samples: 8,
            max_duration: Duration::from_secs(2),
        }
    }
    struct Mock {
        mode: u8,
        shared: Option<Arc<Shared>>,
        queries: usize,
        stopped: Arc<AtomicUsize>,
    }
    impl Driver for Mock {
        fn start(&mut self, shared: Arc<Shared>) -> RadioResult<()> {
            self.shared = Some(shared.clone());
            if self.mode == 1 {
                return Err(RadioError::Source("mock startup".into()));
            }
            if self.mode != 5 {
                shared.receive(&[1; 8]);
            }
            if self.mode == 3 {
                shared.receive(&[2; 80]);
            }
            Ok(())
        }
        fn counters(&mut self) -> RadioResult<(u32, u32)> {
            self.queries += 1;
            let shared = self.shared.as_ref().unwrap();
            // These samples arrive during the query and cannot be published yet.
            if self.queries == 1 && self.mode != 5 {
                shared.receive(&[2; 8]);
            }
            if self.queries == 2 {
                match self.mode {
                    4 => return Ok((1, 0)),
                    6 => return Err(RadioError::Source("mock unavailable".into())),
                    _ => (),
                }
            }
            Ok((0, 0))
        }
        fn streaming(&mut self) -> bool {
            self.mode != 2
        }
        fn stop(&mut self) -> RadioResult<()> {
            if self.shared.take().is_some() {
                self.stopped.fetch_add(1, Ordering::SeqCst);
            }
            // Real firmware may reset shortfall counters here. No post-stop query
            // is made, so such a rollback cannot certify the pending tail.
            Ok(())
        }
    }
    fn source(mode: u8) -> (RadioResult<HackRfSource>, Arc<AtomicUsize>) {
        let stopped = Arc::new(AtomicUsize::new(0));
        let count = stopped.clone();
        let mut rx = config();
        if matches!(mode, 3 | 7) {
            rx.max_buffer_samples = 4;
        }
        if mode == 5 {
            rx.max_duration = Duration::from_millis(10);
        }
        (
            HackRfSource::spawn(rx, move || {
                Ok(Mock {
                    mode,
                    shared: None,
                    queries: 0,
                    stopped: count,
                })
            }),
            stopped,
        )
    }
    #[test]
    fn radio_hackrf_spurious_wakes_do_not_flood_control_queries() {
        let (source, stopped) = source(5);
        let mut source = source.unwrap();
        for _ in 0..40 {
            source.shared.wake.notify_all();
            std::thread::sleep(Duration::from_micros(250));
        }
        assert!(matches!(
            source.next_event().unwrap(),
            IqEvent::End(StreamEnd::LimitReached)
        ));
        assert!((1..=2).contains(&source.stats().counter_queries));
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn radio_hackrf_configuration_and_start_failure() {
        let mut c = HackRfConfig {
            rx: config(),
            serial: "fixture".into(),
            baseband_filter_hz: 20_000_000,
            lna_gain_db: 24,
            vga_gain_db: 20,
            amplifier_enabled: false,
            antenna_power_enabled: false,
        };
        assert!(c.validate().is_ok());
        assert!(!c.amplifier_enabled && !c.antenna_power_enabled);
        c.serial.clear();
        assert!(c.validate().is_err());
        let (s, stopped) = source(1);
        assert!(s.is_err());
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn radio_hackrf_verified_high_water_and_limits() {
        let (s, stopped) = source(0);
        let mut s = s.unwrap();
        let mut bytes = Vec::new();
        loop {
            match s.next_event().unwrap() {
                IqEvent::Chunk(c) => bytes.extend(c.into_cs8()),
                IqEvent::End(e) => {
                    assert_eq!(e, StreamEnd::LimitReached);
                    break;
                }
            }
        }
        assert_eq!(bytes, [vec![1; 8], vec![2; 8]].concat());
        assert_eq!(s.stats().verified_samples, 8);
        assert_eq!(s.stats().queued_samples, 0);
        assert!((4..=8).contains(&s.stats().peak_queued_samples));
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert!(matches!(
            s.next_event().unwrap(),
            IqEvent::End(StreamEnd::LimitReached)
        ));
    }
    #[test]
    fn radio_hackrf_counter_failure_preserves_only_verified_prefix() {
        for mode in [4, 6] {
            let (s, _) = source(mode);
            let mut s = s.unwrap();
            let IqEvent::Chunk(c) = s.next_event().unwrap() else {
                panic!()
            };
            assert_eq!(c.cs8(), &[1; 8]);
            let e = s.next_event().unwrap_err();
            if mode == 4 {
                assert!(e.to_string().contains("shortfalls=1, longest_shortfall=0"));
            } else {
                assert_eq!(e, RadioError::Source("mock unavailable".into()));
            }
            assert_eq!(e, s.next_event().unwrap_err());
            assert_eq!(s.stats().verified_samples, 4);
            assert_eq!(s.stats().discarded_samples, 4);
            assert!(s.stats().unknown_loss_intervals > 0);
        }
    }
    #[test]
    fn radio_hackrf_disconnect_queue_overflow_and_shutdown() {
        for mode in [2, 3, 7] {
            let (s, stopped) = source(mode);
            let mut s = s.unwrap();
            let error = s.next_event().unwrap_err();
            if matches!(mode, 3 | 7) {
                assert!(error.to_string().contains(
                    "pending_samples=4, ready_samples=0, incoming_samples=4, limit_samples=4"
                ));
            }
            assert_eq!(s.stats().verified_samples, 0);
            assert!(s.stats().last_gap.is_some());
            assert_eq!(s.stats().queue_overflows, u64::from(matches!(mode, 3 | 7)));
            if mode == 7 {
                assert_eq!(s.stats().unknown_loss_intervals, 1);
                assert_eq!(s.stats().last_gap.unwrap().reason, GapReason::QueueOverflow);
            }
            drop(s);
            assert_eq!(stopped.load(Ordering::SeqCst), 1);
        }
    }
    #[test]
    fn radio_hackrf_deadline_without_consumer_and_cancellation() {
        let (s, stopped) = source(5);
        let mut s = s.unwrap();
        // Joining waits for the supervisor's own deadline without polling data.
        s.join();
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert!(matches!(
            s.next_event().unwrap(),
            IqEvent::End(StreamEnd::LimitReached)
        ));
        let (s, stopped) = source(0);
        let mut s = s.unwrap();
        s.cancel();
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert!(matches!(
            s.next_event().unwrap(),
            IqEvent::End(StreamEnd::Cancelled)
        ));
        assert!(s.shared.lock().ready.is_empty());
    }
}
