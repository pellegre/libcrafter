//! One device owner with serialized RF directions and independently signalled cancellation.
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HackRfDirection {
    Idle,
    Receive,
    Transmit,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct HackRfDuplexStatus {
    pub direction: HackRfDirection,
    pub epoch: u64,
    pub direction_changes: u64,
    /// Latest receive acquisition, including verified queued samples.
    pub rx: Option<HackRfStats>,
    pub tx: Option<HackRfTxStats>,
    pub cancelled: bool,
    pub last_error: Option<RadioError>,
}
type Wake = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone)]
pub struct HackRfDuplexControl {
    cancelled: Arc<AtomicBool>,
    wake: Arc<Mutex<Option<Wake>>>,
    status: Arc<Mutex<HackRfDuplexStatus>>,
}
impl HackRfDuplexControl {
    /// Signal cancellation without waiting for the receive/transmit operation lock.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(wake) = self.wake.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            wake();
        }
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        status.cancelled = true;
        status.direction = HackRfDirection::Cancelled;
    }
    pub fn status(&self) -> HackRfDuplexStatus {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    fn direction(&self, direction: HackRfDirection) {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        let direction = if self.cancelled.load(Ordering::Acquire) {
            HackRfDirection::Cancelled
        } else {
            direction
        };
        if status.direction != direction {
            status.direction_changes += 1;
        }
        status.direction = direction;
    }
    fn error(&self, error: &RadioError) {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_error = Some(error.clone());
    }
}

trait Receive: IqSource + Send {
    fn stop(&mut self) -> RadioResult<HackRfStats>;
    fn stats(&self) -> HackRfStats;
    fn wake(&self) -> Wake;
}
impl Receive for HackRfSource {
    fn stop(&mut self) -> RadioResult<HackRfStats> {
        self.stop_acquisition()
    }
    fn stats(&self) -> HackRfStats {
        HackRfSource::stats(self)
    }
    fn wake(&self) -> Wake {
        let cancellation = self.cancellation();
        Arc::new(move || cancellation.cancel())
    }
}
trait DeviceIo: Send {
    fn receive(&mut self, config: HackRfConfig) -> RadioResult<Box<dyn Receive>>;
    fn transmit(
        &mut self,
        config: &HackRfTxConfig,
        samples: &OwnedSamples,
        cancelled: Arc<AtomicBool>,
    ) -> (RadioResult<IqSinkOutcome>, Option<HackRfTxStats>);
}
struct NativeDevice(super::hackrf::native::SharedDevice);
impl DeviceIo for NativeDevice {
    fn receive(&mut self, config: HackRfConfig) -> RadioResult<Box<dyn Receive>> {
        Ok(Box::new(HackRfSource::open_shared(
            config,
            Arc::clone(&self.0),
        )?))
    }
    fn transmit(
        &mut self,
        config: &HackRfTxConfig,
        samples: &OwnedSamples,
        cancelled: Arc<AtomicBool>,
    ) -> (RadioResult<IqSinkOutcome>, Option<HackRfTxStats>) {
        let mut sink = HackRfTxSink::shared(config.clone(), Arc::clone(&self.0), cancelled);
        let result = sink.write_outcome(samples);
        (result, sink.last_stats().cloned())
    }
}
struct State {
    device: Box<dyn DeviceIo>,
    rx_config: HackRfConfig,
    tx_config: HackRfTxConfig,
    rx: Option<Box<dyn Receive>>,
    stopped_for_tx: bool,
    restart: bool,
    pending_gap: bool,
    epoch_base: u64,
    last_epoch: u64,
    acquired: bool,
    received: u64,
    deadline: Option<Instant>,
    terminal: Option<StreamEnd>,
    receive_error: Option<RadioError>,
    control: HackRfDuplexControl,
}
impl State {
    fn rx_status(&self) {
        if let Some(rx) = &self.rx {
            self.control
                .status
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .rx = Some(rx.stats());
        }
    }
    fn finish_rx(&mut self) {
        if let Some(rx) = self.rx.take() {
            let stats = rx.stats();
            self.received = self.received.saturating_add(stats.received_samples);
            self.control
                .status
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .rx = Some(stats);
        }
        *self.control.wake.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
    fn next_event(&mut self) -> RadioResult<IqEvent> {
        loop {
            if let Some(error) = &self.receive_error {
                return Err(error.clone());
            }
            if self.control.cancelled.load(Ordering::Acquire) {
                let stopped = if let Some(rx) = &mut self.rx {
                    rx.cancel();
                    rx.stop().map(|_| ())
                } else {
                    Ok(())
                };
                self.finish_rx();
                self.terminal = Some(StreamEnd::Cancelled);
                self.control.direction(HackRfDirection::Cancelled);
                if let Err(error) = stopped {
                    self.receive_error = Some(error.clone());
                    return Err(error);
                }
                return Ok(IqEvent::End(StreamEnd::Cancelled));
            }
            if self.rx.is_none() {
                if let Some(end) = self.terminal {
                    if !self.restart {
                        return Ok(IqEvent::End(end));
                    }
                }
                let mut config = self.rx_config.clone();
                let deadline = *self
                    .deadline
                    .get_or_insert_with(|| Instant::now() + config.rx.max_duration);
                config.rx.max_duration = deadline.saturating_duration_since(Instant::now());
                config.rx.max_capture_samples =
                    config.rx.max_capture_samples.saturating_sub(self.received);
                if config.rx.max_duration.is_zero() || config.rx.max_capture_samples == 0 {
                    self.terminal = Some(StreamEnd::LimitReached);
                    self.restart = false;
                    return Ok(IqEvent::End(StreamEnd::LimitReached));
                }
                let next_epoch = if self.acquired {
                    self.last_epoch.checked_add(1).ok_or(RadioError::Overflow {
                        context: "duplex receive epoch",
                    })?
                } else {
                    0
                };
                let rx = match self.device.receive(config) {
                    Ok(rx) => rx,
                    Err(error) => {
                        self.receive_error = Some(error.clone());
                        self.control.direction(HackRfDirection::Idle);
                        return Err(error);
                    }
                };
                self.epoch_base = next_epoch;
                self.last_epoch = next_epoch;
                self.acquired = true;
                let wake = rx.wake();
                *self.control.wake.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(Arc::clone(&wake));
                if self.control.cancelled.load(Ordering::Acquire) {
                    wake();
                }
                self.rx = Some(rx);
                self.stopped_for_tx = false;
                self.restart = false;
                self.terminal = None;
                self.control.direction(HackRfDirection::Receive);
            }
            let event = match self.rx.as_mut().expect("active receiver").next_event() {
                Ok(event) => event,
                Err(error) => {
                    let stopped = self.rx.as_mut().expect("active receiver").stop();
                    self.finish_rx();
                    self.control.direction(HackRfDirection::Idle);
                    let error = match stopped {
                        Err(stop) if stop != error => {
                            RadioError::Source(format!("{error}; shutdown: {stop}"))
                        }
                        _ => error,
                    };
                    self.receive_error = Some(error.clone());
                    return Err(error);
                }
            };
            self.rx_status();
            match event {
                IqEvent::Chunk(mut chunk) => {
                    chunk.position.epoch =
                        chunk.position.epoch.checked_add(self.epoch_base).ok_or(
                            RadioError::Overflow {
                                context: "duplex receive epoch",
                            },
                        )?;
                    self.last_epoch = self.last_epoch.max(chunk.position.epoch);
                    if self.pending_gap && !self.stopped_for_tx {
                        chunk.position.discontinuity = Some(Discontinuity {
                            reason: GapReason::Reconfiguration,
                            loss: SampleLoss::Unknown,
                        });
                        self.pending_gap = false;
                    }
                    self.control
                        .status
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .epoch = chunk.position.epoch;
                    return Ok(IqEvent::Chunk(chunk));
                }
                IqEvent::End(end) => {
                    let resume = self.stopped_for_tx && self.restart;
                    self.finish_rx();
                    self.terminal = Some(end);
                    self.control.direction(HackRfDirection::Idle);
                    if resume {
                        continue;
                    }
                    return Ok(IqEvent::End(end));
                }
            }
        }
    }
    fn transmit(&mut self, samples: &OwnedSamples) -> RadioResult<IqSinkOutcome> {
        if self.control.cancelled.load(Ordering::Acquire) {
            return Err(RadioError::Source("HackRF interface cancelled".into()));
        }
        samples.validate_samples()?;
        if samples.sample_rate_hz != self.tx_config.sample_rate_hz {
            return Err(RadioError::Invalid {
                field: "sample_rate_hz",
                reason: "encoded samples do not match the configured device rate",
            });
        }
        if let Some(rx) = &mut self.rx {
            let stopped = rx.stop();
            self.stopped_for_tx = true;
            self.rx_status();
            self.control.direction(HackRfDirection::Idle);
            stopped?;
        }
        self.restart = true;
        self.pending_gap = true;
        self.control.direction(HackRfDirection::Transmit);
        let (result, stats) = self.device.transmit(
            &self.tx_config,
            samples,
            Arc::clone(&self.control.cancelled),
        );
        self.control
            .status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tx = stats;
        self.control.direction(HackRfDirection::Idle);
        if let Err(error) = &result {
            self.control.error(error);
        }
        result
    }
}
impl Drop for State {
    fn drop(&mut self) {
        if let Some(rx) = &mut self.rx {
            rx.cancel();
        }
        self.finish_rx();
    }
}

/// Shared native ownership. Opening acquires one handle but starts no RF transfer.
/// Clones share that handle, direction state, and cancellation signal.
#[derive(Clone)]
pub struct HackRfDuplex {
    state: Arc<Mutex<State>>,
    control: HackRfDuplexControl,
}
impl HackRfDuplex {
    /// Configured device settings, not an independent measurement of RF state.
    pub fn configuration(&self) -> (HackRfConfig, HackRfTxConfig) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        (state.rx_config.clone(), state.tx_config.clone())
    }
    pub fn open(rx: HackRfConfig, tx: HackRfTxConfig) -> RadioResult<Self> {
        rx.validate()?;
        tx.validate()?;
        if rx.serial != tx.serial {
            return Err(RadioError::Invalid {
                field: "serial",
                reason: "duplex directions require the same physical device",
            });
        }
        let device = super::hackrf::native::Device::open(&rx.serial)?;
        Ok(Self::with_device(rx, tx, Box::new(NativeDevice(device))))
    }
    fn with_device(
        rx_config: HackRfConfig,
        tx_config: HackRfTxConfig,
        device: Box<dyn DeviceIo>,
    ) -> Self {
        let control = HackRfDuplexControl {
            cancelled: Arc::new(AtomicBool::new(false)),
            wake: Arc::new(Mutex::new(None)),
            status: Arc::new(Mutex::new(HackRfDuplexStatus {
                direction: HackRfDirection::Idle,
                epoch: 0,
                direction_changes: 0,
                rx: None,
                tx: None,
                cancelled: false,
                last_error: None,
            })),
        };
        let state = State {
            device,
            rx_config,
            tx_config,
            rx: None,
            stopped_for_tx: false,
            restart: false,
            pending_gap: false,
            epoch_base: 0,
            last_epoch: 0,
            acquired: false,
            received: 0,
            deadline: None,
            terminal: None,
            receive_error: None,
            control: control.clone(),
        };
        Self {
            state: Arc::new(Mutex::new(state)),
            control,
        }
    }
    pub fn split(self) -> (HackRfDuplexSource, HackRfDuplexSink, HackRfDuplexControl) {
        (
            HackRfDuplexSource {
                state: Arc::clone(&self.state),
                control: self.control.clone(),
            },
            HackRfDuplexSink { state: self.state },
            self.control,
        )
    }
}
pub struct HackRfDuplexSource {
    state: Arc<Mutex<State>>,
    control: HackRfDuplexControl,
}
impl IqSource for HackRfDuplexSource {
    fn cancel_with_result(&mut self) -> RadioResult<()> {
        self.control.cancel();
        self.next_event().map(|_| ())
    }
    fn next_event(&mut self) -> RadioResult<IqEvent> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let result = state.next_event();
        if let Err(error) = &result {
            state.control.error(error);
        }
        result
    }
    fn cancel(&mut self) {
        self.control.cancel();
    }
}
pub struct HackRfDuplexSink {
    state: Arc<Mutex<State>>,
}
impl<T: EncodedSamples> IqSink<T> for HackRfDuplexSink {
    fn write(&mut self, samples: &T) -> RadioResult<()> {
        self.write_outcome(samples).map(|_| ())
    }
    fn write_outcome(&mut self, samples: &T) -> RadioResult<IqSinkOutcome> {
        samples.validate_samples()?;
        let owned = OwnedSamples {
            cs8: samples.samples_cs8().to_vec(),
            sample_rate_hz: samples.sample_rate_hz(),
        };
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let result = state.transmit(&owned);
        if let Err(error) = &result {
            state.control.error(error);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn clone_event(event: &IqEvent) -> IqEvent {
        match event {
            IqEvent::Chunk(chunk) => IqEvent::Chunk(chunk.clone()),
            IqEvent::End(end) => IqEvent::End(*end),
        }
    }
    struct MockDevice {
        events: Vec<IqEvent>,
        active: Arc<AtomicBool>,
        fail_stop: bool,
    }
    struct MockReceive {
        events: VecDeque<IqEvent>,
        active: Arc<AtomicBool>,
        cancelled: Arc<AtomicBool>,
        stats: HackRfStats,
        fail_stop: bool,
    }
    impl IqSource for MockReceive {
        fn next_event(&mut self) -> RadioResult<IqEvent> {
            if self.cancelled.load(Ordering::Acquire) {
                return Ok(IqEvent::End(StreamEnd::Cancelled));
            }
            let event = self
                .events
                .pop_front()
                .unwrap_or(IqEvent::End(StreamEnd::LimitReached));
            match &event {
                IqEvent::Chunk(chunk) => self.stats.queued_samples -= chunk.len(),
                IqEvent::End(_) => self.active.store(false, Ordering::Release),
            }
            Ok(event)
        }
        fn cancel(&mut self) {
            self.cancelled.store(true, Ordering::Release);
            self.stats.discarded_samples += self.stats.queued_samples as u64;
            self.stats.queued_samples = 0;
            self.events.clear();
            self.active.store(false, Ordering::Release);
        }
    }
    impl Receive for MockReceive {
        fn stop(&mut self) -> RadioResult<HackRfStats> {
            self.active.store(false, Ordering::Release);
            if self.fail_stop {
                Err(RadioError::Source("mock stop failure".into()))
            } else {
                Ok(self.stats())
            }
        }
        fn stats(&self) -> HackRfStats {
            self.stats.clone()
        }
        fn wake(&self) -> Wake {
            let cancelled = Arc::clone(&self.cancelled);
            Arc::new(move || cancelled.store(true, Ordering::Release))
        }
    }
    impl Drop for MockReceive {
        fn drop(&mut self) {
            self.active.store(false, Ordering::Release);
        }
    }
    impl DeviceIo for MockDevice {
        fn receive(&mut self, _: HackRfConfig) -> RadioResult<Box<dyn Receive>> {
            assert!(
                !self.active.swap(true, Ordering::AcqRel),
                "overlapping RX acquisition"
            );
            let queued_samples: usize = self
                .events
                .iter()
                .map(|event| match event {
                    IqEvent::Chunk(chunk) => chunk.len(),
                    _ => 0,
                })
                .sum();
            Ok(Box::new(MockReceive {
                events: self.events.iter().map(clone_event).collect(),
                active: Arc::clone(&self.active),
                cancelled: Arc::new(AtomicBool::new(false)),
                stats: HackRfStats {
                    queued_samples,
                    received_samples: queued_samples as u64,
                    verified_samples: queued_samples as u64,
                    ..Default::default()
                },
                fail_stop: self.fail_stop,
            }))
        }
        fn transmit(
            &mut self,
            _: &HackRfTxConfig,
            samples: &OwnedSamples,
            cancelled: Arc<AtomicBool>,
        ) -> (RadioResult<IqSinkOutcome>, Option<HackRfTxStats>) {
            assert!(
                !self.active.load(Ordering::Acquire),
                "TX overlapped RF reception"
            );
            let count = (samples.cs8.len() / 2) as u64;
            if cancelled.load(Ordering::Acquire) {
                return (Err(RadioError::Source("cancelled".into())), None);
            }
            (
                Ok(IqSinkOutcome {
                    samples_requested: count,
                    samples_supplied: Some(count),
                    padded_samples: 0,
                    completion: SampleCompletion::DeviceCompleted,
                    live: Some(true),
                }),
                Some(HackRfTxStats {
                    requested_samples: count,
                    supplied_samples: count,
                    stopped: true,
                    completed_repetitions: 1,
                    ..Default::default()
                }),
            )
        }
    }
    impl HackRfDuplex {
        pub(crate) fn mock(
            rx: HackRfConfig,
            tx: HackRfTxConfig,
            events: Vec<IqEvent>,
        ) -> RadioResult<Self> {
            rx.validate()?;
            tx.validate()?;
            Ok(Self::with_device(
                rx,
                tx,
                Box::new(MockDevice {
                    events,
                    active: Arc::new(AtomicBool::new(false)),
                    fail_stop: false,
                }),
            ))
        }
    }
    fn configs() -> (HackRfConfig, HackRfTxConfig) {
        let rx = HackRfConfig {
            serial: "synthetic".into(),
            rx: RxConfig {
                sample_rate_hz: 20_000_000,
                center_frequency_hz: 2_437_000_000,
                max_chunk_samples: 40_000,
                max_buffer_samples: 200_000,
                max_frame_bytes: 4095,
                max_pending_frames: 8,
                max_capture_samples: 1_000_000,
                max_duration: std::time::Duration::from_secs(2),
            },
            baseband_filter_hz: 20_000_000,
            lna_gain_db: 0,
            vga_gain_db: 0,
            amplifier_enabled: false,
            antenna_power_enabled: false,
        };
        let tx = HackRfTxConfig {
            serial: rx.serial.clone(),
            center_frequency_hz: rx.rx.center_frequency_hz,
            sample_rate_hz: rx.rx.sample_rate_hz,
            baseband_filter_hz: rx.baseband_filter_hz,
            tx_vga_gain_db: 0,
            amplifier_enabled: false,
            antenna_power_enabled: false,
            max_duration: std::time::Duration::from_secs(1),
            max_supplied_samples: 1_000_000,
            repetitions: 1,
            inter_burst_gap_samples: 0,
        };
        (rx, tx)
    }
    fn chunk(config: &HackRfConfig, index: u64, samples: Vec<i8>) -> IqEvent {
        IqEvent::Chunk(
            IqChunk::new(
                config.rx.clone(),
                IqPosition {
                    epoch: 0,
                    sequence: index,
                    sample_index: index,
                    time_anchor: None,
                    discontinuity: None,
                },
                samples,
            )
            .unwrap(),
        )
    }
    #[test]
    fn duplex_preserves_queued_samples_and_marks_direction_gaps() {
        let (rx, tx) = configs();
        let events = vec![chunk(&rx, 0, vec![1, 2]), chunk(&rx, 1, vec![3, 4])];
        let (mut source, mut sink, control) = HackRfDuplex::mock(rx, tx, events).unwrap().split();
        let IqEvent::Chunk(first) = source.next_event().unwrap() else {
            panic!("missing first samples")
        };
        assert_eq!(first.position().epoch, 0);
        let samples = OwnedSamples {
            cs8: vec![1, 2],
            sample_rate_hz: 20_000_000,
        };
        sink.write(&samples).unwrap();
        assert_eq!(control.status().direction, HackRfDirection::Idle);
        assert_eq!(control.status().rx.unwrap().queued_samples, 1);
        let IqEvent::Chunk(queued) = source.next_event().unwrap() else {
            panic!("lost queued samples")
        };
        assert_eq!(queued.cs8(), &[3, 4]);
        assert_eq!(queued.position().epoch, 0);
        let IqEvent::Chunk(resumed) = source.next_event().unwrap() else {
            panic!("no resumed RX")
        };
        assert_eq!(resumed.position().epoch, 1);
        assert_eq!(
            resumed.position().discontinuity,
            Some(Discontinuity {
                reason: GapReason::Reconfiguration,
                loss: SampleLoss::Unknown
            })
        );
        sink.write(&samples).unwrap();
        control.cancel();
        assert!(matches!(
            source.next_event().unwrap(),
            IqEvent::End(StreamEnd::Cancelled)
        ));
        assert!(sink.write(&samples).is_err());
        assert!(control.status().cancelled);
    }
    #[test]
    fn receive_after_terminal_and_transmit_uses_a_new_epoch() {
        let (rx, tx) = configs();
        let events = vec![chunk(&rx, 0, vec![1, 2]), IqEvent::End(StreamEnd::Eof)];
        let (mut source, mut sink, _) = HackRfDuplex::mock(rx, tx, events).unwrap().split();
        source.next_event().unwrap();
        assert!(matches!(
            source.next_event().unwrap(),
            IqEvent::End(StreamEnd::Eof)
        ));
        sink.write(&OwnedSamples {
            cs8: vec![3, 4],
            sample_rate_hz: 20_000_000,
        })
        .unwrap();
        let IqEvent::Chunk(resumed) = source.next_event().unwrap() else {
            panic!("no resumed capture")
        };
        assert_eq!(resumed.position().epoch, 1);
        assert_eq!(
            resumed.position().discontinuity.unwrap().reason,
            GapReason::Reconfiguration
        );
    }

    #[test]
    fn direction_changes_do_not_reset_total_sample_budget() {
        let (mut rx, tx) = configs();
        rx.rx.max_capture_samples = 2;
        let events = vec![chunk(&rx, 0, vec![1, 2]), chunk(&rx, 1, vec![3, 4])];
        let (mut source, mut sink, _) = HackRfDuplex::mock(rx, tx, events).unwrap().split();
        source.next_event().unwrap();
        sink.write(&OwnedSamples {
            cs8: vec![5, 6],
            sample_rate_hz: 20_000_000,
        })
        .unwrap();
        assert!(matches!(source.next_event().unwrap(), IqEvent::Chunk(_)));
        assert!(matches!(
            source.next_event().unwrap(),
            IqEvent::End(StreamEnd::LimitReached)
        ));
        sink.write(&OwnedSamples {
            cs8: vec![5, 6],
            sample_rate_hz: 20_000_000,
        })
        .unwrap();
        assert!(matches!(
            source.next_event().unwrap(),
            IqEvent::End(StreamEnd::LimitReached)
        ));
    }

    #[test]
    fn cancellation_preserves_stop_errors_on_repeated_polls() {
        let (rx, tx) = configs();
        let events = vec![chunk(&rx, 0, vec![1, 2])];
        let duplex = HackRfDuplex::with_device(
            rx,
            tx,
            Box::new(MockDevice {
                events,
                active: Arc::new(AtomicBool::new(false)),
                fail_stop: true,
            }),
        );
        let (mut source, _, control) = duplex.split();
        source.next_event().unwrap();
        control.cancel();
        let error = source.next_event().unwrap_err();
        assert!(error.to_string().contains("mock stop failure"));
        assert_eq!(source.next_event().unwrap_err(), error);
        assert_eq!(control.status().last_error, Some(error));
        assert_eq!(control.status().direction, HackRfDirection::Cancelled);
    }

    #[test]
    fn native_owner_mock_uses_public_packet_wire_pipeline() {
        use crate::prelude::*;
        let (rx, tx) = configs();
        let packet = Dot11::data()
            .addr1(MacAddr::new([2, 0, 0, 0, 0, 1]))
            .addr2(MacAddr::new([2, 0, 0, 0, 0, 2]))
            .addr3(MacAddr::new([2, 0, 0, 0, 0, 3]))
            / Raw::from("test payload");
        let encoded = LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6)
            .encode_packet(&PacketRecord::new(packet.clone()))
            .unwrap();
        let events = vec![chunk(&rx, 0, encoded.cs8().to_vec())];
        let duplex = HackRfDuplex::mock(rx, tx, events).unwrap();
        let wire = PacketWire::wifi(
            WifiBackend::HackRfOpened { duplex },
            WifiInterfaceConfig::default(),
        )
        .unwrap();
        assert!(wire.wifi_descriptor().unwrap().half_duplex);
        let control = wire.wifi_control().unwrap();
        let (mut source, mut writer) = wire.split().unwrap();
        let received = source.next_record().unwrap().unwrap();
        assert_eq!(
            received.packet().compile().unwrap().as_bytes(),
            packet.compile().unwrap().as_bytes()
        );
        writer.write_record(&received).unwrap();
        let status = control.native_status().unwrap();
        assert_eq!(status.tx.unwrap().completed_repetitions, 1);
        assert_eq!(status.direction, HackRfDirection::Idle);
        control.cancel();
        assert!(source.next_record().unwrap().is_none());
        assert!(writer.write_record(&received).is_err());
    }
    #[test]
    fn cloned_native_owners_share_transmission_state_and_cancellation() {
        use crate::prelude::*;
        let (rx, tx) = configs();
        let duplex = HackRfDuplex::mock(rx, tx, vec![]).unwrap();
        let packet = PacketRecord::new(Dot11::data() / Raw::from("shared owner"));
        let config = WifiInterfaceConfig {
            directions: WifiDirections::Transmit,
            ..Default::default()
        };
        let mut controls = Vec::new();
        for _ in 0..2 {
            let wire = PacketWire::wifi(
                WifiBackend::HackRfOpened {
                    duplex: duplex.clone(),
                },
                config.clone(),
            )
            .unwrap();
            controls.push(wire.wifi_control().unwrap());
            wire.writer().unwrap().write_record(&packet).unwrap();
        }
        let first = controls[0].native_status().unwrap();
        let second = controls[1].native_status().unwrap();
        assert_eq!(first.direction, HackRfDirection::Idle);
        assert_eq!(first.direction_changes, second.direction_changes);
        assert!(first.direction_changes >= 4);
        assert_eq!(first.tx.unwrap().completed_repetitions, 1);
        assert_eq!(second.tx.unwrap().completed_repetitions, 1);
        controls[0].cancel();
        assert!(controls[1].native_status().unwrap().cancelled);
        let wire = PacketWire::wifi(WifiBackend::HackRfOpened { duplex }, config).unwrap();
        assert!(wire.writer().unwrap().write_record(&packet).is_err());
    }
    #[test]
    fn opened_native_owner_cannot_misrepresent_frequency_or_rate() {
        use crate::prelude::*;
        for wrong_rate in [false, true] {
            let (rx, mut tx) = configs();
            if wrong_rate {
                tx.sample_rate_hz = 10_000_000;
            } else {
                tx.center_frequency_hz = 2_412_000_000;
            }
            let duplex = HackRfDuplex::mock(rx, tx, vec![]).unwrap();
            assert!(PacketWire::wifi(
                WifiBackend::HackRfOpened { duplex },
                WifiInterfaceConfig::default()
            )
            .is_err());
        }
    }

    #[test]
    fn shutdown_failure_survives_the_public_packet_interface() {
        use crate::prelude::*;
        let (rx, tx) = configs();
        let packet = Dot11::data() / Raw::from("synthetic cancellation fixture");
        let encoded = LegacyWifiTxConfig::ofdm(LegacyOfdmRate::Mbps6)
            .encode_packet(&PacketRecord::new(packet))
            .unwrap();
        let events = vec![chunk(&rx, 0, encoded.cs8().to_vec())];
        let duplex = HackRfDuplex::with_device(
            rx,
            tx,
            Box::new(MockDevice {
                events,
                active: Arc::new(AtomicBool::new(false)),
                fail_stop: true,
            }),
        );
        let wire = PacketWire::wifi(
            WifiBackend::HackRfOpened { duplex },
            WifiInterfaceConfig::default(),
        )
        .unwrap();
        let control = wire.wifi_control().unwrap();
        let mut source = wire.source().unwrap();
        assert!(source.next_record().unwrap().is_some());
        control.cancel();
        assert!(source
            .next_record()
            .unwrap_err()
            .to_string()
            .contains("mock stop failure"));
        assert!(control
            .status()
            .receive_error
            .unwrap()
            .contains("mock stop failure"));
        assert!(control.native_status().unwrap().last_error.is_some());
    }

    #[test]
    fn failed_stop_prevents_false_transmit_success_and_preserves_error() {
        let (rx, tx) = configs();
        let events = vec![chunk(&rx, 0, vec![1, 2]), chunk(&rx, 1, vec![3, 4])];
        let duplex = HackRfDuplex::with_device(
            rx,
            tx,
            Box::new(MockDevice {
                events,
                active: Arc::new(AtomicBool::new(false)),
                fail_stop: true,
            }),
        );
        let (mut source, mut sink, control) = duplex.split();
        source.next_event().unwrap();
        let error = sink
            .write(&OwnedSamples {
                cs8: vec![1, 2],
                sample_rate_hz: 20_000_000,
            })
            .unwrap_err();
        assert!(error.to_string().contains("mock stop failure"));
        assert!(control.status().last_error.is_some());
        assert!(control.status().tx.is_none());
    }
}
