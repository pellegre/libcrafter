//! One Wi-Fi packet pipeline over monitor captures or sample transport.
use std::sync::{Arc, Mutex};

use super::{
    InterfaceMode, MonitorWriter, NormalizedWifiSource, OpenedPacketSource, OpenedPacketWriter,
    PacketFormat, PacketRecord, PacketSource, PacketWire, PacketWireTarget, PacketWriter, Result,
    WireError, WriteReport,
};
use crate::{LinkType, Radiotap};

/// Directions requested at opening. Physical duplex capability is separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiDirections {
    Receive,
    Transmit,
    Both,
}
impl WifiDirections {
    fn receive(self) -> bool {
        self != Self::Transmit
    }
    fn transmit(self) -> bool {
        self != Self::Receive
    }
}

/// PHY settings representable by both a monitor header and the Wi-Fi codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiPhy {
    Ofdm {
        rate_mbps: u8,
    },
    DsssCck {
        rate_500kbps: u8,
        short_preamble: bool,
    },
    Ht20 {
        mcs: u8,
        short_guard: bool,
        greenfield: bool,
        ldpc: bool,
    },
}

/// Requested configuration. Monitor channel preparation remains external.
#[derive(Debug, Clone, PartialEq)]
pub struct WifiInterfaceConfig {
    pub center_frequency_hz: u64,
    /// Optional channel number, checked against the requested frequency.
    pub channel: Option<u16>,
    pub width_mhz: u16,
    pub directions: WifiDirections,
    pub transmit_phy: WifiPhy,
    /// Optional full IQ encoder settings. Monitor drivers cannot express these.
    /// The encoder's PHY must agree with `transmit_phy`.
    #[cfg(feature = "radio")]
    pub radio_encoder: Option<crate::radio::WifiPacketEncoder>,
}
impl Default for WifiInterfaceConfig {
    fn default() -> Self {
        Self {
            center_frequency_hz: 2_437_000_000,
            channel: Some(6),
            width_mhz: 20,
            directions: WifiDirections::Both,
            transmit_phy: WifiPhy::Ofdm { rate_mbps: 6 },
            #[cfg(feature = "radio")]
            radio_encoder: None,
        }
    }
}
impl WifiInterfaceConfig {
    fn validate(&self) -> Result<()> {
        if self.width_mhz != 20 {
            return Err(unsupported(
                "channel width",
                "Wi-Fi packet interfaces currently support 20 MHz only",
            ));
        }
        if self.center_frequency_hz == 0 {
            return Err(invalid("frequency must be nonzero"));
        }
        if let Some(channel) = self.channel {
            let mhz = self.center_frequency_hz / 1_000_000;
            let expected = if mhz < 3000 {
                if channel == 14 {
                    2484
                } else if (1..=13).contains(&channel) {
                    2407 + 5 * u64::from(channel)
                } else {
                    0
                }
            } else if mhz < 5925 {
                5000 + 5 * u64::from(channel)
            } else if channel == 2 {
                5935
            } else {
                5950 + 5 * u64::from(channel)
            };
            if expected * 1_000_000 != self.center_frequency_hz {
                return Err(invalid("channel and center frequency disagree"));
            }
        }
        if !self.directions.transmit() {
            return Ok(());
        }
        #[cfg(feature = "radio")]
        if self
            .radio_encoder
            .as_ref()
            .is_some_and(|encoder| encoder_phy(encoder) != self.transmit_phy)
        {
            return Err(invalid("radio encoder PHY differs from interface request"));
        }
        match self.transmit_phy {
            WifiPhy::Ht20 {
                short_guard: true,
                greenfield: true,
                ..
            } => {
                return Err(unsupported(
                    "transmit PHY",
                    "greenfield transmission with short guard interval is unsupported",
                ));
            }
            WifiPhy::Ofdm { rate_mbps } if [6, 9, 12, 18, 24, 36, 48, 54].contains(&rate_mbps) => {
                ()
            }
            WifiPhy::DsssCck {
                rate_500kbps,
                short_preamble,
            } if [2, 4, 11, 22].contains(&rate_500kbps)
                && !(rate_500kbps == 2 && short_preamble) =>
            {
                ()
            }
            WifiPhy::Ht20 {
                mcs,
                short_guard,
                greenfield,
                ..
            } if mcs <= 7 && !(short_guard && greenfield) => (),
            _ => {
                return Err(unsupported(
                    "transmit PHY",
                    "requires supported legacy rate or single-stream HT20 MCS 0 through 7",
                ))
            }
        }
        Ok(())
    }
    fn radiotap(&self) -> Radiotap {
        match self.transmit_phy {
            WifiPhy::Ofdm { rate_mbps } => Radiotap::new().rate(rate_mbps * 2),
            WifiPhy::DsssCck {
                rate_500kbps,
                short_preamble,
            } => Radiotap::new()
                .rate(rate_500kbps)
                .flags(if short_preamble { 2u8 } else { 0u8 }),
            WifiPhy::Ht20 {
                mcs,
                short_guard,
                greenfield,
                ldpc,
            } => Radiotap::new().mcs([
                0x1f,
                (u8::from(short_guard) << 2) | (u8::from(greenfield) << 3) | (u8::from(ldpc) << 4),
                mcs,
            ]),
        }
    }
}

/// Backend-specific construction ends at `PacketWire::wifi`.
pub enum WifiBackend {
    /// An externally prepared live monitor interface.
    Monitor { interface: String },
    /// Offline captures, recorder pairs, or externally opened monitor adapters.
    MonitorAdapters {
        source: Option<OpenedPacketSource>,
        writer: Option<OpenedPacketWriter>,
        /// Driver framing; bare Dot11 cannot carry requested PHY settings.
        framing: LinkType,
        /// Explicit driver wrapper overrides, preserved verbatim when supplied.
        radiotap_override: Option<Radiotap>,
    },
    #[cfg(feature = "radio")]
    RadioAdapters {
        source: Option<Box<dyn crate::radio::IqSource + Send>>,
        sink: Option<Box<dyn crate::radio::IqSink<crate::radio::OwnedSamples> + Send>>,
        bounds: crate::radio::RxConfig,
    },
    /// Stable feature-disabled constructor for a live HackRF interface.
    #[cfg(not(feature = "radio-hackrf"))]
    HackRf,
    #[cfg(feature = "radio-hackrf")]
    HackRf {
        rx: crate::radio::HackRfConfig,
        tx: crate::radio::HackRfTxConfig,
    },
    /// Reuse one externally configured native owner, including deterministic mocks.
    #[cfg(feature = "radio-hackrf")]
    HackRfOpened { duplex: crate::radio::HackRfDuplex },
}

/// Facts known at opening, without relabeling requests as observations.
#[derive(Debug, Clone, PartialEq)]
pub struct WifiInterfaceDescriptor {
    pub mode: InterfaceMode,
    pub packet_format: PacketFormat,
    pub requested: WifiInterfaceConfig,
    pub observed_frequency_hz: Option<u64>,
    pub observed_width_mhz: Option<u16>,
    /// True when this wire coordinates a shared physical RX/TX owner. False
    /// does not establish simultaneous RF capability for externally supplied adapters.
    pub half_duplex: bool,
}

/// Shared packet-level counters and terminal evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WifiInterfaceStatus {
    pub cancelled: bool,
    pub receive_ended: bool,
    pub received_records: u64,
    pub submitted_records: u64,
    pub receive_error: Option<String>,
    pub transmit_error: Option<String>,
    #[cfg(feature = "radio")]
    pub radio_end: Option<crate::radio::StreamEnd>,
    /// Actual codec counters, including recovered frames that failed packet parsing.
    #[cfg(feature = "radio")]
    pub decoder_stats: Option<crate::radio::DecoderStats>,
}

/// Retain this handle before consuming the opened wire with `split`.
#[derive(Clone, Default)]
pub struct WifiInterfaceControl {
    state: Arc<Mutex<WifiInterfaceStatus>>,
    cancel_backend: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "radio-hackrf")]
    native: Option<crate::radio::HackRfDuplexControl>,
}
impl WifiInterfaceControl {
    /// Physical direction, discontinuities, and native completion evidence.
    #[cfg(feature = "radio-hackrf")]
    pub fn native_status(&self) -> Option<crate::radio::HackRfDuplexStatus> {
        self.native.as_ref().map(|native| native.status())
    }
    pub fn status(&self) -> WifiInterfaceStatus {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    /// Request cancellation. Native backends also interrupt ongoing device I/O.
    pub fn cancel(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancelled = true;
        if let Some(cancel) = &self.cancel_backend {
            cancel();
        }
    }
}

struct ControlledSource {
    inner: OpenedPacketSource,
    control: WifiInterfaceControl,
    handles_cancellation: bool,
}
impl PacketSource for ControlledSource {
    fn next_record(&mut self) -> Result<Option<PacketRecord>> {
        if self.control.status().cancelled && !self.handles_cancellation {
            self.control
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .receive_ended = true;
            return Ok(None);
        }
        let result = self.inner.next_record();
        let mut state = self.control.state.lock().unwrap_or_else(|e| e.into_inner());
        match &result {
            Ok(Some(_)) => state.received_records += 1,
            Ok(None) => state.receive_ended = true,
            Err(error) => state.receive_error = Some(error.to_string()),
        }
        result
    }
}
struct ControlledWriter {
    inner: OpenedPacketWriter,
    control: WifiInterfaceControl,
}
impl PacketWriter for ControlledWriter {
    fn write_record(&mut self, record: &PacketRecord) -> Result<WriteReport> {
        let result = if self.control.status().cancelled {
            Err(WireError::backend("wifi", "write", "interface cancelled"))
        } else {
            self.inner.write_record(record)
        };
        let mut state = self.control.state.lock().unwrap_or_else(|e| e.into_inner());
        match &result {
            Ok(_) => state.submitted_records += 1,
            Err(error) => state.transmit_error = Some(error.to_string()),
        }
        result
    }
}

impl PacketWire {
    /// Open a normalized Wi-Fi interface. All downstream I/O uses existing traits.
    pub fn wifi(backend: WifiBackend, config: WifiInterfaceConfig) -> Result<Self> {
        config.validate()?;
        #[cfg(feature = "radio")]
        if config.directions.transmit()
            && config.radio_encoder.is_some()
            && matches!(
                &backend,
                WifiBackend::Monitor { .. } | WifiBackend::MonitorAdapters { .. }
            )
        {
            return Err(unsupported(
                "radio encoder overrides",
                "monitor drivers do not accept IQ encoder settings",
            ));
        }
        let control = WifiInterfaceControl::default();
        #[cfg(feature = "radio")]
        let mut control = control;
        let (source, writer, mode, half_duplex) = match backend {
            WifiBackend::Monitor { interface } => {
                use super::backend::pcap::{PcapInterfaceSource, PcapInterfaceWriter};
                let source = if config.directions.receive() {
                    let source = PcapInterfaceSource::builder(&interface).open()?;
                    if !matches!(
                        source.pcap_link_type().link_type(),
                        LinkType::Radiotap | LinkType::Ieee80211
                    ) {
                        return Err(unsupported(
                            "monitor receive framing",
                            "opened interface does not expose radiotap or bare Dot11",
                        ));
                    }
                    Some(Box::new(source.normalized_wifi()) as OpenedPacketSource)
                } else {
                    None
                };
                let writer = if config.directions.transmit() {
                    let writer = PcapInterfaceWriter::builder(&interface).open()?;
                    if writer.pcap_link_type().link_type() != LinkType::Radiotap {
                        return Err(unsupported(
                            "monitor transmit framing",
                            "requested PHY settings require a radiotap driver",
                        ));
                    }
                    Some(
                        Box::new(MonitorWriter::new(writer).with_radiotap(config.radiotap()))
                            as OpenedPacketWriter,
                    )
                } else {
                    None
                };
                (source, writer, InterfaceMode::MonitorWifi, false)
            }
            WifiBackend::MonitorAdapters {
                source,
                writer,
                framing,
                radiotap_override,
            } => {
                if !matches!(framing, LinkType::Radiotap | LinkType::Ieee80211) {
                    return Err(unsupported(
                        "monitor framing",
                        "requires radiotap or bare Dot11",
                    ));
                }
                let source =
                    source.map(|s| Box::new(NormalizedWifiSource::new(s)) as OpenedPacketSource);
                let writer =
                    match writer.filter(|_| config.directions.transmit()) {
                        Some(writer) => {
                            if framing != LinkType::Radiotap {
                                return Err(unsupported(
                                    "transmit PHY",
                                    "bare Dot11 framing cannot express requested PHY settings",
                                ));
                            }
                            Some(Box::new(MonitorWriter::new(writer).with_radiotap(
                                radiotap_override.unwrap_or_else(|| config.radiotap()),
                            )) as OpenedPacketWriter)
                        }
                        None => None,
                    };
                (source, writer, InterfaceMode::MonitorWifi, false)
            }
            #[cfg(feature = "radio")]
            WifiBackend::RadioAdapters {
                source,
                sink,
                bounds,
            } => {
                let (source, writer) = radio_adapters(source, sink, bounds, &config, &mut control)?;
                (source, writer, InterfaceMode::WifiIq, false)
            }
            #[cfg(not(feature = "radio-hackrf"))]
            WifiBackend::HackRf => {
                return Err(unsupported("HackRF", "enable the radio-hackrf feature"))
            }
            #[cfg(feature = "radio-hackrf")]
            WifiBackend::HackRf { rx, tx } => {
                if rx.rx.center_frequency_hz != config.center_frequency_hz
                    || tx.center_frequency_hz != config.center_frequency_hz
                {
                    return Err(invalid(
                        "HackRF RX/TX frequency differs from interface request",
                    ));
                }
                if rx.rx.sample_rate_hz != 20_000_000 || tx.sample_rate_hz != 20_000_000 {
                    return Err(unsupported(
                        "sample rate",
                        "Wi-Fi IQ interface requires 20 Msps",
                    ));
                }
                let duplex = crate::radio::HackRfDuplex::open(rx, tx).map_err(radio_error)?;
                return Self::wifi(WifiBackend::HackRfOpened { duplex }, config);
            }
            #[cfg(feature = "radio-hackrf")]
            WifiBackend::HackRfOpened { duplex } => {
                let (rx, tx) = duplex.configuration();
                if rx.rx.center_frequency_hz != config.center_frequency_hz
                    || tx.center_frequency_hz != config.center_frequency_hz
                {
                    return Err(invalid(
                        "HackRF RX/TX frequency differs from interface request",
                    ));
                }
                if tx.sample_rate_hz != 20_000_000 {
                    return Err(unsupported(
                        "sample rate",
                        "Wi-Fi IQ interface requires 20 Msps",
                    ));
                }
                let bounds = rx.rx;
                let (source, sink, native_control) = duplex.split();
                control.native = Some(native_control.clone());
                control.cancel_backend = Some(Arc::new(move || native_control.cancel()));
                let (source, writer) = radio_adapters(
                    Some(Box::new(source)),
                    Some(Box::new(sink)),
                    bounds,
                    &config,
                    &mut control,
                )?;
                (source, writer, InterfaceMode::WifiIq, true)
            }
        };
        if config.directions.receive() && source.is_none() {
            return Err(unsupported(
                "read",
                "selected backend has no receive source",
            ));
        }
        if config.directions.transmit() && writer.is_none() {
            return Err(unsupported(
                "write",
                "selected backend has no transmit sink",
            ));
        }
        let descriptor = WifiInterfaceDescriptor {
            mode,
            packet_format: PacketFormat::Dot11,
            requested: config.clone(),
            observed_frequency_hz: None,
            observed_width_mhz: None,
            half_duplex,
        };
        Ok(Self {
            target: PacketWireTarget::Wifi { mode },
            source: if config.directions.receive() {
                source.map(|inner| {
                    Box::new(ControlledSource {
                        inner,
                        control: control.clone(),
                        handles_cancellation: mode == InterfaceMode::WifiIq,
                    }) as OpenedPacketSource
                })
            } else {
                None
            },
            writer: if config.directions.transmit() {
                writer.map(|inner| {
                    Box::new(ControlledWriter {
                        inner,
                        control: control.clone(),
                    }) as OpenedPacketWriter
                })
            } else {
                None
            },
            wifi_descriptor: Some(descriptor),
            wifi_control: Some(control),
            interface_mode: Some(mode),
        })
    }
    pub fn wifi_descriptor(&self) -> Option<&WifiInterfaceDescriptor> {
        self.wifi_descriptor.as_ref()
    }
    pub fn wifi_control(&self) -> Option<WifiInterfaceControl> {
        self.wifi_control.clone()
    }
}

fn unsupported(operation: &'static str, reason: &'static str) -> WireError {
    WireError::unsupported_capability(operation, Some("wifi"), reason)
}
fn invalid(reason: &'static str) -> WireError {
    crate::CrafterError::invalid_field_value("wifi.interface", reason).into()
}
#[cfg(feature = "radio")]
fn radio_error(error: crate::radio::RadioError) -> WireError {
    match error {
        crate::radio::RadioError::Invalid { field, reason } => {
            crate::CrafterError::invalid_field_value(field, reason).into()
        }
        error => WireError::backend("radio", "open", error.to_string()),
    }
}

#[cfg(feature = "radio")]
struct SampleSource {
    inner: Arc<Mutex<Box<dyn crate::radio::IqSource + Send>>>,
    control: WifiInterfaceControl,
}
#[cfg(feature = "radio")]
impl crate::radio::IqSource for SampleSource {
    fn next_event(&mut self) -> crate::radio::RadioResult<crate::radio::IqEvent> {
        let mut source = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if self.control.status().cancelled {
            source.cancel_with_result()?;
            return Ok(crate::radio::IqEvent::End(
                crate::radio::StreamEnd::Cancelled,
            ));
        }
        let result = source.next_event();
        if self.control.status().cancelled {
            let shutdown = source.cancel_with_result();
            if let Err(error) = result {
                return Err(error);
            }
            shutdown?;
            return Ok(crate::radio::IqEvent::End(
                crate::radio::StreamEnd::Cancelled,
            ));
        }
        result
    }
    fn cancel(&mut self) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel();
    }
    fn cancel_with_result(&mut self) -> crate::radio::RadioResult<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel_with_result()
    }
}
#[cfg(feature = "radio")]
struct SampleSink {
    inner: Box<dyn crate::radio::IqSink<crate::radio::OwnedSamples> + Send>,
    control: WifiInterfaceControl,
}
#[cfg(feature = "radio")]
struct DecodedSource {
    inner: crate::radio::RadioPacketSource<SampleSource, crate::radio::WifiDecoder>,
    control: WifiInterfaceControl,
}
#[cfg(feature = "radio")]
impl PacketSource for DecodedSource {
    fn next_record(&mut self) -> Result<Option<PacketRecord>> {
        let result = if self.control.status().cancelled {
            self.inner
                .cancel_with_result()
                .map(|()| None)
                .map_err(|error| WireError::backend("radio", "cancel", error.to_string()))
        } else {
            self.inner.next_record()
        };
        let mut state = self.control.state.lock().unwrap_or_else(|e| e.into_inner());
        state.radio_end = self.inner.end();
        let a = self.inner.decoder().ofdm_stats();
        let b = self.inner.decoder().dsss_stats();
        state.decoder_stats = Some(crate::radio::DecoderStats {
            valid_frames: a.valid_frames.saturating_add(b.valid_frames),
            invalid_fcs: a.invalid_fcs.saturating_add(b.invalid_fcs),
            rejected_frames: a.rejected_frames.saturating_add(b.rejected_frames),
            truncated_frames: a.truncated_frames.saturating_add(b.truncated_frames),
            dropped_frames: a.dropped_frames.saturating_add(b.dropped_frames),
        });
        result
    }
}
#[cfg(feature = "radio")]
impl crate::radio::IqSink<crate::radio::OwnedSamples> for SampleSink {
    fn write(&mut self, samples: &crate::radio::OwnedSamples) -> crate::radio::RadioResult<()> {
        if self.control.status().cancelled {
            return Err(crate::radio::RadioError::Source(
                "interface cancelled".into(),
            ));
        }
        self.inner.write(samples)
    }
    fn write_outcome(
        &mut self,
        samples: &crate::radio::OwnedSamples,
    ) -> crate::radio::RadioResult<crate::radio::IqSinkOutcome> {
        if self.control.status().cancelled {
            return Err(crate::radio::RadioError::Source(
                "interface cancelled".into(),
            ));
        }
        self.inner.write_outcome(samples)
    }
}

#[cfg(feature = "radio")]
fn default_encoder(phy: WifiPhy) -> crate::radio::RadioResult<crate::radio::WifiPacketEncoder> {
    use crate::radio::*;
    Ok(match phy {
        WifiPhy::Ofdm { rate_mbps } => {
            let rate = LegacyOfdmRate::ALL
                .into_iter()
                .find(|r| r.mbps() == rate_mbps)
                .expect("validated rate");
            WifiPacketEncoder::Legacy(LegacyWifiTxConfig::ofdm(rate))
        }
        WifiPhy::DsssCck {
            rate_500kbps,
            short_preamble,
        } => {
            let rate = match rate_500kbps {
                2 => LegacyDsssCckRate::Mbps1,
                4 => LegacyDsssCckRate::Mbps2,
                11 => LegacyDsssCckRate::Mbps5_5,
                _ => LegacyDsssCckRate::Mbps11,
            };
            WifiPacketEncoder::Legacy(LegacyWifiTxConfig::dsss_cck(
                rate,
                if short_preamble {
                    DsssPreamble::Short
                } else {
                    DsssPreamble::Long
                },
            ))
        }
        WifiPhy::Ht20 {
            mcs,
            short_guard,
            greenfield,
            ldpc,
        } => {
            let mut config = HtTxConfig::new(HtMcs::try_from(mcs)?);
            config.guard_interval = if short_guard {
                HtGuardInterval::Short
            } else {
                HtGuardInterval::Long
            };
            config.format = if greenfield {
                HtFormat::Greenfield
            } else {
                HtFormat::Mixed
            };
            config.coding = if ldpc { HtCoding::Ldpc } else { HtCoding::Bcc };
            WifiPacketEncoder::Ht20(config)
        }
    })
}

#[cfg(feature = "radio")]
fn encoder_phy(encoder: &crate::radio::WifiPacketEncoder) -> WifiPhy {
    use crate::radio::*;
    match encoder {
        WifiPacketEncoder::Legacy(config) => match config.phy {
            LegacyWifiPhy::Ofdm(rate) => WifiPhy::Ofdm {
                rate_mbps: rate.mbps(),
            },
            LegacyWifiPhy::DsssCck { rate, preamble } => WifiPhy::DsssCck {
                rate_500kbps: (rate.bps() / 500_000) as u8,
                short_preamble: preamble.is_short(),
            },
        },
        WifiPacketEncoder::Ht20(config) => WifiPhy::Ht20 {
            mcs: config.mcs.index(),
            short_guard: config.guard_interval == HtGuardInterval::Short,
            greenfield: config.format == HtFormat::Greenfield,
            ldpc: config.coding == HtCoding::Ldpc,
        },
    }
}

#[cfg(feature = "radio")]
fn radio_adapters(
    source: Option<Box<dyn crate::radio::IqSource + Send>>,
    sink: Option<Box<dyn crate::radio::IqSink<crate::radio::OwnedSamples> + Send>>,
    bounds: crate::radio::RxConfig,
    config: &WifiInterfaceConfig,
    control: &mut WifiInterfaceControl,
) -> Result<(Option<OpenedPacketSource>, Option<OpenedPacketWriter>)> {
    use crate::radio::*;
    bounds.validate().map_err(radio_error)?;
    if bounds.center_frequency_hz != config.center_frequency_hz {
        return Err(invalid(
            "sample source frequency differs from interface request",
        ));
    }
    if bounds.sample_rate_hz != 20_000_000 {
        return Err(unsupported(
            "sample rate",
            "Wi-Fi IQ interface requires 20 Msps",
        ));
    }
    let source = source
        .map(|source| {
            let inner = Arc::new(Mutex::new(source));
            let weak = Arc::downgrade(&inner);
            let previous = control.cancel_backend.clone();
            control.cancel_backend = Some(Arc::new(move || {
                if let Some(cancel) = &previous {
                    cancel();
                }
                if let Some(inner) = weak.upgrade() {
                    if let Ok(mut source) = inner.try_lock() {
                        source.cancel();
                    };
                }
            }));
            let source = SampleSource {
                inner,
                control: control.clone(),
            };
            RadioPacketSource::new(source, WifiDecoder::new(), bounds).map(|inner| {
                Box::new(DecodedSource {
                    inner,
                    control: control.clone(),
                }) as OpenedPacketSource
            })
        })
        .transpose()
        .map_err(radio_error)?;
    let encoder = if config.directions.transmit() {
        Some(match &config.radio_encoder {
            Some(encoder) => encoder.clone(),
            None => default_encoder(config.transmit_phy).map_err(radio_error)?,
        })
    } else {
        None
    };
    let writer = sink.filter(|_| config.directions.transmit()).map(|sink| {
        Box::new(RadioPacketWriter::new(
            encoder.expect("transmit encoder constructed above"),
            SampleSink {
                inner: sink,
                control: control.clone(),
            },
        )) as OpenedPacketWriter
    });
    Ok((source, writer))
}
