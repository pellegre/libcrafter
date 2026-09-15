//! Bounded recording/replay through the public normalized packet interface.
use super::{artifact::*, ArtifactSource, IqWriter};
use crafter::{
    radio::*,
    wire::{PacketRecord, PacketWire, WifiBackend, WifiDirections, WifiInterfaceConfig, WireError},
    LinkType,
};
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Cursor, Write},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

struct Observation {
    out: BufWriter<std::io::Stdout>,
    iq: Option<IqWriter>,
    recorded_terminal: bool,
    terminal: Option<StreamEnd>,
    software_start: Option<u64>,
}
impl Observation {
    fn emit(&mut self, value: &Value) -> RadioResult<()> {
        write_json(&mut self.out, value).map_err(|e| RadioError::Source(e.to_string()))
    }
    fn record(&mut self, value: Value, bytes: Option<Vec<u8>>) -> RadioResult<()> {
        if self.recorded_terminal {
            return Ok(());
        }
        if matches!(value["kind"].as_str(), Some("terminal" | "source_error")) {
            self.recorded_terminal = true;
        }
        if let Some(iq) = &self.iq {
            iq.send(value, bytes)?;
        }
        Ok(())
    }
}
struct Observed {
    source: Box<dyn IqSource + Send>,
    observation: Arc<Mutex<Observation>>,
}
impl IqSource for Observed {
    fn next_event(&mut self) -> RadioResult<IqEvent> {
        let result = self.source.next_event();
        let mut observation = self.observation.lock().unwrap_or_else(|e| e.into_inner());
        match &result {
            Ok(IqEvent::Chunk(chunk)) => {
                let value = json!({"kind":"chunk","config":Config::from(chunk.config()),
                    "position":Position::from(chunk.position()),"samples":chunk.len(),"verified_prefix":true,
                    "software_time_bracket_ns":observation.software_start.map(|start| [start, unix_ns(SystemTime::now())])});
                observation.emit(&value)?;
                observation.record(value, Some(chunk.cs8().iter().map(|&v| v as u8).collect()))?;
            }
            Ok(IqEvent::End(end)) => {
                observation.terminal = Some(*end);
                observation.record(json!({"kind":"terminal","reason":format!("{end:?}")}), None)?;
            }
            Err(error) => observation.record(
                json!({"kind":"source_error","error":error.to_string()}),
                None,
            )?,
        }
        result
    }
    fn cancel(&mut self) {
        let _ = self.cancel_with_result();
    }
    fn cancel_with_result(&mut self) -> RadioResult<()> {
        let stopped = self.source.cancel_with_result();
        let mut observation = self.observation.lock().unwrap_or_else(|e| e.into_inner());
        if observation.terminal.is_none() {
            observation.terminal = Some(StreamEnd::Cancelled);
        }
        let value = match &stopped {
            Ok(()) => json!({"kind":"terminal","reason":"Cancelled"}),
            Err(error) => json!({"kind":"source_error","error":error.to_string()}),
        };
        let recorded = observation.record(value, None);
        stopped.and(recorded)
    }
}
#[cfg(feature = "radio-hackrf")]
struct SharedNative(Arc<Mutex<HackRfSource>>);
#[cfg(feature = "radio-hackrf")]
impl IqSource for SharedNative {
    fn next_event(&mut self) -> RadioResult<IqEvent> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .next_event()
    }
    fn cancel(&mut self) {
        let _ = self.cancel_with_result();
    }
    fn cancel_with_result(&mut self) -> RadioResult<()> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel_with_result()
    }
}

fn frame_value(record: &PacketRecord, ordinal: u64) -> Result<Value> {
    let metadata = record.metadata();
    let radio = metadata.radio().ok_or("IQ record lacks radio provenance")?;
    let frame = RecoveredFrame {
        bytes: metadata
            .captured_bytes()
            .ok_or("IQ record lacks original bytes")?
            .to_vec(),
        link_type: LinkType::Ieee80211,
        integrity: radio.integrity,
        framing: radio.framing,
        config: radio.config.clone(),
        start: radio.start.clone(),
        end_sample_index: radio.end_sample_index,
        rate_bps: radio.rate_bps,
        diagnostics: radio.diagnostics.clone(),
    };
    Ok(
        json!({"kind":"frame","ordinal":ordinal,"original_mac_hex":hex(&frame.bytes),
        "fcs":match frame.integrity {FrameIntegrity::ValidFcs=>"present_valid",FrameIntegrity::InvalidFcs=>"present_invalid",FrameIntegrity::FcsAbsent=>"absent"},
        "phy":frame_phy(&frame),"ht":ht_metadata(&frame),"ampdu":ampdu_metadata(&frame),
        "preamble":frame.diagnostics.iter().find_map(|d| match d {PhyDiagnostic::Dsss{short_preamble,..}=>Some(if *short_preamble {"short"} else {"long"}),_=>None}),
        "rate_bps":frame.rate_bps,"config":Config::from(&frame.config),"position":Position::from(&frame.start),
        "end_sample_index":frame.end_sample_index,"diagnostics":frame.diagnostics.iter().map(|d|format!("{d:?}")).collect::<Vec<_>>() }),
    )
}

pub(super) fn run(arguments: &[String]) -> Result<()> {
    let mut args = arguments.to_vec();
    let iq_path = if args.len() >= 2 && args[args.len() - 2] == "--save-iq" {
        let path = args.pop();
        args.pop();
        path
    } else {
        None
    };
    let mut config = RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_412_000_000,
        max_chunk_samples: 65_536,
        max_buffer_samples: 16_777_216,
        max_frame_bytes: 4095,
        max_pending_frames: 1024,
        max_capture_samples: 20_000_000,
        max_duration: Duration::from_secs(1),
    };
    while let Some(flag) = args.first().map(String::as_str) {
        match flag {
            "--modern" => {
                args.remove(0);
            }
            "--buffer-samples" | "--chunk-samples" => {
                let count: usize = args.get(1).ok_or("missing sample bound")?.parse()?;
                if flag == "--buffer-samples" {
                    if !(65_536..=MAX_EXAMPLE_BUFFER_SAMPLES).contains(&count) {
                        return Err("invalid example buffer bound".into());
                    }
                    config.max_buffer_samples = count;
                } else {
                    if !(128..=262_144).contains(&count) {
                        return Err("invalid example chunk bound".into());
                    }
                    config.max_chunk_samples = count;
                }
                args.drain(..2);
            }
            _ => break,
        }
    }
    config.validate()?;
    let position = IqPosition {
        epoch: 0,
        sequence: 0,
        sample_index: 0,
        time_anchor: None,
        discontinuity: None,
    };
    #[cfg(feature = "radio-hackrf")]
    let mut live: Option<Arc<Mutex<HackRfSource>>> = None;
    #[cfg(feature = "radio-hackrf")]
    let mut settings_value: Option<Value> = None;
    #[allow(unused_mut)]
    let mut software_start = None;
    let source: Box<dyn IqSource + Send> = match args.as_slice() {
        [] => Box::new(ReaderIqSource::new(Cursor::new(include_bytes!("../../tests/fixtures/iq/ofdm-6-clean.cs8")), config.clone(), position)?),
        [flag, path] if flag == "--replay" => Box::new(ReaderIqSource::new(File::open(path)?, config.clone(), position)?),
        [flag, path, hz, seconds, samples] if flag == "--replay" => {
            config.center_frequency_hz = hz.parse()?;
            config.max_duration = Duration::from_secs(seconds.parse()?);
            config.max_capture_samples = samples.parse()?;
            Box::new(ReaderIqSource::new(File::open(path)?, config.clone(), position)?)
        }
        [flag, path] if flag == "--replay-artifact" => {
            let source = ArtifactSource::open(path)?;
            config = source.config.clone();
            Box::new(source)
        }
        [flag, serial, hz, seconds, samples, filter, lna, vga, amp, bias] if flag == "--live" => {
            #[cfg(feature = "radio-hackrf")]
            {
                config.center_frequency_hz = hz.parse()?;
                config.max_duration = Duration::from_secs(seconds.parse()?);
                config.max_capture_samples = samples.parse()?;
                let settings = HackRfConfig {
                    rx:config.clone(), serial:serial.clone(), baseband_filter_hz:filter.parse()?,
                    lna_gain_db:lna.parse()?, vga_gain_db:vga.parse()?, amplifier_enabled:amp.parse()?, antenna_power_enabled:bias.parse()?,
                };
                settings_value = Some(json!({"baseband_filter_hz":settings.baseband_filter_hz,"lna_gain_db":settings.lna_gain_db,
                    "vga_gain_db":settings.vga_gain_db,"amplifier_enabled":settings.amplifier_enabled,"antenna_power_enabled":settings.antenna_power_enabled}));
                software_start = Some(unix_ns(SystemTime::now()));
                let source = Arc::new(Mutex::new(HackRfSource::open_live(settings)?));
                live = Some(Arc::clone(&source));
                Box::new(SharedNative(source))
            }
            #[cfg(not(feature = "radio-hackrf"))]
            { let _ = (serial,hz,seconds,samples,filter,lna,vga,amp,bias); return Err("live reception requires radio-hackrf".into()); }
        }
        _ => return Err("use --interface [--modern] [--buffer-samples N] [--chunk-samples N] [--replay FILE [HZ SECONDS MAX_SAMPLES] | --replay-artifact FILE | --live SERIAL HZ SECONDS MAX_SAMPLES FILTER_HZ LNA_DB VGA_DB AMP_BOOL BIAS_BOOL] [--save-iq NEW_FILE]".into()),
    };
    let header = json!({"kind":"header","schema":SCHEMA,"config":Config::from(&config),"decoder":"wifi",
        "dispatch":"serial","packet_interface":true,"time_basis":if software_start.is_some(){"software_bracket_only"}else{"recorded_anchor_or_unknown"}});
    let iq = iq_path
        .as_deref()
        .map(|path| -> Result<IqWriter> {
            let file = OpenOptions::new().write(true).create_new(true).open(path)?;
            let mut header = header.clone();
            header["iq_encoding"] = json!("cs8-binary/v1");
            Ok(IqWriter::new(file, header)?)
        })
        .transpose()?;
    let observation = Arc::new(Mutex::new(Observation {
        out: BufWriter::new(std::io::stdout()),
        iq,
        recorded_terminal: false,
        terminal: None,
        software_start,
    }));
    observation
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .emit(&header)?;
    let backend = WifiBackend::RadioAdapters {
        source: Some(Box::new(Observed {
            source,
            observation: Arc::clone(&observation),
        })),
        sink: None,
        bounds: config.clone(),
    };
    let wire = PacketWire::wifi(
        backend,
        WifiInterfaceConfig {
            center_frequency_hz: config.center_frequency_hz,
            channel: None,
            directions: WifiDirections::Receive,
            ..Default::default()
        },
    )?;
    let control = wire.wifi_control().ok_or("missing interface control")?;
    let mut packets = wire.source()?;
    let mut parsed = 0u64;
    let mut parser_errors = 0u64;
    let mut result: Result<()> = loop {
        match packets.next_record() {
            Ok(Some(record)) => {
                let value = frame_value(&record, parsed + 1)?;
                observation
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .emit(&value)?;
                parsed += 1;
            }
            Ok(None) => break Ok(()),
            Err(error) => {
                if matches!(error, WireError::Packet(_)) {
                    parser_errors += 1;
                }
                break Err(error.into());
            }
        }
    };
    if result.is_err() {
        control.cancel();
    }
    drop(packets);
    let state = control.status();
    let stats = state.decoder_stats.ok_or("missing decoder counters")?;
    #[cfg(not(feature = "radio-hackrf"))]
    let acquisition: Option<Value> = None;
    #[cfg(feature = "radio-hackrf")]
    let acquisition = live.map(|source| {
        let mut source = source.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(error) = source.cancel_with_result() {
            let detail = result.as_ref().err().map_or_else(
                || error.to_string(), |previous| format!("{previous}; shutdown: {error}"));
            result = Err(detail.into());
        }
        let stats = source.stats();
        json!({"kind":"acquisition","received_samples":stats.received_samples,"verified_samples":stats.verified_samples,
            "discarded_samples":stats.discarded_samples,"queue_overflows":stats.queue_overflows,"queued_samples":stats.queued_samples,
            "peak_queued_samples":stats.peak_queued_samples,"unknown_loss_intervals":stats.unknown_loss_intervals,
            "counter_queries":stats.counter_queries,"last_gap":stats.last_gap.map(|g|format!("{g:?}")),"settings":settings_value})
    });
    let mut observation = observation.lock().unwrap_or_else(|e| e.into_inner());
    let recording_error = observation.iq.as_mut().and_then(|iq| iq.finish().err());
    if let Some(error) = &recording_error {
        let detail = result.as_ref().err().map_or_else(
            || error.to_string(),
            |previous| format!("{previous}; recording: {error}"),
        );
        result = Err(detail.into());
    }
    let terminal = state.radio_end.or(observation.terminal);
    if let Some(end) = terminal {
        observation.emit(&json!({"kind":"terminal","reason":format!("{end:?}")}))?;
    }
    observation.emit(&json!({"kind":"summary","complete":result.is_ok(),"terminal":terminal.map(|end|format!("{end:?}")),
        "error":result.as_ref().err().map(ToString::to_string),"recording_error":recording_error.map(|e|e.to_string()),
        "emitted_frames":parsed,"parsed_packets":parsed,"parser_failures":parser_errors,
        "decoder":{"valid_frames":stats.valid_frames,"invalid_fcs":stats.invalid_fcs,"rejected_frames":stats.rejected_frames,
            "truncated_frames":stats.truncated_frames,"dropped_frames":stats.dropped_frames}}))?;
    if let Some(acquisition) = acquisition {
        observation.emit(&acquisition)?;
    }
    observation.out.flush()?;
    result
}
