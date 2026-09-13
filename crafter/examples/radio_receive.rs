//! Offline by default; explicit bounded receive-only native mode. See docs/radio.md.
#[path = "radio_support/artifact.rs"]
mod artifact;
use artifact::*;
use crafter::{
    radio::*,
    wire::{PacketSource, WireError},
};
use serde_json::json;
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Cursor, Read, Write},
    rc::Rc,
    sync::mpsc::{sync_channel, SyncSender},
    thread::JoinHandle,
    time::{Duration, SystemTime},
};

type Output = Rc<RefCell<BufWriter<std::io::Stdout>>>;
fn emit(out: &Output, v: serde_json::Value) -> RadioResult<()> {
    write_json(&mut *out.borrow_mut(), &v).map_err(|e| RadioError::Source(e.to_string()))
}
struct IqRecord {
    metadata: serde_json::Value,
    bytes: Option<Vec<u8>>,
}
struct IqWriter {
    sender: Option<SyncSender<IqRecord>>,
    worker: Option<JoinHandle<RadioResult<()>>>,
}
impl IqWriter {
    fn new(file: File, header: serde_json::Value) -> RadioResult<Self> {
        // Each message owns at most one already bounded source chunk.
        let (sender, receiver) = sync_channel::<IqRecord>(8);
        let worker = std::thread::Builder::new()
            .name("crafter-iq-recorder".into())
            .spawn(move || {
                let record = || -> Result<()> {
                    let mut writer = BufWriter::new(file);
                    write_json(&mut writer, &header)?;
                    let mut terminal = false;
                    for record in receiver {
                        if terminal {
                            return Err("IQ record after terminal".into());
                        }
                        terminal = matches!(
                            record.metadata["kind"].as_str(),
                            Some("terminal" | "source_error")
                        );
                        write_json(&mut writer, &record.metadata)?;
                        if let Some(bytes) = record.bytes {
                            writer.write_all(&bytes)?;
                            writer.write_all(b"\n")?;
                        }
                    }
                    if !terminal {
                        write_json(&mut writer, &json!({"kind":"source_error","error":"IQ recorder ended before terminal"}))?;
                    }
                    writer.flush()?;
                    if !terminal {
                        return Err("IQ recorder ended before terminal".into());
                    }
                    Ok(())
                };
                record().map_err(|e| RadioError::Source(e.to_string()))
            })
            .map_err(|e| RadioError::Source(e.to_string()))?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
        })
    }
    fn send(&self, metadata: serde_json::Value, bytes: Option<Vec<u8>>) -> RadioResult<()> {
        self.sender
            .as_ref()
            .ok_or_else(|| RadioError::Source("IQ recorder is closed".into()))?
            .try_send(IqRecord { metadata, bytes })
            .map_err(|e| RadioError::Source(format!("IQ recording queue: {e}")))
    }
    fn finish(&mut self) -> RadioResult<()> {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| RadioError::Source("IQ recorder panicked".into()))??;
        }
        Ok(())
    }
}
impl Drop for IqWriter {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}
struct ObservedSource<'a, S> {
    source: &'a mut S,
    out: Output,
    iq: Option<&'a mut IqWriter>,
    software_start: Option<u64>,
}
impl<S: IqSource> IqSource for ObservedSource<'_, S> {
    fn next_event(&mut self) -> RadioResult<IqEvent> {
        let event = match self.source.next_event() {
            Ok(event) => event,
            Err(error) => {
                if let Some(w) = &mut self.iq {
                    w.send(
                        json!({"kind":"source_error","error":error.to_string()}),
                        None,
                    )?;
                }
                return Err(error);
            }
        };
        let value = match &event {
            IqEvent::Chunk(c) => {
                json!({"kind":"chunk","config":Config::from(c.config()),"position":Position::from(c.position()),"samples":c.len(),"verified_prefix":true,"software_time_bracket_ns":self.software_start.map(|s|[s,unix_ns(SystemTime::now())])})
            }
            IqEvent::End(e) => json!({"kind":"terminal","reason":format!("{e:?}")}),
        };
        // End-of-source may flush frames from a buffered decoder. The observed
        // decoder emits the terminal record after those frames.
        if matches!(event, IqEvent::Chunk(_)) {
            emit(&self.out, value.clone())?;
        }
        if let Some(w) = &mut self.iq {
            let bytes = match &event {
                IqEvent::Chunk(c) => Some(c.cs8().iter().map(|b| *b as u8).collect()),
                IqEvent::End(_) => None,
            };
            w.send(value, bytes)?;
        }
        Ok(event)
    }
    fn cancel(&mut self) {
        self.source.cancel();
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dispatch {
    Serial,
    Parallel,
    ParallelDsss,
    Windowed,
}
impl Dispatch {
    fn label(self) -> &'static str {
        match self {
            Self::Serial => "serial",
            Self::Parallel => "parallel",
            Self::ParallelDsss => "parallel_dsss",
            Self::Windowed => "windowed",
        }
    }
}
enum SelectedDecoder {
    Ofdm(LegacyOfdmDecoder),
    Wifi(LegacyWifiDecoder),
    Modern(WifiDecoder),
    Parallel(ParallelLegacyWifiDecoder),
    ParallelModern(ParallelWifiDecoder),
    Windowed(WindowedLegacyWifiDecoder),
    WindowedModern(WindowedWifiDecoder),
}
impl SelectedDecoder {
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        match self {
            Self::Ofdm(d) => d.consume(event),
            Self::Wifi(d) => d.consume(event),
            Self::Modern(d) => d.consume(event),
            Self::Parallel(d) => d.consume(event),
            Self::ParallelModern(d) => d.consume(event),
            Self::Windowed(d) => d.consume(event),
            Self::WindowedModern(d) => d.consume(event),
        }
    }
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        match self {
            Self::Ofdm(d) => d.reset(reason),
            Self::Wifi(d) => d.reset(reason),
            Self::Modern(d) => d.reset(reason),
            Self::Parallel(d) => d.reset(reason),
            Self::ParallelModern(d) => d.reset(reason),
            Self::Windowed(d) => d.reset(reason),
            Self::WindowedModern(d) => d.reset(reason),
        }
    }
    fn stats(&self) -> DecoderStats {
        let (a, b) = match self {
            Self::Ofdm(d) => return d.stats(),
            Self::Wifi(d) => (d.ofdm_stats(), d.dsss_stats()),
            Self::Modern(d) => (d.ofdm_stats(), d.dsss_stats()),
            Self::Parallel(d) => (d.ofdm_stats(), d.dsss_stats()),
            Self::ParallelModern(d) => (d.ofdm_stats(), d.dsss_stats()),
            Self::Windowed(d) => (d.ofdm_stats(), d.dsss_stats()),
            Self::WindowedModern(d) => (d.ofdm_stats(), d.dsss_stats()),
        };
        DecoderStats {
            valid_frames: a.valid_frames.saturating_add(b.valid_frames),
            invalid_fcs: a.invalid_fcs.saturating_add(b.invalid_fcs),
            rejected_frames: a.rejected_frames.saturating_add(b.rejected_frames),
            truncated_frames: a.truncated_frames.saturating_add(b.truncated_frames),
            dropped_frames: a.dropped_frames.saturating_add(b.dropped_frames),
        }
    }
}
struct ObservedDecoder {
    inner: SelectedDecoder,
    out: Output,
    ordinal: u64,
}
impl PhyDecoder for ObservedDecoder {
    fn consume(&mut self, event: IqEvent) -> RadioResult<DecodeOutput> {
        let terminal = match &event {
            IqEvent::End(end) => Some(*end),
            IqEvent::Chunk(_) => None,
        };
        let diagnostic_epoch = match &event {
            IqEvent::Chunk(chunk)
                if matches!(
                    self.inner,
                    SelectedDecoder::Modern(_)
                        | SelectedDecoder::ParallelModern(_)
                        | SelectedDecoder::WindowedModern(_)
                ) =>
            {
                Some(chunk.position().epoch)
            }
            _ => None,
        };
        let decoded = self.inner.consume(event)?;
        if let Some(epoch) = diagnostic_epoch {
            for diagnostic in &decoded.diagnostics {
                if let Some(value) =
                    ht_signal_record_with_context(diagnostic, epoch, &decoded.diagnostics)
                        .or_else(|| vht_signal_record(diagnostic, epoch))
                        .or_else(|| he_signal_record(diagnostic, epoch))
                {
                    emit(&self.out, value)?;
                }
            }
        }
        for f in &decoded.frames {
            self.ordinal += 1;
            let mut record = json!({"kind":"frame","ordinal":self.ordinal,"original_mac_hex":hex(&f.bytes),"fcs":match f.integrity {FrameIntegrity::ValidFcs=>"present_valid",FrameIntegrity::InvalidFcs=>"present_invalid",FrameIntegrity::FcsAbsent=>"absent"},"phy":frame_phy(f),"ht":ht_metadata(f),"ampdu":ampdu_metadata(f),"preamble":f.diagnostics.iter().find_map(|d| match d { PhyDiagnostic::Dsss { short_preamble, .. } => Some(if *short_preamble { "short" } else { "long" }), _ => None }),"rate_bps":f.rate_bps,"config":Config::from(&f.config),"position":Position::from(&f.start),"end_sample_index":f.end_sample_index,"diagnostics":f.diagnostics.iter().map(|d|format!("{d:?}")).collect::<Vec<_>>()});
            // Do not add a null field to every existing legacy/HT artifact.
            if let Some(metadata) = vht_metadata(f) {
                record["vht"] = metadata;
            }
            if let Some(metadata) = he_metadata(f) {
                record["he"] = metadata;
            }
            emit(&self.out, record)?;
        }
        if let Some(end) = terminal {
            emit(
                &self.out,
                json!({"kind":"terminal","reason":format!("{end:?}")}),
            )?;
        }
        Ok(decoded)
    }
    fn reset(&mut self, reason: ResetReason) -> DecodeOutput {
        self.inner.reset(reason)
    }
}
fn he_signal_record(diagnostic: &PhyDiagnostic, epoch: u64) -> Option<serde_json::Value> {
    if let PhyDiagnostic::HeTbSignal {
        fields,
        preamble_sample_index,
    } = diagnostic
    {
        return Some(json!({"kind":"he_signal", "phy":"he", "epoch":epoch,
            "preamble_sample_index":preamble_sample_index,
            "mac_integrity":"not_established_by_header",
            "he":he_tb_signal_metadata(fields,*preamble_sample_index)}));
    }
    if let PhyDiagnostic::HeMuSigB {
        fields,
        preamble_sample_index,
    } = diagnostic
    {
        return Some(json!({"kind":"he_sig_b","phy":"he","epoch":epoch,
            "preamble_sample_index":preamble_sample_index,"mac_integrity":"not_established_by_header",
            "he":he_sig_b_metadata(fields,*preamble_sample_index)}));
    }
    if let PhyDiagnostic::HeMuSignal {
        fields,
        preamble_sample_index,
    } = diagnostic
    {
        return Some(json!({"kind":"he_signal", "phy":"he", "epoch":epoch,
            "preamble_sample_index":preamble_sample_index,
            "mac_integrity":"not_established_by_header",
            "he":he_mu_signal_metadata(fields, *preamble_sample_index)}));
    }
    if let PhyDiagnostic::HeErSignal {
        fields,
        preamble_sample_index,
    } = diagnostic
    {
        let metadata = he_er_signal_metadata(fields, *preamble_sample_index);
        return Some(
            json!({"kind":"he_signal","phy":"he","epoch":epoch,"preamble_sample_index":preamble_sample_index,"he":metadata}),
        );
    }
    let PhyDiagnostic::HeSignal {
        fields,
        preamble_sample_index,
    } = diagnostic
    else {
        return None;
    };
    Some(
        json!({"kind":"he_signal", "phy":"he", "epoch":epoch, "preamble_sample_index":preamble_sample_index,
        "he":he_signal_metadata(fields,*preamble_sample_index)}),
    )
}

#[cfg(test)]
#[test]
fn radio_he_sig_b_artifact_metadata() {
    for (name, users, errors, symbols) in [
        ("he-sigb-iq-m0-d1-a191-u0-i0-none-e0", 17, 0, 36),
        ("he-sigb-iq-m0-d0-a0-u0-i1-user-crc-e0", 9, 2, 10),
        ("he-sigb-iq-m5-d0-a-1-u8-i1-none-e0", 8, 0, 1),
    ] {
        let bytes = std::fs::read(format!(
            "{}/tests/fixtures/iq/{name}.cs8",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 10000,
            max_buffer_samples: 120000,
            max_frame_bytes: 4095,
            max_pending_frames: 4,
            max_capture_samples: 100000,
            max_duration: Duration::from_secs(1),
        };
        let chunk = IqChunk::new(
            config,
            IqPosition {
                epoch: 7,
                sequence: 0,
                sample_index: 0,
                time_anchor: None,
                discontinuity: None,
            },
            bytes.iter().map(|b| *b as i8).collect(),
        )
        .unwrap();
        let out = WifiDecoder::new().consume(IqEvent::Chunk(chunk)).unwrap();
        assert!(out.frames.is_empty());
        let records: Vec<_> = out
            .diagnostics
            .iter()
            .filter_map(|d| he_signal_record(d, 7))
            .filter(|r| r["kind"] == "he_sig_b")
            .collect();
        assert_eq!(records.len(), 1, "{name}");
        let record = &records[0];
        assert_eq!(record["epoch"], 7);
        assert_eq!(record["preamble_sample_index"], 37);
        assert_eq!(record["mac_integrity"], "not_established_by_header");
        assert_eq!(record["he"]["sig_b_symbols"], symbols);
        assert_eq!(record["he"]["sig_b_end_sample_index"], bytes.len() / 2);
        let results = record["he"]["users"].as_array().unwrap();
        assert_eq!(results.len(), users);
        assert_eq!(
            results.iter().filter(|r| r["status"] == "error").count(),
            errors
        );
        for (i, r) in results.iter().enumerate().skip(errors) {
            assert_eq!(r["sta_id"], 37 + i);
            assert_eq!(r["mcs"], i % 12);
        }
        assert!(record["he"].get("mcs").is_none());
    }
}
fn vht_signal_record(diagnostic: &PhyDiagnostic, epoch: u64) -> Option<serde_json::Value> {
    let PhyDiagnostic::VhtSignalA {
        fields: f,
        preamble_sample_index,
    } = diagnostic
    else {
        return None;
    };
    let users = match f.users {
        VhtSignalAUsers::Single {
            space_time_streams,
            partial_aid,
            mcs,
            ldpc,
            beamformed,
        } => {
            json!({"mode":"su", "space_time_streams":space_time_streams, "partial_aid":partial_aid, "mcs":mcs, "ldpc":ldpc, "beamformed":beamformed})
        }
        VhtSignalAUsers::Multi {
            space_time_streams,
            ldpc,
        } => json!({"mode":"mu", "space_time_streams":space_time_streams, "ldpc":ldpc}),
    };
    Some(json!({
        "kind":"vht_signal_a", "epoch":epoch,
        "preamble_sample_index":preamble_sample_index,
        "signal_a":{
            "bandwidth_code":f.bandwidth_code, "group_id":f.group_id, "stbc":f.stbc,
            "short_guard_interval":f.short_guard_interval, "short_gi_disambiguation":f.short_gi_disambiguation,
            "ldpc_extra_symbol":f.ldpc_extra_symbol, "txop_ps_not_allowed":f.txop_ps_not_allowed,
            "users":users,
        },
        "mac_integrity":"not_established_by_header",
    }))
}
fn ht_signal_record(diagnostic: &PhyDiagnostic, epoch: u64) -> Option<serde_json::Value> {
    match diagnostic {
        PhyDiagnostic::HtSignal {
            fields,
            preamble_sample_index,
        } => Some(json!({
            "kind":"ht_signal", "epoch":epoch,
            "preamble_sample_index":preamble_sample_index,
            "ht":ht_signal_metadata(fields,*preamble_sample_index),
            "mac_integrity":"not_established_by_header",
        })),
        _ => None,
    }
}
fn ht_signal_record_with_context(
    diagnostic: &PhyDiagnostic,
    epoch: u64,
    context: &[PhyDiagnostic],
) -> Option<serde_json::Value> {
    let mut value = ht_signal_record(diagnostic, epoch)?;
    if let PhyDiagnostic::HtSignal {
        preamble_sample_index,
        ..
    } = diagnostic
    {
        if context.iter().any(|d| matches!(d,
            PhyDiagnostic::HtGreenfield { preamble_sample_index: index } if index == preamble_sample_index)) {
            value["ht"]["format"] = "greenfield".into();
        }
    }
    Some(value)
}
fn receive(
    source: &mut impl IqSource,
    config: RxConfig,
    iq_path: Option<&str>,
    software_start: Option<u64>,
    ofdm_only: bool,
    dispatch: Dispatch,
    modern: bool,
) -> Result<()> {
    if modern && ofdm_only {
        return Err("Wi-Fi 4 decoding includes OFDM and DSSS/CCK".into());
    }
    let out = Rc::new(RefCell::new(BufWriter::new(std::io::stdout())));
    let header = json!({"kind":"header","schema":SCHEMA,"config":Config::from(&config),"decoder":if modern {"wifi"} else if ofdm_only {"ofdm"} else {"legacy_wifi"},"dispatch":dispatch.label(),"time_basis":if software_start.is_some(){"software_bracket_only"}else{"recorded_anchor_or_unknown"}});
    emit(&out, header.clone())?;
    let mut iq = if let Some(path) = iq_path {
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let mut iq_header = header.clone();
        iq_header["iq_encoding"] = json!("cs8-binary/v1");
        Some(IqWriter::new(file, iq_header)?)
    } else {
        None
    };
    let observed = ObservedSource {
        source,
        out: out.clone(),
        iq: iq.as_mut(),
        software_start,
    };
    let decoder = ObservedDecoder {
        inner: if modern && dispatch == Dispatch::ParallelDsss {
            SelectedDecoder::ParallelModern(ParallelWifiDecoder::with_parallel_dsss()?)
        } else if modern && dispatch == Dispatch::Parallel {
            SelectedDecoder::ParallelModern(ParallelWifiDecoder::new()?)
        } else if modern && dispatch == Dispatch::Windowed {
            SelectedDecoder::WindowedModern(WindowedWifiDecoder::new(4)?)
        } else if modern {
            SelectedDecoder::Modern(WifiDecoder::new())
        } else if dispatch == Dispatch::Windowed {
            SelectedDecoder::Windowed(WindowedLegacyWifiDecoder::new(4)?)
        } else if dispatch == Dispatch::ParallelDsss {
            SelectedDecoder::Parallel(ParallelLegacyWifiDecoder::with_parallel_dsss()?)
        } else if dispatch == Dispatch::Parallel {
            SelectedDecoder::Parallel(ParallelLegacyWifiDecoder::new()?)
        } else if ofdm_only {
            SelectedDecoder::Ofdm(LegacyOfdmDecoder::new())
        } else {
            SelectedDecoder::Wifi(LegacyWifiDecoder::new())
        },
        out: out.clone(),
        ordinal: 0,
    };
    let mut packets = RadioPacketSource::new(observed, decoder, config)?;
    let mut parsed = 0u64;
    let mut parser_errors = 0u64;
    let mut result: Result<()> = loop {
        match packets.next_record() {
            Ok(Some(_)) => parsed += 1,
            Ok(None) => break Ok(()),
            Err(WireError::Packet(e)) => {
                parser_errors += 1;
                emit(
                    &out,
                    json!({"kind":"parser_error","error":format!("{e:?}")}),
                )?;
            }
            Err(e) => break Err(e.into()),
        }
    };
    let s = packets.decoder().inner.stats();
    let emitted_frames = packets.decoder().ordinal;
    let terminal = packets.end().map(|e| format!("{e:?}"));
    drop(packets);
    let recording_error = iq.as_mut().and_then(|w| w.finish().err());
    if result.is_ok() {
        if let Some(error) = &recording_error {
            result = Err(error.clone().into());
        }
    }
    emit(
        &out,
        json!({"kind":"summary","complete":result.is_ok(),"terminal":terminal,"error":result.as_ref().err().map(ToString::to_string),"recording_error":recording_error.map(|e|e.to_string()),"emitted_frames":emitted_frames,"parsed_packets":parsed,"parser_failures":parser_errors,"decoder":{"valid_frames":s.valid_frames,"invalid_fcs":s.invalid_fcs,"rejected_frames":s.rejected_frames,"truncated_frames":s.truncated_frames,"dropped_frames":s.dropped_frames}}),
    )?;
    out.borrow_mut().flush()?;
    result
}
struct ArtifactSource {
    reader: BufReader<File>,
    config: RxConfig,
    samples: u64,
    end: Option<StreamEnd>,
    binary: bool,
    ofdm_only: bool,
    dispatch: Dispatch,
    modern: bool,
}
impl ArtifactSource {
    fn open(path: &str) -> Result<Self> {
        let mut reader = BufReader::new(File::open(path)?);
        let h = read_json(&mut reader)?.ok_or("missing IQ header")?;
        if !supported_schema(&h["schema"]) || h["kind"] != "header" {
            return Err("unsupported IQ schema".into());
        }
        let ofdm_only = if h["schema"] == "crafter.radio.receive/v1" {
            true
        } else {
            match h["decoder"].as_str() {
                Some("ofdm") => true,
                Some("legacy_wifi" | "wifi") => false,
                _ => return Err("missing or unsupported IQ decoder".into()),
            }
        };
        let modern = h["schema"] != "crafter.radio.receive/v1" && h["decoder"] == "wifi";
        let dispatch = match h.get("dispatch").and_then(serde_json::Value::as_str) {
            None if h.get("dispatch").is_none() => Dispatch::Serial,
            Some("serial") => Dispatch::Serial,
            Some("parallel") if !ofdm_only => Dispatch::Parallel,
            Some("parallel_dsss") if !ofdm_only => Dispatch::ParallelDsss,
            Some("windowed") if !ofdm_only => Dispatch::Windowed,
            _ => return Err("unsupported or conflicting IQ dispatch".into()),
        };
        let config: Config = serde_json::from_value(h["config"].clone())?;
        let binary = match h.get("iq_encoding") {
            None => false,
            Some(v) if v == "cs8-binary/v1" => true,
            _ => return Err("unsupported IQ encoding".into()),
        };
        Ok(Self {
            reader,
            config: config.rx()?,
            samples: 0,
            end: None,
            binary,
            ofdm_only,
            dispatch,
            modern,
        })
    }
}
impl IqSource for ArtifactSource {
    fn next_event(&mut self) -> RadioResult<IqEvent> {
        if let Some(e) = self.end {
            return Ok(IqEvent::End(e));
        }
        let mut read = || -> Result<IqEvent> {
            let v = read_json(&mut self.reader)?.ok_or("IQ artifact lacks terminal evidence")?;
            match v["kind"].as_str() {
                Some("source_error") => {
                    let message = v["error"].as_str().ok_or("missing source error")?;
                    if read_json(&mut self.reader)?.is_some() {
                        return Err("trailing IQ records after source error".into());
                    }
                    Err(format!("recorded IQ source error: {message}").into())
                }
                Some("terminal") => {
                    let e = match v["reason"].as_str() {
                        Some("Eof") => StreamEnd::Eof,
                        Some("LimitReached") => StreamEnd::LimitReached,
                        Some("Cancelled") => StreamEnd::Cancelled,
                        _ => return Err("invalid terminal".into()),
                    };
                    if read_json(&mut self.reader)?.is_some() {
                        return Err("trailing IQ records after terminal".into());
                    }
                    self.end = Some(e);
                    Ok(IqEvent::End(e))
                }
                Some("chunk") => {
                    if v["verified_prefix"] != true {
                        return Err("unverified IQ prefix".into());
                    }
                    let c: Config = serde_json::from_value(v["config"].clone())?;
                    let c = c.rx()?;
                    let p: Position = serde_json::from_value(v["position"].clone())?;
                    let bytes = if self.binary {
                        let count = v["samples"].as_u64().ok_or("missing sample count")?;
                        if count == 0 || count > c.max_chunk_samples as u64 {
                            return Err("binary IQ chunk bound exceeded".into());
                        }
                        let mut bytes = vec![0u8; count as usize * 2];
                        self.reader.read_exact(&mut bytes)?;
                        let mut separator = [0u8];
                        self.reader.read_exact(&mut separator)?;
                        if separator != *b"\n" {
                            return Err("invalid binary IQ separator".into());
                        }
                        bytes
                    } else {
                        unhex(v["cs8_hex"].as_str().ok_or("missing samples")?)?
                    };
                    let n = bytes.len() / 2;
                    if v["samples"].as_u64() != Some(n as u64) {
                        return Err("sample length mismatch".into());
                    }
                    self.samples = self
                        .samples
                        .checked_add(n as u64)
                        .ok_or("sample overflow")?;
                    let duration_bound = (self.config.max_duration.as_nanos()
                        * self.config.sample_rate_hz as u128)
                        / 1_000_000_000;
                    if self.samples > self.config.max_capture_samples
                        || self.samples as u128 > duration_bound
                        || c != self.config
                    {
                        return Err("IQ replay bounds/configuration mismatch".into());
                    }
                    Ok(IqEvent::Chunk(IqChunk::new(
                        c,
                        p.iq()?,
                        bytes.into_iter().map(|b| b as i8).collect(),
                    )?))
                }
                _ => Err("unexpected IQ event".into()),
            }
        };
        read().map_err(|e| RadioError::Source(e.to_string()))
    }
    fn cancel(&mut self) {
        self.end = Some(StreamEnd::Cancelled)
    }
}
#[path = "radio_support/benchmark.rs"]
mod benchmark;

/// Drain a bounded source without DSP, recording, or per-chunk output.
#[cfg(feature = "radio-hackrf")]
fn capture_only(source: &mut impl IqSource) -> Result<()> {
    let start = std::time::Instant::now();
    let mut samples = 0u64;
    let mut chunks = 0u64;
    let mut terminal = None;
    let result: Result<()> = loop {
        match source.next_event() {
            Ok(IqEvent::Chunk(chunk)) => {
                samples += chunk.len() as u64;
                chunks += 1;
            }
            Ok(IqEvent::End(end)) => {
                terminal = Some(format!("{end:?}"));
                break if end == StreamEnd::Cancelled {
                    Err("capture-only source was cancelled".into())
                } else {
                    Ok(())
                };
            }
            Err(error) => break Err(error.into()),
        }
    };
    println!(
        "{}",
        json!({
            "kind": "capture_only", "complete": result.is_ok(),
            "consumed_samples": samples, "chunks": chunks,
            "drain_wall_seconds": start.elapsed().as_secs_f64(),
            "terminal": terminal, "error": result.as_ref().err().map(ToString::to_string),
        })
    );
    result
}

fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--benchmark-artifact") {
        return match args.as_slice() {
            [_, path, mode] => benchmark::run(path, mode, None),
            [_, path, mode, frames] => benchmark::run(path, mode, Some(frames)),
            _ => Err("use --benchmark-artifact FILE wifi|wifi-parallel|wifi-parallel-dsss|wifi-windowed-3|wifi-windowed-4|combined|parallel|parallel-dsss|windowed-3|windowed-4|ofdm|dsss [FRAMES_JSONL]".into()),
        };
    }
    let capture_only_mode = if args.first().map(String::as_str) == Some("--capture-only") {
        args.remove(0);
        true
    } else {
        false
    };
    let dispatch = match args.first().map(String::as_str) {
        Some("--parallel") => {
            args.remove(0);
            Dispatch::Parallel
        }
        Some("--parallel-dsss") => {
            args.remove(0);
            Dispatch::ParallelDsss
        }
        Some("--parallel-windows") => {
            args.remove(0);
            Dispatch::Windowed
        }
        _ => Dispatch::Serial,
    };
    let modern = if args.first().map(String::as_str) == Some("--modern") {
        args.remove(0);
        true
    } else {
        false
    };
    let ofdm_only = if args.first().map(String::as_str) == Some("--ofdm-only") {
        args.remove(0);
        true
    } else {
        false
    };
    if dispatch != Dispatch::Serial && ofdm_only {
        return Err("parallel dispatch and --ofdm-only are mutually exclusive".into());
    }
    if modern && ofdm_only {
        return Err("--modern and --ofdm-only are mutually exclusive".into());
    }
    let iq_path = if args.len() >= 2 && args[args.len() - 2] == "--save-iq" {
        let path = args.pop();
        args.pop();
        path
    } else {
        None
    };
    let buffer_samples = if args.first().map(String::as_str) == Some("--buffer-samples") {
        if args.len() < 2 {
            return Err("--buffer-samples requires a sample count".into());
        }
        let count: usize = args[1].parse()?;
        if !(65_536..=MAX_EXAMPLE_BUFFER_SAMPLES).contains(&count) {
            return Err(format!(
                "example buffer must contain 65536..{MAX_EXAMPLE_BUFFER_SAMPLES} complex samples"
            )
            .into());
        }
        args.drain(..2);
        if args.first().map(String::as_str) == Some("--replay-artifact") {
            return Err("saved IQ artifacts supply their own buffer configuration".into());
        }
        count
    } else {
        16_777_216
    };
    let chunk_samples = if args.first().map(String::as_str) == Some("--chunk-samples") {
        if args.len() < 2 {
            return Err("--chunk-samples requires a sample count".into());
        }
        let count: usize = args[1].parse()?;
        if !(128..=262_144).contains(&count) || count > buffer_samples {
            return Err(
                "example chunk must contain 128..262144 complex samples and fit the buffer".into(),
            );
        }
        args.drain(..2);
        if args.first().map(String::as_str) == Some("--replay-artifact") {
            return Err("saved IQ artifacts supply their own chunk configuration".into());
        }
        count
    } else {
        65_536
    };
    if capture_only_mode
        && (args.first().map(String::as_str) != Some("--live")
            || iq_path.is_some()
            || ofdm_only
            || modern
            || dispatch != Dispatch::Serial)
    {
        return Err(
            "--capture-only requires --live and cannot record IQ or select a decoder".into(),
        );
    }
    let config = RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_412_000_000,
        max_chunk_samples: chunk_samples,
        max_buffer_samples: buffer_samples,
        max_frame_bytes: if modern { 16383 } else { 4095 },
        // Coarse window workers can finish together at stream end, so their
        // bounded aggregate needs more room than a serial decoder response.
        max_pending_frames: if modern {
            1024
        } else if dispatch == Dispatch::Windowed {
            256
        } else {
            64
        },
        max_capture_samples: 20_000_000,
        max_duration: Duration::from_secs(1),
    };
    let position = IqPosition {
        epoch: 0,
        sequence: 0,
        sample_index: 0,
        time_anchor: None,
        discontinuity: None,
    };
    if args.first().map(String::as_str) == Some("--live") {
        if args.len() != 10 {
            return Err("expected --live SERIAL HZ SECONDS MAX_SAMPLES FILTER_HZ LNA_DB VGA_DB AMP_BOOL BIAS_BOOL [--save-iq NEW_FILE]".into());
        }
        #[cfg(feature = "radio-hackrf")]
        {
            let mut config = config;
            config.center_frequency_hz = args[2].parse()?;
            config.max_duration = Duration::from_secs(args[3].parse()?);
            config.max_capture_samples = args[4].parse()?;
            let settings = HackRfConfig {
                rx: config.clone(),
                serial: args[1].clone(),
                baseband_filter_hz: args[5].parse()?,
                lna_gain_db: args[6].parse()?,
                vga_gain_db: args[7].parse()?,
                amplifier_enabled: args[8].parse()?,
                antenna_power_enabled: args[9].parse()?,
            };
            let start = unix_ns(SystemTime::now());
            let mut source = HackRfSource::open_live(settings)?;
            let result = if capture_only_mode {
                capture_only(&mut source)
            } else {
                receive(
                    &mut source,
                    config,
                    iq_path.as_deref(),
                    Some(start),
                    ofdm_only,
                    dispatch,
                    modern,
                )
            };
            let s = source.stats();
            println!(
                "{}",
                json!({"kind":"acquisition","received_samples":s.received_samples,"verified_samples":s.verified_samples,"discarded_samples":s.discarded_samples,"queue_overflows":s.queue_overflows,"queued_samples":s.queued_samples,"peak_queued_samples":s.peak_queued_samples,"unknown_loss_intervals":s.unknown_loss_intervals,"counter_queries":s.counter_queries,"last_gap":s.last_gap.map(|g|format!("{g:?}")),"settings":{"baseband_filter_hz":args[5].parse::<u32>()?,"lna_gain_db":args[6].parse::<u32>()?,"vga_gain_db":args[7].parse::<u32>()?,"amplifier_enabled":args[8].parse::<bool>()?,"antenna_power_enabled":args[9].parse::<bool>()?}})
            );
            return result;
        }
        #[cfg(not(feature = "radio-hackrf"))]
        return Err("live reception requires radio-hackrf".into());
    }
    match args.as_slice() {
        []=>receive(&mut ReaderIqSource::new(Cursor::new(include_bytes!("../tests/fixtures/iq/ofdm-6-clean.cs8")),config.clone(),position)?,config,iq_path.as_deref(),None,ofdm_only,dispatch,modern),
        [flag,path] if flag=="--replay"=>receive(&mut ReaderIqSource::new(File::open(path)?,config.clone(),position)?,config,iq_path.as_deref(),None,ofdm_only,dispatch,modern),
        [flag,path,hz,seconds,samples] if flag=="--replay"=>{let mut c=config;c.center_frequency_hz=hz.parse()?;c.max_duration=Duration::from_secs(seconds.parse()?);c.max_capture_samples=samples.parse()?;receive(&mut ReaderIqSource::new(File::open(path)?,c.clone(),position)?,c,iq_path.as_deref(),None,ofdm_only,dispatch,modern)},
        [flag,path] if flag=="--replay-artifact"=>{
            let mut s=ArtifactSource::open(path)?;
            let c=s.config.clone();
            let (selected_ofdm, selected_dispatch, selected_modern) = replay_selection(s.ofdm_only, s.dispatch, s.modern, ofdm_only, dispatch, modern)?;
            receive(&mut s,c,iq_path.as_deref(),None,selected_ofdm,selected_dispatch,selected_modern)
        },
        _=>Err("use no arguments, --replay FILE [HZ SECONDS MAX_SAMPLES], --replay-artifact FILE, or --live parameters; optional final --save-iq NEW_FILE".into()),
    }
}

fn replay_selection(
    recorded_ofdm: bool,
    recorded_dispatch: Dispatch,
    recorded_modern: bool,
    ofdm: bool,
    dispatch: Dispatch,
    modern: bool,
) -> Result<(bool, Dispatch, bool)> {
    if modern && (ofdm || dispatch != Dispatch::Serial) {
        return Err("modern decoding requires serial combined dispatch".into());
    }
    if modern {
        return Ok((false, Dispatch::Serial, true));
    }
    if ofdm {
        return Ok((true, Dispatch::Serial, false));
    }
    if dispatch != Dispatch::Serial {
        if recorded_modern {
            return Err("recorded modern decoding cannot use legacy parallel dispatch".into());
        }
        return Ok((false, dispatch, false));
    }
    Ok((recorded_ofdm, recorded_dispatch, recorded_modern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn radio_iq_large_queue_preserves_artifact_allocation_guards() {
        let mut config = Config {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 65_536,
            max_buffer_samples: 400_000_000,
            max_frame_bytes: 4095,
            max_pending_frames: 64,
            max_capture_samples: 400_000_000,
            max_duration_ns: 20_000_000_000,
        };
        assert!(config.rx().is_ok());
        config.max_buffer_samples = MAX_EXAMPLE_BUFFER_SAMPLES + 1;
        assert!(config.rx().is_err());
        config.max_buffer_samples = 400_000_000;
        config.max_chunk_samples = 262_145;
        assert!(config.rx().is_err());
        config.max_chunk_samples = 65_536;
        config.max_pending_frames = 1025;
        assert!(config.rx().is_err());
    }

    #[test]
    fn radio_iq_recording_queue_is_bounded() {
        let (sender, _receiver) = sync_channel(8);
        let writer = IqWriter {
            sender: Some(sender),
            worker: None,
        };
        for _ in 0..8 {
            writer
                .send(json!({"kind":"chunk"}), Some(vec![0, 1]))
                .unwrap();
        }
        assert!(writer.send(json!({"kind":"terminal"}), None).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn radio_iq_recording_flush_failure_is_reported() {
        let file = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let mut writer = IqWriter::new(file, json!({"kind":"header"})).unwrap();
        writer
            .send(json!({"kind":"terminal","reason":"Eof"}), None)
            .unwrap();
        assert!(writer.finish().is_err());
    }

    #[test]
    fn radio_iq_v2_requires_known_decoder() {
        let path = std::env::temp_dir().join(format!(
            "crafter-iq-decoder-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for decoder in [serde_json::Value::Null, json!("future_wifi"), json!(42)] {
            let header = json!({"kind":"header", "schema":SCHEMA, "decoder":decoder});
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            write_json(&mut file, &header).unwrap();
            drop(file);
            let error = ArtifactSource::open(path.to_str().unwrap()).err().unwrap();
            assert_eq!(error.to_string(), "missing or unsupported IQ decoder");
            std::fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn radio_iq_dispatch_is_validated_and_preserved() {
        let path = std::env::temp_dir().join(format!(
            "crafter-iq-dispatch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 128,
            max_buffer_samples: 512,
            max_frame_bytes: 4095,
            max_pending_frames: 64,
            max_capture_samples: 1024,
            max_duration: Duration::from_secs(1),
        };
        for (decoder, dispatch, expected) in [
            ("wifi", None, Some(Dispatch::Serial)),
            ("wifi", Some(json!("serial")), Some(Dispatch::Serial)),
            ("wifi", Some(json!("parallel")), Some(Dispatch::Parallel)),
            (
                "wifi",
                Some(json!("parallel_dsss")),
                Some(Dispatch::ParallelDsss),
            ),
            ("wifi", Some(json!("windowed")), Some(Dispatch::Windowed)),
            ("legacy_wifi", None, Some(Dispatch::Serial)),
            ("legacy_wifi", Some(json!("serial")), Some(Dispatch::Serial)),
            (
                "legacy_wifi",
                Some(json!("parallel")),
                Some(Dispatch::Parallel),
            ),
            (
                "legacy_wifi",
                Some(json!("parallel_dsss")),
                Some(Dispatch::ParallelDsss),
            ),
            (
                "legacy_wifi",
                Some(json!("windowed")),
                Some(Dispatch::Windowed),
            ),
            ("ofdm", Some(json!("parallel_dsss")), None),
            ("ofdm", Some(json!("windowed")), None),
            ("ofdm", Some(json!("parallel")), None),
            ("legacy_wifi", Some(json!("future")), None),
            ("legacy_wifi", Some(json!(null)), None),
        ] {
            let mut header = json!({"kind":"header", "schema":SCHEMA, "decoder":decoder, "config":Config::from(&config)});
            if let Some(dispatch) = dispatch {
                header["dispatch"] = dispatch;
            }
            std::fs::write(&path, format!("{header}\n")).unwrap();
            let actual = ArtifactSource::open(path.to_str().unwrap());
            match expected {
                Some(expected) => {
                    let actual = actual.unwrap();
                    assert_eq!(actual.dispatch, expected);
                    assert_eq!(actual.modern, decoder == "wifi");
                }
                None => assert!(actual.is_err()),
            }
            std::fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn radio_he_frame_artifact_metadata() {
        let bytes = include_bytes!("../tests/fixtures/iq/he-ampdu-iq-mcs9-ltf4-gi3200-single.cs8");
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 10_000,
            max_buffer_samples: 120_000,
            max_frame_bytes: 4095,
            max_pending_frames: 4,
            max_capture_samples: 100_000,
            max_duration: Duration::from_secs(1),
        };
        let chunk = IqChunk::new(
            config,
            IqPosition {
                epoch: 7,
                sequence: 0,
                sample_index: 0,
                time_anchor: None,
                discontinuity: None,
            },
            bytes.iter().map(|b| *b as i8).collect(),
        )
        .unwrap();
        let out = WifiDecoder::new().consume(IqEvent::Chunk(chunk)).unwrap();
        assert_eq!(out.frames.len(), 1);
        let frame = &out.frames[0];
        assert_eq!(frame_phy(frame), "he");
        let metadata = he_metadata(frame).unwrap();
        assert_eq!(metadata["mcs"], 9);
        assert_eq!(metadata["guard_interval_ns"], 3200);
        assert_eq!(metadata["coding"], "bcc");
        assert_eq!(metadata["ltf_size"], 4);
        assert!(ht_metadata(frame).is_none());
        assert!(vht_metadata(frame).is_none());
        assert!(out
            .diagnostics
            .iter()
            .any(|d| he_signal_record(d, 7)
                .is_some_and(|v| v["epoch"] == 7 && v["kind"] == "he_signal")));
    }

    #[test]
    fn radio_he_mu_frame_artifact_metadata() {
        for (bytes, stbc) in [
            (
                include_bytes!("../tests/fixtures/iq/he-mu-ampdu-a0-m4-l1-d0-clean.cs8").as_slice(),
                false,
            ),
            (
                include_bytes!(
                    "../tests/fixtures/iq/he-mu-stbc-a0-m4-l1-ltf4-g16-n2-p0-c0-flat.cs8"
                )
                .as_slice(),
                true,
            ),
        ] {
            let config = RxConfig {
                sample_rate_hz: 20_000_000,
                center_frequency_hz: 2_412_000_000,
                max_chunk_samples: 120000,
                max_buffer_samples: 120000,
                max_frame_bytes: 4095,
                max_pending_frames: 32,
                max_capture_samples: 120000,
                max_duration: Duration::from_secs(1),
            };
            let chunk = IqChunk::new(
                config,
                IqPosition {
                    epoch: 7,
                    sequence: 0,
                    sample_index: 0,
                    time_anchor: None,
                    discontinuity: None,
                },
                bytes.iter().map(|b| *b as i8).collect(),
            )
            .unwrap();
            let out = WifiDecoder::new().consume(IqEvent::Chunk(chunk)).unwrap();
            assert_eq!(out.frames.len(), 18);
            for (n, frame) in out.frames.iter().enumerate() {
                assert_eq!(frame_phy(frame), "he");
                let metadata = he_metadata(frame).unwrap();
                assert_eq!(metadata["format"], "mu");
                assert_eq!(metadata["user_index"], n / 2);
                assert_eq!(metadata["user"]["sta_id"], 37 + n / 2);
                assert_eq!(metadata["user"]["mcs"], 4);
                assert_eq!(metadata["user"]["coding"], "ldpc");
                assert_eq!(metadata["stbc"], stbc);
                assert_eq!(
                    metadata["user"]["space_time_streams"],
                    if stbc { 2 } else { 1 }
                );
                assert!(ampdu_metadata(frame).is_some());
            }
        }
    }

    #[test]
    fn radio_he_tb_header_artifact_metadata() {
        for row in include_str!("../tests/fixtures/iq/he-tb-prefix-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
            let fields = HeTbSignalFields::decode(&bits).unwrap();
            let config = RxConfig {
                sample_rate_hz: 20_000_000,
                center_frequency_hz: 2_412_000_000,
                max_chunk_samples: 1000,
                max_buffer_samples: 1024,
                max_frame_bytes: 4095,
                max_pending_frames: 4,
                max_capture_samples: 1000,
                max_duration: Duration::from_secs(1),
            };
            let chunk = IqChunk::new(
                config,
                IqPosition {
                    epoch: 7,
                    sequence: 0,
                    sample_index: 0,
                    time_anchor: None,
                    discontinuity: None,
                },
                bytes.iter().map(|b| *b as i8).collect(),
            )
            .unwrap();
            let out = WifiDecoder::new().consume(IqEvent::Chunk(chunk)).unwrap();
            assert!(out.frames.is_empty());
            let headers: Vec<_> = out
                .diagnostics
                .iter()
                .filter_map(|d| he_signal_record(d, 7))
                .collect();
            assert_eq!(headers.len(), 1, "{}", c[0]);
            assert_eq!(headers[0]["he"], he_tb_signal_metadata(&fields, 37));
            assert_eq!(headers[0]["epoch"], 7);
            assert_eq!(headers[0]["mac_integrity"], "not_established_by_header");
            for absent in ["mcs", "coding", "ru_tones", "ltf_size", "stbc"] {
                assert!(headers[0]["he"].get(absent).is_none());
            }
        }
    }

    #[test]
    fn radio_he_tb_frame_artifact_metadata() {
        let bytes = include_bytes!("../tests/fixtures/iq/he-tb-exchange-004-clean.cs8");
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: bytes.len() / 2,
            max_buffer_samples: 120_000,
            max_frame_bytes: 4095,
            max_pending_frames: 64,
            max_capture_samples: bytes.len() as u64 / 2,
            max_duration: Duration::from_secs(1),
        };
        let chunk = IqChunk::new(
            config,
            IqPosition {
                epoch: 7,
                sequence: 0,
                sample_index: 0,
                time_anchor: None,
                discontinuity: None,
            },
            bytes.iter().map(|b| *b as i8).collect(),
        )
        .unwrap();
        let out = WifiDecoder::new().consume(IqEvent::Chunk(chunk)).unwrap();
        assert_eq!(out.frames.len(), 3);
        assert_eq!(frame_phy(&out.frames[0]), "legacy_ofdm");
        assert!(he_metadata(&out.frames[0]).is_none());
        for frame in &out.frames[1..] {
            assert_eq!(frame_phy(frame), "he");
            assert_eq!(frame.integrity, FrameIntegrity::ValidFcs);
            let metadata = he_metadata(frame).unwrap();
            assert_eq!(metadata["format"], "tb");
            assert_eq!(metadata["mcs"], 4);
            assert_eq!(metadata["coding"], "bcc");
            assert_eq!(metadata["stbc"], false);
            assert_eq!(metadata["ru_allocation"], 0);
            assert_eq!(metadata["aid12"], 1);
            assert_eq!(metadata["trigger_preamble_sample_index"], 64);
            assert_eq!(metadata["preamble_sample_index"], frame.start.sample_index);
            let (common, user) = frame
                .diagnostics
                .iter()
                .find_map(|d| match d {
                    PhyDiagnostic::HeTbUser { common, user, .. } => Some((common, user)),
                    _ => None,
                })
                .unwrap();
            assert_eq!(metadata["trigger_common_bits"], common.bits());
            assert_eq!(metadata["effective_user_bits"], user.bits());
        }
    }

    #[test]
    fn radio_he_mu_header_artifact_metadata() {
        for row in include_str!("../tests/fixtures/iq/he-mu-prefix-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
            let fields = HeMuSignalFields::decode(&bits).unwrap();
            let config = RxConfig {
                sample_rate_hz: 20_000_000,
                center_frequency_hz: 2_412_000_000,
                max_chunk_samples: 1000,
                max_buffer_samples: 1024,
                max_frame_bytes: 4095,
                max_pending_frames: 4,
                max_capture_samples: 1000,
                max_duration: Duration::from_secs(1),
            };
            let chunk = IqChunk::new(
                config,
                IqPosition {
                    epoch: 7,
                    sequence: 0,
                    sample_index: 0,
                    time_anchor: None,
                    discontinuity: None,
                },
                bytes.iter().map(|b| *b as i8).collect(),
            )
            .unwrap();
            let out = WifiDecoder::new().consume(IqEvent::Chunk(chunk)).unwrap();
            assert!(out.frames.is_empty());
            let headers: Vec<_> = out
                .diagnostics
                .iter()
                .filter_map(|d| he_signal_record(d, 7))
                .collect();
            assert_eq!(headers.len(), 1, "{}", c[0]);
            let header = &headers[0];
            assert_eq!(header["kind"], "he_signal");
            assert_eq!(header["epoch"], 7);
            assert_eq!(header["preamble_sample_index"], 37);
            assert_eq!(header["mac_integrity"], "not_established_by_header");
            assert_eq!(header["he"], he_mu_signal_metadata(&fields, 37));
            assert_eq!(header["he"]["format"], "mu");
            assert_eq!(
                header["he"]["sig_b_symbols_or_users_raw"],
                fields.sig_b_symbols_or_users
            );
            assert!(header["he"].get("mcs").is_none());
            assert!(header["he"].get("coding").is_none());
        }
    }

    #[test]
    fn radio_he_er_header_artifact_metadata() {
        for row in include_str!("../tests/fixtures/iq/he-er-prefix-index.tsv")
            .lines()
            .skip(1)
        {
            let c: Vec<_> = row.split('\t').collect();
            let bits: Vec<_> = c[1].bytes().map(|v| v - b'0').collect();
            let fields = HeSuSignalFields::decode_er(&bits).unwrap();
            let d = PhyDiagnostic::HeErSignal {
                fields,
                preamble_sample_index: 37,
            };
            let header = he_signal_record(&d, 7).unwrap();
            assert_eq!(header["kind"], "he_signal");
            assert_eq!(header["phy"], "he");
            assert_eq!(header["epoch"], 7);
            assert_eq!(header["he"]["format"], "er_su");
            assert_eq!(header["he"]["channel_width_mhz"], 20);
            assert_eq!(
                header["he"]["ru_tones"],
                if fields.bandwidth == 0 { 242 } else { 106 }
            );
            assert_eq!(header["he"]["mcs"], fields.mcs);
            assert_eq!(header["he"]["stbc"], fields.stbc);
            assert_eq!(header["he"]["dcm"], fields.dcm);
        }
    }

    #[test]
    fn radio_he_er_frame_artifact_metadata() {
        for row in include_str!("../tests/fixtures/iq/he-er-iq-index.tsv")
            .lines()
            .skip(1)
            .chain(
                include_str!("../tests/fixtures/iq/he-er106-iq-index.tsv")
                    .lines()
                    .skip(1),
            )
            .filter(|r| {
                let name = r.split('\t').next().unwrap();
                name.contains("-mcs0-") && name.ends_with("-ltf4-gi3200-pad3")
            })
        {
            let c: Vec<_> = row.split('\t').collect();
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/iq/{}.cs8",
                env!("CARGO_MANIFEST_DIR"),
                c[0]
            ))
            .unwrap();
            let config = RxConfig {
                sample_rate_hz: 20_000_000,
                center_frequency_hz: 2_412_000_000,
                max_chunk_samples: 100_000,
                max_buffer_samples: 120_000,
                max_frame_bytes: 4095,
                max_pending_frames: 4,
                max_capture_samples: 100_000,
                max_duration: Duration::from_secs(1),
            };
            let chunk = IqChunk::new(
                config,
                IqPosition {
                    epoch: 7,
                    sequence: 0,
                    sample_index: 0,
                    time_anchor: None,
                    discontinuity: None,
                },
                bytes.iter().map(|v| *v as i8).collect(),
            )
            .unwrap();
            let out = WifiDecoder::new().consume(IqEvent::Chunk(chunk)).unwrap();
            assert_eq!(out.frames.len(), 2, "{}", c[0]);
            for frame in &out.frames {
                assert_eq!(frame_phy(frame), "he");
                let metadata = he_metadata(frame).unwrap();
                assert_eq!(metadata["format"], "er_su");
                assert_eq!(
                    metadata["ru_tones"],
                    if c[0].starts_with("he-er106-") {
                        106
                    } else {
                        242
                    }
                );
                assert_eq!(metadata["channel_width_mhz"], 20);
                assert_eq!(metadata["mcs"], 0);
                assert_eq!(metadata["coding"], if c[2] == "1" { "ldpc" } else { "bcc" });
                assert_eq!(metadata["dcm"], c[11] == "1");
                assert_eq!(metadata["stbc"], c[12] == "1");
                assert_eq!(metadata["midamble_period"], 10);
                assert!(ht_metadata(frame).is_none());
                assert!(vht_metadata(frame).is_none());
                assert!(out
                    .diagnostics
                    .iter()
                    .filter_map(|d| he_signal_record(d, 7))
                    .any(|header| header["he"] == metadata));
            }
        }
    }
    #[test]
    fn radio_vht_frame_artifact_metadata() {
        let bytes = include_bytes!("../tests/fixtures/iq/vht-bcc-8-gi400-case0-clean.cs8");
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 5_180_000_000,
            max_chunk_samples: 10_000,
            max_buffer_samples: 120_000,
            max_frame_bytes: 4095,
            max_pending_frames: 4,
            max_capture_samples: 100_000,
            max_duration: Duration::from_secs(1),
        };
        let chunk = IqChunk::new(
            config,
            IqPosition {
                epoch: 7,
                sequence: 0,
                sample_index: 0,
                time_anchor: None,
                discontinuity: None,
            },
            bytes.iter().map(|b| *b as i8).collect(),
        )
        .unwrap();
        let out = WifiDecoder::new().consume(IqEvent::Chunk(chunk)).unwrap();
        assert_eq!(out.frames.len(), 1);
        let frame = &out.frames[0];
        assert_eq!(frame_phy(frame), "vht");
        assert!(ht_metadata(frame).is_none());
        let metadata = vht_metadata(frame).unwrap();
        assert_eq!(metadata["mcs"], 8);
        assert_eq!(metadata["coding"], "bcc");
        assert_eq!(metadata["bandwidth_code"], 0);
        assert_eq!(metadata["space_time_streams"], 1);
        assert_eq!(metadata["guard_interval_ns"], 400);
        assert_eq!(metadata["preamble_sample_index"], 37);
        assert_eq!(metadata["service_crc_verified"], true);
        assert_eq!(ampdu_metadata(frame).unwrap()["control_bits"], 1);
        let headers: Vec<_> = out
            .diagnostics
            .iter()
            .filter_map(|d| vht_signal_record(d, 7))
            .collect();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0]["signal_a"]["users"]["mcs"], 8);
        assert_eq!(headers[0]["mac_integrity"], "not_established_by_header");
        assert_eq!(headers[0]["epoch"], 7);
        let mut absent = frame.clone();
        absent.diagnostics.clear();
        assert!(vht_metadata(&absent).is_none());
    }
    #[test]
    fn radio_iq_modern_replay_selection_preserves_explicit_intent() {
        assert_eq!(
            replay_selection(
                false,
                Dispatch::Parallel,
                false,
                false,
                Dispatch::Serial,
                true
            )
            .unwrap(),
            (false, Dispatch::Serial, true)
        );
        assert_eq!(
            replay_selection(true, Dispatch::Serial, false, false, Dispatch::Serial, true).unwrap(),
            (false, Dispatch::Serial, true)
        );
        assert_eq!(
            replay_selection(
                false,
                Dispatch::Serial,
                true,
                false,
                Dispatch::Serial,
                false
            )
            .unwrap(),
            (false, Dispatch::Serial, true)
        );
        assert_eq!(
            replay_selection(false, Dispatch::Serial, true, true, Dispatch::Serial, false).unwrap(),
            (true, Dispatch::Serial, false)
        );
        assert!(replay_selection(
            false,
            Dispatch::Serial,
            true,
            false,
            Dispatch::Parallel,
            false
        )
        .is_err());
        assert!(
            replay_selection(false, Dispatch::Serial, false, true, Dispatch::Serial, true).is_err()
        );
        assert!(replay_selection(
            false,
            Dispatch::Serial,
            false,
            false,
            Dispatch::Parallel,
            true
        )
        .is_err());
    }

    #[test]
    fn radio_iq_greenfield_metadata_preserves_format() {
        for (bytes, stbc, extension) in [
            (
                include_bytes!("../tests/fixtures/iq/ht-greenfield-7-ldpc-len100-clean.cs8")
                    .as_slice(),
                0,
                0,
            ),
            (
                include_bytes!("../tests/fixtures/iq/ht-stbc-7-ldpc-gf-gi800-len100-clean.cs8")
                    .as_slice(),
                1,
                0,
            ),
            (
                include_bytes!(
                    "../tests/fixtures/iq/ht-extension-7-ldpc-gf-gi800-stbc1-ess2-len100-clean.cs8"
                )
                .as_slice(),
                1,
                2,
            ),
        ] {
            let config = RxConfig {
                sample_rate_hz: 20_000_000,
                center_frequency_hz: 2_412_000_000,
                max_chunk_samples: 10_000,
                max_buffer_samples: 120_000,
                max_frame_bytes: 4095,
                max_pending_frames: 4,
                max_capture_samples: 100_000,
                max_duration: Duration::from_secs(1),
            };
            let chunk = IqChunk::new(
                config,
                IqPosition {
                    epoch: 7,
                    sequence: 0,
                    sample_index: 0,
                    time_anchor: None,
                    discontinuity: None,
                },
                bytes.iter().map(|b| *b as i8).collect(),
            )
            .unwrap();
            let out = WifiDecoder::new().consume(IqEvent::Chunk(chunk)).unwrap();
            assert_eq!(out.frames.len(), 1);
            assert_eq!(ht_metadata(&out.frames[0]).unwrap()["format"], "greenfield");
            assert_eq!(ht_metadata(&out.frames[0]).unwrap()["stbc"], stbc);
            assert_eq!(
                ht_metadata(&out.frames[0]).unwrap()["extension_spatial_streams"],
                extension
            );
            let records: Vec<_> = out
                .diagnostics
                .iter()
                .filter_map(|d| ht_signal_record_with_context(d, 7, &out.diagnostics))
                .collect();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["ht"]["format"], "greenfield");
            assert_eq!(records[0]["ht"]["stbc"], stbc);
            assert_eq!(records[0]["ht"]["extension_spatial_streams"], extension);
            assert_eq!(records[0]["epoch"], 7);
            let signal = out
                .diagnostics
                .iter()
                .find(|d| matches!(d, PhyDiagnostic::HtSignal { .. }))
                .unwrap();
            assert!(ht_signal_record_with_context(
                signal,
                7,
                &[PhyDiagnostic::HtGreenfield {
                    preamble_sample_index: 38
                }]
            )
            .unwrap()["ht"]
                .get("format")
                .is_none());
        }
    }
    #[test]
    fn radio_iq_modern_artifact_recovers_distinct_frames_and_typed_metadata() {
        let bytes = include_bytes!("../tests/fixtures/iq/ht-ampdu-7-gi800-ldpc-duplicate.cs8");
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 10_000,
            max_buffer_samples: 120_000,
            max_frame_bytes: 64,
            max_pending_frames: 4,
            max_capture_samples: 100_000,
            max_duration: Duration::from_secs(1),
        };
        let path = std::env::temp_dir().join(format!(
            "crafter-iq-modern-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        write_json(&mut file, &json!({"kind":"header","schema":SCHEMA,"decoder":"wifi","dispatch":"serial","config":Config::from(&config),"iq_encoding":"cs8-binary/v1"})).unwrap();
        write_json(&mut file, &json!({"kind":"chunk","config":Config::from(&config),"position":{"epoch":0,"sequence":0,"sample_index":0,"anchor":null,"gap_reason":null,"lost_samples":null},"samples":bytes.len()/2,"verified_prefix":true})).unwrap();
        file.write_all(bytes).unwrap();
        file.write_all(b"\n").unwrap();
        write_json(&mut file, &json!({"kind":"terminal","reason":"Eof"})).unwrap();
        drop(file);
        let mut source = ArtifactSource::open(path.to_str().unwrap()).unwrap();
        assert!(source.modern);
        let mut decoder = SelectedDecoder::Modern(WifiDecoder::new());
        let out = decoder.consume(source.next_event().unwrap()).unwrap();
        assert_eq!(out.frames.len(), 2);
        let signals: Vec<_> = out
            .diagnostics
            .iter()
            .filter_map(|d| ht_signal_record(d, 0))
            .collect();
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0]["kind"], "ht_signal");
        assert_eq!(signals[0]["ht"]["mcs"], 7);
        assert_eq!(signals[0]["preamble_sample_index"], 37);
        assert_eq!(signals[0]["mac_integrity"], "not_established_by_header");
        assert!(ht_signal_record(&PhyDiagnostic::InvalidData, 0).is_none());
        assert_eq!(out.frames[0].bytes, out.frames[1].bytes);
        for (frame, offset) in out.frames.iter().zip([0, 60]) {
            assert_eq!(frame_phy(frame), "ht");
            let ht = ht_metadata(frame).unwrap();
            assert_eq!(ht["mcs"], 7);
            assert_eq!(ht["coding"], "ldpc");
            assert_eq!(ht["bandwidth_mhz"], 20);
            assert_eq!(ht["guard_interval_ns"], 800);
            assert_eq!(ht["aggregation"], true);
            assert_eq!(ht["stbc"], 0);
            assert_eq!(ht["preamble_sample_index"], 37);
            assert_eq!(ampdu_metadata(frame).unwrap()["delimiter_offset"], offset);
            let mut legacy = frame.clone();
            legacy.diagnostics.clear();
            legacy.rate_bps = 6_000_000;
            assert_eq!(frame_phy(&legacy), "legacy_ofdm");
            assert!(ht_metadata(&legacy).is_none());
            assert!(ampdu_metadata(&legacy).is_none());
        }
        assert!(matches!(
            source.next_event().unwrap(),
            IqEvent::End(StreamEnd::Eof)
        ));
        assert_eq!(decoder.stats().valid_frames, 2);
        drop(source);
        std::fs::remove_file(path).unwrap();
    }

    fn exercise(binary: bool, body: &[u8], count: u64, succeeds: bool) {
        let config = RxConfig {
            sample_rate_hz: 20_000_000,
            center_frequency_hz: 2_412_000_000,
            max_chunk_samples: 16,
            max_buffer_samples: 384,
            max_frame_bytes: 4095,
            max_pending_frames: 1,
            max_capture_samples: 16,
            max_duration: Duration::from_secs(1),
        };
        let mut header = json!({"kind":"header","schema":if binary {SCHEMA} else {"crafter.radio.receive/v1"},"config":Config::from(&config)});
        if binary {
            header["iq_encoding"] = json!("cs8-binary/v1");
            header["decoder"] = json!("legacy_wifi");
        }
        let mut chunk = json!({"kind":"chunk","config":Config::from(&config),"position":{"epoch":0,"sequence":0,"sample_index":0,"anchor":null,"gap_reason":null,"lost_samples":null},"samples":count,"verified_prefix":true});
        if !binary {
            chunk["cs8_hex"] = json!(hex(body));
        }
        let path = std::env::temp_dir().join(format!(
            "crafter-iq-test-{}-{}-{}",
            std::process::id(),
            unix_ns(SystemTime::now()),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            write_json(&mut file, &header).unwrap();
            write_json(&mut file, &chunk).unwrap();
            if binary {
                file.write_all(body).unwrap();
                file.write_all(b"\n").unwrap();
            }
            write_json(&mut file, &json!({"kind":"terminal","reason":"Eof"})).unwrap();
        }
        let mut source = ArtifactSource::open(path.to_str().unwrap()).unwrap();
        assert_eq!(source.ofdm_only, !binary);
        let event = source.next_event();
        if succeeds {
            let IqEvent::Chunk(chunk) = event.unwrap() else {
                panic!("expected chunk")
            };
            assert_eq!(
                chunk.cs8().iter().map(|v| *v as u8).collect::<Vec<_>>(),
                body
            );
            assert!(matches!(
                source.next_event().unwrap(),
                IqEvent::End(StreamEnd::Eof)
            ));
        } else {
            assert!(event.is_err());
        }
        drop(source);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn radio_iq_binary_and_legacy_preserve_arbitrary_bytes() {
        for binary in [false, true] {
            exercise(binary, &[0, 255, 10, 13, 128, 127, b'{', b'}'], 4, true);
        }
    }

    #[test]
    fn radio_iq_binary_rejects_truncated_and_oversize_blocks() {
        exercise(true, &[1, 2], 4, false);
        exercise(true, &[1, 2], 17, false);
    }
}
