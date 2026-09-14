//! Offline, bounded-memory measurement of source reading and decoder execution.
use super::*;
use sha2::{Digest, Sha256};
use std::time::Instant;

pub(super) fn run(path: &str, mode: &str, frames_path: Option<&str>) -> Result<()> {
    use std::io::Write;
    let mut frame_report = frames_path
        .map(|path| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map(std::io::BufWriter::new)
        })
        .transpose()?;
    let mut decoder: Box<dyn PhyDecoder> = match mode {
        "combined" => Box::new(LegacyWifiDecoder::new()),
        "wifi" => Box::new(WifiDecoder::new()),
        "wifi-parallel" => Box::new(ParallelWifiDecoder::new()?),
        "wifi-parallel-dsss" => Box::new(ParallelWifiDecoder::with_parallel_dsss()?),
        "parallel-dsss" => Box::new(ParallelLegacyWifiDecoder::with_parallel_dsss()?),
        "parallel" => Box::new(ParallelLegacyWifiDecoder::new()?),
        "windowed-3" => Box::new(WindowedLegacyWifiDecoder::new(3)?),
        "windowed-4" => Box::new(WindowedLegacyWifiDecoder::new(4)?),
        "ofdm" => Box::new(LegacyOfdmDecoder::new()),
        "dsss" => Box::new(DsssCckDecoder::new()),
        _ => return Err(
            "benchmark mode must be wifi, wifi-parallel, wifi-parallel-dsss, combined, parallel, parallel-dsss, windowed-3, windowed-4, ofdm, or dsss"
                .into(),
        ),
    };
    let mut source = ArtifactSource::open(path)?;
    let mut input_hash = Sha256::new();
    let mut frame_hash = Sha256::new();
    let mut source_time = Duration::ZERO;
    let mut decoder_time = Duration::ZERO;
    let mut verification_time = Duration::ZERO;
    let mut samples = 0u64;
    let mut frames = 0u64;
    let mut diagnostics = 0u64;
    let wall = Instant::now();
    let terminal = loop {
        let start = Instant::now();
        let event = source.next_event()?;
        source_time += start.elapsed();
        let start = Instant::now();
        let end = match &event {
            IqEvent::Chunk(chunk) => {
                samples += chunk.len() as u64;
                // Canonical byte encoding, independent of signed CS8 representation.
                for bytes in chunk.cs8().chunks(4096) {
                    let mut block = [0u8; 4096];
                    for (out, value) in block.iter_mut().zip(bytes) {
                        *out = *value as u8;
                    }
                    input_hash.update(&block[..bytes.len()]);
                }
                None
            }
            IqEvent::End(end) => Some(*end),
        };
        verification_time += start.elapsed();
        let start = Instant::now();
        let output = decoder.consume(event)?;
        decoder_time += start.elapsed();
        let start = Instant::now();
        diagnostics += output.diagnostics.len() as u64;
        for frame in output.frames {
            frames += 1;
            if let Some(report) = &mut frame_report {
                serde_json::to_writer(
                    &mut *report,
                    &json!({
                        "epoch": frame.start.epoch, "start": frame.start.sample_index,
                        "end": frame.end_sample_index, "rate_bps": frame.rate_bps,
                        "integrity": format!("{:?}", frame.integrity), "bytes": frame.bytes,
                        "phy":frame_phy(&frame), "ht":ht_metadata(&frame), "ampdu":ampdu_metadata(&frame),
                    }),
                )?;
                report.write_all(b"\n")?;
            }
            // Length-prefix every variable field; preserve occurrence coordinates.
            frame_hash.update(frame.start.epoch.to_le_bytes());
            frame_hash.update(frame.start.sample_index.to_le_bytes());
            frame_hash.update(frame.end_sample_index.to_le_bytes());
            frame_hash.update(frame.rate_bps.to_le_bytes());
            frame_hash.update((frame.bytes.len() as u64).to_le_bytes());
            frame_hash.update(&frame.bytes);
            // Preserve legacy digest compatibility; HT aggregate occurrences
            // additionally identify their position within the shared PPDU.
            if let Some(metadata) = ampdu_metadata(&frame) {
                frame_hash.update(b"ht-ampdu-offset/v1");
                frame_hash.update(metadata["delimiter_offset"].as_u64().unwrap().to_le_bytes());
            }
        }
        verification_time += start.elapsed();
        if let Some(end) = end {
            break end;
        }
    };
    if let Some(report) = &mut frame_report {
        report.flush()?;
    }
    let elapsed = wall.elapsed();
    println!(
        "{}",
        json!({
            "kind": "offline_benchmark", "mode": mode, "samples": samples,
            "frames": frames, "diagnostics": diagnostics,
            "terminal": format!("{terminal:?}"),
            "source_seconds": source_time.as_secs_f64(),
            "decoder_seconds": decoder_time.as_secs_f64(),
            "verification_seconds": verification_time.as_secs_f64(),
            "wall_seconds": elapsed.as_secs_f64(),
            "decoder_samples_per_second": samples as f64 / decoder_time.as_secs_f64(),
            "iq_bytes_sha256": format!("{:x}", input_hash.finalize()),
            "frame_occurrences_sha256": format!("{:x}", frame_hash.finalize()),
        })
    );
    if terminal == StreamEnd::Cancelled {
        return Err("benchmark source was cancelled".into());
    }
    Ok(())
}
