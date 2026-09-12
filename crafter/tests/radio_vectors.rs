#![cfg(feature = "radio")]

use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[test]
fn radio_sampling_clock_exact_frame_recovery() {
    use crafter::radio::*;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("ofdm-clock-manifest.json")).unwrap()).unwrap();
    let mut failures = Vec::new();
    for fixture in manifest["fixtures"].as_array().unwrap() {
        let name = fixture["name"].as_str().unwrap();
        let bytes = fs::read(root.join(format!("{name}.cs8"))).unwrap();
        for chunk in [127, 65536] {
            let config = RxConfig {
                sample_rate_hz: 20_000_000,
                center_frequency_hz: 2_412_000_000,
                max_chunk_samples: chunk,
                max_buffer_samples: 120_000,
                max_frame_bytes: 4095,
                max_pending_frames: 4,
                max_capture_samples: 200_000,
                max_duration: std::time::Duration::from_secs(1),
            };
            let position = IqPosition {
                epoch: 0,
                sequence: 0,
                sample_index: 0,
                time_anchor: None,
                discontinuity: None,
            };
            let mut source =
                ReaderIqSource::new(std::io::Cursor::new(&bytes), config, position).unwrap();
            let mut decoder = LegacyOfdmDecoder::new();
            let mut frames = Vec::new();
            loop {
                let event = source.next_event().unwrap();
                let end = matches!(event, IqEvent::End(_));
                frames.extend(decoder.consume(event).unwrap().frames);
                if end {
                    break;
                }
            }
            if frames.len() != 1
                || hex(&frames[0].bytes) != fixture["psdu_hex"].as_str().unwrap()
                || frames[0].integrity != FrameIntegrity::ValidFcs
            {
                failures.push(format!("{name} chunk={chunk} frames={}", frames.len()));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Deliberately byte-oriented MAC CRC; fixture generation uses Python zlib.
fn crc(bytes: &[u8]) -> u32 {
    let mut value = !0u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb88320 & (0u32.wrapping_sub(value & 1)));
        }
    }
    !value
}

#[test]
fn radio_sampling_clock_vector_inventory_and_integrity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("ofdm-clock-manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["schema"], "crafter.radio.ofdm-clock/v1");
    assert_eq!(manifest["sample_rate_hz"], 20_000_000);
    assert_eq!(manifest["format"], "cs8");
    let fixtures = manifest["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 48);
    let mut combinations = std::collections::BTreeSet::new();
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let rate = fixture["rate_mbps"].as_u64().unwrap();
        let ppm = fixture["receiver_clock_ppm"].as_i64().unwrap();
        assert!([6, 9, 12, 18, 24, 36, 48, 54].contains(&rate));
        assert!([-20, 0, 20].contains(&ppm));
        assert_eq!(fixture["cfo_hz"], 0);
        let maximum = name.contains("max_length");
        assert!(combinations.insert((rate, ppm, maximum)));
        let iq = fs::read(root.join(format!("{name}.cs8"))).unwrap();
        assert_eq!(
            iq.len() as u64,
            2 * fixture["sample_count"].as_u64().unwrap()
        );
        assert_eq!(
            hex(&Sha256::digest(&iq)),
            fixture["sha256"].as_str().unwrap()
        );
        let encoded = fixture["psdu_hex"].as_str().unwrap();
        assert_eq!(encoded.len() % 2, 0);
        let psdu: Vec<u8> = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(psdu.len() == 4095, maximum);
        let split = psdu.len() - 4;
        assert_eq!(
            crc(&psdu[..split]),
            u32::from_le_bytes(psdu[split..].try_into().unwrap())
        );
        let symbols = (16 + 8 * psdu.len() + 6).div_ceil(rate as usize * 4);
        let origin = fixture["preamble_start"].as_u64().unwrap();
        let ratio = 1.0 + ppm as f64 * 1e-6;
        let expected_end = (origin as f64 + (400 + 80 * symbols) as f64 * ratio).ceil() as u64;
        assert_eq!(fixture["frame_end"], expected_end);
        assert_eq!(
            fixture["sample_count"],
            (origin as f64 + (432 + 80 * symbols) as f64 * ratio).ceil() as u64
        );
    }
    for (field, file) in [
        ("generator_sha256", "ofdm_clock_vectors.py"),
        ("encoder_sha256", "ofdm_vectors.py"),
    ] {
        let source = root
            .join("../../../../tools/oracle/engine/backends")
            .join(file);
        assert_eq!(
            manifest[field].as_str().unwrap(),
            hex(&Sha256::digest(fs::read(source).unwrap()))
        );
    }
}

#[test]
fn radio_independent_vector_inventory_and_integrity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let index = fs::read_to_string(root.join("ofdm-index.tsv")).unwrap();
    let rates = [6, 9, 12, 18, 24, 36, 48, 54];
    assert_eq!(crc(b"123456789"), 0xcbf43926);
    assert_eq!(index.lines().skip(1).count(), 20);
    for (i, line) in index.lines().skip(1).enumerate() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 10);
        let name = fields[0];
        let number = |n: usize| fields[n].parse::<usize>().unwrap();
        let samples = fs::read(root.join(format!("{name}.cs8"))).unwrap();
        assert_eq!(samples.len(), number(5) * 2);
        assert_eq!(hex(&Sha256::digest(&samples)), fields[7]);
        let psdu: Vec<u8> = fields[6]
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let split = psdu.len() - 4;
        let received = u32::from_le_bytes(psdu[split..].try_into().unwrap());
        assert_eq!(crc(&psdu[..split]) == received, fields[8] == "True");
        assert_eq!(number(4), (16 + 8 * psdu.len() + 6).div_ceil(number(3)));
        let full_samples = 37 + 400 + 80 * number(4) + 32;
        assert_eq!(
            number(5),
            full_samples - if name.ends_with("truncated") { 73 } else { 0 }
        );
        if i < 8 {
            assert_eq!(number(1), rates[i]);
            assert_eq!(fields[9], "frame");
            assert_eq!(number(2), [1, 1, 2, 2, 4, 4, 6, 6][i]);
        }
        if i == 0 {
            // Fixed independently generated golden FCS, not calculated from fixture metadata.
            assert_eq!(received, 0x2dc356fb);
        }
        let intermediate = fs::read_to_string(root.join(format!("{name}.json"))).unwrap();
        for key in [
            "signal",
            "signal_coded",
            "signal_interleaved",
            "data",
            "scrambled",
            "coded",
            "punctured",
            "interleaved",
        ] {
            assert!(intermediate.contains(&format!("\"{key}\":")));
        }
    }
    let manifest = fs::read_to_string(root.join("ofdm-manifest.json")).unwrap();
    assert!(manifest.contains("\"sample_rate_hz\": 20000000"));
    assert!(manifest.contains("\"generator_version\": \"6\""));
}
