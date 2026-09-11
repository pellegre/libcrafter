#![cfg(feature = "radio")]

use crafter::radio::{
    IqChunk, IqEvent, IqPosition, LegacyOfdmDecoder, LegacyOfdmRate, LegacyOfdmTransmission,
    LegacyOfdmTxConfig, PhyDecoder, RxConfig,
};
use serde_json::Value;
use std::{fs, path::PathBuf, time::Duration};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq")
}

fn rates() -> [(LegacyOfdmRate, &'static str); 8] {
    [
        (LegacyOfdmRate::Mbps6, "ofdm-tx-6"),
        (LegacyOfdmRate::Mbps9, "ofdm-tx-9"),
        (LegacyOfdmRate::Mbps12, "ofdm-tx-12"),
        (LegacyOfdmRate::Mbps18, "ofdm-tx-18"),
        (LegacyOfdmRate::Mbps24, "ofdm-tx-24"),
        (LegacyOfdmRate::Mbps36, "ofdm-tx-36"),
        (LegacyOfdmRate::Mbps48, "ofdm-tx-48"),
        (LegacyOfdmRate::Mbps54, "ofdm-tx-54"),
    ]
}

fn fixture_cs8(stem: &str) -> Vec<i8> {
    fs::read(fixtures().join(format!("{stem}.cs8")))
        .unwrap()
        .into_iter()
        .map(|byte| byte as i8)
        .collect()
}

fn fixture_psdu(stem: &str) -> Vec<u8> {
    fs::read(fixtures().join(format!("{stem}.psdu"))).unwrap()
}

fn assert_cs8(stem: &str, actual: &[i8]) {
    let expected = fixture_cs8(stem);
    assert_eq!(actual.len(), expected.len(), "{stem} sample byte length");
    let differences: Vec<_> = actual
        .iter()
        .zip(&expected)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .take(20)
        .collect();
    if !differences.is_empty() {
        panic!("{stem} CS8 mismatches: {differences:?}");
    }
}

fn decode(cs8: &[i8], chunk_samples: usize, max_frame_bytes: usize) -> Vec<Vec<u8>> {
    let config = RxConfig {
        sample_rate_hz: 20_000_000,
        center_frequency_hz: 2_412_000_000,
        max_chunk_samples: chunk_samples,
        max_buffer_samples: 400_000,
        max_frame_bytes,
        max_pending_frames: 4,
        max_capture_samples: 1_000_000,
        max_duration: Duration::from_secs(1),
    };
    let mut decoder = LegacyOfdmDecoder::new();
    let mut frames = Vec::new();
    let mut sample_index = 0u64;
    for (sequence, chunk) in cs8.chunks(chunk_samples * 2).enumerate() {
        let event = IqEvent::Chunk(
            IqChunk::new(
                config.clone(),
                IqPosition {
                    epoch: 0,
                    sequence: sequence as u64,
                    sample_index,
                    time_anchor: None,
                    discontinuity: None,
                },
                chunk.to_vec(),
            )
            .unwrap(),
        );
        sample_index += (chunk.len() / 2) as u64;
        frames.extend(
            decoder
                .consume(event)
                .unwrap()
                .frames
                .into_iter()
                .map(|frame| frame.bytes),
        );
    }
    frames
}

#[test]
fn radio_ofdm_tx_matches_all_oracle_vectors_and_round_trips() {
    let manifest: Value =
        serde_json::from_slice(&fs::read(fixtures().join("ofdm-transmit-manifest.json")).unwrap())
            .unwrap();
    let cases = manifest["cases"].as_array().unwrap();
    for (rate, stem) in rates() {
        let psdu = fixture_psdu(stem);
        let tx = LegacyOfdmTransmission::encode(
            &psdu[..psdu.len() - 4],
            None,
            &LegacyOfdmTxConfig::new(rate),
        )
        .unwrap();
        let oracle = cases
            .iter()
            .find(|case| case["artifact_stem"] == stem)
            .unwrap();
        assert_eq!(tx.psdu_bytes, psdu, "{stem} PSDU");
        assert_cs8(stem, &tx.cs8);
        assert_eq!(tx.rate.mbps() as u64, oracle["rate_mbps"].as_u64().unwrap());
        assert_eq!(
            tx.sample_count() as u64,
            oracle["sample_count"].as_u64().unwrap()
        );
        assert_eq!(tx.data_symbols as u64, oracle["nsym"].as_u64().unwrap());
        assert_eq!(
            tx.signal.transmitted.as_slice(),
            oracle["signal_bits"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect::<Vec<_>>()
        );
        for chunk_samples in [1, 17, 257, tx.sample_count()] {
            assert_eq!(
                decode(&tx.cs8, chunk_samples, 4095),
                vec![psdu.clone()],
                "{stem} chunks={chunk_samples}"
            );
        }
    }
}

#[test]
fn radio_ofdm_tx_preserves_explicit_malformed_wire_fields() {
    let canonical = fixture_psdu("ofdm-tx-6");
    let mac = &canonical[..canonical.len() - 4];

    let wrong_fcs = LegacyOfdmTransmission::encode(
        mac,
        Some([0; 4]),
        &LegacyOfdmTxConfig::new(LegacyOfdmRate::Mbps6),
    )
    .unwrap();
    assert_eq!(
        wrong_fcs.psdu_bytes,
        fixture_psdu("ofdm-tx-6-explicit-wrong-fcs")
    );
    assert_cs8("ofdm-tx-6-explicit-wrong-fcs", &wrong_fcs.cs8);
    assert!(decode(&wrong_fcs.cs8, 73, 4095).is_empty());

    let mut config = LegacyOfdmTxConfig::new(LegacyOfdmRate::Mbps6);
    config.signal_override = Some([
        1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    ]);
    let wrong_signal = LegacyOfdmTransmission::encode(mac, None, &config).unwrap();
    assert_cs8("ofdm-tx-6-explicit-wrong-signal", &wrong_signal.cs8);
    assert!(decode(&wrong_signal.cs8, 73, 4095).is_empty());
}

#[test]
fn radio_ofdm_tx_minimum_and_maximum_lengths() {
    for bytes in [0usize, 4091] {
        let mac = vec![0x5a; bytes];
        for rate in LegacyOfdmRate::ALL {
            let tx =
                LegacyOfdmTransmission::encode(&mac, None, &LegacyOfdmTxConfig::new(rate)).unwrap();
            assert_eq!(tx.psdu_bytes.len(), bytes + 4);
            assert_eq!(decode(&tx.cs8, 509, 4095), vec![tx.psdu_bytes.clone()]);
        }
    }
}
