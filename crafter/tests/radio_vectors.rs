#![cfg(feature = "radio")]

use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

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
fn radio_independent_vector_inventory_and_integrity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/iq");
    let index = fs::read_to_string(root.join("ofdm-index.tsv")).unwrap();
    let rates = [6, 9, 12, 18, 24, 36, 48, 54];
    assert_eq!(crc(b"123456789"), 0xcbf43926);
    assert_eq!(index.lines().skip(1).count(), 13);
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
    assert!(manifest.contains("\"generator_version\": \"1\""));
}
