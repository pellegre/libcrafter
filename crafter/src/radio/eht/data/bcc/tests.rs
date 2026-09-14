use super::*;

fn case(row: &str) -> (Capacity, usize, Vec<f32>, Vec<u8>) {
    let columns: Vec<_> = row.split('\t').collect();
    let numbers: Vec<usize> = columns[..15]
        .iter()
        .map(|value| value.parse().unwrap())
        .collect();
    let capacity = Capacity {
        mcs: numbers[0] as u8,
        bits_per_tone: numbers[4],
        rate_num: numbers[5],
        rate_den: numbers[6],
        dcm: numbers[0] == 15,
        ldpc: false,
        coded_per_symbol: numbers[7],
        coded_short: numbers[8],
        data_per_symbol: numbers[9],
        coded_last: numbers[10],
        coded_bits: numbers[11],
        data_bits: numbers[12],
        psdu_bytes: numbers[13],
        phy_pad_bits: numbers[14],
        tail_bits: 6,
        bcc_dcm_filler: numbers[0] == 15,
    };
    let metrics = columns[17]
        .bytes()
        .map(|bit| if bit == b'1' { 1. } else { -1. })
        .collect();
    let psdu = columns[16]
        .as_bytes()
        .chunks_exact(2)
        .map(|octet| u8::from_str_radix(std::str::from_utf8(octet).unwrap(), 16).unwrap())
        .collect();
    (capacity, numbers[2], metrics, psdu)
}

#[test]
fn radio_eht_data_bcc_independent_payloads() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-data-bcc-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 88);
    for row in rows.lines().skip(1) {
        let (capacity, symbols, metrics, expected) = case(row);
        assert_eq!(
            recover(capacity, symbols, &metrics, usize::MAX),
            Ok(expected.clone()),
            "{row}"
        );
        assert_eq!(
            recover(capacity, symbols, &metrics, expected.len() - 1),
            Err(Error::FrameLimit),
            "{row}"
        );
    }
}

#[test]
fn radio_eht_data_bcc_rejects_coding_metrics_and_service() {
    let row = include_str!("../../../../../tests/fixtures/iq/eht-data-bcc-index.tsv")
        .lines()
        .nth(1)
        .unwrap();
    let (mut capacity, symbols, metrics, _) = case(row);
    for length in [0, metrics.len() - 1, metrics.len() + 1] {
        assert_eq!(
            recover(capacity, symbols, &vec![1.; length], usize::MAX),
            Err(Error::Fec)
        );
    }
    let mut invalid = metrics.clone();
    invalid[0] = f32::NAN;
    assert_eq!(
        recover(capacity, symbols, &invalid, usize::MAX),
        Err(Error::Fec)
    );
    capacity.ldpc = true;
    assert_eq!(
        recover(capacity, symbols, &metrics, usize::MAX),
        Err(Error::Coding)
    );
}
