use super::*;
use crate::radio::eht::{
    sig::iq::{Fields, SignalFields},
    EhtNonOfdmaSignal, EhtNonOfdmaUsers, EhtUsigFields,
};

fn bits(text: &str) -> Vec<u8> {
    text.bytes().map(|value| value - b'0').collect()
}

fn fields() -> Fields {
    let columns: Vec<_> = include_str!("../../../../../tests/fixtures/iq/eht-sig-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .collect();
    let usig = EhtUsigFields::decode(&bits(columns[0])).unwrap();
    let signal = EhtNonOfdmaSignal::decode(&bits(columns[1]), &usig).unwrap();
    Fields {
        usig,
        signal: SignalFields::NonOfdma(signal),
        legacy_length: 300,
        symbols: 1,
        end_sample: 0,
    }
}

fn parameters(
    fields: &mut Fields,
) -> (
    &mut crate::radio::EhtNonOfdmaCommon,
    &mut crate::radio::EhtNonMuUser,
) {
    let SignalFields::NonOfdma(signal) = &mut fields.signal else {
        unreachable!()
    };
    let EhtNonOfdmaUsers::Single(user) = &mut signal.users else {
        unreachable!()
    };
    (&mut signal.common, user)
}

#[test]
fn radio_eht_data_ldpc_independent_layouts() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-data-ldpc-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 4_259);
    let mut coverage = [false; 6];
    for row in rows.lines().skip(1) {
        let values: Vec<usize> = row
            .split('\t')
            .map(|value| value.parse().unwrap())
            .collect();
        let mut fields = fields();
        let (common, user) = parameters(&mut fields);
        user.mcs = values[0] as u8;
        user.ldpc = true;
        common.pre_fec_padding_factor = values[4] as u8;
        common.ldpc_extra_symbol = values[5] != 0;
        let layout = Layout::eht(&fields, values[3] as u16)
            .unwrap_or_else(|error| panic!("{row}: {error:?}"));
        let capacity = Capacity::new(&fields, values[3]).unwrap();
        assert_eq!(
            [
                layout.symbols,
                layout.codewords,
                layout.block_bits,
                layout.shortened_bits,
                layout.punctured_bits,
                layout.repeated_bits,
                usize::from(layout.extra_symbol_group),
                layout.payload_bits,
                layout.transmitted_bits,
            ],
            [
                values[3], values[6], values[7], values[8], values[9], values[10], values[5],
                values[11], values[12],
            ],
            "{row}"
        );
        assert_eq!(layout.coded_bits_per_symbol, capacity.coded_per_symbol);
        assert_eq!(layout.payload_bits, capacity.data_bits);
        assert_eq!(layout.transmitted_bits, capacity.coded_bits);
        let mut totals = [0usize; 5];
        for index in 0..layout.codewords {
            let word = layout.word(index).unwrap();
            for (total, value) in totals.iter_mut().zip([
                word.information_bits,
                word.shortened_bits,
                word.punctured_bits,
                word.repeated_bits,
                word.transmitted_bits,
            ]) {
                *total += value;
            }
        }
        assert_eq!(
            totals,
            [
                layout.payload_bits,
                layout.shortened_bits,
                layout.punctured_bits,
                layout.repeated_bits,
                layout.transmitted_bits,
            ],
            "{row}"
        );
        assert!(layout.word(layout.codewords).is_none());
        coverage[match layout.block_bits {
            648 => 0,
            1296 => 1,
            1944 => 2,
            _ => panic!("{row}: block size"),
        }] = true;
        coverage[3] |= layout.extra_symbol_group;
        coverage[4] |= layout.punctured_bits != 0;
        coverage[5] |= layout.repeated_bits != 0;
    }
    assert!(coverage.into_iter().all(|covered| covered));
}

#[test]
fn radio_eht_data_ldpc_rejects_invalid_signaling() {
    let mut fields = fields();
    parameters(&mut fields).1.ldpc = false;
    assert_eq!(Layout::eht(&fields, 4), Err(rate::Error::EhtTiming));
    parameters(&mut fields).1.ldpc = true;
    parameters(&mut fields).1.mcs = 14;
    assert_eq!(Layout::eht(&fields, 4), Err(rate::Error::EhtTiming));
    parameters(&mut fields).1.mcs = 0;
    for symbols in [0, 401, u16::MAX] {
        assert_eq!(Layout::eht(&fields, symbols), Err(rate::Error::EhtTiming));
    }
}

#[test]
fn radio_eht_data_ldpc_independent_payloads() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-data-ldpc-payload-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 120);
    for row in rows.lines().skip(1) {
        let columns: Vec<_> = row.split('\t').collect();
        let mut fields = fields();
        let (common, user) = parameters(&mut fields);
        user.mcs = columns[0].parse().unwrap();
        user.ldpc = true;
        common.pre_fec_padding_factor = columns[4].parse().unwrap();
        common.ldpc_extra_symbol = columns[5] == "1";
        let symbols: usize = columns[3].parse().unwrap();
        let capacity = Capacity::new(&fields, symbols).unwrap();
        assert_eq!(
            [
                capacity.coded_per_symbol,
                capacity.coded_short,
                capacity.data_per_symbol,
                capacity.coded_last,
                capacity.coded_bits,
                capacity.data_bits,
                capacity.psdu_bytes,
                capacity.phy_pad_bits,
            ],
            std::array::from_fn(|index| columns[11 + index].parse().unwrap()),
            "{row}"
        );
        let metrics: Vec<_> = columns[25]
            .bytes()
            .map(|bit| if bit == b'1' { 1. } else { -1. })
            .collect();
        let expected: Vec<_> = columns[24]
            .as_bytes()
            .chunks_exact(2)
            .map(|octet| u8::from_str_radix(std::str::from_utf8(octet).unwrap(), 16).unwrap())
            .collect();
        let recovered = recover(&fields, capacity, symbols, &metrics, usize::MAX, false)
            .unwrap_or_else(|error| panic!("{row}: {error:?}"));
        assert_eq!(recovered.psdu, expected, "{row}");
        assert_eq!(recovered.failed_codewords, 0, "{row}");
        assert_eq!(recovered.first_failure, None, "{row}");
        assert_eq!(
            recover(
                &fields,
                capacity,
                symbols,
                &metrics,
                expected.len() - 1,
                false,
            )
            .map(|recovered| recovered.psdu),
            Err(Error::FrameLimit),
            "{row}"
        );
    }
}

#[test]
fn radio_eht_data_ldpc_rejects_coding_metrics_and_service() {
    let columns: Vec<_> =
        include_str!("../../../../../tests/fixtures/iq/eht-data-ldpc-payload-index.tsv")
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .collect();
    let mut fields = fields();
    let (common, user) = parameters(&mut fields);
    user.mcs = columns[0].parse().unwrap();
    user.ldpc = true;
    common.pre_fec_padding_factor = columns[4].parse().unwrap();
    common.ldpc_extra_symbol = columns[5] == "1";
    let symbols: usize = columns[3].parse().unwrap();
    let capacity = Capacity::new(&fields, symbols).unwrap();
    let metrics: Vec<_> = columns[25]
        .bytes()
        .map(|bit| if bit == b'1' { 1. } else { -1. })
        .collect();
    for length in [0, metrics.len() - 1, metrics.len() + 1] {
        assert!(matches!(
            recover(
                &fields,
                capacity,
                symbols,
                &vec![1.; length],
                usize::MAX,
                false,
            ),
            Err(Error::Fec)
        ));
    }
    let mut nonfinite = metrics.clone();
    nonfinite[0] = f32::NAN;
    assert!(matches!(
        recover(&fields, capacity, symbols, &nonfinite, usize::MAX, false,),
        Err(Error::Fec)
    ));
    let mut bcc = capacity;
    bcc.ldpc = false;
    assert!(matches!(
        recover(&fields, bcc, symbols, &metrics, usize::MAX, false,),
        Err(Error::Coding)
    ));
}
