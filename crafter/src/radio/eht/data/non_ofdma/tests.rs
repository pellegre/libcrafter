use super::*;
use crate::radio::eht::{
    sig::iq::{Fields, SignalFields},
    training::{Trained, TrainedResource},
    EhtLtfMode, EhtNonOfdmaSignal, EhtNonOfdmaUsers, EhtOfdmaSignal, EhtResourceUnit,
    EhtUsigFields,
};
use crate::radio::ComplexSample;

fn bits(text: &str) -> Vec<u8> {
    text.bytes().map(|value| value - b'0').collect()
}

fn single_user() -> Fields {
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

fn ofdma() -> Fields {
    let columns: Vec<_> = include_str!("../../../../../tests/fixtures/iq/eht-ofdma-sig-index.tsv")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .collect();
    let usig = EhtUsigFields::decode(&bits(columns[0])).unwrap();
    let signal = EhtOfdmaSignal::decode(&bits(columns[1]), &usig).unwrap();
    Fields {
        usig,
        signal: SignalFields::Ofdma(signal),
        legacy_length: 300,
        symbols: 1,
        end_sample: 0,
    }
}

fn common(fields: &mut Fields) -> &mut crate::radio::EhtNonOfdmaCommon {
    let SignalFields::NonOfdma(signal) = &mut fields.signal else {
        unreachable!()
    };
    &mut signal.common
}

fn user(fields: &mut Fields) -> &mut crate::radio::EhtNonMuUser {
    let SignalFields::NonOfdma(signal) = &mut fields.signal else {
        unreachable!()
    };
    let EhtNonOfdmaUsers::Single(user) = &mut signal.users else {
        unreachable!()
    };
    user
}

#[test]
fn radio_eht_data_timing_independent_inventory() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-data-timing-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 18_990);
    for row in rows.lines().skip(1) {
        let values: Vec<usize> = row
            .split('\t')
            .map(|value| value.parse().unwrap())
            .collect();
        let mut fields = single_user();
        fields.legacy_length = values[0];
        fields.symbols = values[1];
        let common = common(&mut fields);
        common.ltf_mode = [
            EhtLtfMode::TwoXGi800,
            EhtLtfMode::TwoXGi1600,
            EhtLtfMode::FourXGi800,
            EhtLtfMode::FourXGi3200,
        ][values[2]];
        common.ltf_symbols = values[5] as u8;
        common.pe_disambiguity = values[6] != 0;
        let timing = Timing::new(&fields).unwrap_or_else(|error| panic!("{row}: {error:?}"));
        assert_eq!(
            [
                timing.data_symbols,
                timing.pe_samples,
                timing.data_start,
                timing.data_end,
                timing.packet_end,
                timing.signaled_end,
            ],
            [values[7], values[8], values[9], values[10], values[11], values[12]],
            "{row}"
        );
        assert_eq!(timing.symbol_samples, 256 + values[4], "{row}");
        for symbol in 0..timing.data_symbols {
            assert_eq!(
                timing.symbol_start(symbol),
                Some(timing.data_start + symbol * timing.symbol_samples),
                "{row}"
            );
        }
        assert_eq!(timing.symbol_start(timing.data_symbols), None, "{row}");
        assert_eq!(timing.symbol_start(usize::MAX), None, "{row}");
    }
}

#[test]
fn radio_eht_data_timing_rejects_invalid_layouts() {
    let mut fields = single_user();
    for length in [1, 2, 4, 4096, usize::MAX] {
        fields.legacy_length = length;
        assert!(matches!(Timing::new(&fields), Err(Error::Length)));
    }
    fields.legacy_length = 3;
    assert!(matches!(Timing::new(&fields), Err(Error::Duration)));
    fields.legacy_length = 4095;
    fields.symbols = usize::MAX;
    assert!(matches!(Timing::new(&fields), Err(Error::Overflow)));
    assert!(matches!(
        Timing::new(&ofdma()),
        Err(Error::UnsupportedFormat)
    ));
}

#[test]
fn radio_eht_data_capacity_independent_inventory() {
    let rows = include_str!("../../../../../tests/fixtures/iq/eht-data-capacity-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 2_269);
    for row in rows.lines().skip(1) {
        let values: Vec<usize> = row
            .split('\t')
            .map(|value| value.parse().unwrap())
            .collect();
        let mut fields = single_user();
        let mcs = values[0] as u8;
        let ldpc = values[1] != 0;
        let extra = values[2] != 0;
        let padding = values[3] as u8;
        user(&mut fields).mcs = mcs;
        user(&mut fields).ldpc = ldpc;
        common(&mut fields).ldpc_extra_symbol = extra;
        common(&mut fields).pre_fec_padding_factor = padding;
        let capacity =
            Capacity::new(&fields, values[4]).unwrap_or_else(|error| panic!("{row}: {error:?}"));
        assert_eq!(
            [
                capacity.bits_per_tone,
                capacity.rate_num,
                capacity.rate_den,
                usize::from(capacity.dcm),
                capacity.coded_per_symbol,
                capacity.coded_short,
                capacity.data_per_symbol,
                capacity.coded_last,
                capacity.coded_bits,
                capacity.data_bits,
                capacity.psdu_bytes,
                capacity.phy_pad_bits,
                capacity.tail_bits,
                usize::from(capacity.bcc_dcm_filler),
            ],
            values[5..19],
            "{row}"
        );
        assert_eq!(capacity.mcs, mcs);
        assert_eq!(capacity.ldpc, ldpc);
        assert_eq!(
            capacity.data_bits,
            16 + 8 * capacity.psdu_bytes + capacity.phy_pad_bits + capacity.tail_bits
        );
    }
}

#[test]
fn radio_eht_data_capacity_rejects_invalid_layouts() {
    let mut fields = single_user();
    user(&mut fields).mcs = 14;
    assert!(matches!(
        Capacity::new(&fields, 4),
        Err(Error::Modulation(14))
    ));
    user(&mut fields).mcs = 10;
    user(&mut fields).ldpc = false;
    assert!(matches!(Capacity::new(&fields, 4), Err(Error::Coding)));
    user(&mut fields).mcs = 0;
    assert!(matches!(Capacity::new(&fields, 0), Err(Error::Duration)));
    user(&mut fields).space_time_streams = 2;
    assert!(matches!(
        Capacity::new(&fields, 4),
        Err(Error::UnsupportedFormat)
    ));
    user(&mut fields).space_time_streams = 1;
    common(&mut fields).pre_fec_padding_factor = 0;
    assert!(matches!(Capacity::new(&fields, 4), Err(Error::Padding)));
    common(&mut fields).pre_fec_padding_factor = 4;
    assert!(matches!(
        Capacity::new(&fields, usize::MAX),
        Err(Error::Overflow)
    ));
    assert!(matches!(
        Capacity::new(&ofdma(), 4),
        Err(Error::UnsupportedFormat)
    ));
}

#[test]
fn radio_eht_data_receiver_admits_bounded_training() {
    let mut fields = single_user();
    fields.end_sample = 357 + 320 + 80 * fields.symbols as u64;
    let timing = Timing::new(&fields).unwrap();
    let guard = usize::from(common(&mut fields).ltf_mode.guard_interval_ns()) / 50;
    let data_start = 37 + timing.data_start as u64;
    let trained = Trained {
        signal: fields.clone(),
        resources: vec![TrainedResource {
            resource: EhtResourceUnit::full_band(1).unwrap(),
            users: 0..1,
            channel: Some([ComplexSample { i: 1., q: 0. }; 256]),
        }],
        data_start,
        guard,
    };
    let admitted = Receiver::admit(trained, usize::MAX, usize::MAX).unwrap();
    assert_eq!(admitted.timing, timing);
    assert_eq!(
        admitted.capacity,
        Capacity::new(&fields, timing.data_symbols).unwrap()
    );
    assert_eq!(admitted.info.data_start, data_start);
    assert_eq!(admitted.info.end_sample_index, 37 + timing.data_end as u64);
    assert_eq!(admitted.required_samples, timing.data_end - 320);
    assert_eq!(admitted.trained.signal, fields);

    let make = |start| Trained {
        signal: fields.clone(),
        resources: vec![TrainedResource {
            resource: EhtResourceUnit::full_band(1).unwrap(),
            users: 0..1,
            channel: Some([ComplexSample { i: 1., q: 0. }; 256]),
        }],
        data_start: start,
        guard,
    };
    assert!(matches!(
        Receiver::admit(
            make(data_start),
            admitted.capacity.psdu_bytes - 1,
            usize::MAX
        ),
        Err(Error::FrameLimit)
    ));
    assert!(matches!(
        Receiver::admit(make(data_start), usize::MAX, admitted.required_samples - 1),
        Err(Error::SampleLimit)
    ));
    assert!(matches!(
        Receiver::admit(make(data_start + 1), usize::MAX, usize::MAX),
        Err(Error::Training)
    ));
}
