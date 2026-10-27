use super::*;

fn bits(s: &str) -> Vec<u8> {
    s.bytes().map(|b| b - b'0').collect()
}

#[test]
fn independent_signal_a_bits_and_coded_metrics() {
    // Independently encoded IEEE 802.11-2020 Table 21-12 SU vector.
    let raw = bits("001000000000010111100001001100001110010010000000");
    let coded=bits("010011000001100100001100101100111110000011101000111001100111000011100010000000111100101101110000");
    let expected = VhtSignalAFields {
        bandwidth_code: 0,
        group_id: 0,
        stbc: false,
        short_guard_interval: false,
        short_gi_disambiguation: false,
        ldpc_extra_symbol: true,
        txop_ps_not_allowed: false,
        users: VhtSignalAUsers::Single {
            space_time_streams: 1,
            partial_aid: 61,
            mcs: 0,
            ldpc: true,
            beamformed: true,
        },
    };
    assert_eq!(VhtSignalAFields::decode(&raw).unwrap(), expected);
    assert_eq!(expected.encode().as_slice(), raw);
    for scale in [1., f32::MIN_POSITIVE, f32::MAX] {
        let metrics: Vec<_> = coded
            .iter()
            .map(|b| if *b == 1 { scale } else { -scale })
            .collect();
        assert_eq!(
            VhtSignalAFields::decode_interleaved(&metrics).unwrap(),
            expected
        );
    }
    for i in 0..48 {
        let mut damaged = raw.clone();
        damaged[i] ^= 1;
        assert!(VhtSignalAFields::decode(&damaged).is_err(), "bit {i}");
    }
}

#[test]
fn signaling_lengths_metrics_and_service_integrity() {
    for n in 0..48 {
        assert!(VhtSignalAFields::decode(&vec![0; n]).is_err());
    }
    assert_eq!(
        VhtSignalAFields::decode_interleaved(&[0.; 96]),
        Err(VhtSignalError::UnusableMetrics)
    );
    let mut metrics = [1.; 96];
    metrics[17] = f32::NAN;
    assert_eq!(
        VhtSignalAFields::decode_interleaved(&metrics),
        Err(VhtSignalError::NonFiniteMetric { index: 17 })
    );
    for content in [
        VhtSignalB20Content::SingleUser { length_units: 25 },
        VhtSignalB20Content::MultiUser {
            length_units: 100,
            mcs: 9,
        },
        VhtSignalB20Content::Ndp,
    ] {
        let raw = VhtSignalB20Fields::encode(content);
        let fields = VhtSignalB20Fields::decode(
            &raw,
            matches!(content, VhtSignalB20Content::MultiUser { .. }),
        )
        .unwrap();
        assert_eq!(fields.content(), content);
        if let Some(check) = fields.expected_service_crc() {
            let mut service = [0; 16];
            for i in 0..8 {
                service[8 + i] = (check >> (7 - i)) & 1;
            }
            assert!(fields.verify_service(&service).is_ok());
            for i in 0..16 {
                let mut bad = service;
                bad[i] ^= 1;
                assert!(fields.verify_service(&bad).is_err());
            }
        } else {
            assert_eq!(
                fields.verify_service(&[0; 16]),
                Err(VhtSignalError::NoServiceForNdp)
            );
        }
    }
    let fields = VhtSignalB20Fields::decode(
        &VhtSignalB20Fields::encode(VhtSignalB20Content::SingleUser { length_units: 25 }),
        false,
    )
    .unwrap();
    assert_eq!(fields.apep_length_bounds(), Some((97, 100)));
}

#[test]
fn vht20_one_stream_rate_boundaries() {
    assert_eq!(VhtMcs::Mcs0.rate_bps(VhtGuardInterval::Long), 6_500_000);
    assert_eq!(VhtMcs::Mcs8.rate_bps(VhtGuardInterval::Long), 78_000_000);
    assert_eq!(VhtMcs::Mcs8.rate_bps(VhtGuardInterval::Short), 86_666_666);
    for i in 9..=255 {
        assert!(VhtMcs::try_from(i).is_err());
    }
    assert_eq!(VhtTxConfig::new(VhtMcs::Mcs0).coding, VhtCoding::Bcc);
}

#[test]
fn packet_encoder_preserves_mac_and_explicit_wire_overrides() {
    use crate::{
        prelude::*,
        radio::{PacketEncoder, RadioError},
    };
    let packet = Dot11::data() / Raw::from("VHT offline payload");
    let record = PacketRecord::new(packet);
    let mac = record.packet().compile().unwrap();
    for mcs in VhtMcs::ALL {
        for coding in [VhtCoding::Bcc, VhtCoding::Ldpc] {
            for guard in [VhtGuardInterval::Long, VhtGuardInterval::Short] {
                let config = VhtTxConfig::new(mcs)
                    .with_coding(coding)
                    .with_guard_interval(guard);
                let tx = config.encode_packet(&record).unwrap();
                assert_eq!(tx.mac_bytes, mac.as_bytes());
                assert_eq!(
                    tx.sample_count(),
                    tx.leading_samples + 800 + tx.data_samples + tx.trailing_samples
                );
                assert!(tx
                    .mpdu_bytes
                    .ends_with(&super::super::ofdm::waveform::crc32(mac.as_bytes()).to_le_bytes()));
                assert_eq!(&tx.psdu_bytes[4..4 + tx.mpdu_bytes.len()], tx.mpdu_bytes);
                assert_eq!(tx.signal_a.transmitted, tx.signal_a.derived);
                assert_eq!(tx.signal_b.transmitted, tx.signal_b.derived);
                let sig = VhtSignalAFields::decode(&tx.signal_a.transmitted).unwrap();
                assert_eq!(sig.short_guard_interval, guard == VhtGuardInterval::Short);
            }
        }
    }
    let mut config = VhtTxConfig::new(VhtMcs::Mcs3).with_fcs(WifiFcsPolicy::Explicit([1, 2, 3, 4]));
    config.signal_a_override = Some([0; 48]);
    config.signal_b_override = Some([0; 26]);
    config.legacy_signal_override = Some([0; 24]);
    let tx = config.encode_packet(&record).unwrap();
    assert!(tx.mpdu_bytes.ends_with(&[1, 2, 3, 4]));
    assert_eq!(tx.signal_a.transmitted, [0; 48]);
    assert_eq!(tx.signal_b.transmitted, [0; 26]);
    assert_eq!(tx.legacy_signal.transmitted, [0; 24]);
    assert!(
        tx.signal_a.explicit
            && tx.signal_b.explicit
            && tx.legacy_signal.explicit
            && tx.explicit_fcs
    );
    config.max_samples = 1;
    assert!(matches!(
        config.encode_packet(&record),
        Err(RadioError::Limit { .. })
    ));
    config.max_samples = usize::MAX;
    config.leading_samples = usize::MAX;
    assert!(matches!(
        config.encode_packet(&record),
        Err(RadioError::Overflow { .. })
    ));
}
