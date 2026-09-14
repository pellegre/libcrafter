use super::*;
fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn read_samples(name: &str) -> Vec<ComplexSample> {
    let bytes = std::fs::read(format!(
        "{}/tests/fixtures/iq/{name}.cs8",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    bytes
        .chunks_exact(2)
        .map(|b| ComplexSample {
            i: b[0] as i8 as f32 / 128.,
            q: b[1] as i8 as f32 / 128.,
        })
        .collect()
}
fn acquire(samples: &[ComplexSample]) -> Acquisition {
    let mut sync = crate::radio::sync::Synchronizer::default();
    samples
        .iter()
        .enumerate()
        .find_map(|(n, s)| match sync.push(*s, n as u64) {
            Some(crate::radio::sync::SyncEvent::Acquired(a)) => Some(a),
            _ => None,
        })
        .expect("legacy preamble acquisition")
}
#[test]
fn radio_vht_stbc_full_iq_kernel() {
    let rows = include_str!("../../../../tests/fixtures/iq/vht-stbc-iq-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 110);
    for row in rows.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        let samples = read_samples(c[0]);
        let a = acquire(&samples);
        let start = a.signal_start as usize;
        let (fields, info) = admit(&samples[start..start + 240], &a)
            .unwrap_or_else(|_| panic!("{} admission", c[0]));
        assert!(fields.stbc);
        assert!(matches!(
            fields.users,
            VhtSignalAUsers::Single {
                space_time_streams: 2,
                ..
            }
        ));
        let decoded = decode(&samples[start..], &a).unwrap_or_else(|_| panic!("{} recovery", c[0]));
        assert_eq!(decoded.info, info);
        assert_eq!(info.data_start, 917);
        assert_eq!(info.end_sample_index, c[7].parse::<u64>().unwrap());
        assert_eq!(info.psdu_bytes, decoded.bytes.len());
        if c[0].ends_with("codeword") {
            let offset = c[4].parse::<usize>().unwrap();
            let expected = hex(c[5]);
            assert_eq!(&decoded.bytes[offset..offset + expected.len()], &expected);
        } else {
            assert_eq!(decoded.bytes, hex(c[3]), "{}", c[0]);
        }
        assert_eq!(
            decoded.coding.iter().any(|d| matches!(
                d,
                PhyDiagnostic::LdpcPartial {
                    failed_codewords: 1
                }
            )),
            c[0].ends_with("codeword")
        );
    }
}

#[test]
fn radio_vht_ldpc_full_iq_kernel() {
    let rows = include_str!("../../../../tests/fixtures/iq/vht-ldpc-iq-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 73);
    let mut extra = [false; 2];
    for row in rows.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        let samples = read_samples(c[0]);
        let a = acquire(&samples);
        let start = a.signal_start as usize;
        let (fields, info) = admit(&samples[start..start + 240], &a)
            .unwrap_or_else(|_| panic!("{} admission", c[0]));
        let decoded = decode(&samples[start..], &a).unwrap_or_else(|_| panic!("{} decode", c[0]));
        if !c[0].ends_with("bad-codeword") {
            assert_eq!(decoded.bytes, hex(c[3]), "{}", c[0]);
        } else {
            // The first MPDU is deliberately damaged; never assert guessed
            // bytes as ground truth. The later MPDU remains exactly known.
            let offset = c[4].parse::<usize>().unwrap();
            let expected = hex(c[5]);
            assert_eq!(&decoded.bytes[offset..offset + expected.len()], &expected);
            assert!(crate::radio::data::valid_fcs(&expected));
        }
        assert_eq!(info, decoded.info);
        assert_eq!(info.psdu_bytes, decoded.bytes.len());
        assert_eq!(info.end_sample_index, c[7].parse::<u64>().unwrap());
        assert_eq!(decoded.signal_a, fields);
        extra[usize::from(fields.ldpc_extra_symbol)] = true;
        assert!(decoded.coding.iter().any(|d| matches!(d,PhyDiagnostic::Ldpc { codewords,iterations } if *codewords>0 && *iterations<=64*codewords)));
        assert_eq!(
            decoded.coding.iter().any(|d| matches!(
                d,
                PhyDiagnostic::LdpcPartial {
                    failed_codewords: 1
                }
            )),
            c[0].ends_with("bad-codeword")
        );
    }
    assert_eq!(extra, [true, true]);
    for row in include_str!("../../../../tests/fixtures/iq/vht-ldpc-iq-invalid-index.tsv")
        .lines()
        .skip(1)
    {
        let name = row.split('\t').next().unwrap();
        let samples = read_samples(name);
        let a = acquire(&samples);
        assert!(
            decode(&samples[a.signal_start as usize..], &a).is_err(),
            "{name}"
        );
    }
}

#[test]
fn radio_vht_bcc_full_iq_kernel() {
    let inventory = include_str!("../../../../tests/fixtures/iq/vht-bcc-iq-index.tsv");
    assert_eq!(inventory.lines().skip(1).count(), 108);
    for row in inventory.lines().skip(1) {
        let c: Vec<_> = row.split('\t').collect();
        let samples = read_samples(c[0]);
        let a = acquire(&samples);
        // Streaming must know the exact DATA extent with only L-SIG/SIG-A
        // buffered, including short-GI duration rounding/disambiguation.
        let start = a.signal_start as usize;
        let (admitted_fields, admitted) = admit(&samples[start..start + 240], &a)
            .unwrap_or_else(|_| panic!("{} header admission failed", c[0]));
        let decoded = decode(&samples[a.signal_start as usize..], &a)
            .unwrap_or_else(|_| panic!("{} IQ recovery failed", c[0]));
        let siga = c[5].bytes().map(|b| b - b'0').collect::<Vec<_>>();
        let sigb = c[6].bytes().map(|b| b - b'0').collect::<Vec<_>>();
        assert_eq!(decoded.signal_a, VhtSignalAFields::decode(&siga).unwrap());
        assert_eq!(admitted_fields, decoded.signal_a);
        assert_eq!(admitted.data_start, decoded.info.data_start);
        assert_eq!(admitted.end_sample_index, decoded.info.end_sample_index);
        assert_eq!(admitted.psdu_bytes, decoded.bytes.len());
        assert_eq!(
            decoded.signal_b,
            VhtSignalB20Fields::decode(&sigb, false).unwrap()
        );
        assert_eq!(decoded.info.data_symbols, c[3].parse::<usize>().unwrap());
        assert_eq!(decoded.info.data_start, c[10].parse::<u64>().unwrap());
        assert_eq!(decoded.info.end_sample_index, c[11].parse::<u64>().unwrap());
        assert_eq!(decoded.bytes, hex(c[7]), "{} PSDU differs", c[0]);
        let mpdu = hex(c[8]);
        assert_eq!(&decoded.bytes[4..4 + mpdu.len()], &mpdu);
        assert!(crate::radio::data::valid_fcs(
            &decoded.bytes[4..4 + mpdu.len()]
        ));
    }
}

#[test]
fn radio_vht_iq_truncation_and_unusable_fields() {
    let invalid = include_str!("../../../../tests/fixtures/iq/vht-bcc-iq-invalid-index.tsv");
    assert_eq!(invalid.lines().skip(1).count(), 8);
    for row in invalid.lines().skip(1) {
        let name = row.split('\t').next().unwrap();
        let all = read_samples(name);
        let a = acquire(&all);
        let start = a.signal_start as usize;
        // SIG-B/SERVICE corruption is deliberately not a header-admission
        // failure: that integrity check requires the later DATA field.
        assert_eq!(
            admit(&all[start..start + 240], &a).is_ok(),
            name == "vht-bcc-invalid-sigb-crc",
            "{name} header admission"
        );
        assert!(
            decode(&all[a.signal_start as usize..], &a).is_err(),
            "{name}"
        );
    }
    let row = include_str!("../../../../tests/fixtures/iq/vht-bcc-iq-index.tsv")
        .lines()
        .nth(1)
        .unwrap();
    let c: Vec<_> = row.split('\t').collect();
    let all = read_samples(c[0]);
    let a = acquire(&all);
    let samples = &all[a.signal_start as usize..];
    let end = c[11].parse::<usize>().unwrap() - a.signal_start as usize;
    for count in [0, 79, 80, 239, 399, 479, end - 1] {
        assert!(decode(&samples[..count], &a).is_err(), "length {count}");
        if count < 240 {
            assert!(admit(&samples[..count], &a).is_err());
        }
    }
    for range in [80..240, 320..400, 400..480, 480..end] {
        let mut damaged = samples.to_vec();
        damaged[range].fill(ComplexSample::ZERO);
        assert!(decode(&damaged, &a).is_err());
    }
    let mut invalid = a.clone();
    invalid.signal_start = u64::MAX;
    assert!(decode(samples, &invalid).is_err());
    invalid = a.clone();
    invalid.phase_origin = u64::MAX;
    assert!(decode(samples, &invalid).is_err());
    let ht = read_samples("ht-bcc-0-gi800-len100-clean");
    let ht_a = acquire(&ht);
    assert!(decode(&ht[ht_a.signal_start as usize..], &ht_a).is_err());
}
