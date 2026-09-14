use super::*;

fn parse_size(value: &str) -> EhtRuSize {
    match value {
        "26" => EhtRuSize::Ru26,
        "52" => EhtRuSize::Ru52,
        "106" => EhtRuSize::Ru106,
        "242" => EhtRuSize::Ru242,
        _ => panic!("unknown RU size {value}"),
    }
}

#[test]
fn radio_eht_ofdma_allocation_table() {
    let rows = include_str!("../../../../../../tests/fixtures/iq/eht-ofdma-ru-index.tsv");
    assert_eq!(rows.lines().skip(1).count(), 512);
    for row in rows.lines().skip(1) {
        let fields: Vec<_> = row.split('\t').collect();
        let code = fields[0].parse::<u16>().unwrap();
        let decoded = EhtRuAllocation20::decode(code);
        if fields[1] == "unsupported" {
            assert_eq!(decoded, Err(EhtSigError::RuAllocation(code)));
            continue;
        }

        let allocation = decoded.unwrap();
        assert_eq!(allocation.code(), code);
        assert_eq!(allocation.user_count(), fields[2].parse::<u8>().unwrap());
        assert_eq!(
            allocation.user_kind(),
            if fields[3] == "mu" {
                EhtOfdmaUserKind::MuMimo
            } else {
                EhtOfdmaUserKind::NonMu
            }
        );
        let expected: Vec<_> = fields[4].split(';').collect();
        assert_eq!(allocation.resources().len(), expected.len(), "code {code}");
        for (resource, expected) in allocation.resources().iter().zip(expected) {
            let (components, users) = expected
                .split_once('@')
                .map_or((expected, 1), |(parts, users)| {
                    (parts, users.parse::<u8>().unwrap())
                });
            let expected_components: Vec<_> = components
                .split('+')
                .map(|component| {
                    let (size, index) = component.split_once(':').unwrap();
                    (parse_size(size), index.parse::<u8>().unwrap())
                })
                .collect();
            assert_eq!(resource.user_count(), users);
            assert_eq!(resource.components().len(), expected_components.len());
            for (actual, &(size, index)) in resource.components().iter().zip(&expected_components) {
                assert_eq!((actual.size(), actual.index()), (size, index));
            }
            assert_eq!(
                resource.tone_count(),
                expected_components
                    .iter()
                    .map(|(size, _)| size.tone_count())
                    .sum()
            );
        }

        let occupied: Vec<_> = (-128..=127)
            .filter(|&tone| {
                allocation
                    .resources()
                    .iter()
                    .any(|resource| resource.contains_tone(tone))
            })
            .collect();
        assert_eq!(occupied.len(), fields[5].parse::<usize>().unwrap());
        assert!(allocation
            .resources()
            .windows(2)
            .all(|pair| pair[0].first_tone() < pair[1].first_tone()));
        for (index, first) in allocation.resources().iter().enumerate() {
            for second in &allocation.resources()[index + 1..] {
                assert!((-128..=127)
                    .all(|tone| { !first.contains_tone(tone) || !second.contains_tone(tone) }));
            }
        }
    }
}
