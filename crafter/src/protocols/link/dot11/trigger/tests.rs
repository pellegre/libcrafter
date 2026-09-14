use super::*;
use crate::error::CrafterError;
use crate::packet::{Layer, Packet};

fn roundtrip(bytes: &[u8]) -> Dot11Trigger {
    let decoded = Dot11Trigger::decode(bytes).unwrap();
    let packet = Packet::from_layer(decoded.clone());
    assert_eq!(packet.compile().unwrap().as_bytes(), bytes);
    assert_eq!(decoded.encoded_len(), bytes.len());
    decoded
}

#[test]
fn trigger_fields_preserve_every_wire_bit() {
    for bit in 0..64 {
        let bits = 1u64 << bit;
        let fields = Dot11TriggerCommonFields::from_le_bytes(bits.to_le_bytes());
        assert_eq!(fields.bits(), bits);
        assert_eq!(fields.compile(), bits.to_le_bytes());
        let values = [
            fields.trigger_type as u64,
            fields.ul_length as u64,
            fields.more_tf as u64,
            fields.cs_required as u64,
            fields.bandwidth as u64,
            fields.gi_ltf as u64,
            fields.masked_ltf as u64,
            fields.ltf_symbols_midamble as u64,
            fields.stbc as u64,
            fields.ldpc_extra_segment as u64,
            fields.ap_tx_power as u64,
            fields.pre_fec_padding_raw as u64,
            fields.pe_disambiguity as u64,
            fields.spatial_reuse as u64,
            fields.doppler as u64,
            fields.sig_a2_reserved as u64,
            fields.reserved as u64,
        ];
        let widths = [4, 12, 1, 1, 2, 2, 1, 3, 1, 1, 6, 2, 1, 16, 1, 9, 1];
        let mut offset = 0;
        for (value, width) in values.into_iter().zip(widths) {
            assert_eq!(value, (bits >> offset) & ((1 << width) - 1));
            offset += width;
        }
    }
    for bit in 0..40 {
        let bits = 1u64 << bit;
        let bytes: [u8; 5] = bits.to_le_bytes()[..5].try_into().unwrap();
        let fields = Dot11TriggerUserFields::from_le_bytes(bytes);
        assert_eq!(fields.bits(), bits);
        assert_eq!(fields.compile(), bytes);
        let values = [
            fields.aid12 as u64,
            fields.ru_allocation as u64,
            fields.ldpc as u64,
            fields.mcs as u64,
            fields.dcm as u64,
            fields.spatial_allocation as u64,
            fields.target_receive_power as u64,
            fields.reserved as u64,
        ];
        let mut offset = 0;
        for (value, width) in values.into_iter().zip([12, 8, 1, 4, 1, 6, 7, 1]) {
            assert_eq!(value, (bits >> offset) & ((1 << width) - 1));
            offset += width;
        }
    }
    assert_eq!(
        Dot11TriggerCommonFields::from_bits(u64::MAX).compile(),
        [255; 8]
    );
    assert_eq!(
        Dot11TriggerUserFields::from_bits(u64::MAX).compile(),
        [255; 5]
    );
}

#[test]
fn eht_trigger_fields_preserve_every_wire_bit() {
    for bit in 0..64 {
        let bits = 1u64 << bit;
        let fields = Dot11EhtTriggerCommonFields::from_le_bytes(bits.to_le_bytes());
        assert_eq!(fields.bits(), bits);
        assert_eq!(fields.compile(), bits.to_le_bytes());
        let values = [
            fields.trigger_type as u64,
            fields.ul_length as u64,
            fields.more_tf as u64,
            fields.cs_required as u64,
            fields.bandwidth as u64,
            fields.gi_ltf as u64,
            fields.reserved_22 as u64,
            fields.ltf_symbols as u64,
            fields.reserved_26 as u64,
            fields.ldpc_extra_segment as u64,
            fields.ap_tx_power as u64,
            fields.pre_fec_padding_raw as u64,
            fields.pe_disambiguity as u64,
            fields.spatial_reuse as u64,
            fields.reserved_53 as u64,
            fields.he_eht_p160 as u64,
            fields.special_user_info_absent as u64,
            fields.eht_reserved as u64,
            fields.reserved_63 as u64,
        ];
        let widths = [4, 12, 1, 1, 2, 2, 1, 3, 1, 1, 6, 2, 1, 16, 1, 1, 1, 7, 1];
        let mut offset = 0;
        for (value, width) in values.into_iter().zip(widths) {
            assert_eq!(value, (bits >> offset) & ((1 << width) - 1));
            offset += width;
        }
    }
    for bit in 0..40 {
        let bits = 1u64 << bit;
        let bytes: [u8; 5] = bits.to_le_bytes()[..5].try_into().unwrap();
        let special = Dot11EhtTriggerSpecialUserFields::from_le_bytes(bytes);
        let special_values = [
            special.aid12 as u64,
            special.phy_version as u64,
            special.bandwidth_extension as u64,
            special.spatial_reuse_1 as u64,
            special.spatial_reuse_2 as u64,
            special.usig_disregard_validate as u64,
            special.reserved as u64,
        ];
        let mut offset = 0;
        for (value, width) in special_values.into_iter().zip([12, 3, 2, 4, 4, 12, 3]) {
            assert_eq!(value, (bits >> offset) & ((1 << width) - 1));
            offset += width;
        }
        assert_eq!(special.bits(), bits);
        assert_eq!(special.compile(), bytes);

        let user = Dot11EhtTriggerUserFields::from_le_bytes(bytes);
        let user_values = [
            user.aid12 as u64,
            user.ru_allocation as u64,
            user.ldpc as u64,
            user.mcs as u64,
            user.reserved as u64,
            user.spatial_allocation as u64,
            user.target_receive_power as u64,
            user.ps160 as u64,
        ];
        let mut offset = 0;
        for (value, width) in user_values.into_iter().zip([12, 8, 1, 4, 1, 6, 7, 1]) {
            assert_eq!(value, (bits >> offset) & ((1 << width) - 1));
            offset += width;
        }
        assert_eq!(user.bits(), bits);
        assert_eq!(user.compile(), bytes);
    }
}

#[test]
fn eht_trigger_typed_view_and_layer_roundtrip() {
    let common = Dot11EhtTriggerCommonFields {
        cs_required: true,
        ldpc_extra_segment: true,
        ap_tx_power: 42,
        pre_fec_padding_raw: 2,
        pe_disambiguity: true,
        spatial_reuse: 0x4321,
        ..Default::default()
    };
    let special = Dot11EhtTriggerSpecialUser {
        fields: Dot11EhtTriggerSpecialUserFields {
            spatial_reuse_1: 3,
            spatial_reuse_2: 12,
            ..Default::default()
        },
        dependent: vec![0x5a],
    };
    let mut original = Dot11EhtTrigger::new(common, special).user(Dot11EhtTriggerUser {
        fields: Dot11EhtTriggerUserFields {
            aid12: 37,
            ru_allocation: 4,
            ldpc: true,
            mcs: 11,
            target_receive_power: 68,
            ..Default::default()
        },
        dependent: vec![0xa5],
    });
    original.remainder = Dot11TriggerRemainder::Padding(vec![0xff, 0x0f]);
    let layer = original.clone().into_trigger();
    let bytes = Packet::from_layer(layer)
        .compile()
        .unwrap()
        .as_bytes()
        .to_vec();
    assert_eq!(
        bytes,
        [
            0xd0, 0x12, 0x12, 0xa8, 0x3a, 0x64, 0x08, 0x7f, 0xd7, 0x07, 0x86, 0xff, 0x1f, 0x5a,
            0x25, 0x40, 0x70, 0x01, 0x44, 0xa5, 0xff, 0x0f,
        ]
    );
    let decoded = roundtrip(&bytes);
    assert_eq!(decoded.eht().unwrap(), original);
}

#[test]
fn eht_trigger_requires_variant_and_leading_special_user() {
    let ordinary_he = Dot11Trigger::new();
    assert!(ordinary_he.eht().is_err());

    let mut common: Dot11TriggerCommonFields = Dot11EhtTriggerCommonFields::default().into();
    common.sig_a2_reserved &= !1;
    let missing = Dot11Trigger::new().common(common);
    assert_eq!(
        missing.eht().unwrap_err(),
        CrafterError::invalid_field_value(
            "dot11.trigger.users",
            "EHT Trigger frame has no Special User Info field"
        )
    );

    let not_special = missing.user(Dot11TriggerUser {
        fields: Dot11TriggerUserFields::default(),
        dependent: vec![0],
    });
    assert!(not_special.eht().is_err());
}

#[test]
fn eht_trigger_classifies_mixed_user_info_without_losing_order() {
    let common = Dot11EhtTriggerCommonFields {
        he_eht_p160: true,
        ..Default::default()
    };
    let special = Dot11EhtTriggerSpecialUser {
        fields: Dot11EhtTriggerSpecialUserFields::default(),
        dependent: vec![0],
    };
    let he = Dot11TriggerUser {
        fields: Dot11TriggerUserFields {
            aid12: 17,
            ..Default::default()
        },
        dependent: vec![1],
    };
    let eht = Dot11EhtTriggerUser {
        fields: Dot11EhtTriggerUserFields {
            aid12: 18,
            ps160: true,
            ..Default::default()
        },
        dependent: vec![2],
    };
    let typed = Dot11EhtTrigger::new(common, special)
        .he_user(he.clone())
        .user(eht.clone());
    let decoded = typed.clone().into_trigger().eht().unwrap();
    assert_eq!(decoded, typed);
    assert!(matches!(&decoded.users[0], Dot11EhtTriggerUserInfo::He(user) if user == &he));
    assert!(matches!(&decoded.users[1], Dot11EhtTriggerUserInfo::Eht(user) if user == &eht));
    assert_eq!(decoded.eht_users().collect::<Vec<_>>(), vec![&eht]);
}

#[test]
fn trigger_variant_boundaries_and_padding() {
    for variant in 0..7 {
        let mut bytes = vec![variant, 0, 0, 0, 0, 0, 0, 0];
        if variant == 5 {
            bytes.extend([4, 0, 0x30, 0x12]);
        }
        for aid in [1, 2] {
            bytes.extend([aid, 0, 0, 0, 0]);
            match variant {
                0 | 1 => bytes.push(0xa5),
                2 => bytes.extend([4, 0, 0x30, 0x12]),
                _ => (),
            }
        }
        bytes.extend([255, 15, 0x12]);
        let decoded = roundtrip(&bytes);
        assert_eq!(decoded.users.len(), 2);
        assert_eq!(decoded.users[1].fields.aid12, 2);
        assert_eq!(
            decoded.remainder,
            Dot11TriggerRemainder::Padding(vec![255, 15, 0x12])
        );
    }
}

#[test]
fn trigger_multi_tid_count_includes_sixteen() {
    for count in 1..=16usize {
        let mut bytes = vec![2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        bytes.extend((6u16 | (((count - 1) as u16) << 12)).to_le_bytes());
        bytes.extend(vec![0x23; 4 * count]);
        bytes.extend([255, 255]);
        let decoded = roundtrip(&bytes);
        assert_eq!(decoded.users.len(), 1);
        assert_eq!(decoded.users[0].dependent.len(), 2 + 4 * count);
        for missing in 1..=4 * count {
            assert!(Dot11Trigger::decode(&bytes[..bytes.len() - 2 - missing]).is_err());
        }
    }
}

#[test]
fn trigger_unknown_boundaries_are_lossless_not_guessed() {
    for variant in 7..16 {
        let bytes = [variant, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1];
        let decoded = roundtrip(&bytes);
        assert!(decoded.users.is_empty());
        assert_eq!(
            decoded.remainder,
            Dot11TriggerRemainder::Opaque(vec![255, 255, 1])
        );
    }
    let bytes = [2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 42];
    assert_eq!(
        roundtrip(&bytes).remainder,
        Dot11TriggerRemainder::Opaque(bytes[8..].to_vec())
    );
}

#[test]
fn trigger_short_fields_are_structured_errors() {
    for len in 0..8 {
        assert_eq!(
            Dot11Trigger::decode(&[0; 8][..len]).unwrap_err(),
            CrafterError::buffer_too_short("dot11.trigger.common", 8, len)
        );
    }
    for len in 1..6 {
        let bytes = vec![0; 8 + len];
        assert!(Dot11Trigger::decode(&bytes).is_err());
    }
    for len in 0..4 {
        let mut bytes = vec![0; 8 + len];
        bytes[0] = 5;
        assert_eq!(
            Dot11Trigger::decode(&bytes).unwrap_err(),
            CrafterError::buffer_too_short("dot11.trigger.gcr_common", 4, len)
        );
    }
}
