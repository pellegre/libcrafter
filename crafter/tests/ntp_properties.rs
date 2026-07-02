use crafter::prelude::*;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

fn prop_result<T>(result: crafter::Result<T>) -> std::result::Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn unknown_extension_type() -> impl Strategy<Value = u16> {
    any::<u16>().prop_filter("extension field type is unassigned", |field_type| {
        ntp_extension_type(*field_type).category()
            == NtpExtensionFieldTypeCategory::UnknownOrUnassigned
    })
}

fn aligned_body() -> impl Strategy<Value = Vec<u8>> {
    (6usize..=16).prop_flat_map(|words| {
        prop::collection::vec(any::<u8>(), words * std::mem::size_of::<u32>())
    })
}

fn unknown_extension_field() -> impl Strategy<Value = NtpExtensionField> {
    (unknown_extension_type(), aligned_body())
        .prop_map(|(field_type, body)| NtpExtensionField::unknown(field_type, body))
}

fn optional_legacy_mac() -> impl Strategy<Value = Option<NtpLegacyMac>> {
    prop_oneof![
        Just(None),
        (any::<u32>(), any::<[u8; 16]>()).prop_map(|(key_id, digest)| Some(
            NtpLegacyMac::from_key_id_and_digest(key_id, digest)
        )),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn ntp_extension_property_unknown_fields_roundtrip_byte_exact(
        fields in prop::collection::vec(unknown_extension_field(), 1..=4),
    ) {
        let packet = Packet::from_layer(Ntp::client().extension_fields(fields.clone()));
        let compiled = prop_result(packet.compile())?;
        let decoded = prop_result(Ntp::decode(compiled.as_bytes()))?;

        prop_assert_eq!(decoded.extension_fields_value().len(), fields.len());
        prop_assert!(decoded.legacy_mac_value().is_none());

        for (decoded_field, expected_field) in
            decoded.extension_fields_value().iter().zip(fields.iter())
        {
            prop_assert!(decoded_field.is_unknown_or_unassigned());
            prop_assert_eq!(decoded_field.field_type(), expected_field.field_type());
            prop_assert_eq!(decoded_field.value(), expected_field.value());
            prop_assert_eq!(
                decoded_field.declared_length_value(),
                Some((NTP_EXTENSION_FIELD_HEADER_LEN + expected_field.value().len()) as u16)
            );
        }

        let recompiled = prop_result(Packet::from_layer(decoded).compile())?;
        prop_assert_eq!(recompiled.as_bytes(), compiled.as_bytes());
    }

    #[test]
    fn ntp_packet_property_complete_packet_roundtrip_byte_exact(
        leap in 0u8..=3,
        version in 0u8..=7,
        mode in 0u8..=7,
        stratum in any::<u8>(),
        poll in any::<i8>(),
        precision in any::<i8>(),
        root_delay in any::<u32>(),
        root_dispersion in any::<u32>(),
        reference_id in any::<[u8; 4]>(),
        reference_timestamp in any::<u64>(),
        origin_timestamp in any::<u64>(),
        receive_timestamp in any::<u64>(),
        transmit_timestamp in any::<u64>(),
        fields in prop::collection::vec(unknown_extension_field(), 0..=3),
        legacy_mac in optional_legacy_mac(),
    ) {
        let mut ntp = Ntp::new()
            .leap_indicator(NtpLeapIndicator::from_wire(leap))
            .version(NtpVersion::from_wire(version))
            .mode(NtpMode::from_wire(mode))
            .stratum(stratum)
            .poll(poll)
            .precision(precision)
            .root_delay_raw(root_delay)
            .root_dispersion_raw(root_dispersion)
            .reference_id(reference_id)
            .reference_timestamp(reference_timestamp)
            .origin_timestamp(origin_timestamp)
            .receive_timestamp(receive_timestamp)
            .transmit_timestamp(transmit_timestamp)
            .extension_fields(fields.clone());

        if let Some(mac) = legacy_mac.clone() {
            ntp = ntp.legacy_mac(mac);
        }

        let compiled = prop_result(Packet::from_layer(ntp).compile())?;
        let decoded = prop_result(Ntp::decode(compiled.as_bytes()))?;

        prop_assert_eq!(decoded.leap_indicator_value(), NtpLeapIndicator::from_wire(leap));
        prop_assert_eq!(decoded.version_value_effective(), NtpVersion::from_wire(version));
        prop_assert_eq!(decoded.mode_value(), NtpMode::from_wire(mode));
        prop_assert_eq!(decoded.stratum_value().value(), stratum);
        prop_assert_eq!(decoded.poll_value(), poll);
        prop_assert_eq!(decoded.precision_value(), precision);
        prop_assert_eq!(decoded.root_delay_value().raw(), root_delay);
        prop_assert_eq!(decoded.root_dispersion_value().raw(), root_dispersion);
        prop_assert_eq!(decoded.reference_id_value().bytes(), reference_id);
        prop_assert_eq!(decoded.reference_timestamp_value().raw(), reference_timestamp);
        prop_assert_eq!(decoded.origin_timestamp_value().raw(), origin_timestamp);
        prop_assert_eq!(decoded.receive_timestamp_value().raw(), receive_timestamp);
        prop_assert_eq!(decoded.transmit_timestamp_value().raw(), transmit_timestamp);
        prop_assert_eq!(decoded.extension_fields_value().len(), fields.len());

        for (decoded_field, expected_field) in
            decoded.extension_fields_value().iter().zip(fields.iter())
        {
            prop_assert_eq!(decoded_field.field_type(), expected_field.field_type());
            prop_assert_eq!(decoded_field.value(), expected_field.value());
        }

        match (decoded.legacy_mac_value(), legacy_mac.as_ref()) {
            (Some(decoded_mac), Some(expected_mac)) => {
                prop_assert_eq!(decoded_mac.bytes(), expected_mac.bytes());
            }
            (None, None) => {}
            other => {
                return Err(TestCaseError::fail(format!(
                    "legacy MAC mismatch: {other:?}"
                )));
            }
        }

        let recompiled = prop_result(Packet::from_layer(decoded).compile())?;
        prop_assert_eq!(recompiled.as_bytes(), compiled.as_bytes());
    }
}
