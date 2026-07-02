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
}
