use crafter::prelude::*;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

const IMPLEMENTED_PARAMETER_TYPES: &[u16] = &[
    SCTP_PARAMETER_TYPE_HEARTBEAT_INFO,
    SCTP_PARAMETER_TYPE_IPV4_ADDRESS,
    SCTP_PARAMETER_TYPE_IPV6_ADDRESS,
    SCTP_PARAMETER_TYPE_STATE_COOKIE,
    SCTP_PARAMETER_TYPE_UNRECOGNIZED_PARAMETER,
    SCTP_PARAMETER_TYPE_COOKIE_PRESERVATIVE,
    SCTP_PARAMETER_TYPE_HOST_NAME_ADDRESS,
    SCTP_PARAMETER_TYPE_SUPPORTED_ADDRESS_TYPES,
    SCTP_PARAMETER_TYPE_OUTGOING_SSN_RESET_REQUEST,
    SCTP_PARAMETER_TYPE_INCOMING_SSN_RESET_REQUEST,
    SCTP_PARAMETER_TYPE_SSN_TSN_RESET_REQUEST,
    SCTP_PARAMETER_TYPE_RE_CONFIGURATION_RESPONSE,
    SCTP_PARAMETER_TYPE_ADD_OUTGOING_STREAMS_REQUEST,
    SCTP_PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST,
    SCTP_PARAMETER_TYPE_ZERO_CHECKSUM_ACCEPTABLE,
    SCTP_PARAMETER_TYPE_RANDOM,
    SCTP_PARAMETER_TYPE_CHUNK_LIST,
    SCTP_PARAMETER_TYPE_REQUESTED_HMAC_ALGORITHM,
    SCTP_PARAMETER_TYPE_PADDING,
    SCTP_PARAMETER_TYPE_SUPPORTED_EXTENSIONS,
    SCTP_PARAMETER_TYPE_FORWARD_TSN_SUPPORTED,
    SCTP_PARAMETER_TYPE_ADD_IP_ADDRESS,
    SCTP_PARAMETER_TYPE_DELETE_IP_ADDRESS,
    SCTP_PARAMETER_TYPE_ERROR_CAUSE_INDICATION,
    SCTP_PARAMETER_TYPE_SET_PRIMARY_ADDRESS,
    SCTP_PARAMETER_TYPE_SUCCESS_INDICATION,
    SCTP_PARAMETER_TYPE_ADAPTATION_LAYER_INDICATION,
];

#[derive(Clone, Debug)]
struct ParameterCase {
    parameter_type: u16,
    value: Vec<u8>,
    padding: Vec<u8>,
}

fn prop_result<T>(result: crafter::Result<T>) -> std::result::Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn unknown_parameter_type() -> impl Strategy<Value = u16> {
    any::<u16>().prop_filter("SCTP parameter type is unassigned", |parameter_type| {
        sctp_parameter_type_is_unassigned(*parameter_type)
    })
}

fn implemented_parameter_type() -> impl Strategy<Value = u16> {
    prop::sample::select(IMPLEMENTED_PARAMETER_TYPES.to_vec())
}

fn value_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=32)
}

fn parameter_case(
    parameter_type: impl Strategy<Value = u16>,
) -> impl Strategy<Value = ParameterCase> {
    (parameter_type, value_bytes()).prop_flat_map(|(parameter_type, value)| {
        let declared_length = SCTP_PARAMETER_HEADER_LEN + value.len();
        let padding_len = sctp_parameter_padding_len(declared_length);
        (
            Just(parameter_type),
            Just(value),
            prop::collection::vec(any::<u8>(), padding_len..=padding_len),
        )
            .prop_map(|(parameter_type, value, padding)| ParameterCase {
                parameter_type,
                value,
                padding,
            })
    })
}

fn encode_single(parameter: &SctpParameter) -> crafter::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    encode_parameters(std::slice::from_ref(parameter), &mut bytes)?;
    Ok(bytes)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn sctp_parameter_roundtrip_unknown_parameters_preserve_bytes(
        case in parameter_case(unknown_parameter_type()),
    ) {
        let declared_length = (SCTP_PARAMETER_HEADER_LEN + case.value.len()) as u16;
        let parameter = SctpParameter::from_preserved_parts(
            case.parameter_type,
            declared_length,
            case.value.clone(),
            case.padding.clone(),
        );

        let encoded = prop_result(encode_single(&parameter))?;
        let decoded = prop_result(decode_parameters(&encoded))?;

        prop_assert_eq!(decoded.len(), 1);
        prop_assert!(matches!(decoded[0], SctpParameter::Unknown(_)));
        prop_assert_eq!(decoded[0].parameter_type_value(), case.parameter_type);
        prop_assert_eq!(decoded[0].parameter_type_status(), SctpParameterTypeStatus::Unassigned);
        prop_assert_eq!(decoded[0].unknown_action_bits(), (case.parameter_type >> 14) as u8);
        prop_assert_eq!(decoded[0].explicit_declared_length(), Some(declared_length));
        prop_assert_eq!(decoded[0].value(), case.value.as_slice());
        prop_assert_eq!(decoded[0].padding(), case.padding.as_slice());

        let reencoded = prop_result(encode_single(&decoded[0]))?;
        prop_assert_eq!(reencoded, encoded);
    }

    #[test]
    fn sctp_parameter_roundtrip_known_parameters_dispatch_and_preserve_bytes(
        case in parameter_case(implemented_parameter_type()),
    ) {
        let declared_length = (SCTP_PARAMETER_HEADER_LEN + case.value.len()) as u16;
        let parameter = SctpParameter::from_preserved_parts(
            case.parameter_type,
            declared_length,
            case.value.clone(),
            case.padding.clone(),
        );

        let encoded = prop_result(encode_single(&parameter))?;
        let decoded = prop_result(decode_parameters(&encoded))?;

        prop_assert_eq!(decoded.len(), 1);
        prop_assert!(!matches!(decoded[0], SctpParameter::Unknown(_)));
        prop_assert_eq!(decoded[0].parameter_type_value(), case.parameter_type);
        prop_assert_eq!(decoded[0].explicit_declared_length(), Some(declared_length));
        prop_assert_eq!(decoded[0].value(), case.value.as_slice());
        prop_assert_eq!(decoded[0].padding(), case.padding.as_slice());

        let reencoded = prop_result(encode_single(&decoded[0]))?;
        prop_assert_eq!(reencoded, encoded);
    }

    #[test]
    fn sctp_parameter_roundtrip_auto_padding_uses_zero_bytes(
        parameter_type in unknown_parameter_type(),
        value in value_bytes(),
    ) {
        let parameter = SctpParameter::from_raw_parts(parameter_type, value.clone(), []);
        let declared_length = SCTP_PARAMETER_HEADER_LEN + value.len();
        let padding_len = sctp_parameter_padding_len(declared_length);
        let encoded = prop_result(encode_single(&parameter))?;

        prop_assert_eq!(encoded.len(), declared_length + padding_len);
        prop_assert_eq!(&encoded[0..2], &parameter_type.to_be_bytes());
        prop_assert_eq!(&encoded[2..4], &(declared_length as u16).to_be_bytes());
        prop_assert_eq!(&encoded[4..declared_length], value.as_slice());
        prop_assert!(encoded[declared_length..].iter().all(|byte| *byte == 0));

        let decoded = prop_result(decode_parameters(&encoded))?;
        prop_assert_eq!(decoded.len(), 1);
        prop_assert_eq!(decoded[0].value(), value.as_slice());
        let expected_padding = vec![0; padding_len];
        prop_assert_eq!(decoded[0].padding(), expected_padding.as_slice());

        let reencoded = prop_result(encode_single(&decoded[0]))?;
        prop_assert_eq!(reencoded, encoded);
    }

    #[test]
    fn sctp_parameter_roundtrip_length_boundaries_report_structured_errors(
        parameter_type in unknown_parameter_type(),
        short_declared_length in 0u16..SCTP_PARAMETER_HEADER_LEN as u16,
        value in value_bytes(),
    ) {
        let mut too_short = Vec::new();
        too_short.extend_from_slice(&parameter_type.to_be_bytes());
        too_short.extend_from_slice(&short_declared_length.to_be_bytes());

        let short_error = decode_parameters(&too_short).expect_err("short declared length must fail");
        prop_assert!(short_error.to_string().contains("sctp.parameter.length"));

        let declared_length = SCTP_PARAMETER_HEADER_LEN + value.len();
        let padding_len = sctp_parameter_padding_len(declared_length);
        let full_length = declared_length + padding_len;
        let mut truncated = Vec::with_capacity(full_length);
        truncated.extend_from_slice(&parameter_type.to_be_bytes());
        truncated.extend_from_slice(&(declared_length as u16).to_be_bytes());
        truncated.extend_from_slice(value.as_slice());
        truncated.resize(full_length, 0);
        if !truncated.is_empty() {
            truncated.pop();
        }

        if full_length > 0 {
            let truncation_error = decode_parameters(&truncated)
                .expect_err("truncated declared value or padding must fail");
            prop_assert!(truncation_error.to_string().contains("sctp.parameter"));
        }
    }
}

#[test]
fn sctp_parameter_roundtrip_minimum_length_boundary() -> crafter::Result<()> {
    let parameter = SctpParameter::unknown(0x9234, []);
    let encoded = encode_single(&parameter)?;
    assert_eq!(encoded, [0x92, 0x34, 0x00, 0x04]);

    let decoded = decode_parameters(&encoded)?;
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].parameter_type_value(), 0x9234);
    assert_eq!(decoded[0].value(), &[]);
    assert_eq!(decoded[0].padding(), &[]);
    assert_eq!(encode_single(&decoded[0])?, encoded);

    Ok(())
}
