//! Bounded TLS codec properties.
//!
//! These tests exercise small, valid wire fragments only. They are intended for
//! normal `cargo test`, not broad fuzzing.

use crafter::prelude::*;
use crafter::protocols::tls::vector::{TlsVectorBounds, TlsVectorLengthPrefix};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

const U8_VECTOR_BOUNDS: TlsVectorBounds = TlsVectorBounds::u8(
    0,
    64,
    "tls.property.u8_vector",
    "tls.property.u8_vector.length",
);
const U16_VECTOR_BOUNDS: TlsVectorBounds = TlsVectorBounds::u16(
    0,
    512,
    "tls.property.u16_vector",
    "tls.property.u16_vector.length",
);
const U24_VECTOR_BOUNDS: TlsVectorBounds = TlsVectorBounds::u24(
    0,
    512,
    "tls.property.u24_vector",
    "tls.property.u24_vector.length",
);

fn prop_result<T>(result: crafter::Result<T>) -> std::result::Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max_len)
}

fn raw_extensions(
    max_count: usize,
    max_body_len: usize,
) -> impl Strategy<Value = Vec<(u16, Vec<u8>)>> {
    prop::collection::vec((any::<u16>(), bytes(max_body_len)), 0..=max_count)
}

fn assert_vector_roundtrip(
    bounds: TlsVectorBounds,
    expected_prefix: TlsVectorLengthPrefix,
    body: &[u8],
) -> std::result::Result<(), TestCaseError> {
    let encoded = prop_result(bounds.encode_to_vec(body))?;

    let mut with_tail = encoded.clone();
    with_tail.extend_from_slice(&[0xaa, 0xbb]);

    let (decoded, tail) = prop_result(bounds.decode_prefix(&with_tail))?;
    prop_assert_eq!(decoded.prefix(), expected_prefix);
    prop_assert_eq!(decoded.body(), body);
    prop_assert_eq!(decoded.len(), body.len());
    prop_assert_eq!(decoded.encoded_len(), encoded.len());
    prop_assert_eq!(tail, &[0xaa, 0xbb]);

    let mut cursor = 0;
    let decoded_from_cursor = prop_result(bounds.decode_from(&with_tail, &mut cursor))?;
    prop_assert_eq!(decoded_from_cursor.body(), body);
    prop_assert_eq!(cursor, encoded.len());

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn tls_property_vector_u8_roundtrips(body in bytes(64)) {
        assert_vector_roundtrip(U8_VECTOR_BOUNDS, TlsVectorLengthPrefix::U8, &body)?;
    }

    #[test]
    fn tls_property_vector_u16_roundtrips(body in bytes(512)) {
        assert_vector_roundtrip(U16_VECTOR_BOUNDS, TlsVectorLengthPrefix::U16, &body)?;
    }

    #[test]
    fn tls_property_vector_u24_roundtrips(body in bytes(512)) {
        assert_vector_roundtrip(U24_VECTOR_BOUNDS, TlsVectorLengthPrefix::U24, &body)?;
    }

    #[test]
    fn tls_property_extension_lists_roundtrip(entries in raw_extensions(8, 32)) {
        let extensions = TlsExtensions::from_raws(entries.clone());
        let encoded = prop_result(extensions.encode_to_vec())?;
        let decoded = prop_result(TlsExtensions::decode(&encoded))?;

        prop_assert_eq!(&decoded, &extensions);
        prop_assert_eq!(prop_result(decoded.encode_to_vec())?, encoded);
        prop_assert_eq!(decoded.raw_types(), entries.iter().map(|(raw_type, _)| *raw_type).collect::<Vec<_>>());
        prop_assert_eq!(
            decoded.extensions().iter().map(TlsRawExtension::body).collect::<Vec<_>>(),
            entries.iter().map(|(_, body)| body.as_slice()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn tls_property_unknown_extensions_preserve_type_and_body(body in bytes(64)) {
        let extension = TlsRawExtension::from_raw(0xbeef, body.clone());
        let encoded = prop_result(extension.encode_to_vec())?;
        let decoded = prop_result(TlsRawExtension::decode(&encoded))?;

        prop_assert_eq!(decoded.raw_type(), 0xbeef);
        prop_assert_eq!(decoded.body(), body.as_slice());
        prop_assert_eq!(prop_result(decoded.encode_to_vec())?, encoded);
        prop_assert!(decoded.summary().contains("0xbeef"));
    }

    #[test]
    fn tls_property_opaque_handshake_bodies_roundtrip(body in bytes(128)) {
        let message = TlsHandshake::from_body(TlsHandshakeType::from_u8(0xfe), body.clone());
        let encoded = prop_result(message.encode_to_vec())?;
        let decoded = prop_result(TlsHandshake::decode(&encoded))?;

        prop_assert_eq!(decoded.raw_handshake_type(), 0xfe);
        prop_assert_eq!(decoded.body_bytes(), body.as_slice());
        prop_assert_eq!(prop_result(decoded.encode_to_vec())?, encoded);
    }

    #[test]
    fn tls_property_explicit_length_overrides_are_preserved(
        body in bytes(64),
        declared_record_len in any::<u16>(),
        declared_handshake_len in 0u32..=0x00ff_ffff,
    ) {
        let record = TlsRecord::application_data(body.clone()).with_length(declared_record_len);
        let record_bytes = prop_result(record.encode_to_vec())?;
        prop_assert_eq!(&record_bytes[3..5], &declared_record_len.to_be_bytes());
        prop_assert_eq!(&record_bytes[5..], body.as_slice());

        let handshake = TlsHandshake::from_body(TlsHandshakeType::from_u8(0xfe), body.clone())
            .with_length(declared_handshake_len);
        let handshake_bytes = prop_result(handshake.encode_to_vec())?;
        prop_assert_eq!(handshake_bytes[0], 0xfe);
        prop_assert_eq!(
            &handshake_bytes[1..4],
            &[
                ((declared_handshake_len >> 16) & 0xff) as u8,
                ((declared_handshake_len >> 8) & 0xff) as u8,
                (declared_handshake_len & 0xff) as u8,
            ]
        );
        prop_assert_eq!(&handshake_bytes[4..], body.as_slice());
    }
}
