//! Bounded QUIC encode/decode roundtrip properties.
//!
//! These tests exercise small, valid wire fragments only. They are intended for
//! normal `cargo test`, not broad fuzzing.

use crafter::{QuicConnectionId, QuicFrame, QuicPacketNumber, QuicTransportParameter, QuicVarInt};
use proptest::prelude::*;

fn packet_number_value_for_len() -> impl Strategy<Value = (usize, u64)> {
    prop_oneof![
        (Just(1usize), 0u64..=0xff),
        (Just(2usize), 0u64..=0xffff),
        (Just(3usize), 0u64..=0xff_ffff),
        (Just(4usize), 0u64..=0xffff_ffff),
    ]
}

fn varint_value_for_len() -> impl Strategy<Value = (usize, u64)> {
    prop_oneof![
        (Just(1usize), 0u64..=63),
        (Just(2usize), 0u64..=16_383),
        (Just(4usize), 0u64..=1_000_000),
        (Just(8usize), 0u64..=1_000_000),
    ]
}

fn small_bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max_len)
}

fn quic_property_frame_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(vec![0x01]),
        small_bytes(8).prop_map(|data| {
            let mut bytes = vec![0x06, 0x00, data.len() as u8];
            bytes.extend(data);
            bytes
        }),
        small_bytes(8).prop_map(|data| {
            let mut bytes = vec![0x31, data.len() as u8];
            bytes.extend(data);
            bytes
        }),
    ]
}

fn quic_property_transport_parameter() -> impl Strategy<Value = QuicTransportParameter> {
    (0x40u64..=0x7f, small_bytes(8)).prop_map(|(identifier, value)| {
        QuicTransportParameter::raw(QuicVarInt::from_u64_unchecked(identifier), value)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn quic_property_varint_shortest_encode_decodes(value in 0u64..(1u64 << 62)) {
        let varint = QuicVarInt::new(value).expect("generated value is in QUIC varint range");
        let mut encoded = Vec::new();
        let encoded_len = varint.encode(&mut encoded).expect("generated varint should encode");
        let (decoded, consumed) = QuicVarInt::decode(&encoded).expect("encoded varint should decode");

        prop_assert_eq!(decoded.value(), value);
        prop_assert_eq!(consumed, encoded_len);
        prop_assert_eq!(consumed, encoded.len());
        prop_assert_eq!(varint.encode_to_vec().expect("varint should encode to vec"), encoded);
    }

    #[test]
    fn quic_property_varint_explicit_lengths_roundtrip((encoded_len, value) in varint_value_for_len()) {
        let varint = QuicVarInt::from_u64_unchecked(value);
        let mut encoded = Vec::new();
        varint
            .encode_with_len(encoded_len, &mut encoded)
            .expect("generated value fits explicit QUIC varint length");
        let (decoded, consumed) = QuicVarInt::decode(&encoded).expect("explicit-length varint should decode");

        prop_assert_eq!(decoded.value(), value);
        prop_assert_eq!(consumed, encoded_len);
        prop_assert_eq!(encoded.len(), encoded_len);
    }

    #[test]
    fn quic_property_packet_numbers_explicit_lengths_roundtrip((encoded_len, value) in packet_number_value_for_len()) {
        let packet_number = QuicPacketNumber::new(value).with_encoded_len(encoded_len);
        let encoded = packet_number
            .encode_to_vec()
            .expect("generated packet number should encode");
        let (decoded, consumed) = QuicPacketNumber::decode(&encoded, encoded_len)
            .expect("encoded packet number should decode");

        prop_assert_eq!(decoded.value(), value);
        prop_assert_eq!(decoded.encoded_len_value(), Some(encoded_len));
        prop_assert_eq!(consumed, encoded_len);
        prop_assert_eq!(encoded.len(), encoded_len);
    }

    #[test]
    fn quic_property_connection_ids_preserve_generated_bytes(bytes in small_bytes(20)) {
        let cid = QuicConnectionId::try_from_bytes(&bytes)
            .expect("generated connection ID fits QUIC v1/v2 length limit");
        let infallible_cid = QuicConnectionId::from_bytes(&bytes);
        prop_assert_eq!(cid.as_bytes(), bytes.as_slice());
        prop_assert_eq!(infallible_cid.as_bytes(), bytes.as_slice());
        prop_assert_eq!(cid.to_hex(), infallible_cid.to_hex());
    }

    #[test]
    fn quic_property_frame_sequences_roundtrip(
        frames in prop::collection::vec(quic_property_frame_bytes(), 0..=8),
    ) {
        let encoded = frames.into_iter().flatten().collect::<Vec<_>>();
        let decoded = QuicFrame::decode_sequence(&encoded)
            .expect("generated frame sequence should decode");
        prop_assert_eq!(QuicFrame::encode_sequence(decoded), encoded);
    }

    #[test]
    fn quic_property_transport_parameter_sequences_roundtrip(
        parameters in prop::collection::vec(quic_property_transport_parameter(), 0..=8),
    ) {
        let encoded = QuicTransportParameter::encode_sequence(parameters)
            .expect("generated transport parameters should encode");
        let decoded = QuicTransportParameter::decode_sequence(&encoded)
            .expect("generated transport parameter sequence should decode");
        prop_assert_eq!(
            QuicTransportParameter::encode_sequence(decoded)
                .expect("decoded transport parameters should re-encode"),
            encoded
        );
    }
}
