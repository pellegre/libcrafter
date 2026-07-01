//! TLS malformed decode resilience coverage.
//!
//! These tests are offline-only and assert that malformed TLS inputs either
//! decode successfully with raw preservation or fail with a structured
//! `CrafterError`, never a panic.

#[macro_use]
mod support;

use std::panic::{catch_unwind, AssertUnwindSafe};

use crafter::prelude::*;
use crafter::protocols::tls::vector::TlsVectorBounds;
use crafter::protocols::tls::{
    TlsAlpnProtocols, TlsCertificateAuthorities, TlsExtensionListContext, TlsExtensions,
    TlsHandshake, TlsHandshakeHeader, TlsKeyShare, TlsPreSharedKey, TlsRawExtension, TlsRecord,
    TlsRecordHeader, TlsServerNameList, TlsSupportedVersions,
};
use crafter::wire::backend::pcap::{
    PcapError, PcapLinkType, PcapReader, PcapRecord, PcapTimestamp, PcapWriter,
};
use crafter::CrafterError;

const PARTIAL_TLS_RECORD_HEADER: &[u8] = &[0x16, 0x03, 0x03, 0x00];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedDecode {
    StructuredError,
    Success,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandaloneTarget {
    Record,
    RecordHeader,
    RecordTailAfterValid,
    Handshake,
    HandshakeHeader,
    HandshakeRecordFragment,
    RawExtension,
    ExtensionListClient,
    ServerNameList,
    AlpnProtocols,
    SupportedVersionsClient,
    KeyShareClient,
    PreSharedKeyClient,
    CertificateAuthorities,
    VectorU8,
    VectorU16,
    VectorU24,
}

#[derive(Debug, Clone, Copy)]
struct StandaloneCase {
    name: &'static str,
    target: StandaloneTarget,
    expected: ExpectedDecode,
    bytes: &'static [u8],
}

#[derive(Debug, Clone, Copy)]
enum PacketExpectation {
    RawFallback,
    TlsThenRawTail(&'static [u8]),
}

#[derive(Debug)]
struct PcapDerivedCase {
    name: &'static str,
    bytes: Vec<u8>,
    expected: PacketExpectation,
}

#[test]
fn tls_resilience_standalone_helpers_never_panic() {
    for case in standalone_cases() {
        let decoded = catch_unwind(AssertUnwindSafe(|| decode_standalone_case(case)))
            .unwrap_or_else(|_| panic!("TLS resilience case {} panicked", case.name));
        assert_expected_decode(case.name, case.expected, decoded);
    }
}

#[test]
fn tls_resilience_pcap_derived_packet_entrypoints_never_panic() {
    for case in pcap_derived_cases() {
        let direct = catch_unwind(AssertUnwindSafe(|| PcapLinkType::RawIp.decode(&case.bytes)))
            .unwrap_or_else(|_| panic!("TLS pcap-derived case {} panicked", case.name));
        assert_packet_result(case.name, case.expected, direct);

        let pcap = wrap_raw_ip_pcap_record(&case);
        let packets = catch_unwind(AssertUnwindSafe(|| {
            PcapReader::from_reader(pcap.as_slice())?.collect_packets()
        }))
        .unwrap_or_else(|_| panic!("TLS pcap reader case {} panicked", case.name));
        assert_pcap_result(case.name, case.expected, packets);
    }
}

#[test]
fn tls_resilience_vector_cursor_decode_never_panics_or_advances_on_error() {
    let bounds = TlsVectorBounds::u16(
        0,
        8,
        "tls.resilience.cursor_vector",
        "tls.resilience.cursor_vector.length",
    );
    let mut cursor = 1usize;
    let bytes = [0x55, 0x00, 0x04, 0xaa];

    let decoded = catch_unwind(AssertUnwindSafe(|| {
        bounds.decode_from(&bytes, &mut cursor).map(drop)
    }))
    .unwrap_or_else(|_| panic!("TLS vector cursor decode panicked"));

    assert_expected_decode(
        "vector-cursor-body-overrun",
        ExpectedDecode::StructuredError,
        decoded,
    );
    assert_eq!(
        cursor, 1,
        "TLS vector cursor must not advance after a decode error"
    );
}

fn standalone_cases() -> &'static [StandaloneCase] {
    &[
        StandaloneCase {
            name: "record-empty",
            target: StandaloneTarget::Record,
            expected: ExpectedDecode::StructuredError,
            bytes: &[],
        },
        StandaloneCase {
            name: "record-short-header",
            target: StandaloneTarget::RecordHeader,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x16, 0x03, 0x03, 0x00],
        },
        StandaloneCase {
            name: "record-declared-length-overrun",
            target: StandaloneTarget::Record,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x16, 0x03, 0x03, 0x00, 0x04, 0xaa],
        },
        StandaloneCase {
            name: "record-valid-anchor-partial-tail",
            target: StandaloneTarget::RecordTailAfterValid,
            expected: ExpectedDecode::StructuredError,
            bytes: &[
                0x17, 0x03, 0x03, 0x00, 0x03, b'a', b'b', b'c', 0x16, 0x03, 0x03, 0x00, 0x04, 0xde,
            ],
        },
        StandaloneCase {
            name: "record-unknown-content-type-preserved",
            target: StandaloneTarget::Record,
            expected: ExpectedDecode::Success,
            bytes: &[0xfe, 0x42, 0x42, 0x00, 0x02, 0xde, 0xad],
        },
        StandaloneCase {
            name: "handshake-short-header",
            target: StandaloneTarget::HandshakeHeader,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x01, 0x00, 0x00],
        },
        StandaloneCase {
            name: "handshake-declared-body-overrun",
            target: StandaloneTarget::Handshake,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x01, 0x00, 0x00, 0x04, 0xaa],
        },
        StandaloneCase {
            name: "handshake-clienthello-short-cipher-suite-vector",
            target: StandaloneTarget::Handshake,
            expected: ExpectedDecode::StructuredError,
            bytes: &[
                0x01, 0x00, 0x00, 0x27, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x04,
                0x13, 0x01,
            ],
        },
        StandaloneCase {
            name: "handshake-record-fragment-raw-tail",
            target: StandaloneTarget::HandshakeRecordFragment,
            expected: ExpectedDecode::Success,
            bytes: &[0xfa, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x04, 0xaa],
        },
        StandaloneCase {
            name: "extension-short-header",
            target: StandaloneTarget::RawExtension,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x00, 0x00, 0x00],
        },
        StandaloneCase {
            name: "extension-list-body-overrun",
            target: StandaloneTarget::ExtensionListClient,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x00, 0x04, 0xbe],
        },
        StandaloneCase {
            name: "extension-sni-list-overrun",
            target: StandaloneTarget::ServerNameList,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x00, 0x04, 0x00, 0x00],
        },
        StandaloneCase {
            name: "extension-alpn-name-overrun",
            target: StandaloneTarget::AlpnProtocols,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x00, 0x02, 0x03, b'h'],
        },
        StandaloneCase {
            name: "extension-supported-versions-odd-length",
            target: StandaloneTarget::SupportedVersionsClient,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x01, 0x03],
        },
        StandaloneCase {
            name: "extension-key-share-vector-overrun",
            target: StandaloneTarget::KeyShareClient,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x00, 0x05, 0x00, 0x1d, 0x00, 0x02, 0xaa],
        },
        StandaloneCase {
            name: "extension-psk-binder-overrun",
            target: StandaloneTarget::PreSharedKeyClient,
            expected: ExpectedDecode::StructuredError,
            bytes: &[
                0x00, 0x07, 0x00, 0x01, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x21, 0x21, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb,
            ],
        },
        StandaloneCase {
            name: "extension-certificate-authorities-overrun",
            target: StandaloneTarget::CertificateAuthorities,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x00, 0x04, 0x00, 0x03, 0xaa, 0xbb],
        },
        StandaloneCase {
            name: "vector-u8-prefix-short",
            target: StandaloneTarget::VectorU8,
            expected: ExpectedDecode::StructuredError,
            bytes: &[],
        },
        StandaloneCase {
            name: "vector-u16-body-overrun",
            target: StandaloneTarget::VectorU16,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x00, 0x04, 0xaa, 0xbb],
        },
        StandaloneCase {
            name: "vector-u24-body-overrun",
            target: StandaloneTarget::VectorU24,
            expected: ExpectedDecode::StructuredError,
            bytes: &[0x00, 0x00, 0x04, 0xaa],
        },
        StandaloneCase {
            name: "vector-u8-valid-zero",
            target: StandaloneTarget::VectorU8,
            expected: ExpectedDecode::Success,
            bytes: &[0x00],
        },
    ]
}

fn decode_standalone_case(case: &StandaloneCase) -> crafter::Result<()> {
    match case.target {
        StandaloneTarget::Record => TlsRecord::decode(case.bytes).map(drop),
        StandaloneTarget::RecordHeader => TlsRecordHeader::decode(case.bytes).map(drop),
        StandaloneTarget::RecordTailAfterValid => {
            let (_record, tail) = TlsRecord::decode_prefix(case.bytes)?;
            TlsRecord::decode(tail).map(drop)
        }
        StandaloneTarget::Handshake => TlsHandshake::decode(case.bytes).map(drop),
        StandaloneTarget::HandshakeHeader => TlsHandshakeHeader::decode(case.bytes).map(drop),
        StandaloneTarget::HandshakeRecordFragment => {
            let encoded = TlsRecord::handshake(case.bytes.to_vec()).encode_to_vec()?;
            TlsRecord::decode(encoded).map(drop)
        }
        StandaloneTarget::RawExtension => TlsRawExtension::decode(case.bytes).map(drop),
        StandaloneTarget::ExtensionListClient => {
            TlsExtensions::decode_with_context(TlsExtensionListContext::client_hello(), case.bytes)
                .map(drop)
        }
        StandaloneTarget::ServerNameList => TlsServerNameList::decode(case.bytes).map(drop),
        StandaloneTarget::AlpnProtocols => TlsAlpnProtocols::decode(case.bytes).map(drop),
        StandaloneTarget::SupportedVersionsClient => {
            TlsSupportedVersions::decode_client(case.bytes).map(drop)
        }
        StandaloneTarget::KeyShareClient => TlsKeyShare::decode_client(case.bytes).map(drop),
        StandaloneTarget::PreSharedKeyClient => {
            TlsPreSharedKey::decode_client(case.bytes).map(drop)
        }
        StandaloneTarget::CertificateAuthorities => {
            TlsCertificateAuthorities::decode(case.bytes).map(drop)
        }
        StandaloneTarget::VectorU8 => TlsVectorBounds::u8(
            0,
            4,
            "tls.resilience.u8_vector",
            "tls.resilience.u8_vector.length",
        )
        .decode_prefix(case.bytes)
        .map(drop),
        StandaloneTarget::VectorU16 => TlsVectorBounds::u16(
            0,
            8,
            "tls.resilience.u16_vector",
            "tls.resilience.u16_vector.length",
        )
        .decode_prefix(case.bytes)
        .map(drop),
        StandaloneTarget::VectorU24 => TlsVectorBounds::u24(
            0,
            8,
            "tls.resilience.u24_vector",
            "tls.resilience.u24_vector.length",
        )
        .decode_prefix(case.bytes)
        .map(drop),
    }
}

fn pcap_derived_cases() -> Vec<PcapDerivedCase> {
    let base = first_raw_ip_tls_fixture_record();
    let payload_offset = ipv4_tcp_payload_offset(&base);

    let mut first_record_overrun = base.clone();
    let length_offset = payload_offset + 3;
    let length = u16::from_be_bytes([
        first_record_overrun[length_offset],
        first_record_overrun[length_offset + 1],
    ]);
    first_record_overrun[length_offset..length_offset + 2]
        .copy_from_slice(&(length + 1).to_be_bytes());

    let mut partial_tail_after_valid_record = base;
    partial_tail_after_valid_record.extend_from_slice(PARTIAL_TLS_RECORD_HEADER);
    set_ipv4_total_length_to_buffer_len(&mut partial_tail_after_valid_record);

    vec![
        PcapDerivedCase {
            name: "pcap-derived-first-record-length-overrun",
            bytes: first_record_overrun,
            expected: PacketExpectation::RawFallback,
        },
        PcapDerivedCase {
            name: "pcap-derived-complete-record-with-partial-tail",
            bytes: partial_tail_after_valid_record,
            expected: PacketExpectation::TlsThenRawTail(PARTIAL_TLS_RECORD_HEADER),
        },
    ]
}

fn first_raw_ip_tls_fixture_record() -> Vec<u8> {
    let records = PcapReader::from_reader(
        fixture_bytes!("pcaps/raw-ipv4-tcp-tls-client-hello.pcap").as_slice(),
    )
    .expect("TLS pcap fixture should parse header")
    .collect_records()
    .expect("TLS pcap fixture should read records");

    records
        .first()
        .expect("TLS pcap fixture should have at least one record")
        .data()
        .to_vec()
}

fn ipv4_tcp_payload_offset(bytes: &[u8]) -> usize {
    assert!(
        bytes.len() >= 40,
        "pcap-derived TLS packet should contain IPv4 and TCP headers"
    );
    assert_eq!(bytes[0] >> 4, 4, "pcap-derived packet must be IPv4");
    assert_eq!(bytes[9], 6, "pcap-derived packet must carry TCP");

    let ipv4_header_len = usize::from(bytes[0] & 0x0f) * 4;
    let tcp_offset = ipv4_header_len;
    assert!(
        bytes.len() >= tcp_offset + 20,
        "pcap-derived packet must contain a complete TCP header"
    );

    let tcp_header_len = usize::from(bytes[tcp_offset + 12] >> 4) * 4;
    assert!(
        tcp_header_len >= 20,
        "pcap-derived packet TCP data offset must be at least 20 bytes"
    );
    assert!(
        bytes.len() >= tcp_offset + tcp_header_len,
        "pcap-derived packet must contain the declared TCP header"
    );

    tcp_offset + tcp_header_len
}

fn set_ipv4_total_length_to_buffer_len(bytes: &mut [u8]) {
    let total_len = u16::try_from(bytes.len()).expect("pcap-derived packet fits IPv4 length");
    bytes[2..4].copy_from_slice(&total_len.to_be_bytes());
}

fn wrap_raw_ip_pcap_record(case: &PcapDerivedCase) -> Vec<u8> {
    let record = PcapRecord::new(
        PcapTimestamp::micros(92, 0).expect("pcap timestamp should be valid"),
        case.bytes.len() as u32,
        case.bytes.clone(),
        PcapLinkType::RawIp,
    )
    .expect("pcap-derived record should be valid");

    let mut pcap = Vec::new();
    {
        let mut writer = PcapWriter::from_writer(&mut pcap, PcapLinkType::RawIp)
            .expect("pcap writer should initialize");
        writer
            .write_record(&record)
            .expect("pcap writer should accept raw IP record");
        writer.flush().expect("pcap writer should flush");
    }
    pcap
}

fn assert_expected_decode(name: &str, expected: ExpectedDecode, result: crafter::Result<()>) {
    match (expected, result) {
        (ExpectedDecode::Success, Ok(())) => {}
        (ExpectedDecode::Success, Err(err)) => {
            panic!("TLS resilience case {name} expected decode success, got {err:?}");
        }
        (ExpectedDecode::StructuredError, Ok(())) => {
            panic!("TLS resilience case {name} expected a structured error");
        }
        (ExpectedDecode::StructuredError, Err(err)) => assert_structured_error(name, err),
    }
}

fn assert_packet_result(name: &str, expected: PacketExpectation, result: crafter::Result<Packet>) {
    match result {
        Ok(packet) => assert_packet_expectation(name, expected, &packet),
        Err(err) => assert_structured_error(name, err),
    }
}

fn assert_pcap_result(
    name: &str,
    expected: PacketExpectation,
    result: std::result::Result<Vec<crafter::wire::backend::pcap::PcapPacket>, PcapError>,
) {
    match result {
        Ok(packets) => {
            assert_eq!(packets.len(), 1, "TLS pcap case {name} packet count");
            assert_packet_expectation(name, expected, packets[0].packet());
        }
        Err(PcapError::Packet(err)) => assert_structured_error(name, err),
        Err(other) => panic!("TLS pcap case {name} returned non-packet error {other:?}"),
    }
}

fn assert_packet_expectation(name: &str, expected: PacketExpectation, packet: &Packet) {
    let _ = packet.summary();
    let _ = packet.show();
    let _ = packet.compile();

    match expected {
        PacketExpectation::RawFallback => {
            assert!(
                packet.layer::<Tls>().is_none(),
                "TLS pcap case {name} should remain raw after malformed first record"
            );
            assert!(
                packet.layer::<Raw>().is_some(),
                "TLS pcap case {name} should preserve malformed payload as Raw"
            );
        }
        PacketExpectation::TlsThenRawTail(expected_tail) => {
            assert!(
                packet.layer::<Tls>().is_some(),
                "TLS pcap case {name} should decode the complete TLS anchor"
            );
            assert!(
                packet
                    .layers::<Raw>()
                    .any(|raw| raw.as_bytes() == expected_tail),
                "TLS pcap case {name} should preserve the trailing partial record as Raw"
            );
        }
    }
}

fn assert_structured_error(name: &str, err: CrafterError) {
    match err {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert!(
                !context.is_empty(),
                "TLS resilience case {name} returned an empty buffer context"
            );
            assert!(
                required > available,
                "TLS resilience case {name} BufferTooShort must require more bytes than available"
            );
        }
        CrafterError::InvalidFieldValue { field, reason } => {
            assert!(
                !field.is_empty(),
                "TLS resilience case {name} returned an empty invalid-field name"
            );
            assert!(
                !reason.is_empty(),
                "TLS resilience case {name} returned an empty invalid-field reason"
            );
        }
        CrafterError::InvalidMacAddress { .. } => {
            panic!("TLS resilience case {name} returned an unrelated MAC address error");
        }
    }
}
