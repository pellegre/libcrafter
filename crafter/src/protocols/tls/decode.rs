//! TLS decode entrypoints.
//!
//! TLS over TCP is record-framed, so one byte stream segment can contain one
//! complete record, multiple complete records, or a complete record followed by
//! a partial tail. This module decodes byte-complete record frames; record
//! bodies may expose typed handshake messages while encrypted or unsupported
//! content stays opaque.

use crate::packet::{Packet, Raw};
use crate::registry::ProtocolRegistry;
use crate::{CrafterError, Result};

use super::constants::{
    TLS_CONTENT_TYPE_ALERT, TLS_CONTENT_TYPE_APPLICATION_DATA, TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    TLS_CONTENT_TYPE_HANDSHAKE, TLS_CONTENT_TYPE_HEARTBEAT, TLS_VERSION_1_0, TLS_VERSION_1_1,
    TLS_VERSION_1_2, TLS_VERSION_SSL_3_0,
};
use super::{Tls, TlsRecord, TLS_RECORD_HEADER_LEN};

/// Return true when a TCP payload is plausible TLS-over-TCP record data.
///
/// The gate is deliberately narrower than the raw-preserving TLS record model:
/// it recognizes selected TLS-over-TCP record content types, SSLv3/TLS legacy
/// record-version values, and at least one complete record that this crate can
/// decode. After that valid anchor, a trailing partial record header or
/// fragment is allowed so segmented streams can still route to TLS with a raw
/// tail.
pub(crate) fn looks_like_tls_payload(payload: &[u8]) -> bool {
    let mut remaining = payload;
    let mut complete_records = 0usize;

    while !remaining.is_empty() {
        if remaining.len() < TLS_RECORD_HEADER_LEN {
            return complete_records > 0;
        }

        if !looks_like_tls_record_header(remaining) {
            return false;
        }

        let fragment_len = u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
        let required = TLS_RECORD_HEADER_LEN + fragment_len;
        if remaining.len() < required {
            return complete_records > 0;
        }

        match TlsRecord::decode_with_consumed(remaining) {
            Ok((_record, consumed)) if consumed == required => {
                complete_records += 1;
                remaining = &remaining[consumed..];
            }
            _ => return false,
        }
    }

    complete_records > 0
}

fn looks_like_tls_record_header(bytes: &[u8]) -> bool {
    if bytes.len() < TLS_RECORD_HEADER_LEN {
        return false;
    }

    looks_like_tls_record_content_type(bytes[0])
        && looks_like_tls_legacy_record_version(u16::from_be_bytes([bytes[1], bytes[2]]))
}

fn looks_like_tls_record_content_type(content_type: u8) -> bool {
    matches!(
        content_type,
        TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC
            | TLS_CONTENT_TYPE_ALERT
            | TLS_CONTENT_TYPE_HANDSHAKE
            | TLS_CONTENT_TYPE_APPLICATION_DATA
            | TLS_CONTENT_TYPE_HEARTBEAT
    )
}

fn looks_like_tls_legacy_record_version(version: u16) -> bool {
    matches!(
        version,
        TLS_VERSION_SSL_3_0 | TLS_VERSION_1_0 | TLS_VERSION_1_1 | TLS_VERSION_1_2
    )
}

/// Decode one or more complete TLS records from a TCP payload into `packet`.
///
/// Complete records are appended as one ordered [`Tls`] layer. Once at least
/// one record has decoded successfully, any trailing bytes that do not form
/// another complete record are preserved as a single [`Raw`] tail. If the first
/// record is malformed or partial, the structured [`CrafterError`] from the
/// record decoder is returned because there is no valid framing anchor to
/// attach a raw tail to.
#[allow(dead_code)]
pub(crate) fn append_tls_packet_with_registry(
    _registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    decode_tls_payload_from(packet, bytes)
}

fn decode_tls_payload_from(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let mut remaining = bytes;
    let mut records = Vec::new();

    while !remaining.is_empty() {
        match TlsRecord::decode_with_consumed(remaining) {
            Ok((record, consumed)) if consumed > 0 => {
                records.push(record);
                remaining = &remaining[consumed..];
            }
            Ok((_record, _consumed)) => {
                if !records.is_empty() {
                    packet = packet.push(Tls::from_records(records));
                    packet = packet.push_raw(Raw::from_bytes(remaining));
                    return Ok(packet);
                }
                return Err(CrafterError::invalid_field_value(
                    "tls.record.length",
                    "decoded record consumed no bytes",
                ));
            }
            Err(_err) if !records.is_empty() => {
                packet = packet.push(Tls::from_records(records));
                packet = packet.push_raw(Raw::from_bytes(remaining));
                return Ok(packet);
            }
            Err(err) => return Err(err),
        }
    }

    if !records.is_empty() {
        packet = packet.push(Tls::from_records(records));
    }

    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Packet, Raw};
    use crate::protocols::tls::constants::TLS_COMMON_TCP_PORTS;
    use crate::protocols::tls::{
        TlsClientHello, TlsContentType, TlsHandshake, TlsHandshakeType, TlsHeartbeat,
        TlsRecordBody, TlsVersion, TLS_HEARTBEAT_MIN_PADDING_LEN, TLS_RECORD_HEADER_LEN,
    };

    fn tls_registry_gate_client_hello_payload() -> Result<Vec<u8>> {
        let client_hello = TlsClientHello::new()
            .with_raw_cipher_suites([0x1301])
            .without_extensions();
        let client_hello_message =
            TlsHandshake::from_client_hello(client_hello)?.encode_to_vec()?;
        let record = TlsRecord::handshake(client_hello_message);
        record.encode_to_vec()
    }

    #[test]
    fn tls_registry_gate_accepts_complete_tls_records() -> Result<()> {
        assert!(looks_like_tls_payload(
            &tls_registry_gate_client_hello_payload()?
        ));
        assert!(looks_like_tls_payload(
            &TlsRecord::alert([0x01, 0x00]).encode_to_vec()?
        ));
        assert!(looks_like_tls_payload(
            &TlsRecord::change_cipher_spec([0x01]).encode_to_vec()?
        ));
        assert!(looks_like_tls_payload(
            &TlsRecord::application_data(b"abc").encode_to_vec()?
        ));

        let heartbeat = TlsHeartbeat::request([0xaa, 0xbb], [0x55; TLS_HEARTBEAT_MIN_PADDING_LEN]);
        assert!(looks_like_tls_payload(
            &TlsRecord::from_heartbeat(heartbeat)?.encode_to_vec()?
        ));

        Ok(())
    }

    #[test]
    fn tls_registry_gate_accepts_partial_tail_only_after_complete_anchor() -> Result<()> {
        let mut payload = TlsRecord::application_data(b"abc").encode_to_vec()?;
        payload.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x04, 0xde]);
        assert!(looks_like_tls_payload(&payload));

        let mut payload = TlsRecord::application_data(b"abc").encode_to_vec()?;
        payload.extend_from_slice(&[0x16, 0x03]);
        assert!(looks_like_tls_payload(&payload));

        assert!(!looks_like_tls_payload(&[0x16, 0x03, 0x03, 0x00]));
        assert!(!looks_like_tls_payload(&[
            0x16, 0x03, 0x03, 0x00, 0x04, 0xde
        ]));

        Ok(())
    }

    #[test]
    fn tls_registry_gate_rejects_non_tls_headers_and_malformed_first_records() {
        assert!(!looks_like_tls_payload(b""));
        assert!(!looks_like_tls_payload(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_tls_payload(&[
            0xfe, 0x03, 0x03, 0x00, 0x02, 0xde, 0xad
        ]));
        assert!(!looks_like_tls_payload(&[0x16, 0xfe, 0xfd, 0x00, 0x00]));
        assert!(!looks_like_tls_payload(&[0x14, 0x03, 0x03, 0x00, 0x00]));
    }

    #[test]
    fn tls_registry_gate_rejects_non_tls_payloads_on_tls_ports() {
        let non_tls_payloads: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
            b"SSH-2.0-OpenSSH_9.6\r\n",
            &[0x10, 0x10, 0x00, 0x04, b'M', b'Q', b'T', b'T'],
            &[0x16, 0xfe, 0xfd, 0x00, 0x00],
        ];

        for port in TLS_COMMON_TCP_PORTS {
            for payload in non_tls_payloads {
                assert!(
                    !looks_like_tls_payload(payload),
                    "payload on TCP/{port} should not pass TLS gate: {payload:02x?}"
                );
            }
        }
    }

    #[test]
    fn tls_multi_record_decode_appends_ordered_tls_layers() -> Result<()> {
        let client_hello = TlsClientHello::new()
            .with_raw_cipher_suites([0x1301])
            .without_extensions();
        let client_hello_message =
            TlsHandshake::from_client_hello(client_hello)?.encode_to_vec()?;
        let mut payload = vec![
            0x16,
            0x03,
            0x03,
            ((client_hello_message.len() >> 8) & 0xff) as u8,
            (client_hello_message.len() & 0xff) as u8,
        ];
        payload.extend_from_slice(&client_hello_message);
        payload.extend_from_slice(&[0x15, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00]);

        let packet =
            append_tls_packet_with_registry(&ProtocolRegistry::empty(), Packet::new(), &payload)?;
        let names = packet.iter().map(|layer| layer.name()).collect::<Vec<_>>();
        let tls_layers = packet.layers::<Tls>().collect::<Vec<_>>();

        assert_eq!(names, ["TLS"]);
        assert_eq!(tls_layers.len(), 1);
        assert_eq!(tls_layers[0].record_count(), 2);
        assert_eq!(
            tls_layers[0].records()[0].content_type(),
            TlsContentType::handshake()
        );
        assert_eq!(
            tls_layers[0].records()[0].fragment(),
            client_hello_message.as_slice()
        );
        let TlsRecordBody::Handshake(handshake) = tls_layers[0].records()[0].body() else {
            panic!("handshake record should decode typed handshake body");
        };
        assert_eq!(handshake.messages().len(), 1);
        assert_eq!(
            handshake.messages()[0].handshake_type(),
            TlsHandshakeType::CLIENT_HELLO
        );
        assert!(handshake.raw_tail().is_empty());
        assert_eq!(
            tls_layers[0].records()[1].content_type(),
            TlsContentType::alert()
        );
        assert_eq!(
            tls_layers[0].records()[1].legacy_record_version(),
            TlsVersion::tls_1_0()
        );
        assert_eq!(tls_layers[0].records()[1].fragment(), &[0x01, 0x00]);
        assert_eq!(packet.compile()?.as_bytes(), payload.as_slice());
        Ok(())
    }

    #[test]
    fn tls_multi_record_decode_preserves_trailing_partial_tail_as_raw() -> Result<()> {
        let payload = [
            0x17, 0x03, 0x03, 0x00, 0x03, b'a', b'b', b'c', 0x16, 0x03, 0x03, 0x00, 0x04, 0xde,
        ];

        let packet =
            append_tls_packet_with_registry(&ProtocolRegistry::empty(), Packet::new(), &payload)?;
        let names = packet.iter().map(|layer| layer.name()).collect::<Vec<_>>();
        let tls_layers = packet.layers::<Tls>().collect::<Vec<_>>();
        let raw = packet.layer::<Raw>().expect("partial TLS tail is Raw");

        assert_eq!(names, ["TLS", "Raw"]);
        assert_eq!(tls_layers.len(), 1);
        assert_eq!(
            tls_layers[0].records()[0].content_type(),
            TlsContentType::application_data()
        );
        assert_eq!(tls_layers[0].records()[0].fragment(), b"abc");
        assert_eq!(raw.as_bytes(), &[0x16, 0x03, 0x03, 0x00, 0x04, 0xde]);
        assert_eq!(packet.compile()?.as_bytes(), &payload);
        Ok(())
    }

    #[test]
    fn tls_multi_record_decode_errors_when_first_record_is_partial() {
        let short_header = [0x16, 0x03, 0x03, 0x00];
        let short_fragment = [0x16, 0x03, 0x03, 0x00, 0x04, 0xaa];

        assert_eq!(
            append_tls_packet_with_registry(
                &ProtocolRegistry::empty(),
                Packet::new(),
                &short_header
            )
            .unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.record.header",
                TLS_RECORD_HEADER_LEN,
                short_header.len()
            )
        );
        assert_eq!(
            append_tls_packet_with_registry(
                &ProtocolRegistry::empty(),
                Packet::new(),
                &short_fragment
            )
            .unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.record.fragment",
                TLS_RECORD_HEADER_LEN + 4,
                short_fragment.len()
            )
        );
    }
}
