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

use super::{Tls, TlsRecord};

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
    use crate::protocols::tls::{
        TlsClientHello, TlsContentType, TlsHandshake, TlsHandshakeType, TlsRecordBody, TlsVersion,
        TLS_RECORD_HEADER_LEN,
    };

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
