//! IKEv2 message decode: header + Next Payload chain, and the registry hook
//! (RFC 7296 §3.1–§3.2).
//!
//! An IKEv2 message is a fixed 28-octet header followed by a linked chain of
//! generic payloads. The header's Next Payload names the type of the *first*
//! payload; each generic payload header's Next Payload names the type of the
//! payload that *follows* it, and a Next Payload of `0` terminates the chain
//! (RFC 7296 §3.2). This module walks that chain, building one typed payload
//! layer per link (Steps 35–44) or a preserved [`Raw`] payload for a payload
//! type this build does not model — matching the crate's unknown-next-protocol
//! contract.
//!
//! The header carries the total message Length (RFC 7296 §3.1). The decode
//! validates it against the buffer it was handed: a Length shorter than the
//! 28-octet header, or longer than the available bytes, is a structured error
//! (`context`, `required`, `available`) rather than a panic. The chain walk
//! itself is driven by each generic header's own Payload Length, so the decode
//! is robust to a Length that merely over-counts trailing bytes; it only fails
//! when a payload runs off the end of the buffer.
//!
//! The Encrypted (SK) payload (type 46) is decoded *opaquely* here: the built-in
//! registry carries no Security Association, so its inner payloads cannot be
//! decrypted (RFC 7296 §3.14). The whole SK payload — generic header plus the
//! `IV || ciphertext || ICV` body — is preserved verbatim as a [`Raw`] layer so
//! the encrypted bytes survive and the message re-compiles byte-for-byte. A
//! caller that holds keys decodes the SK payload with
//! [`decode_sk_payload_with_sa`](super::payload::encrypted::decode_sk_payload_with_sa).

use crate::endian::read_u32_be;
use crate::error::{CrafterError, Result};
use crate::packet::{Packet, Raw};
use crate::registry::ProtocolRegistry;

use super::header::{IkeHeader, IKE_HEADER_LEN};
use super::payload::auth::parse_auth_payload_body;
use super::payload::cert::{parse_cert_payload_body, parse_certreq_payload_body};
use super::payload::config::parse_config_payload_body;
use super::payload::delete::parse_delete_payload_body;
use super::payload::eap::parse_eap_payload_body;
use super::payload::id::{parse_id_payload_body, IdRole};
use super::payload::ke::parse_ke_payload_body;
use super::payload::nonce::parse_nonce_payload_body;
use super::payload::notify::parse_notify_payload_body;
use super::payload::sa::parse_sa_payload_body;
use super::payload::ts::{parse_ts_payload_body, TsRole};
use super::payload::vendor::parse_vendor_id_payload_body;
use super::payload::{PayloadType, GENERIC_PAYLOAD_HEADER_LEN};

fn read_u64_be_field(
    bytes: &[u8],
    range: std::ops::Range<usize>,
    context: &'static str,
) -> Result<u64> {
    let field = bytes
        .get(range.clone())
        .ok_or_else(|| CrafterError::buffer_too_short(context, range.end, bytes.len()))?;
    let field: [u8; 8] = field
        .try_into()
        .map_err(|_| CrafterError::buffer_too_short(context, range.end, bytes.len()))?;
    Ok(u64::from_be_bytes(field))
}

/// Read the 28-octet IKE header (RFC 7296 §3.1) into an [`IkeHeader`] layer.
///
/// Every field is stored with `Field::user` (through the builder setters) so a
/// re-compile reproduces the decoded header byte-for-byte, including the on-wire
/// Next Payload and total Length rather than the auto-filled values. A buffer
/// shorter than the 28-octet header is a structured
/// [`CrafterError::buffer_too_short`] — never a panic.
fn parse_ike_header(bytes: &[u8]) -> Result<IkeHeader> {
    if bytes.len() < IKE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.header",
            IKE_HEADER_LEN,
            bytes.len(),
        ));
    }

    let initiator_spi = read_u64_be_field(bytes, 0..8, "ikev2.header.initiator_spi")?;
    let responder_spi = read_u64_be_field(bytes, 8..16, "ikev2.header.responder_spi")?;
    let next_payload = bytes[16];
    let version = bytes[17];
    let exchange_type = bytes[18];
    let flags = bytes[19];
    let message_id = read_u32_be(&bytes[20..24])?;
    let length = read_u32_be(&bytes[24..28])?;

    Ok(IkeHeader::new()
        .initiator_spi(initiator_spi)
        .responder_spi(responder_spi)
        .next_payload(next_payload)
        .version(version)
        .exchange(exchange_type)
        .flags(flags)
        .message_id(message_id)
        .length(length))
}

/// Build the typed payload layer for `payload_type` from its full payload bytes
/// (the 4-octet generic header plus the body) and push it onto `packet`.
///
/// `payload` is one complete generic payload: `Next Payload (1) | C+Reserved (1)
/// | Payload Length (2) | body…` (RFC 7296 §3.2). The body parsers added in
/// Steps 35–44 take the body alone, so the 4-octet generic header is stripped
/// here before dispatch. A payload type this build does not model — including the
/// Encrypted (SK) payload, which needs an SA to open — is preserved as a [`Raw`]
/// layer carrying the *whole* payload (generic header included) so it round-trips
/// byte-for-byte and its bytes survive untouched.
fn push_typed_payload(packet: Packet, payload_type: PayloadType, payload: &[u8]) -> Result<Packet> {
    // The body is everything after the 4-octet generic payload header. The caller
    // has already validated `payload.len() >= GENERIC_PAYLOAD_HEADER_LEN`.
    let body = &payload[GENERIC_PAYLOAD_HEADER_LEN..];

    let packet = match payload_type {
        PayloadType::SecurityAssociation => packet.push(parse_sa_payload_body(body)?),
        PayloadType::KeyExchange => packet.push(parse_ke_payload_body(body)?),
        PayloadType::IdInitiator => packet.push(parse_id_payload_body(IdRole::Initiator, body)?),
        PayloadType::IdResponder => packet.push(parse_id_payload_body(IdRole::Responder, body)?),
        PayloadType::Certificate => packet.push(parse_cert_payload_body(body)?),
        PayloadType::CertificateRequest => packet.push(parse_certreq_payload_body(body)?),
        PayloadType::Authentication => packet.push(parse_auth_payload_body(body)?),
        PayloadType::Nonce => packet.push(parse_nonce_payload_body(body)?),
        PayloadType::Notify => packet.push(parse_notify_payload_body(body)?),
        PayloadType::Delete => packet.push(parse_delete_payload_body(body)?),
        PayloadType::VendorId => packet.push(parse_vendor_id_payload_body(body)?),
        PayloadType::TrafficSelectorInitiator => {
            packet.push(parse_ts_payload_body(TsRole::Initiator, body)?)
        }
        PayloadType::TrafficSelectorResponder => {
            packet.push(parse_ts_payload_body(TsRole::Responder, body)?)
        }
        PayloadType::Configuration => packet.push(parse_config_payload_body(body)?),
        PayloadType::ExtensibleAuthentication => packet.push(parse_eap_payload_body(body)?),
        // The Encrypted (SK) payload needs an SA to open (RFC 7296 §3.14); the
        // built-in registry has none, so preserve the whole payload opaquely.
        PayloadType::Encrypted | PayloadType::None | PayloadType::Unknown(_) => {
            packet.push(Raw::from_bytes(payload))
        }
    };
    Ok(packet)
}

/// Walk the IKEv2 generic-payload chain, pushing one layer per payload
/// (RFC 7296 §3.2).
///
/// `first_payload_type` is the header's Next Payload (the type of the first
/// payload); `bytes` is the message body after the 28-octet header. Each step
/// reads the 4-octet generic header to learn this payload's Payload Length and
/// the Next Payload that names the *following* payload's type, slices off this
/// complete payload, builds its typed layer (or a preserved [`Raw`]), and
/// advances. The walk stops when the Next Payload is `0` (chain terminator) or
/// the buffer is exhausted.
///
/// A generic header that does not fit, or a Payload Length that is below the
/// 4-octet minimum or runs past the remaining buffer, is a structured
/// [`CrafterError`] (`context`, `required`, `available`) — never a panic.
fn decode_payload_chain(
    mut packet: Packet,
    first_payload_type: u8,
    bytes: &[u8],
) -> Result<Packet> {
    let mut next_payload = first_payload_type;
    let mut offset = 0usize;

    while next_payload != PayloadType::None.codepoint() {
        let remaining = &bytes[offset..];
        if remaining.len() < GENERIC_PAYLOAD_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "ikev2.payload.header",
                GENERIC_PAYLOAD_HEADER_LEN,
                remaining.len(),
            ));
        }

        // Generic payload header: Next Payload (1) | C+Reserved (1) | Length (2).
        let this_next_payload = remaining[0];
        let payload_length = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));

        if payload_length < GENERIC_PAYLOAD_HEADER_LEN || payload_length > remaining.len() {
            return Err(CrafterError::buffer_too_short(
                "ikev2.payload.length",
                payload_length.max(GENERIC_PAYLOAD_HEADER_LEN),
                remaining.len(),
            ));
        }

        let payload = &remaining[..payload_length];
        let this_payload_type = PayloadType::from(next_payload);
        packet = push_typed_payload(packet, this_payload_type, payload)?;

        offset += payload_length;

        // RFC 7296 §3.14: the Encrypted (SK) payload is always the last payload of
        // a message — its body is `IV || ciphertext || ICV`, and the inner payload
        // chain it protects lives *inside* the ciphertext, not in the cleartext
        // chain. So although the SK generic header's Next Payload names the first
        // *inner* payload type, there is no further cleartext generic payload to
        // walk. Terminate the chain here; following that Next Payload into the SK
        // ciphertext would misread encrypted bytes as a generic header.
        if matches!(this_payload_type, PayloadType::Encrypted) {
            break;
        }

        next_payload = this_next_payload;
    }

    Ok(packet)
}

/// Decode a full IKEv2 message: header + Next Payload chain (RFC 7296 §3.1–§3.2).
///
/// Parses the 28-octet IKE header, validates the on-wire total Length against the
/// buffer it was handed, then walks the generic-payload chain from the header's
/// Next Payload, appending one typed payload layer per link (or a preserved
/// [`Raw`] for an unmodeled type). The pushed layers re-compile byte-for-byte: the
/// header carries its decoded Next Payload and Length as caller-set fields, and
/// each payload is rebuilt from its own bytes.
///
/// Length validation is lenient enough that a correct message always decodes: the
/// Length must be at least the 28-octet header and must not exceed the buffer, but
/// the chain walk itself is bounded by each payload's own Payload Length, so a
/// Length that under- or over-counts trailing bytes does not by itself fail the
/// decode. A truncated header, a generic header that does not fit, or a Payload
/// Length that runs off the end is a structured [`CrafterError`] — never a panic.
pub(crate) fn decode_ike_message(
    _registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let header = parse_ike_header(bytes)?;

    // RFC 7296 §3.1: the Length covers the whole message (header + payloads). It
    // must be at least the fixed header and must not claim more than the buffer
    // holds. Both bounds surface a structured error rather than a panic; the
    // chain walk below is bounded by each payload's own Payload Length, so a
    // correct message (Length == bytes.len()) always decodes.
    let length = usize::try_from(header.length_value().unwrap_or(0)).unwrap_or(usize::MAX);
    if length < IKE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.header.length",
            IKE_HEADER_LEN,
            length,
        ));
    }
    if length > bytes.len() {
        return Err(CrafterError::buffer_too_short(
            "ikev2.message",
            length,
            bytes.len(),
        ));
    }

    let first_payload_type = header.next_payload_value().unwrap_or(0);
    let packet = packet.push(header);

    // The payload chain occupies the message bytes after the 28-octet header, up
    // to the declared total Length (trailing bytes past Length are not part of
    // this message).
    decode_payload_chain(packet, first_payload_type, &bytes[IKE_HEADER_LEN..length])
}

/// Append a decoded IKEv2 message to `packet` using an explicit registry.
///
/// This is the hook the UDP/500 registry binding calls with the UDP payload
/// (RFC 7296 §3.1): IKEv2 messages are carried in UDP datagrams, so the bytes
/// handed here are the UDP payload — the IKE header followed by its payload
/// chain. Mirrors the `append_<proto>_packet_with_registry` shape: decode parts,
/// push the layers.
pub(crate) fn append_ikev2_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    decode_ike_message(registry, packet, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{NetworkLayer, Packet, Raw};
    use crate::protocols::ipsec::ikev2::header::{IkeHeader, IKE_SA_INIT};
    use crate::protocols::ipsec::ikev2::payload::ke::IkeKePayload;
    use crate::protocols::ipsec::ikev2::payload::nonce::IkeNoncePayload;
    use crate::protocols::ipsec::ikev2::payload::notify::NOTIFY_PROTOCOL_NONE;
    use crate::protocols::ipsec::ikev2::payload::sa::{IkeSaPayload, Proposal, Transform};
    use crate::protocols::ipsec::ikev2::payload::{
        IkeNotifyPayload, IkeVendorIdPayload, NotifyType, PAYLOAD_SA,
    };
    use crate::protocols::ipv4::{Ipv4, IPPROTO_UDP};
    use crate::protocols::transport::Udp;

    /// UDP port 500, the IKEv2 well-known port (RFC 7296 §2).
    const IKE_UDP_PORT: u16 = 500;

    /// Build an `IKE_SA_INIT` message with SA, KE, and Ni payloads (RFC 7296
    /// §1.2): the minimal initiator first message.
    fn ike_sa_init_payloads() -> (IkeSaPayload, IkeKePayload, IkeNoncePayload) {
        // One ESP proposal carrying a single ENCR transform (codepoints are
        // arbitrary here; the chain decode does not interpret them).
        let proposal = Proposal::new(1, 3).with_transform(Transform::new(1, 20));
        let sa = IkeSaPayload::new().with_proposal(proposal);
        // DH group 14 (2048-bit MODP) with arbitrary key-exchange data.
        let ke = IkeKePayload::new(14, vec![0xAB; 32]);
        let ni = IkeNoncePayload::new(vec![0x5A; 16]);
        (sa, ke, ni)
    }

    /// Build `Ipv4 / Udp(500) / IkeHeader / SA / KE / Ni` and compile it.
    fn compile_ike_sa_init_packet() -> Packet {
        let (sa, ke, ni) = ike_sa_init_payloads();
        let ipv4 = Ipv4::new()
            .protocol(IPPROTO_UDP)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap());
        let udp = Udp::new().sport(IKE_UDP_PORT).dport(IKE_UDP_PORT);
        let header = IkeHeader::new().exchange(IKE_SA_INIT).initiator();
        Packet::from_layer(ipv4) / udp / header / sa / ke / ni
    }

    #[test]
    fn full_message_decodes_all_four_payload_layers_and_round_trips() {
        // Compile Ipv4 / Udp(500) / IkeHeader / SA / KE / Ni, then decode from L3.
        let packet = compile_ike_sa_init_packet();
        let wire = packet.compile().expect("compile IKE message").into_bytes();

        let decoded =
            Packet::decode_from_l3(NetworkLayer::Ipv4, &wire).expect("decode IKE_SA_INIT from L3");

        // Layers: Ipv4, Udp, IkeHeader, SA, KE, Ni — six in total.
        assert!(
            decoded.layer::<IkeHeader>().is_some(),
            "IkeHeader must be present"
        );
        assert!(decoded.layer::<IkeSaPayload>().is_some(), "SA present");
        assert!(decoded.layer::<IkeKePayload>().is_some(), "KE present");
        assert!(decoded.layer::<IkeNoncePayload>().is_some(), "Ni present");

        // The header's decoded Next Payload names the first payload (SA, type 33).
        let header = decoded.layer::<IkeHeader>().unwrap();
        assert_eq!(header.next_payload_value(), Some(PAYLOAD_SA));
        assert_eq!(header.exchange_type_value(), Some(IKE_SA_INIT));

        // The decoded packet re-compiles to the original wire bytes byte-for-byte.
        let recompiled = decoded.compile().expect("recompile decoded").into_bytes();
        assert_eq!(recompiled, wire, "round-trip must be byte-exact");
    }

    #[test]
    fn decode_ike_message_pushes_header_then_payload_chain() {
        // Drive decode_ike_message directly on the IKE message bytes (the UDP
        // payload) and check the layer sequence.
        let packet = compile_ike_sa_init_packet();
        let wire = packet.compile().expect("compile").into_bytes();
        // Strip the IPv4 (20) + UDP (8) headers to get the IKE message bytes.
        let ip_header_len = usize::from(wire[0] & 0x0f) * 4;
        let ike_bytes = &wire[ip_header_len + 8..];

        let registry = ProtocolRegistry::with_builtin_bindings();
        let decoded =
            decode_ike_message(&registry, Packet::new(), ike_bytes).expect("decode IKE message");

        // IkeHeader, SA, KE, Ni — four layers, in order.
        assert_eq!(decoded.len(), 4);
        assert_eq!(decoded.get(0).unwrap().name(), "IkeHeader");
        assert_eq!(decoded.get(1).unwrap().name(), "IkeSaPayload");
        assert_eq!(decoded.get(2).unwrap().name(), "IkeKePayload");
        assert_eq!(decoded.get(3).unwrap().name(), "IkeNoncePayload");
    }

    #[test]
    fn unknown_payload_type_decodes_as_raw() {
        // A header whose Next Payload names a payload type this build does not
        // model must decode the payload as a preserved Raw layer (the crate's
        // unknown-next-protocol contract), and re-compile byte-for-byte.
        //
        // Build the message bytes by hand: a 28-octet header pointing at payload
        // type 60 (unassigned), followed by one generic payload of that type with
        // Next Payload 0 (terminator).
        let unknown_type = 60u8;
        let payload_body = [0x11u8, 0x22, 0x33, 0x44];
        let payload_len = GENERIC_PAYLOAD_HEADER_LEN + payload_body.len();
        let total_len = IKE_HEADER_LEN + payload_len;

        let mut message = Vec::new();
        // Header.
        message.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes()); // ispi
        message.extend_from_slice(&0u64.to_be_bytes()); // rspi
        message.push(unknown_type); // Next Payload -> first payload type
        message.push(0x20); // version
        message.push(IKE_SA_INIT); // exchange type
        message.push(0x08); // flags (initiator)
        message.extend_from_slice(&0u32.to_be_bytes()); // message id
        message.extend_from_slice(&(total_len as u32).to_be_bytes()); // length
                                                                      // One generic payload of the unknown type, terminating the chain.
        message.push(0); // Next Payload = 0 (terminator)
        message.push(0); // Critical/Reserved
        message.extend_from_slice(&(payload_len as u16).to_be_bytes()); // Payload Length
        message.extend_from_slice(&payload_body); // body

        let registry = ProtocolRegistry::with_builtin_bindings();
        let decoded = decode_ike_message(&registry, Packet::new(), &message)
            .expect("decode message with unknown payload");

        // IkeHeader, then the unknown payload preserved as Raw.
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.get(0).unwrap().name(), "IkeHeader");
        let raw = decoded
            .get(1)
            .unwrap()
            .as_any()
            .downcast_ref::<Raw>()
            .expect("unknown payload preserved as Raw");
        // The Raw carries the WHOLE payload (generic header + body) verbatim.
        assert_eq!(
            raw.as_bytes(),
            &message[IKE_HEADER_LEN..],
            "unknown payload preserved verbatim"
        );

        // The message re-compiles byte-for-byte.
        let recompiled = decoded.compile().expect("recompile").into_bytes();
        assert_eq!(recompiled, message);
    }

    #[test]
    fn truncated_header_is_structured_error() {
        // A buffer shorter than the 28-octet header is a structured error.
        let registry = ProtocolRegistry::with_builtin_bindings();
        let err = decode_ike_message(&registry, Packet::new(), &[0u8; 10])
            .expect_err("must reject truncated header");
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    #[test]
    fn payload_running_off_the_end_is_structured_error() {
        // A generic payload whose Payload Length runs past the buffer is a
        // structured error, never a panic.
        let mut message = Vec::new();
        message.extend_from_slice(&0u64.to_be_bytes()); // ispi
        message.extend_from_slice(&0u64.to_be_bytes()); // rspi
        message.push(PAYLOAD_SA); // Next Payload -> SA
        message.push(0x20); // version
        message.push(IKE_SA_INIT); // exchange
        message.push(0x08); // flags
        message.extend_from_slice(&0u32.to_be_bytes()); // message id
                                                        // Length claims the whole 36-octet message.
        message.extend_from_slice(&36u32.to_be_bytes());
        // One SA generic header claiming Payload Length 100 (way past the buffer).
        message.push(0); // Next Payload = terminator
        message.push(0); // C+Reserved
        message.extend_from_slice(&100u16.to_be_bytes()); // Payload Length (too big)
        message.extend_from_slice(&[0u8; 4]); // partial body

        let registry = ProtocolRegistry::with_builtin_bindings();
        // Length (36) <= buffer (40), so the message-length gate passes; the chain
        // walk then catches the oversized Payload Length.
        let err = decode_ike_message(&registry, Packet::new(), &message)
            .expect_err("oversized payload length must error");
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    #[test]
    fn notify_and_vendor_chain_decodes_to_typed_layers() {
        // A second exchange shape — Notify + Vendor ID — confirms the chain walk
        // dispatches more than the IKE_SA_INIT triple. Build via the layer API.
        let notify =
            IkeNotifyPayload::new(NOTIFY_PROTOCOL_NONE, NotifyType::InitialContact, Vec::new());
        let vendor = IkeVendorIdPayload::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let header = IkeHeader::new().exchange(IKE_SA_INIT).initiator();
        let udp = Udp::new().sport(IKE_UDP_PORT).dport(IKE_UDP_PORT);
        let ipv4 = Ipv4::new()
            .protocol(IPPROTO_UDP)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap());
        let packet = Packet::from_layer(ipv4) / udp / header / notify / vendor;
        let wire = packet.compile().expect("compile").into_bytes();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire).expect("decode from L3");
        assert!(
            decoded.layer::<IkeNotifyPayload>().is_some(),
            "Notify present"
        );
        assert!(
            decoded.layer::<IkeVendorIdPayload>().is_some(),
            "Vendor ID present"
        );
        let recompiled = decoded.compile().expect("recompile").into_bytes();
        assert_eq!(recompiled, wire, "round-trip byte-exact");
    }
}
