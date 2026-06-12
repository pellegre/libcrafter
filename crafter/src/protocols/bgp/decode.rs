//! BGP-4 (RFC 4271) decode entrypoints.
//!
//! BGP decode follows the crate's structured-error contract: a buffer too short
//! for the field being read surfaces a typed [`CrafterError::BufferTooShort`]
//! carrying `context`, `required`, and `available` — never a panic and never a
//! half-read field. Mirrors the IPsec/ICMP decode shape (see
//! `crate::protocols::ipsec::ah::decode` and
//! `crate::protocols::ipsec::esp::decode`).
//!
//! The decode contract for BGP messages and path attributes:
//!
//! - **Unknown items are preserved.** An unrecognized message type, path
//!   attribute type code, or capability is kept as opaque bytes rather than
//!   discarded, matching the crate's unknown-next-protocol `Raw` fallback. The
//!   enclosing framing stays valid and re-compiles byte-for-byte.
//! - **Malformed items are typed.** A length that overruns the buffer, or a
//!   header shorter than its fixed minimum, becomes a structured
//!   [`CrafterError`] with the field's `context`, the bytes it `required`, and
//!   the bytes `available` — the same shape every other decoder emits.
//! - **Never panic.** Every slice into the buffer is length-checked first
//!   (through [`take`]), so truncation can only ever produce an `Err`, not an
//!   out-of-bounds index.

use std::net::Ipv4Addr;

use crate::error::{CrafterError, Result};
use crate::packet::{Packet, Raw};
use crate::registry::ProtocolRegistry;

use super::attribute::{decode_attribute, BgpPathAttribute, BgpPrefix};
use super::capability::{decode_capabilities, BgpOptParam, BGP_OPT_PARAM_CAPABILITIES};
use super::constants::{
    BGP_HEADER_LEN, BGP_MARKER_LEN, BGP_MAX_MESSAGE_LEN, BGP_TYPE_KEEPALIVE, BGP_TYPE_NOTIFICATION,
    BGP_TYPE_OPEN, BGP_TYPE_ROUTE_REFRESH, BGP_TYPE_UPDATE,
};
use super::message::{BgpNotification, BgpOpen, BgpRouteRefresh, BgpUpdate};
use super::{Bgp, BgpBody};

/// Build the structured truncation error BGP decode uses for a short buffer.
///
/// `context` names the field being read, `required` is the byte count that
/// field needs, and `available` is what the buffer actually holds. This is the
/// crate-wide [`CrafterError::buffer_too_short`] shape, named locally so the BGP
/// decoders read uniformly (RFC 4271 framing has many fixed-width fields).
#[allow(dead_code)]
fn need(context: &'static str, required: usize, available: usize) -> CrafterError {
    CrafterError::buffer_too_short(context, required, available)
}

fn invalid_bgp_length(length: usize) -> Option<CrafterError> {
    if length < BGP_HEADER_LEN {
        Some(CrafterError::invalid_field_value(
            "bgp.header.length",
            "BGP message Length is below the 19-octet header minimum",
        ))
    } else if length > BGP_MAX_MESSAGE_LEN {
        Some(CrafterError::invalid_field_value(
            "bgp.header.length",
            "BGP message Length exceeds the 4096-octet maximum",
        ))
    } else {
        None
    }
}

/// Split `n` bytes off the front of `buf`, returning `(head, rest)`.
///
/// Returns `Ok((&buf[..n], &buf[n..]))` when the buffer holds at least `n`
/// bytes, or the structured [`need`] error (context `context`, required `n`,
/// available `buf.len()`) when it does not. Every BGP field read goes through
/// this helper so a truncated buffer can only ever yield an `Err`, never an
/// out-of-bounds panic.
#[allow(dead_code)]
pub(crate) fn take<'a>(
    buf: &'a [u8],
    n: usize,
    context: &'static str,
) -> Result<(&'a [u8], &'a [u8])> {
    if buf.len() < n {
        return Err(need(context, n, buf.len()));
    }
    Ok(buf.split_at(n))
}

/// Decode one or more BGP messages from a TCP payload into the packet stack.
///
/// Complete messages are appended as typed [`Bgp`] layers. A trailing partial
/// message is preserved as [`Raw`] so stream-oriented callers can keep the bytes
/// inspectable without losing synchronization. A malformed length in the first
/// header is still a structured decode error because there is no earlier valid
/// BGP frame to anchor a raw tail.
#[allow(dead_code)]
pub(crate) fn append_bgp_packet_with_registry(
    _registry: &ProtocolRegistry,
    mut packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let mut remaining = bytes;
    let mut decoded_any = false;

    while !remaining.is_empty() {
        if remaining.len() < BGP_HEADER_LEN {
            packet = packet.push(Raw::from_bytes(remaining));
            break;
        }

        let length =
            u16::from_be_bytes([remaining[BGP_MARKER_LEN], remaining[BGP_MARKER_LEN + 1]]) as usize;

        if let Some(err) = invalid_bgp_length(length) {
            if decoded_any {
                packet = packet.push(Raw::from_bytes(remaining));
                break;
            }
            return Err(err);
        }

        if remaining.len() < length {
            packet = packet.push(Raw::from_bytes(remaining));
            break;
        }

        match decode_bgp_message(remaining) {
            Ok((bgp, consumed)) => {
                packet = packet.push(bgp);
                remaining = &remaining[consumed..];
                decoded_any = true;
            }
            Err(CrafterError::BufferTooShort { .. }) if decoded_any => {
                packet = packet.push(Raw::from_bytes(remaining));
                break;
            }
            Err(_err) if decoded_any => {
                packet = packet.push(Raw::from_bytes(remaining));
                break;
            }
            Err(err) => return Err(err),
        }
    }

    Ok(packet)
}

/// Decode a single BGP message (RFC 4271 §4.1) from the front of `bytes`.
///
/// Reads the shared 19-octet header — the 16-octet Marker, the 2-octet Length,
/// and the 1-octet Type — through [`take`] so a buffer too short for any header
/// field surfaces a structured [`CrafterError::BufferTooShort`] (context
/// `"bgp header"`) rather than a panic. The declared Length is then validated
/// against the RFC 4271 §4.1 bounds (`[BGP_HEADER_LEN, BGP_MAX_MESSAGE_LEN]`)
/// and confirmed to fit within the buffer (a short buffer for the declared
/// length is a truncation error, context `"bgp message"`).
///
/// On success the returned [`Bgp`] carries the observed marker/length/type so a
/// round-trip re-compiles byte-for-byte, and the `usize` is the number of bytes
/// consumed (the message Length). KEEPALIVE (RFC 4271 §4.4) is header-only.
/// Every other type is preserved as a [`BgpBody::Unknown`] holding the raw body
/// bytes (the `length - BGP_HEADER_LEN` octets after the header); the real
/// typed bodies arrive in later steps.
#[allow(dead_code)]
pub fn decode_bgp_message(bytes: &[u8]) -> Result<(Bgp, usize)> {
    // The fixed 19-octet header: Marker (16), Length (2), Type (1). Each field
    // is length-checked through `take` so truncation can only yield an `Err`.
    let (marker_bytes, rest) = take(bytes, BGP_MARKER_LEN, "bgp header")?;
    let (length_bytes, rest) = take(rest, 2, "bgp header")?;
    let (type_bytes, _rest) = take(rest, 1, "bgp header")?;

    let mut marker = [0u8; BGP_MARKER_LEN];
    marker.copy_from_slice(marker_bytes);
    let length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]);
    let message_type = type_bytes[0];

    // RFC 4271 §4.1: Length covers the whole message and must lie within
    // [19, 4096]. A value outside that range is a malformed header, not a
    // truncation, so it is a structured InvalidFieldValue.
    let length_usize = length as usize;
    if let Some(err) = invalid_bgp_length(length_usize) {
        return Err(err);
    }

    // The buffer must hold the whole declared message; a short buffer here is a
    // truncation error carrying the declared length as `required`.
    if bytes.len() < length_usize {
        return Err(need("bgp message", length_usize, bytes.len()));
    }

    // The body is the octets after the 19-octet header, up to the declared
    // message length.
    let body_bytes = &bytes[BGP_HEADER_LEN..length_usize];
    let body = match message_type {
        BGP_TYPE_OPEN => BgpBody::Open(decode_open_body(body_bytes)?),
        BGP_TYPE_UPDATE => BgpBody::Update(decode_update_body(body_bytes)?),
        BGP_TYPE_NOTIFICATION => BgpBody::Notification(decode_notification_body(body_bytes)?),
        BGP_TYPE_ROUTE_REFRESH => BgpBody::RouteRefresh(decode_route_refresh_body(body_bytes)?),
        BGP_TYPE_KEEPALIVE => BgpBody::Keepalive,
        // Other message types are preserved verbatim for now; later steps
        // replace this with the typed OPEN/UPDATE/NOTIFICATION bodies.
        other => BgpBody::Unknown {
            type_code: other,
            body: body_bytes.to_vec(),
        },
    };

    let bgp = Bgp::from_decoded_parts(marker, length, message_type, body);
    Ok((bgp, length_usize))
}

fn decode_update_body(body_bytes: &[u8]) -> Result<BgpUpdate> {
    let (withdrawn_len, rest) = take(body_bytes, 2, "bgp update withdrawn routes length")?;
    let withdrawn_len = u16::from_be_bytes([withdrawn_len[0], withdrawn_len[1]]);
    let (withdrawn_bytes, rest) =
        take(rest, withdrawn_len as usize, "bgp update withdrawn routes")?;

    let (attr_len, rest) = take(rest, 2, "bgp update path attributes length")?;
    let attr_len = u16::from_be_bytes([attr_len[0], attr_len[1]]);
    let (attr_bytes, nlri_bytes) = take(rest, attr_len as usize, "bgp update path attributes")?;

    Ok(BgpUpdate::from_decoded_parts(
        decode_ipv4_prefixes(withdrawn_bytes)?,
        withdrawn_len,
        decode_path_attributes(attr_bytes)?,
        attr_len,
        decode_ipv4_prefixes(nlri_bytes)?,
    ))
}

fn decode_ipv4_prefixes(mut bytes: &[u8]) -> Result<Vec<BgpPrefix>> {
    let mut prefixes = Vec::new();
    while !bytes.is_empty() {
        let (prefix, consumed) = BgpPrefix::decode_prefix(bytes)?;
        prefixes.push(prefix);
        bytes = &bytes[consumed..];
    }
    Ok(prefixes)
}

fn decode_path_attributes(mut bytes: &[u8]) -> Result<Vec<BgpPathAttribute>> {
    let mut attributes = Vec::new();
    while !bytes.is_empty() {
        let (attribute, consumed) = decode_attribute(bytes)?;
        attributes.push(attribute);
        bytes = &bytes[consumed..];
    }
    Ok(attributes)
}

fn decode_notification_body(body_bytes: &[u8]) -> Result<BgpNotification> {
    if body_bytes.len() < 2 {
        return Err(CrafterError::invalid_field_value(
            "bgp.notification.length",
            "NOTIFICATION message Length is below the 21-octet minimum",
        ));
    }

    let (error_code, rest) = take(body_bytes, 1, "bgp notification error_code")?;
    let (error_subcode, data) = take(rest, 1, "bgp notification error_subcode")?;

    let mut notification = BgpNotification::new(error_code[0], error_subcode[0]);
    notification.data = data.to_vec();
    Ok(notification)
}

fn decode_route_refresh_body(body_bytes: &[u8]) -> Result<BgpRouteRefresh> {
    let (afi, rest) = take(body_bytes, 2, "bgp route refresh afi")?;
    let (subtype, rest) = take(rest, 1, "bgp route refresh subtype")?;
    let (safi, trailing) = take(rest, 1, "bgp route refresh safi")?;

    if !trailing.is_empty() {
        return Err(CrafterError::invalid_field_value(
            "bgp.route_refresh.length",
            "ROUTE-REFRESH body has trailing bytes after AFI/subtype/SAFI",
        ));
    }

    Ok(BgpRouteRefresh::from_decoded_parts(
        u16::from_be_bytes([afi[0], afi[1]]),
        subtype[0],
        safi[0],
    ))
}

fn decode_open_body(body_bytes: &[u8]) -> Result<BgpOpen> {
    let (version, rest) = take(body_bytes, 1, "bgp open version")?;
    let (my_as, rest) = take(rest, 2, "bgp open my_as")?;
    let (hold_time, rest) = take(rest, 2, "bgp open hold_time")?;
    let (bgp_id, rest) = take(rest, 4, "bgp open bgp_id")?;
    let (opt_params_len, rest) = take(rest, 1, "bgp open optional parameters length")?;
    let opt_params_len = opt_params_len[0];
    let (param_bytes, trailing) = take(
        rest,
        opt_params_len as usize,
        "bgp open optional parameters",
    )?;

    if !trailing.is_empty() {
        return Err(CrafterError::invalid_field_value(
            "bgp.open.length",
            "OPEN body has trailing bytes after optional parameters",
        ));
    }

    let mut params = Vec::new();
    let mut capabilities = Vec::new();
    let mut rest = param_bytes;
    while !rest.is_empty() {
        let (param, remaining) = BgpOptParam::decode(rest)?;
        if param.param_type == BGP_OPT_PARAM_CAPABILITIES {
            capabilities.extend(decode_capabilities(&param.value)?);
        }
        params.push(param);
        rest = remaining;
    }

    Ok(BgpOpen::from_decoded_parts(
        version[0],
        u16::from_be_bytes([my_as[0], my_as[1]]),
        u16::from_be_bytes([hold_time[0], hold_time[1]]),
        Ipv4Addr::new(bgp_id[0], bgp_id[1], bgp_id[2], bgp_id[3]),
        opt_params_len,
        params,
        capabilities,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    use crate::packet::{Layer, Packet, Raw};
    use crate::protocols::bgp::attribute::{
        BgpAttrValue, BgpPathAttribute, BgpPrefix, BGP_ORIGIN_IGP,
    };
    use crate::protocols::bgp::capability::BGP_MP_IPV4_UNICAST;
    use crate::protocols::bgp::{
        BgpCapability, AFI_IPV4, AFI_IPV6, ATTR_MP_REACH_NLRI, SAFI_UNICAST,
    };
    use crate::registry::ProtocolRegistry;

    #[test]
    fn take_splits_when_enough_bytes() {
        let buf = [0x01, 0x02, 0x03, 0x04];
        let (head, rest) = take(&buf, 2, "bgp.test").expect("buffer has enough bytes");
        assert_eq!(head, &[0x01, 0x02]);
        assert_eq!(rest, &[0x03, 0x04]);
    }

    #[test]
    fn take_on_short_buffer_is_structured_error() {
        // A buffer shorter than the requested split surfaces the structured
        // truncation error carrying context/required/available — never a panic.
        let buf = [0x01, 0x02];
        let err = take(&buf, 4, "bgp.header").expect_err("must reject a short buffer");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "bgp.header");
                assert_eq!(required, 4);
                assert_eq!(available, buf.len());
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    /// A valid 19-octet KEEPALIVE decodes to a `Bgp` KEEPALIVE layer and reports
    /// 19 bytes consumed (RFC 4271 §4.4).
    #[test]
    fn decode_keepalive_consumes_nineteen_bytes() {
        let mut bytes = [0u8; BGP_HEADER_LEN];
        bytes[..BGP_MARKER_LEN].copy_from_slice(&[0xFF; BGP_MARKER_LEN]);
        bytes[BGP_MARKER_LEN..BGP_MARKER_LEN + 2]
            .copy_from_slice(&(BGP_HEADER_LEN as u16).to_be_bytes());
        bytes[BGP_MARKER_LEN + 2] = BGP_TYPE_KEEPALIVE;

        let (bgp, consumed) = decode_bgp_message(&bytes).expect("valid keepalive decodes");
        assert_eq!(consumed, BGP_HEADER_LEN);
        assert_eq!(bgp.summary(), "BGP KEEPALIVE len=19");
    }

    #[test]
    fn decode_length_below_header_minimum_is_structured_error() {
        let mut bytes = [0u8; BGP_HEADER_LEN];
        bytes[..BGP_MARKER_LEN].copy_from_slice(&[0xFF; BGP_MARKER_LEN]);
        bytes[BGP_MARKER_LEN..BGP_MARKER_LEN + 2]
            .copy_from_slice(&((BGP_HEADER_LEN - 1) as u16).to_be_bytes());
        bytes[BGP_MARKER_LEN + 2] = BGP_TYPE_KEEPALIVE;

        let err = decode_bgp_message(&bytes).expect_err("short declared length is invalid");
        match err {
            CrafterError::InvalidFieldValue { field, reason } => {
                assert_eq!(field, "bgp.header.length");
                assert!(
                    reason.contains("19-octet header minimum"),
                    "reason should mention the minimum, got: {reason}"
                );
            }
            other => panic!("expected invalid_field_value, got {other:?}"),
        }
    }

    #[test]
    fn decode_length_above_maximum_is_structured_error() {
        let mut bytes = [0u8; BGP_HEADER_LEN];
        bytes[..BGP_MARKER_LEN].copy_from_slice(&[0xFF; BGP_MARKER_LEN]);
        bytes[BGP_MARKER_LEN..BGP_MARKER_LEN + 2]
            .copy_from_slice(&((BGP_MAX_MESSAGE_LEN + 1) as u16).to_be_bytes());
        bytes[BGP_MARKER_LEN + 2] = BGP_TYPE_KEEPALIVE;

        let err = decode_bgp_message(&bytes).expect_err("oversized declared length is invalid");
        match err {
            CrafterError::InvalidFieldValue { field, reason } => {
                assert_eq!(field, "bgp.header.length");
                assert!(
                    reason.contains("4096-octet maximum"),
                    "reason should mention the maximum, got: {reason}"
                );
            }
            other => panic!("expected invalid_field_value, got {other:?}"),
        }
    }

    #[test]
    fn decode_declared_length_past_buffer_is_truncation_error() {
        let declared_len = BGP_HEADER_LEN + 8;
        let mut bytes = vec![0u8; BGP_HEADER_LEN + 3];
        bytes[..BGP_MARKER_LEN].copy_from_slice(&[0xFF; BGP_MARKER_LEN]);
        bytes[BGP_MARKER_LEN..BGP_MARKER_LEN + 2]
            .copy_from_slice(&(declared_len as u16).to_be_bytes());
        bytes[BGP_MARKER_LEN + 2] = BGP_TYPE_KEEPALIVE;

        let err = decode_bgp_message(&bytes).expect_err("declared length overruns buffer");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "bgp message");
                assert_eq!(required, declared_len);
                assert_eq!(available, bytes.len());
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    #[test]
    fn decode_preserves_non_all_ones_marker_on_round_trip() {
        let mut bytes = [0u8; BGP_HEADER_LEN];
        bytes[..BGP_MARKER_LEN].copy_from_slice(&[0xA5; BGP_MARKER_LEN]);
        bytes[BGP_MARKER_LEN..BGP_MARKER_LEN + 2]
            .copy_from_slice(&(BGP_HEADER_LEN as u16).to_be_bytes());
        bytes[BGP_MARKER_LEN + 2] = BGP_TYPE_KEEPALIVE;

        let (bgp, consumed) = decode_bgp_message(&bytes).expect("modified marker decodes");
        assert_eq!(consumed, bytes.len());
        assert!(matches!(&bgp.body, BgpBody::Keepalive));

        let recompiled = Packet::from_layer(bgp)
            .compile()
            .expect("modified marker re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes);
    }

    #[test]
    fn append_bgp_packet_with_registry_decodes_two_keepalives() {
        let keepalive = Packet::from_layer(Bgp::keepalive())
            .compile()
            .expect("KEEPALIVE compiles");
        let bytes = [keepalive.as_bytes(), keepalive.as_bytes()].concat();

        let packet =
            append_bgp_packet_with_registry(&ProtocolRegistry::new(), Packet::new(), &bytes)
                .expect("concatenated KEEPALIVEs decode");

        let bgp_layers: Vec<_> = packet.layers::<Bgp>().collect();
        assert_eq!(bgp_layers.len(), 2);
        assert!(bgp_layers
            .iter()
            .all(|bgp| matches!(&bgp.body, BgpBody::Keepalive)));
        assert_eq!(packet.layers::<Raw>().count(), 0);
    }

    #[test]
    fn append_bgp_packet_with_registry_preserves_trailing_partial_as_raw() {
        let keepalive = Packet::from_layer(Bgp::keepalive())
            .compile()
            .expect("KEEPALIVE compiles");
        let trailing = [0xde, 0xad, 0xbe, 0xef, 0x00];
        let bytes = [keepalive.as_bytes(), &trailing].concat();

        let packet =
            append_bgp_packet_with_registry(&ProtocolRegistry::new(), Packet::new(), &bytes)
                .expect("KEEPALIVE plus trailing bytes decodes");

        let bgp_layers: Vec<_> = packet.layers::<Bgp>().collect();
        assert_eq!(bgp_layers.len(), 1);
        assert!(matches!(&bgp_layers[0].body, BgpBody::Keepalive));

        let raw_layers: Vec<_> = packet.layers::<Raw>().collect();
        assert_eq!(raw_layers.len(), 1);
        assert_eq!(raw_layers[0].as_bytes(), trailing);
    }

    #[test]
    fn decode_open_with_known_capabilities() {
        let expected_capabilities = vec![
            BgpCapability::ipv4_unicast(),
            BgpCapability::four_octet_as(4_200_000_000),
            BgpCapability::route_refresh(),
        ];
        let bytes = Packet::from_layer(
            Bgp::open()
                .my_as(23456)
                .hold_time(180)
                .bgp_id([192, 0, 2, 1])
                .capabilities(expected_capabilities.clone()),
        )
        .compile()
        .expect("OPEN compiles");

        let (bgp, consumed) = decode_bgp_message(&bytes).expect("OPEN decodes");
        assert_eq!(consumed, bytes.len());

        match &bgp.body {
            BgpBody::Open(open) => {
                assert_eq!(open.version.value(), Some(&4));
                assert_eq!(open.my_as.value(), Some(&23456));
                assert_eq!(open.hold_time.value(), Some(&180));
                assert_eq!(open.bgp_id.value(), Some(&Ipv4Addr::new(192, 0, 2, 1)));
                assert_eq!(open.params.len(), 1);
                assert_eq!(open.capabilities, expected_capabilities);
                assert_eq!(
                    open.capabilities[0]
                        .multiprotocol_afi_safi()
                        .expect("MP-BGP parses"),
                    BGP_MP_IPV4_UNICAST
                );
                assert_eq!(
                    open.capabilities[1]
                        .four_octet_asn()
                        .expect("four-octet AS parses"),
                    4_200_000_000
                );
                assert_eq!(open.capabilities[2], BgpCapability::route_refresh());
            }
            other => panic!("expected OPEN body, got {other:?}"),
        }

        let recompiled = Packet::from_layer(bgp)
            .compile()
            .expect("recompile succeeds");
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn decode_open_preserves_unknown_capability() {
        let unknown = BgpCapability::raw(200, vec![0xaa, 0xbb, 0xcc]);
        let bytes = Packet::from_layer(
            Bgp::open()
                .my_as(65000)
                .hold_time(90)
                .bgp_id([192, 0, 2, 2])
                .capabilities([unknown.clone()]),
        )
        .compile()
        .expect("OPEN compiles");

        let (bgp, consumed) = decode_bgp_message(&bytes).expect("OPEN decodes");
        assert_eq!(consumed, bytes.len());

        match &bgp.body {
            BgpBody::Open(open) => {
                assert_eq!(open.capabilities, vec![unknown.clone()]);
                assert_eq!(open.params.len(), 1);
                assert_eq!(open.params[0].value, [200, 3, 0xaa, 0xbb, 0xcc]);
            }
            other => panic!("expected OPEN body, got {other:?}"),
        }

        let recompiled = Packet::from_layer(bgp)
            .compile()
            .expect("recompile succeeds");
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn decode_notification_preserves_data_and_summary() {
        let bytes = Packet::from_layer(Bgp::cease().data(vec![0xde, 0xad, 0xbe]))
            .compile()
            .expect("NOTIFICATION compiles");

        let (bgp, consumed) = decode_bgp_message(&bytes).expect("NOTIFICATION decodes");
        assert_eq!(consumed, bytes.len());

        match &bgp.body {
            BgpBody::Notification(notification) => {
                assert_eq!(notification.error_code.value(), Some(&6));
                assert_eq!(notification.error_subcode.value(), Some(&0));
                assert_eq!(notification.data, vec![0xde, 0xad, 0xbe]);
            }
            other => panic!("expected NOTIFICATION body, got {other:?}"),
        }

        let summary = bgp.summary();
        assert!(
            summary.contains("NOTIFICATION"),
            "summary should name NOTIFICATION, got: {summary}"
        );
        assert!(
            summary.contains("data=3 bytes"),
            "summary should report data length, got: {summary}"
        );

        let recompiled = Packet::from_layer(bgp)
            .compile()
            .expect("recompile succeeds");
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn decode_route_refresh_round_trips_ipv4_unicast() {
        let bytes = Packet::from_layer(Bgp::route_refresh(AFI_IPV4, SAFI_UNICAST))
            .compile()
            .expect("ROUTE-REFRESH compiles");
        assert_eq!(bytes.len(), 23);

        let (bgp, consumed) = decode_bgp_message(&bytes).expect("ROUTE-REFRESH decodes");
        assert_eq!(consumed, bytes.len());
        assert_eq!(bgp.summary(), "BGP ROUTE-REFRESH afi=1 safi=1");

        match &bgp.body {
            BgpBody::RouteRefresh(route_refresh) => {
                assert_eq!(route_refresh.afi.value(), Some(&AFI_IPV4));
                assert_eq!(route_refresh.subtype.value(), Some(&0));
                assert_eq!(route_refresh.safi.value(), Some(&SAFI_UNICAST));
            }
            other => panic!("expected ROUTE-REFRESH body, got {other:?}"),
        }

        let recompiled = Packet::from_layer(bgp)
            .compile()
            .expect("recompile succeeds");
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn decode_update_announcement_round_trips_attributes_and_nlri() {
        let origin = BgpPathAttribute::origin(BGP_ORIGIN_IGP);
        let as_path = BgpPathAttribute::as_sequence(&[65000]);
        let next_hop = BgpPathAttribute::next_hop(Ipv4Addr::new(192, 0, 2, 1));
        let nlri =
            BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix");
        let bytes = Packet::from_layer(
            Bgp::update()
                .attribute(origin.clone())
                .attribute(as_path.clone())
                .attribute(next_hop.clone())
                .nlri(nlri.clone()),
        )
        .compile()
        .expect("UPDATE compiles");

        let (bgp, consumed) = decode_bgp_message(&bytes).expect("UPDATE decodes");
        assert_eq!(consumed, bytes.len());

        match &bgp.body {
            BgpBody::Update(update) => {
                assert!(update.withdrawn.is_empty());
                assert_eq!(update.withdrawn_len.value(), Some(&0));
                assert_eq!(
                    update.attr_len.value(),
                    Some(&(update.attributes_len() as u16))
                );
                assert_eq!(update.attributes.len(), 3);
                assert_eq!(update.attributes[0].type_code, origin.type_code);
                assert_eq!(update.attributes[0].value, origin.value);
                assert_eq!(update.attributes[1].type_code, as_path.type_code);
                assert_eq!(update.attributes[1].value, as_path.value);
                assert_eq!(update.attributes[2].type_code, next_hop.type_code);
                assert_eq!(update.attributes[2].value, next_hop.value);
                assert_eq!(update.nlri, vec![nlri]);
            }
            other => panic!("expected UPDATE body, got {other:?}"),
        }

        let recompiled = Packet::from_layer(bgp)
            .compile()
            .expect("recompile succeeds");
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn decode_update_preserves_unknown_attribute_flags_and_value() {
        let bytes = Packet::from_layer(
            Bgp::update()
                .attribute(BgpPathAttribute::unknown(99, vec![0xaa, 0xbb]).with_flags(0xe0)),
        )
        .compile()
        .expect("UPDATE compiles");

        let (bgp, consumed) = decode_bgp_message(&bytes).expect("UPDATE decodes");
        assert_eq!(consumed, bytes.len());

        match &bgp.body {
            BgpBody::Update(update) => {
                assert_eq!(update.attributes.len(), 1);
                assert_eq!(update.attributes[0].flags.value(), Some(&0xe0));
                assert_eq!(update.attributes[0].type_code, 99);
                assert_eq!(
                    update.attributes[0].value,
                    BgpAttrValue::Unknown(vec![0xaa, 0xbb])
                );
            }
            other => panic!("expected UPDATE body, got {other:?}"),
        }

        let recompiled = Packet::from_layer(bgp)
            .compile()
            .expect("recompile succeeds");
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn decode_update_mp_reach_attribute_is_typed_and_round_trips() {
        let next_hop = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let nlri = [
            BgpPrefix::from_ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
                .expect("valid IPv6 prefix"),
        ];
        let bytes = Packet::from_layer(
            Bgp::update().attribute(BgpPathAttribute::mp_reach_ipv6(next_hop, &nlri)),
        )
        .compile()
        .expect("UPDATE compiles");

        let (bgp, consumed) = decode_bgp_message(&bytes).expect("UPDATE decodes");
        assert_eq!(consumed, bytes.len());
        assert!(
            bgp.summary()
                .contains("MP_REACH afi=2 safi=1 nh=2001:db8::1 nlri=[2001:db8::/32]"),
            "summary was: {}",
            bgp.summary()
        );

        match &bgp.body {
            BgpBody::Update(update) => {
                assert_eq!(update.attributes.len(), 1);
                assert_eq!(update.attributes[0].type_code, ATTR_MP_REACH_NLRI);
                assert_eq!(
                    update.attributes[0].value,
                    BgpAttrValue::MpReachNlri {
                        afi: AFI_IPV6,
                        safi: SAFI_UNICAST,
                        next_hop: next_hop.octets().to_vec(),
                        nlri: nlri.to_vec(),
                    }
                );
            }
            other => panic!("expected UPDATE body, got {other:?}"),
        }

        let recompiled = Packet::from_layer(bgp)
            .compile()
            .expect("recompile succeeds");
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn decode_update_attribute_length_overrun_is_structured_error() {
        let bytes = [
            [0xff; BGP_MARKER_LEN].as_slice(),
            &(25u16).to_be_bytes(),
            &[BGP_TYPE_UPDATE],
            &[0x00, 0x00, 0x00, 0x04, 0x40, 0x01],
        ]
        .concat();

        let err = decode_bgp_message(&bytes).expect_err("attribute length overruns message body");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "bgp update path attributes");
                assert_eq!(required, 4);
                assert_eq!(available, 2);
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    /// A 10-byte buffer cannot even hold the 16-octet marker, so decode surfaces
    /// the structured truncation error; its rendered message references the
    /// required length.
    #[test]
    fn decode_short_buffer_is_truncation_error() {
        let bytes = [0u8; 10];
        let err = decode_bgp_message(&bytes).expect_err("a 10-byte buffer is too short");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "bgp header");
                assert_eq!(required, BGP_MARKER_LEN);
                assert_eq!(available, 10);
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
        // The rendered message references the required length so an agent sees
        // why the buffer was rejected without log-fishing.
        let rendered = decode_bgp_message(&bytes).unwrap_err().to_string();
        assert!(
            rendered.contains(&BGP_MARKER_LEN.to_string()),
            "truncation message should reference the required length, got: {rendered}"
        );
    }
}
