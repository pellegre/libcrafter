//! WHAD 802.15.4 backend module.
//!
//! Builders that construct the WHAD `dot15d4` command messages from Rust
//! values, mirroring the BLE `build_ble_*` builders in `messages.rs`. Each
//! builder wraps a `proto::dot15d4` command in the `proto::dot15d4::Message`
//! oneof and then in the top-level WHAD `proto::Message` envelope via
//! [`build_dot15d4_message`].

#![allow(dead_code)]

#[cfg(feature = "whad")]
use super::proto;

/// Radio + MAC descriptor parsed from a WHAD `dot15d4` received-PDU
/// notification, mirroring the BLE `WhadRxPdu` in `messages.rs`. The reader
/// (step 47) maps this to a `Dot15d4Radio / Dot15d4` packet.
#[cfg(feature = "whad")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WhadDot15d4Rx {
    pub(crate) channel: u8,
    pub(crate) rssi: i16,
    pub(crate) fcs_valid: bool,
    pub(crate) lqi: u8,
    pub(crate) pdu: Vec<u8>,
}

/// Clamp a protobuf `int32` RSSI into the descriptor's `i16` range,
/// mirroring the BLE parser's `saturating_i32_to_i16`.
#[cfg(feature = "whad")]
fn saturating_i32_to_i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

/// Parse a WHAD `dot15d4` received-PDU notification into a [`WhadDot15d4Rx`]
/// descriptor, mirroring the BLE `parse_received_pdu`.
///
/// When the device sniffs it streams both `RawPduReceived` (oneof field 15,
/// carries an FCS and its validity bit) and `PduReceived` (oneof field 16, no
/// FCS) notifications, so BOTH variants must produce a descriptor. Returns
/// `None` for non-`dot15d4` messages and for `dot15d4` control/command frames
/// so the reader can skip them.
#[cfg(feature = "whad")]
pub(crate) fn parse_dot15d4_received(message: &proto::Message) -> Option<WhadDot15d4Rx> {
    let dot15d4 = match message.msg.as_ref()? {
        proto::message::Msg::Dot15d4(dot15d4) => dot15d4,
        _ => return None,
    };

    match dot15d4.msg.as_ref()? {
        proto::dot15d4::message::Msg::RawPdu(received) => Some(WhadDot15d4Rx {
            channel: u8::try_from(received.channel).ok()?,
            rssi: saturating_i32_to_i16(received.rssi.unwrap_or(0)),
            // RawPduReceived reports FCS validity explicitly.
            fcs_valid: received.fcs_validity,
            lqi: u8::try_from(received.lqi.unwrap_or(0)).ok()?,
            pdu: received.pdu.clone(),
        }),
        proto::dot15d4::message::Msg::Pdu(received) => Some(WhadDot15d4Rx {
            channel: u8::try_from(received.channel).ok()?,
            rssi: saturating_i32_to_i16(received.rssi.unwrap_or(0)),
            // PduReceived is the firmware-validated PDU with the FCS stripped;
            // mirror the BLE AdvPduReceived path and report a valid FCS.
            fcs_valid: true,
            lqi: u8::try_from(received.lqi.unwrap_or(0)).ok()?,
            pdu: received.pdu.clone(),
        }),
        _ => None,
    }
}

/// Wrap a `proto::dot15d4` oneof payload in the top-level WHAD `Message`
/// envelope via `proto::message::Msg::Dot15d4`, mirroring `build_ble_message`.
#[cfg(feature = "whad")]
pub(crate) fn build_dot15d4_message(msg: proto::dot15d4::message::Msg) -> proto::Message {
    proto::Message {
        msg: Some(proto::message::Msg::Dot15d4(proto::dot15d4::Message {
            msg: Some(msg),
        })),
    }
}

/// Build a `SniffCmd` for the given channel.
#[cfg(feature = "whad")]
pub(crate) fn build_dot15d4_sniff(channel: u32) -> proto::Message {
    build_dot15d4_message(proto::dot15d4::message::Msg::Sniff(
        proto::dot15d4::SniffCmd { channel },
    ))
}

/// Build a `SendCmd` carrying a PDU on the given channel.
#[cfg(feature = "whad")]
pub(crate) fn build_dot15d4_send(channel: u32, pdu: Vec<u8>) -> proto::Message {
    build_dot15d4_message(proto::dot15d4::message::Msg::Send(
        proto::dot15d4::SendCmd { channel, pdu },
    ))
}

/// Build a `SendRawCmd` carrying a PDU plus an explicit FCS on the given
/// channel.
#[cfg(feature = "whad")]
pub(crate) fn build_dot15d4_send_raw(channel: u32, pdu: Vec<u8>, fcs: u32) -> proto::Message {
    build_dot15d4_message(proto::dot15d4::message::Msg::SendRaw(
        proto::dot15d4::SendRawCmd { channel, pdu, fcs },
    ))
}

/// Build a `StartCmd`.
#[cfg(feature = "whad")]
pub(crate) fn build_dot15d4_start() -> proto::Message {
    build_dot15d4_message(proto::dot15d4::message::Msg::Start(
        proto::dot15d4::StartCmd {},
    ))
}

/// Build a `StopCmd`.
#[cfg(feature = "whad")]
pub(crate) fn build_dot15d4_stop() -> proto::Message {
    build_dot15d4_message(proto::dot15d4::message::Msg::Stop(
        proto::dot15d4::StopCmd {},
    ))
}

#[cfg(all(test, feature = "whad"))]
mod tests {
    use prost::Message as _;

    use super::super::proto;
    use super::*;

    fn decode_top_level(message: &proto::Message) -> proto::Message {
        let encoded = message.encode_to_vec();
        assert!(!encoded.is_empty());
        proto::Message::decode(encoded.as_slice()).expect("WHAD dot15d4 message decodes")
    }

    fn dot15d4_payload(message: proto::Message) -> proto::dot15d4::message::Msg {
        match message.msg {
            Some(proto::message::Msg::Dot15d4(dot15d4)) => {
                dot15d4.msg.expect("dot15d4 message carries a payload")
            }
            _ => panic!("expected top-level dot15d4 message"),
        }
    }

    #[test]
    fn dot15d4_message_builders() {
        // Sniff
        let sniff = dot15d4_payload(decode_top_level(&build_dot15d4_sniff(15)));
        match sniff {
            proto::dot15d4::message::Msg::Sniff(command) => {
                assert_eq!(command.channel, 15);
            }
            _ => panic!("expected dot15d4 sniff command"),
        }

        // Send
        let send_pdu = vec![0x01, 0x88, 0x42, 0xAB, 0xCD];
        let send = dot15d4_payload(decode_top_level(&build_dot15d4_send(20, send_pdu.clone())));
        match send {
            proto::dot15d4::message::Msg::Send(command) => {
                assert_eq!(command.channel, 20);
                assert_eq!(command.pdu, send_pdu);
            }
            _ => panic!("expected dot15d4 send command"),
        }

        // SendRaw
        let raw_pdu = vec![0x61, 0x88, 0x01, 0xFF, 0xFF];
        let send_raw = dot15d4_payload(decode_top_level(&build_dot15d4_send_raw(
            26,
            raw_pdu.clone(),
            0xBEEF,
        )));
        match send_raw {
            proto::dot15d4::message::Msg::SendRaw(command) => {
                assert_eq!(command.channel, 26);
                assert_eq!(command.pdu, raw_pdu);
                assert_eq!(command.fcs, 0xBEEF);
            }
            _ => panic!("expected dot15d4 send-raw command"),
        }

        // Start
        let start = dot15d4_payload(decode_top_level(&build_dot15d4_start()));
        match start {
            proto::dot15d4::message::Msg::Start(_) => {}
            _ => panic!("expected dot15d4 start command"),
        }

        // Stop
        let stop = dot15d4_payload(decode_top_level(&build_dot15d4_stop()));
        match stop {
            proto::dot15d4::message::Msg::Stop(_) => {}
            _ => panic!("expected dot15d4 stop command"),
        }
    }

    #[test]
    fn dot15d4_parse_received() {
        // RawPduReceived: carries an explicit FCS and its validity bit.
        let raw_pdu = vec![0x61, 0x88, 0x01, 0xFF, 0xFF, 0x00, 0x00];
        let raw_message = build_dot15d4_message(proto::dot15d4::message::Msg::RawPdu(
            proto::dot15d4::RawPduReceived {
                channel: 15,
                rssi: Some(-57),
                timestamp: Some(123),
                fcs_validity: true,
                pdu: raw_pdu.clone(),
                fcs: 0xBEEF,
                lqi: Some(200),
            },
        ));
        let decoded_raw = decode_top_level(&raw_message);
        let parsed_raw = parse_dot15d4_received(&decoded_raw).expect("raw PDU parses");
        assert_eq!(
            parsed_raw,
            WhadDot15d4Rx {
                channel: 15,
                rssi: -57,
                fcs_valid: true,
                lqi: 200,
                pdu: raw_pdu,
            }
        );

        // A RawPduReceived flagged with an invalid FCS surfaces that bit.
        let bad_fcs_message = build_dot15d4_message(proto::dot15d4::message::Msg::RawPdu(
            proto::dot15d4::RawPduReceived {
                channel: 26,
                rssi: None,
                timestamp: None,
                fcs_validity: false,
                pdu: vec![0x01, 0x02, 0x03],
                fcs: 0,
                lqi: None,
            },
        ));
        let decoded_bad_fcs = decode_top_level(&bad_fcs_message);
        let parsed_bad_fcs =
            parse_dot15d4_received(&decoded_bad_fcs).expect("raw PDU with bad FCS parses");
        assert_eq!(
            parsed_bad_fcs,
            WhadDot15d4Rx {
                channel: 26,
                // rssi defaults to 0 when absent.
                rssi: 0,
                fcs_valid: false,
                // lqi defaults to 0 when absent.
                lqi: 0,
                pdu: vec![0x01, 0x02, 0x03],
            }
        );

        // PduReceived: FCS already stripped/validated by firmware -> fcs_valid true.
        let pdu = vec![0x41, 0x88, 0x02, 0xAB, 0xCD];
        let pdu_message = build_dot15d4_message(proto::dot15d4::message::Msg::Pdu(
            proto::dot15d4::PduReceived {
                channel: 20,
                rssi: Some(-70),
                timestamp: Some(456),
                fcs_validity: false,
                pdu: pdu.clone(),
                lqi: Some(120),
            },
        ));
        let decoded_pdu = decode_top_level(&pdu_message);
        let parsed_pdu = parse_dot15d4_received(&decoded_pdu).expect("PDU parses");
        assert_eq!(
            parsed_pdu,
            WhadDot15d4Rx {
                channel: 20,
                rssi: -70,
                fcs_valid: true,
                lqi: 120,
                pdu,
            }
        );

        // A non-dot15d4 message (a dot15d4 command, not a PDU notification)
        // returns None so the reader skips control frames.
        let command_message = build_dot15d4_sniff(11);
        let decoded_command = decode_top_level(&command_message);
        assert!(parse_dot15d4_received(&decoded_command).is_none());

        // A wholly different domain message (discovery) also returns None.
        let discovery_message = proto::Message {
            msg: Some(proto::message::Msg::Discovery(proto::discovery::Message {
                msg: Some(proto::discovery::message::Msg::ResetQuery(
                    proto::discovery::DeviceResetQuery {},
                )),
            })),
        };
        let decoded_discovery = decode_top_level(&discovery_message);
        assert!(parse_dot15d4_received(&decoded_discovery).is_none());
    }
}
