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
}
