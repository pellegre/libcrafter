//! WHAD 802.15.4 backend module.
//!
//! This step only proves the prost-generated `proto::dot15d4` surface is
//! reachable and round-trips. Backend logic (modes, builders, parsers) is
//! added in later steps.

#[cfg(all(test, feature = "whad"))]
mod tests {
    use prost::Message as _;

    use super::super::proto;

    #[test]
    fn dot15d4_proto_types() {
        // Construct a generated dot15d4 command and wrap it in the dot15d4
        // `Message` oneof, then in the top-level WHAD `Message` envelope. This
        // exercises `proto::dot15d4::{SniffCmd, Message}`, the
        // `proto::dot15d4::message::Msg::Sniff` oneof variant, and the
        // top-level `proto::message::Msg::Dot15d4` variant.
        let message = proto::Message {
            msg: Some(proto::message::Msg::Dot15d4(proto::dot15d4::Message {
                msg: Some(proto::dot15d4::message::Msg::Sniff(
                    proto::dot15d4::SniffCmd { channel: 15 },
                )),
            })),
        };

        let encoded = message.encode_to_vec();
        assert!(!encoded.is_empty());

        let decoded = proto::Message::decode(encoded.as_slice())
            .expect("WHAD dot15d4 message decodes");

        match decoded.msg {
            Some(proto::message::Msg::Dot15d4(dot15d4)) => match dot15d4.msg {
                Some(proto::dot15d4::message::Msg::Sniff(command)) => {
                    assert_eq!(command.channel, 15);
                }
                _ => panic!("expected dot15d4 sniff command"),
            },
            _ => panic!("expected top-level dot15d4 message"),
        }

        // Reference the remaining generated dot15d4 types so the smoke test
        // proves the full generated surface compiles.
        let _send = proto::dot15d4::SendCmd {
            channel: 15,
            pdu: Vec::new(),
        };
        let _send_raw = proto::dot15d4::SendRawCmd {
            channel: 15,
            pdu: Vec::new(),
            fcs: 0,
        };
        let _raw_pdu = proto::dot15d4::RawPduReceived {
            channel: 15,
            rssi: None,
            timestamp: None,
            fcs_validity: true,
            pdu: Vec::new(),
            fcs: 0,
            lqi: None,
        };
        let _pdu = proto::dot15d4::PduReceived {
            channel: 15,
            rssi: None,
            timestamp: None,
            fcs_validity: true,
            pdu: Vec::new(),
            lqi: None,
        };
        let _command = proto::dot15d4::Dot15d4Command::Sniff;
    }
}
