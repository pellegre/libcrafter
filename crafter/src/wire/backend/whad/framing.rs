//! WHAD serial framing helpers.

#![allow(dead_code)]

use prost::Message;

const WHAD_SYNC: [u8; 2] = [0xAC, 0xBE];
const WHAD_HEADER_LEN: usize = 4;

pub fn encode_frame(message_bytes: &[u8]) -> Vec<u8> {
    let len = u16::try_from(message_bytes.len()).expect("WHAD frame payload exceeds u16 length");
    let mut frame = Vec::with_capacity(WHAD_HEADER_LEN + message_bytes.len());
    frame.extend_from_slice(&WHAD_SYNC);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(message_bytes);
    frame
}

pub fn encode_message(msg: &impl Message) -> Vec<u8> {
    encode_frame(&msg.encode_to_vec())
}

#[cfg(all(test, feature = "whad"))]
mod tests {
    use super::*;

    #[test]
    fn whad_frame_encode_payload() {
        assert_eq!(
            encode_frame(&[0x01, 0x02, 0x03]),
            vec![0xAC, 0xBE, 0x03, 0x00, 0x01, 0x02, 0x03]
        );
    }

    #[test]
    fn whad_frame_encode_empty() {
        assert_eq!(encode_frame(&[]), vec![0xAC, 0xBE, 0x00, 0x00]);
    }
}
