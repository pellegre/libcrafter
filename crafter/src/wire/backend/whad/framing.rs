//! WHAD serial framing helpers.

#![allow(dead_code)]

use prost::Message;

const WHAD_SYNC: [u8; 2] = [0xAC, 0xBE];
const WHAD_HEADER_LEN: usize = 4;

#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.buf.len() < WHAD_HEADER_LEN {
                return None;
            }

            if self.buf[..WHAD_SYNC.len()] != WHAD_SYNC {
                self.buf.remove(0);
                continue;
            }

            let len = u16::from_le_bytes([self.buf[2], self.buf[3]]) as usize;
            let frame_len = WHAD_HEADER_LEN + len;
            if self.buf.len() < frame_len {
                return None;
            }

            let payload = self.buf[WHAD_HEADER_LEN..frame_len].to_vec();
            self.buf.drain(..frame_len);
            return Some(payload);
        }
    }
}

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

    #[test]
    fn whad_frame_decode_full_frame() {
        let mut decoder = FrameDecoder::default();
        decoder.push(&encode_frame(&[0x01, 0x02, 0x03]));

        assert_eq!(decoder.next(), Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(decoder.next(), None);
    }

    #[test]
    fn whad_frame_decode_partial_chunks() {
        let mut decoder = FrameDecoder::default();
        let frame = encode_frame(&[0xAA, 0xBB, 0xCC]);

        decoder.push(&frame[..3]);
        assert_eq!(decoder.next(), None);

        decoder.push(&frame[3..]);
        assert_eq!(decoder.next(), Some(vec![0xAA, 0xBB, 0xCC]));
        assert_eq!(decoder.next(), None);
    }

    #[test]
    fn whad_frame_decode_resyncs_after_garbage() {
        let mut decoder = FrameDecoder::default();
        decoder.push(&[0x00]);
        decoder.push(&encode_frame(&[0x42]));

        assert_eq!(decoder.next(), Some(vec![0x42]));
        assert_eq!(decoder.next(), None);
    }

    #[test]
    fn whad_frame_decode_concatenated_frames() {
        let mut decoder = FrameDecoder::default();
        let mut frames = encode_frame(&[0x01]);
        frames.extend_from_slice(&encode_frame(&[0x02, 0x03]));
        decoder.push(&frames);

        assert_eq!(decoder.next(), Some(vec![0x01]));
        assert_eq!(decoder.next(), Some(vec![0x02, 0x03]));
        assert_eq!(decoder.next(), None);
    }
}
