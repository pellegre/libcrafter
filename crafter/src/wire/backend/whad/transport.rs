//! Byte-channel transport for WHAD serial links.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use prost::Message;

use super::framing::{encode_frame, FrameDecoder};
use crate::wire::{Result, WireError};

/// WHAD's default serial baud rate for USB CDC-ACM dongles.
pub(crate) const WHAD_DEFAULT_BAUD: u32 = 115_200;

const SERIAL_TIMEOUT: Duration = Duration::from_millis(100);

/// Minimal byte channel used by the WHAD backend.
pub(crate) trait WhadByteChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write_all(&mut self, data: &[u8]) -> Result<()>;
}

/// Framed WHAD protobuf message I/O over a byte channel.
pub(crate) struct WhadLink<C: WhadByteChannel> {
    channel: C,
    decoder: FrameDecoder,
}

impl<C: WhadByteChannel> WhadLink<C> {
    pub(crate) fn new(channel: C) -> Self {
        Self {
            channel,
            decoder: FrameDecoder::default(),
        }
    }

    pub(crate) fn send_message(&mut self, msg: &impl Message) -> Result<()> {
        let message_bytes = msg.encode_to_vec();
        if message_bytes.len() > u16::MAX as usize {
            return Err(WireError::backend(
                "whad link",
                "send message",
                "encoded message exceeds WHAD frame length",
            ));
        }

        let frame = encode_frame(&message_bytes);
        self.channel
            .write_all(&frame)
            .map_err(|err| WireError::backend("whad link", "send message", err.to_string()))
    }

    pub(crate) fn recv_message(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let start = Instant::now();
        let mut buf = [0; 1024];

        loop {
            if let Some(frame) = self.decoder.next() {
                return Ok(frame);
            }

            if start.elapsed() >= timeout {
                return Err(WireError::backend(
                    "whad link",
                    "receive message",
                    "timeout waiting for WHAD frame",
                ));
            }

            match self.channel.read(&mut buf) {
                Ok(0) => wait_for_more_input(start, timeout),
                Ok(n) => self.decoder.push(&buf[..n]),
                Err(err) => {
                    return Err(WireError::backend(
                        "whad link",
                        "receive message",
                        err.to_string(),
                    ));
                }
            }
        }
    }
}

/// Serial WHAD byte channel backed by a named TTY port.
pub(crate) struct SerialChannel {
    port: Box<dyn serialport::SerialPort>,
}

impl SerialChannel {
    /// Open `port` using WHAD's default serial baud rate.
    pub(crate) fn open(port: &str) -> Result<Self> {
        Self::open_with_baud(port, WHAD_DEFAULT_BAUD)
    }

    /// Open `port` with an explicit serial baud rate.
    pub(crate) fn open_with_baud(port: &str, baud: u32) -> Result<Self> {
        let port = serialport::new(port, baud)
            .data_bits(serialport::DataBits::Eight)
            .flow_control(serialport::FlowControl::None)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .timeout(SERIAL_TIMEOUT)
            .open()
            .map_err(|err| map_serialport_error("open serial port", err))?;

        Ok(Self { port })
    }
}

impl WhadByteChannel for SerialChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.port.read(buf) {
            Ok(n) => Ok(n),
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => Ok(0),
            Err(err) => Err(map_serial_io_error("read")(err)),
        }
    }

    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.port
            .write_all(data)
            .map_err(map_serial_io_error("write"))
    }
}

fn map_serialport_error(operation: &'static str, err: serialport::Error) -> WireError {
    WireError::backend("whad serial", operation, err.to_string())
}

fn map_serial_io_error(operation: &'static str) -> impl FnOnce(std::io::Error) -> WireError {
    move |err| WireError::backend("whad serial", operation, err.to_string())
}

fn wait_for_more_input(start: Instant, timeout: Duration) {
    let elapsed = start.elapsed();
    if elapsed >= timeout {
        return;
    }

    let remaining = timeout - elapsed;
    std::thread::sleep(remaining.min(Duration::from_millis(1)));
}

#[cfg(all(test, feature = "whad"))]
#[derive(Debug, Default)]
pub(crate) struct LoopbackChannel {
    buf: std::collections::VecDeque<u8>,
    max_read: Option<usize>,
}

#[cfg(all(test, feature = "whad"))]
impl LoopbackChannel {
    pub(crate) fn with_max_read(max_read: usize) -> Self {
        Self {
            buf: std::collections::VecDeque::new(),
            max_read: Some(max_read),
        }
    }
}

#[cfg(all(test, feature = "whad"))]
impl WhadByteChannel for LoopbackChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let max_read = self.max_read.unwrap_or(buf.len());
        let n = buf.len().min(max_read).min(self.buf.len());
        for slot in &mut buf[..n] {
            *slot = self.buf.pop_front().expect("loopback byte disappeared");
        }
        Ok(n)
    }

    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.buf.extend(data);
        Ok(())
    }
}

#[cfg(all(test, feature = "whad"))]
mod tests {
    use super::super::messages::build_device_reset_query;
    use super::*;

    #[test]
    fn whad_transport_loopback_roundtrips_bytes() {
        let mut channel = LoopbackChannel::default();
        channel.write_all(b"whad").unwrap();

        let mut first = [0; 2];
        assert_eq!(channel.read(&mut first).unwrap(), 2);
        assert_eq!(&first, b"wh");

        let mut second = [0; 4];
        assert_eq!(channel.read(&mut second).unwrap(), 2);
        assert_eq!(&second[..2], b"ad");
        assert_eq!(channel.read(&mut second).unwrap(), 0);
    }

    #[test]
    fn whad_link_io_roundtrips_message_bytes() {
        let message = build_device_reset_query();
        let expected = message.encode_to_vec();
        let mut link = WhadLink::new(LoopbackChannel::default());

        link.send_message(&message).unwrap();

        assert_eq!(
            link.recv_message(Duration::from_millis(20)).unwrap(),
            expected
        );
    }

    #[test]
    fn whad_link_io_roundtrips_message_bytes_with_partial_reads() {
        let message = build_device_reset_query();
        let expected = message.encode_to_vec();
        let first_chunk_len = encode_frame(&expected).len() - 1;
        let mut link = WhadLink::new(LoopbackChannel::with_max_read(first_chunk_len));

        link.send_message(&message).unwrap();

        assert_eq!(
            link.recv_message(Duration::from_millis(20)).unwrap(),
            expected
        );
    }
}
