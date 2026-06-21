//! Byte-channel transport for WHAD serial links.

use std::io::{Read, Write};
use std::time::Duration;

use crate::wire::{Result, WireError};

/// WHAD's default serial baud rate for USB CDC-ACM dongles.
pub(crate) const WHAD_DEFAULT_BAUD: u32 = 115_200;

const SERIAL_TIMEOUT: Duration = Duration::from_millis(100);

/// Minimal byte channel used by the WHAD backend.
pub(crate) trait WhadByteChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write_all(&mut self, data: &[u8]) -> Result<()>;
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
        self.port.read(buf).map_err(map_serial_io_error("read"))
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

#[cfg(all(test, feature = "whad"))]
#[derive(Debug, Default)]
pub(crate) struct LoopbackChannel {
    buf: std::collections::VecDeque<u8>,
}

#[cfg(all(test, feature = "whad"))]
impl WhadByteChannel for LoopbackChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = buf.len().min(self.buf.len());
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
}
