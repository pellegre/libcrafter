//! IEEE 802.11 DSSS/CCK receive and transmit implementations.

mod rx;
mod tx;

pub use rx::DsssCckDecoder;
pub use tx::{
    DsssPlcpFields, DsssPreamble, LegacyDsssCckRate, LegacyDsssCckTransmission,
    LegacyDsssCckTxConfig,
};

fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in bytes {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x8408 & 0u16.wrapping_sub(crc & 1));
        }
    }
    !crc
}
