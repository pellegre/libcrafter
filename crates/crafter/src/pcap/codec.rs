use std::io::{self, Read, Write};

use crate::{NetworkLayer, Packet, ProtocolRegistry};

use super::{PcapError, PcapHeader, PcapLinkType, Result, TimestampPrecision};

pub(super) const PCAP_HEADER_LEN: usize = 24;
pub(super) const PCAP_RECORD_HEADER_LEN: usize = 16;
pub(super) const PCAP_VERSION_MAJOR: u16 = 2;
pub(super) const PCAP_VERSION_MINOR: u16 = 4;
pub(super) const DEFAULT_SNAPLEN: u32 = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Endian {
    Little,
    Big,
}

pub(super) fn decode_raw_ip_with_registry(
    registry: &ProtocolRegistry,
    bytes: &[u8],
) -> crate::Result<Packet> {
    match bytes.first().map(|byte| byte >> 4) {
        Some(4) => registry.decode_from_l3(NetworkLayer::Ipv4, bytes),
        Some(6) => registry.decode_from_l3(NetworkLayer::Ipv6, bytes),
        _ => Packet::decode_raw(bytes),
    }
}

pub(super) fn parse_header(bytes: &[u8; PCAP_HEADER_LEN]) -> Result<(PcapHeader, Endian)> {
    let (endian, precision) = match &bytes[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, TimestampPrecision::Microseconds),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, TimestampPrecision::Microseconds),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, TimestampPrecision::Nanoseconds),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, TimestampPrecision::Nanoseconds),
        _ => return Err(PcapError::InvalidHeader("unknown magic number")),
    };

    let version_major = read_u16(&bytes[4..6], endian);
    let version_minor = read_u16(&bytes[6..8], endian);
    if version_major != PCAP_VERSION_MAJOR {
        return Err(PcapError::InvalidHeader("unsupported major version"));
    }

    let thiszone = read_i32(&bytes[8..12], endian);
    let sigfigs = read_u32(&bytes[12..16], endian);
    let snaplen = read_u32(&bytes[16..20], endian);
    if snaplen == 0 {
        return Err(PcapError::InvalidHeader("snapshot length must be non-zero"));
    }
    let link_type = PcapLinkType::from_datalink(read_u32(&bytes[20..24], endian));

    Ok((
        PcapHeader {
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            link_type,
            precision,
        },
        endian,
    ))
}

pub(super) fn write_header<W>(writer: &mut W, header: PcapHeader, endian: Endian) -> Result<()>
where
    W: Write,
{
    let magic = match (endian, header.precision) {
        (Endian::Little, TimestampPrecision::Microseconds) => [0xd4, 0xc3, 0xb2, 0xa1],
        (Endian::Big, TimestampPrecision::Microseconds) => [0xa1, 0xb2, 0xc3, 0xd4],
        (Endian::Little, TimestampPrecision::Nanoseconds) => [0x4d, 0x3c, 0xb2, 0xa1],
        (Endian::Big, TimestampPrecision::Nanoseconds) => [0xa1, 0xb2, 0x3c, 0x4d],
    };

    writer.write_all(&magic)?;
    write_u16(writer, endian, header.version_major)?;
    write_u16(writer, endian, header.version_minor)?;
    write_i32(writer, endian, header.thiszone)?;
    write_u32(writer, endian, header.sigfigs)?;
    write_u32(writer, endian, header.snaplen)?;
    write_u32(writer, endian, header.link_type.datalink())?;
    Ok(())
}

pub(super) fn read_exact_or_eof<R>(reader: &mut R, out: &mut [u8]) -> io::Result<bool>
where
    R: Read,
{
    let mut offset = 0;
    while offset < out.len() {
        match reader.read(&mut out[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "partial pcap record header",
                ))
            }
            Ok(read) => offset += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(true)
}

pub(super) fn read_u16(bytes: &[u8], endian: Endian) -> u16 {
    let mut value = [0u8; 2];
    value.copy_from_slice(bytes);
    match endian {
        Endian::Little => u16::from_le_bytes(value),
        Endian::Big => u16::from_be_bytes(value),
    }
}

pub(super) fn read_u32(bytes: &[u8], endian: Endian) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(bytes);
    match endian {
        Endian::Little => u32::from_le_bytes(value),
        Endian::Big => u32::from_be_bytes(value),
    }
}

pub(super) fn read_i32(bytes: &[u8], endian: Endian) -> i32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(bytes);
    match endian {
        Endian::Little => i32::from_le_bytes(value),
        Endian::Big => i32::from_be_bytes(value),
    }
}

pub(super) fn write_u16<W>(writer: &mut W, endian: Endian, value: u16) -> io::Result<()>
where
    W: Write,
{
    match endian {
        Endian::Little => writer.write_all(&value.to_le_bytes()),
        Endian::Big => writer.write_all(&value.to_be_bytes()),
    }
}

pub(super) fn write_u32<W>(writer: &mut W, endian: Endian, value: u32) -> io::Result<()>
where
    W: Write,
{
    match endian {
        Endian::Little => writer.write_all(&value.to_le_bytes()),
        Endian::Big => writer.write_all(&value.to_be_bytes()),
    }
}

pub(super) fn write_i32<W>(writer: &mut W, endian: Endian, value: i32) -> io::Result<()>
where
    W: Write,
{
    match endian {
        Endian::Little => writer.write_all(&value.to_le_bytes()),
        Endian::Big => writer.write_all(&value.to_be_bytes()),
    }
}
