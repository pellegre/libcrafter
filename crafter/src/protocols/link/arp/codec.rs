use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Packet, Raw};

use super::address::ArpAddressBytes;
use super::constants::ARP_FIXED_HEADER_LEN;
use super::layer::Arp;

const ARP_ETHERNET_IPV4_LEN: usize = ARP_FIXED_HEADER_LEN + 6 + 4 + 6 + 4;

/// Append a decoded ARP packet to an existing packet stack.
pub(crate) fn append_arp_packet(mut packet: Packet, payload: &[u8]) -> Result<Packet> {
    let (arp, rest) = decode_arp(payload)?;
    packet.push_arp_mut(arp);
    if !rest.is_empty() {
        packet.push_mut(Raw::from_bytes(rest));
    }
    Ok(packet)
}

pub(crate) fn decode_arp(bytes: &[u8]) -> Result<(Arp, &[u8])> {
    if bytes.len() < ARP_FIXED_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "arp header",
            ARP_FIXED_HEADER_LEN,
            bytes.len(),
        ));
    }

    let hardware_len = bytes[4] as usize;
    let protocol_len = bytes[5] as usize;
    let total_len = ARP_FIXED_HEADER_LEN + hardware_len * 2 + protocol_len * 2;
    if bytes.len() < total_len {
        return Err(CrafterError::buffer_too_short(
            "arp addresses",
            total_len,
            bytes.len(),
        ));
    }

    if hardware_len == 6 && protocol_len == 4 {
        let fixed = <&[u8; ARP_ETHERNET_IPV4_LEN]>::try_from(&bytes[..ARP_ETHERNET_IPV4_LEN])
            .expect("standard ARP length was checked before fixed decode");
        let arp = Arp {
            hardware_type: Field::user(u16::from_be_bytes([fixed[0], fixed[1]])),
            protocol_type: Field::user(u16::from_be_bytes([fixed[2], fixed[3]])),
            hardware_len: Field::user(fixed[4]),
            protocol_len: Field::user(fixed[5]),
            operation: Field::user(u16::from_be_bytes([fixed[6], fixed[7]])),
            sender_hardware_addr: Field::user(ArpAddressBytes::from_len6([
                fixed[8], fixed[9], fixed[10], fixed[11], fixed[12], fixed[13],
            ])),
            sender_protocol_addr: Field::user(ArpAddressBytes::from_len4([
                fixed[14], fixed[15], fixed[16], fixed[17],
            ])),
            target_hardware_addr: Field::user(ArpAddressBytes::from_len6([
                fixed[18], fixed[19], fixed[20], fixed[21], fixed[22], fixed[23],
            ])),
            target_protocol_addr: Field::user(ArpAddressBytes::from_len4([
                fixed[24], fixed[25], fixed[26], fixed[27],
            ])),
        };

        return Ok((arp, &bytes[ARP_ETHERNET_IPV4_LEN..]));
    }

    let sender_hardware_start = ARP_FIXED_HEADER_LEN;
    let sender_protocol_start = sender_hardware_start + hardware_len;
    let target_hardware_start = sender_protocol_start + protocol_len;
    let target_protocol_start = target_hardware_start + hardware_len;

    let arp = Arp {
        hardware_type: Field::user(u16::from_be_bytes([bytes[0], bytes[1]])),
        protocol_type: Field::user(u16::from_be_bytes([bytes[2], bytes[3]])),
        hardware_len: Field::user(bytes[4]),
        protocol_len: Field::user(bytes[5]),
        operation: Field::user(u16::from_be_bytes([bytes[6], bytes[7]])),
        sender_hardware_addr: Field::user(ArpAddressBytes::from_slice(
            &bytes[sender_hardware_start..sender_protocol_start],
        )),
        sender_protocol_addr: Field::user(ArpAddressBytes::from_slice(
            &bytes[sender_protocol_start..target_hardware_start],
        )),
        target_hardware_addr: Field::user(ArpAddressBytes::from_slice(
            &bytes[target_hardware_start..target_protocol_start],
        )),
        target_protocol_addr: Field::user(ArpAddressBytes::from_slice(
            &bytes[target_protocol_start..total_len],
        )),
    };

    Ok((arp, &bytes[total_len..]))
}
