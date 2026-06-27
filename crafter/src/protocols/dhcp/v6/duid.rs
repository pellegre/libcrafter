//! DHCPv6 DUID packet data.

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};

use super::constants::{DHCPV6_DUID_EN, DHCPV6_DUID_LL, DHCPV6_DUID_LLT, DHCPV6_DUID_UUID};

/// DHCPv6 DHCP Unique Identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Dhcpv6Duid {
    /// DUID-LLT: link-layer address plus time.
    Llt {
        /// Hardware type from the ARP hardware type namespace.
        hardware_type: u16,
        /// Time value in seconds since 2000-01-01 00:00 UTC.
        time: u32,
        /// Link-layer address bytes.
        link_layer_address: Vec<u8>,
    },
    /// DUID-EN: enterprise number plus vendor identifier bytes.
    En {
        /// Private enterprise number.
        enterprise_number: u32,
        /// Enterprise-specific identifier bytes.
        identifier: Vec<u8>,
    },
    /// DUID-LL: link-layer address.
    Ll {
        /// Hardware type from the ARP hardware type namespace.
        hardware_type: u16,
        /// Link-layer address bytes.
        link_layer_address: Vec<u8>,
    },
    /// DUID-UUID: 16-octet UUID bytes.
    Uuid([u8; 16]),
    /// Unknown DUID type preserving its payload bytes.
    Unknown {
        /// Raw DUID type.
        duid_type: u16,
        /// Payload bytes after the 2-octet DUID type.
        payload: Vec<u8>,
    },
}

impl Dhcpv6Duid {
    /// Create a DUID-LLT value.
    pub fn llt(hardware_type: u16, time: u32, link_layer_address: impl Into<Vec<u8>>) -> Self {
        Self::Llt {
            hardware_type,
            time,
            link_layer_address: link_layer_address.into(),
        }
    }

    /// Create a DUID-EN value.
    pub fn en(enterprise_number: u32, identifier: impl Into<Vec<u8>>) -> Self {
        Self::En {
            enterprise_number,
            identifier: identifier.into(),
        }
    }

    /// Create a DUID-LL value.
    pub fn ll(hardware_type: u16, link_layer_address: impl Into<Vec<u8>>) -> Self {
        Self::Ll {
            hardware_type,
            link_layer_address: link_layer_address.into(),
        }
    }

    /// Create a DUID-UUID value.
    pub const fn uuid(uuid: [u8; 16]) -> Self {
        Self::Uuid(uuid)
    }

    /// Create an unknown DUID value.
    pub fn unknown(duid_type: u16, payload: impl Into<Vec<u8>>) -> Self {
        Self::Unknown {
            duid_type,
            payload: payload.into(),
        }
    }

    /// Decode DHCPv6 DUID bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(CrafterError::buffer_too_short(
                "dhcpv6.duid.type",
                2,
                bytes.len(),
            ));
        }

        let duid_type = read_u16_be(&bytes[..2])?;
        match duid_type {
            DHCPV6_DUID_LLT => decode_duid_llt(bytes),
            DHCPV6_DUID_EN => decode_duid_en(bytes),
            DHCPV6_DUID_LL => decode_duid_ll(bytes),
            DHCPV6_DUID_UUID => decode_duid_uuid(bytes),
            value => Ok(Self::Unknown {
                duid_type: value,
                payload: bytes[2..].to_vec(),
            }),
        }
    }

    /// Encode this DUID to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Llt {
                hardware_type,
                time,
                link_layer_address,
            } => {
                append_u16_be(&mut out, DHCPV6_DUID_LLT);
                append_u16_be(&mut out, *hardware_type);
                out.extend_from_slice(&time.to_be_bytes());
                out.extend_from_slice(link_layer_address);
            }
            Self::En {
                enterprise_number,
                identifier,
            } => {
                append_u16_be(&mut out, DHCPV6_DUID_EN);
                out.extend_from_slice(&enterprise_number.to_be_bytes());
                out.extend_from_slice(identifier);
            }
            Self::Ll {
                hardware_type,
                link_layer_address,
            } => {
                append_u16_be(&mut out, DHCPV6_DUID_LL);
                append_u16_be(&mut out, *hardware_type);
                out.extend_from_slice(link_layer_address);
            }
            Self::Uuid(uuid) => {
                append_u16_be(&mut out, DHCPV6_DUID_UUID);
                out.extend_from_slice(uuid);
            }
            Self::Unknown { duid_type, payload } => {
                append_u16_be(&mut out, *duid_type);
                out.extend_from_slice(payload);
            }
        }
        out
    }

    /// Raw DUID type value.
    pub const fn duid_type(&self) -> u16 {
        match self {
            Self::Llt { .. } => DHCPV6_DUID_LLT,
            Self::En { .. } => DHCPV6_DUID_EN,
            Self::Ll { .. } => DHCPV6_DUID_LL,
            Self::Uuid(_) => DHCPV6_DUID_UUID,
            Self::Unknown { duid_type, .. } => *duid_type,
        }
    }

    /// Hardware type for DUID-LLT and DUID-LL.
    pub const fn hardware_type(&self) -> Option<u16> {
        match self {
            Self::Llt { hardware_type, .. } | Self::Ll { hardware_type, .. } => {
                Some(*hardware_type)
            }
            Self::En { .. } | Self::Uuid(_) | Self::Unknown { .. } => None,
        }
    }

    /// Time value for DUID-LLT.
    pub const fn time(&self) -> Option<u32> {
        match self {
            Self::Llt { time, .. } => Some(*time),
            Self::En { .. } | Self::Ll { .. } | Self::Uuid(_) | Self::Unknown { .. } => None,
        }
    }

    /// Link-layer address for DUID-LLT and DUID-LL.
    pub fn link_layer_address(&self) -> Option<&[u8]> {
        match self {
            Self::Llt {
                link_layer_address, ..
            }
            | Self::Ll {
                link_layer_address, ..
            } => Some(link_layer_address),
            Self::En { .. } | Self::Uuid(_) | Self::Unknown { .. } => None,
        }
    }

    /// Enterprise number for DUID-EN.
    pub const fn enterprise_number(&self) -> Option<u32> {
        match self {
            Self::En {
                enterprise_number, ..
            } => Some(*enterprise_number),
            Self::Llt { .. } | Self::Ll { .. } | Self::Uuid(_) | Self::Unknown { .. } => None,
        }
    }

    /// Enterprise identifier for DUID-EN.
    pub fn enterprise_identifier(&self) -> Option<&[u8]> {
        match self {
            Self::En { identifier, .. } => Some(identifier),
            Self::Llt { .. } | Self::Ll { .. } | Self::Uuid(_) | Self::Unknown { .. } => None,
        }
    }

    /// UUID bytes for DUID-UUID.
    pub const fn uuid_value(&self) -> Option<[u8; 16]> {
        match self {
            Self::Uuid(uuid) => Some(*uuid),
            Self::Llt { .. } | Self::En { .. } | Self::Ll { .. } | Self::Unknown { .. } => None,
        }
    }

    /// Unknown DUID payload bytes.
    pub fn unknown_payload(&self) -> Option<&[u8]> {
        match self {
            Self::Unknown { payload, .. } => Some(payload),
            Self::Llt { .. } | Self::En { .. } | Self::Ll { .. } | Self::Uuid(_) => None,
        }
    }
}

impl From<Dhcpv6Duid> for Vec<u8> {
    fn from(duid: Dhcpv6Duid) -> Self {
        duid.encode()
    }
}

impl From<&Dhcpv6Duid> for Vec<u8> {
    fn from(duid: &Dhcpv6Duid) -> Self {
        duid.encode()
    }
}

fn decode_duid_llt(bytes: &[u8]) -> Result<Dhcpv6Duid> {
    ensure_duid_len(bytes, 8, "dhcpv6.duid.llt")?;
    Ok(Dhcpv6Duid::Llt {
        hardware_type: read_u16_be(&bytes[2..4])?,
        time: read_u32_be(&bytes[4..8])?,
        link_layer_address: bytes[8..].to_vec(),
    })
}

fn decode_duid_en(bytes: &[u8]) -> Result<Dhcpv6Duid> {
    ensure_duid_len(bytes, 6, "dhcpv6.duid.en")?;
    Ok(Dhcpv6Duid::En {
        enterprise_number: read_u32_be(&bytes[2..6])?,
        identifier: bytes[6..].to_vec(),
    })
}

fn decode_duid_ll(bytes: &[u8]) -> Result<Dhcpv6Duid> {
    ensure_duid_len(bytes, 4, "dhcpv6.duid.ll")?;
    Ok(Dhcpv6Duid::Ll {
        hardware_type: read_u16_be(&bytes[2..4])?,
        link_layer_address: bytes[4..].to_vec(),
    })
}

fn decode_duid_uuid(bytes: &[u8]) -> Result<Dhcpv6Duid> {
    ensure_duid_len(bytes, 18, "dhcpv6.duid.uuid")?;
    if bytes.len() != 18 {
        return Err(CrafterError::invalid_field_value(
            "dhcpv6.duid.uuid",
            "payload length must be 16 bytes",
        ));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes[2..18]);
    Ok(Dhcpv6Duid::Uuid(uuid))
}

fn ensure_duid_len(bytes: &[u8], required: usize, context: &'static str) -> Result<()> {
    if bytes.len() < required {
        Err(CrafterError::buffer_too_short(
            context,
            required,
            bytes.len(),
        ))
    } else {
        Ok(())
    }
}

fn append_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod dhcpv6_duid_tests {
    use super::Dhcpv6Duid;
    use crate::error::CrafterError;
    use crate::packet::Packet;
    use crate::protocols::dhcp::v6::{Dhcpv6, Dhcpv6Option};

    #[test]
    fn dhcpv6_duid_valid_values_encode_and_decode() {
        let llt = Dhcpv6Duid::llt(1, 0x01020304, [0xaa, 0xbb, 0xcc]);
        assert_eq!(
            llt.encode(),
            vec![0x00, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc]
        );
        assert_eq!(Dhcpv6Duid::decode(&llt.encode()).unwrap(), llt);
        assert_eq!(llt.hardware_type(), Some(1));
        assert_eq!(llt.time(), Some(0x01020304));
        assert_eq!(llt.link_layer_address(), Some(&[0xaa, 0xbb, 0xcc][..]));

        let en = Dhcpv6Duid::en(32_4242, [0xde, 0xad]);
        assert_eq!(
            Dhcpv6Duid::decode(&en.encode())
                .unwrap()
                .enterprise_number(),
            Some(32_4242),
        );
        assert_eq!(en.enterprise_identifier(), Some(&[0xde, 0xad][..]));

        let ll = Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        assert_eq!(Dhcpv6Duid::decode(&ll.encode()).unwrap(), ll);
        assert_eq!(
            ll.link_layer_address(),
            Some(&[0x02, 0x00, 0x5e, 0x00, 0x53, 0x01][..]),
        );

        let uuid = Dhcpv6Duid::uuid([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        assert_eq!(Dhcpv6Duid::decode(&uuid.encode()).unwrap(), uuid);
        assert_eq!(
            uuid.uuid_value(),
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]),
        );
    }

    #[test]
    fn dhcpv6_duid_unknown_types_preserve_payload() {
        let raw = [0x12, 0x34, 0xde, 0xad, 0xbe, 0xef];
        let duid = Dhcpv6Duid::decode(&raw).unwrap();

        assert_eq!(duid, Dhcpv6Duid::unknown(0x1234, [0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(duid.duid_type(), 0x1234);
        assert_eq!(duid.unknown_payload(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
        assert_eq!(duid.encode(), raw);
    }

    #[test]
    fn dhcpv6_duid_truncated_payloads_are_structured_errors() {
        let mut short_uuid = vec![0x00, 0x04];
        short_uuid.resize(17, 0);

        assert_eq!(
            Dhcpv6Duid::decode(&[0x00]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.duid.type", 2, 1),
        );
        assert_eq!(
            Dhcpv6Duid::decode(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.duid.llt", 8, 7),
        );
        assert_eq!(
            Dhcpv6Duid::decode(&[0x00, 0x02, 0x00, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.duid.en", 6, 5),
        );
        assert_eq!(
            Dhcpv6Duid::decode(&[0x00, 0x03, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.duid.ll", 4, 3),
        );
        assert_eq!(
            Dhcpv6Duid::decode(&short_uuid).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.duid.uuid", 18, 17),
        );
    }

    #[test]
    fn dhcpv6_duid_integrates_with_identifier_options() {
        let client_duid = Dhcpv6Duid::ll(1, [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        let server_duid = Dhcpv6Duid::en(32_4242, [0xde, 0xad, 0xbe, 0xef]);

        let client_option = Dhcpv6Option::client_id(&client_duid);
        assert_eq!(
            client_option.client_duid_value().unwrap(),
            Some(client_duid.clone()),
        );

        let message = Dhcpv6::solicit(0x010203)
            .client_duid(client_duid.clone())
            .server_duid(server_duid.clone());
        let bytes = Packet::from_layer(message).compile().unwrap();
        let decoded = Dhcpv6::decode(bytes.as_bytes()).unwrap();

        assert_eq!(decoded.client_duid_value().unwrap(), Some(client_duid));
        assert_eq!(decoded.server_duid_value().unwrap(), Some(server_duid));
    }
}
