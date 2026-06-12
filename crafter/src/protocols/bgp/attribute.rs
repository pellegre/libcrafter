//! BGP-4 (RFC 4271) path attribute types.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::field::Field;
use crate::{CrafterError, Result};

use super::constants::{
    AFI_IPV4, AFI_IPV6, AS_PATH_SEG_AS_SEQUENCE, AS_PATH_SEG_AS_SET, ATTR_AGGREGATOR,
    ATTR_AGGREGATOR_FLAGS, ATTR_AS4_AGGREGATOR, ATTR_AS4_AGGREGATOR_FLAGS, ATTR_AS4_PATH,
    ATTR_AS4_PATH_FLAGS, ATTR_AS_PATH, ATTR_AS_PATH_FLAGS, ATTR_ATOMIC_AGGREGATE,
    ATTR_ATOMIC_AGGREGATE_FLAGS, ATTR_COMMUNITIES, ATTR_COMMUNITIES_FLAGS,
    ATTR_EXTENDED_COMMUNITIES, ATTR_EXTENDED_COMMUNITIES_FLAGS, ATTR_LARGE_COMMUNITY,
    ATTR_LARGE_COMMUNITY_FLAGS, ATTR_LOCAL_PREF, ATTR_LOCAL_PREF_FLAGS, ATTR_MP_REACH_NLRI,
    ATTR_MP_REACH_NLRI_FLAGS, ATTR_MP_UNREACH_NLRI, ATTR_MP_UNREACH_NLRI_FLAGS,
    ATTR_MULTI_EXIT_DISC, ATTR_MULTI_EXIT_DISC_FLAGS, ATTR_NEXT_HOP, ATTR_NEXT_HOP_FLAGS,
    ATTR_ORIGIN, ATTR_ORIGIN_FLAGS, BGP_ATTR_FLAG_EXTENDED_LENGTH, BGP_ATTR_FLAG_OPTIONAL,
    COMMUNITY_NO_ADVERTISE, COMMUNITY_NO_EXPORT, COMMUNITY_NO_EXPORT_SUBCONFED, ORIGIN_EGP,
    ORIGIN_IGP, ORIGIN_INCOMPLETE, SAFI_UNICAST,
};
use super::decode::take;

/// ORIGIN = IGP. RFC 4271 §5.1.1.
pub const BGP_ORIGIN_IGP: u8 = ORIGIN_IGP;
/// ORIGIN = EGP. RFC 4271 §5.1.1.
pub const BGP_ORIGIN_EGP: u8 = ORIGIN_EGP;
/// ORIGIN = INCOMPLETE. RFC 4271 §5.1.1.
pub const BGP_ORIGIN_INCOMPLETE: u8 = ORIGIN_INCOMPLETE;

/// AS_SET segment type. RFC 4271 §4.3.
pub const BGP_AS_SEGMENT_SET: u8 = AS_PATH_SEG_AS_SET;
/// AS_SEQUENCE segment type. RFC 4271 §4.3.
pub const BGP_AS_SEGMENT_SEQUENCE: u8 = AS_PATH_SEG_AS_SEQUENCE;

/// One AS_PATH segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPathSegment {
    /// Segment type, such as AS_SET or AS_SEQUENCE.
    pub kind: u8,
    /// AS numbers carried by this segment.
    pub asns: Vec<u32>,
}

/// BGP path-attribute value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpAttrValue {
    /// ORIGIN path attribute (RFC 4271 §5.1.1).
    Origin(u8),
    /// AS_PATH path attribute (RFC 4271 §5.1.2).
    AsPath {
        /// Whether AS numbers are encoded as four octets instead of two.
        four_octet: bool,
        /// Ordered AS_PATH segments.
        segments: Vec<AsPathSegment>,
    },
    /// NEXT_HOP path attribute (RFC 4271 §5.1.3).
    NextHop(Ipv4Addr),
    /// MULTI_EXIT_DISC path attribute (RFC 4271 §5.1.4).
    MultiExitDisc(u32),
    /// LOCAL_PREF path attribute (RFC 4271 §5.1.5).
    LocalPref(u32),
    /// ATOMIC_AGGREGATE path attribute (RFC 4271 §5.1.6).
    AtomicAggregate,
    /// AGGREGATOR path attribute (RFC 4271 §5.1.7).
    Aggregator {
        /// Last AS number that formed the aggregate route.
        asn: u32,
        /// BGP speaker address that formed the aggregate route.
        addr: Ipv4Addr,
    },
    /// COMMUNITIES path attribute (RFC 1997).
    Communities(Vec<u32>),
    /// EXTENDED COMMUNITIES path attribute (RFC 4360).
    ExtendedCommunities(Vec<[u8; 8]>),
    /// LARGE_COMMUNITIES path attribute (RFC 8092).
    LargeCommunities(Vec<[u32; 3]>),
    /// MP_REACH_NLRI path attribute (RFC 4760 §3).
    MpReachNlri {
        /// Address Family Identifier.
        afi: u16,
        /// Subsequent Address Family Identifier.
        safi: u8,
        /// Network address of next hop.
        next_hop: Vec<u8>,
        /// Network Layer Reachability Information.
        nlri: Vec<BgpPrefix>,
    },
    /// MP_UNREACH_NLRI path attribute (RFC 4760 §4).
    MpUnreachNlri {
        /// Address Family Identifier.
        afi: u16,
        /// Subsequent Address Family Identifier.
        safi: u8,
        /// Withdrawn Network Layer Reachability Information.
        withdrawn: Vec<BgpPrefix>,
    },
    /// A value whose type-specific structure is not modeled yet.
    Unknown(Vec<u8>),
}

impl BgpAttrValue {
    /// Encoded attribute value length, in octets.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Origin(_) => 1,
            Self::AsPath {
                four_octet,
                segments,
            } => as_path_encoded_len(segments, *four_octet),
            Self::NextHop(_) => 4,
            Self::MultiExitDisc(_) | Self::LocalPref(_) => 4,
            Self::AtomicAggregate => 0,
            Self::Aggregator { .. } => 6,
            Self::Communities(communities) => communities.len() * 4,
            Self::ExtendedCommunities(communities) => communities.len() * 8,
            Self::LargeCommunities(communities) => communities.len() * 12,
            Self::MpReachNlri { next_hop, nlri, .. } => {
                5 + next_hop.len() + prefixes_encoded_len(nlri)
            }
            Self::MpUnreachNlri { withdrawn, .. } => 3 + prefixes_encoded_len(withdrawn),
            Self::Unknown(value) => value.len(),
        }
    }

    /// Append the raw attribute value bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Origin(origin) => out.push(*origin),
            Self::AsPath {
                four_octet,
                segments,
            } => encode_as_path(segments, *four_octet, out),
            Self::NextHop(next_hop) => out.extend_from_slice(&next_hop.octets()),
            Self::MultiExitDisc(metric) | Self::LocalPref(metric) => {
                out.extend_from_slice(&metric.to_be_bytes());
            }
            Self::AtomicAggregate => {}
            Self::Aggregator { asn, addr } => {
                out.extend_from_slice(&(*asn as u16).to_be_bytes());
                out.extend_from_slice(&addr.octets());
            }
            Self::Communities(communities) => {
                for community in communities {
                    out.extend_from_slice(&community.to_be_bytes());
                }
            }
            Self::ExtendedCommunities(communities) => {
                for community in communities {
                    out.extend_from_slice(community);
                }
            }
            Self::LargeCommunities(communities) => {
                for [global, local1, local2] in communities {
                    out.extend_from_slice(&global.to_be_bytes());
                    out.extend_from_slice(&local1.to_be_bytes());
                    out.extend_from_slice(&local2.to_be_bytes());
                }
            }
            Self::MpReachNlri {
                afi,
                safi,
                next_hop,
                nlri,
            } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(*safi);
                out.push(next_hop.len() as u8);
                out.extend_from_slice(next_hop);
                out.push(0);
                for prefix in nlri {
                    prefix.encode_prefix(out);
                }
            }
            Self::MpUnreachNlri {
                afi,
                safi,
                withdrawn,
            } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(*safi);
                for prefix in withdrawn {
                    prefix.encode_prefix(out);
                }
            }
            Self::Unknown(value) => out.extend_from_slice(value),
        }
    }
}

/// Generic BGP path attribute frame (RFC 4271 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPathAttribute {
    /// Attribute Flags octet.
    pub flags: Field<u8>,
    /// Attribute Type Code.
    pub type_code: u8,
    /// Attribute Value.
    pub value: BgpAttrValue,
}

impl BgpPathAttribute {
    /// Build an ORIGIN path attribute (RFC 4271 §5.1.1).
    pub fn origin(origin: u8) -> Self {
        Self {
            flags: Field::defaulted(ATTR_ORIGIN_FLAGS),
            type_code: ATTR_ORIGIN,
            value: BgpAttrValue::Origin(origin),
        }
    }

    /// Build an AS_PATH attribute containing one AS_SEQUENCE segment.
    pub fn as_sequence(asns: &[u32]) -> Self {
        Self::as_path_segment(BGP_AS_SEGMENT_SEQUENCE, asns)
    }

    /// Build an AS_PATH attribute containing one AS_SET segment.
    pub fn as_set(asns: &[u32]) -> Self {
        Self::as_path_segment(BGP_AS_SEGMENT_SET, asns)
    }

    /// Build a NEXT_HOP path attribute carrying an IPv4 next hop.
    pub fn next_hop(next_hop: impl Into<Ipv4Addr>) -> Self {
        Self {
            flags: Field::defaulted(ATTR_NEXT_HOP_FLAGS),
            type_code: ATTR_NEXT_HOP,
            value: BgpAttrValue::NextHop(next_hop.into()),
        }
    }

    /// Build a MULTI_EXIT_DISC path attribute.
    pub fn multi_exit_disc(metric: u32) -> Self {
        Self {
            flags: Field::defaulted(ATTR_MULTI_EXIT_DISC_FLAGS),
            type_code: ATTR_MULTI_EXIT_DISC,
            value: BgpAttrValue::MultiExitDisc(metric),
        }
    }

    /// Build a LOCAL_PREF path attribute.
    pub fn local_pref(preference: u32) -> Self {
        Self {
            flags: Field::defaulted(ATTR_LOCAL_PREF_FLAGS),
            type_code: ATTR_LOCAL_PREF,
            value: BgpAttrValue::LocalPref(preference),
        }
    }

    /// Build an ATOMIC_AGGREGATE path attribute.
    pub fn atomic_aggregate() -> Self {
        Self {
            flags: Field::defaulted(ATTR_ATOMIC_AGGREGATE_FLAGS),
            type_code: ATTR_ATOMIC_AGGREGATE,
            value: BgpAttrValue::AtomicAggregate,
        }
    }

    /// Build an AGGREGATOR path attribute.
    pub fn aggregator(asn: u16, addr: impl Into<Ipv4Addr>) -> Self {
        Self {
            flags: Field::defaulted(ATTR_AGGREGATOR_FLAGS),
            type_code: ATTR_AGGREGATOR,
            value: BgpAttrValue::Aggregator {
                asn: asn as u32,
                addr: addr.into(),
            },
        }
    }

    /// Build a COMMUNITIES path attribute.
    pub fn communities(communities: &[u32]) -> Self {
        Self {
            flags: Field::defaulted(ATTR_COMMUNITIES_FLAGS),
            type_code: ATTR_COMMUNITIES,
            value: BgpAttrValue::Communities(communities.to_vec()),
        }
    }

    /// Build an EXTENDED COMMUNITIES path attribute.
    pub fn extended_communities(communities: &[[u8; 8]]) -> Self {
        Self {
            flags: Field::defaulted(ATTR_EXTENDED_COMMUNITIES_FLAGS),
            type_code: ATTR_EXTENDED_COMMUNITIES,
            value: BgpAttrValue::ExtendedCommunities(communities.to_vec()),
        }
    }

    /// Build a LARGE_COMMUNITIES path attribute.
    pub fn large_communities(communities: &[[u32; 3]]) -> Self {
        Self {
            flags: Field::defaulted(ATTR_LARGE_COMMUNITY_FLAGS),
            type_code: ATTR_LARGE_COMMUNITY,
            value: BgpAttrValue::LargeCommunities(communities.to_vec()),
        }
    }

    /// Build an MP_REACH_NLRI path attribute for IPv6 unicast NLRI.
    pub fn mp_reach_ipv6(next_hop: Ipv6Addr, nlri: &[BgpPrefix]) -> Self {
        Self {
            flags: Field::defaulted(ATTR_MP_REACH_NLRI_FLAGS),
            type_code: ATTR_MP_REACH_NLRI,
            value: BgpAttrValue::MpReachNlri {
                afi: AFI_IPV6,
                safi: SAFI_UNICAST,
                next_hop: next_hop.octets().to_vec(),
                nlri: nlri.to_vec(),
            },
        }
    }

    /// Build an MP_UNREACH_NLRI path attribute for IPv6 unicast withdrawn NLRI.
    pub fn mp_unreach_ipv6(withdrawn: &[BgpPrefix]) -> Self {
        Self {
            flags: Field::defaulted(ATTR_MP_UNREACH_NLRI_FLAGS),
            type_code: ATTR_MP_UNREACH_NLRI,
            value: BgpAttrValue::MpUnreachNlri {
                afi: AFI_IPV6,
                safi: SAFI_UNICAST,
                withdrawn: withdrawn.to_vec(),
            },
        }
    }

    /// Build a raw path attribute with canonical flags inferred from type code.
    pub fn unknown(type_code: u8, value: impl Into<Vec<u8>>) -> Self {
        Self {
            flags: Field::unset(),
            type_code,
            value: BgpAttrValue::Unknown(value.into()),
        }
    }

    /// Force a specific Attribute Flags octet.
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Encoded path-attribute length, including flags, type, length, and value.
    pub fn encoded_len(&self) -> usize {
        let flags = self.effective_flags();
        let length_len = if flags & BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
            2
        } else {
            1
        };
        2 + length_len + self.value.encoded_len()
    }

    /// Append `Flags | Type Code | Length | Value` to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let flags = self.effective_flags();
        let value_len = self.value.encoded_len();

        out.push(flags);
        out.push(self.type_code);
        if flags & BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
            out.extend_from_slice(&(value_len as u16).to_be_bytes());
        } else {
            out.push(value_len as u8);
        }
        self.value.encode(out);
    }

    /// Human-readable path-attribute summary.
    pub fn summary(&self) -> String {
        match &self.value {
            BgpAttrValue::Origin(origin) => format!("ORIGIN={}", origin_value_name(*origin)),
            BgpAttrValue::AsPath { segments, .. } => as_path_summary(segments),
            BgpAttrValue::NextHop(next_hop) => format!("NEXT_HOP={next_hop}"),
            BgpAttrValue::MultiExitDisc(metric) => format!("MULTI_EXIT_DISC={metric}"),
            BgpAttrValue::LocalPref(preference) => format!("LOCAL_PREF={preference}"),
            BgpAttrValue::AtomicAggregate => "ATOMIC_AGGREGATE".to_string(),
            BgpAttrValue::Aggregator { asn, addr } => format!("AGGREGATOR={asn} {addr}"),
            BgpAttrValue::Communities(communities) => communities_summary(communities),
            BgpAttrValue::ExtendedCommunities(communities) => {
                extended_communities_summary(communities)
            }
            BgpAttrValue::LargeCommunities(communities) => large_communities_summary(communities),
            BgpAttrValue::MpReachNlri {
                afi,
                safi,
                next_hop,
                nlri,
            } => mp_reach_summary(*afi, *safi, next_hop, nlri),
            BgpAttrValue::MpUnreachNlri {
                afi,
                safi,
                withdrawn,
            } => mp_unreach_summary(*afi, *safi, withdrawn),
            BgpAttrValue::Unknown(value) => format!("attr-{} len={}", self.type_code, value.len()),
        }
    }

    fn effective_flags(&self) -> u8 {
        let mut flags = self
            .flags
            .value()
            .copied()
            .unwrap_or_else(|| well_known_flags(self.type_code));
        if !self.flags.is_user_set() && self.value.encoded_len() > u8::MAX as usize {
            flags |= BGP_ATTR_FLAG_EXTENDED_LENGTH;
        }
        flags
    }

    fn as_path_segment(kind: u8, asns: &[u32]) -> Self {
        Self {
            flags: Field::defaulted(ATTR_AS_PATH_FLAGS),
            type_code: ATTR_AS_PATH,
            value: BgpAttrValue::AsPath {
                four_octet: false,
                segments: vec![AsPathSegment {
                    kind,
                    asns: asns.to_vec(),
                }],
            },
        }
    }
}

/// Canonical default flags for known BGP path-attribute type codes.
pub fn well_known_flags(type_code: u8) -> u8 {
    match type_code {
        ATTR_ORIGIN => ATTR_ORIGIN_FLAGS,
        ATTR_AS_PATH => ATTR_AS_PATH_FLAGS,
        ATTR_NEXT_HOP => ATTR_NEXT_HOP_FLAGS,
        ATTR_MULTI_EXIT_DISC => ATTR_MULTI_EXIT_DISC_FLAGS,
        ATTR_LOCAL_PREF => ATTR_LOCAL_PREF_FLAGS,
        ATTR_ATOMIC_AGGREGATE => ATTR_ATOMIC_AGGREGATE_FLAGS,
        ATTR_AGGREGATOR => ATTR_AGGREGATOR_FLAGS,
        ATTR_COMMUNITIES => ATTR_COMMUNITIES_FLAGS,
        ATTR_MP_REACH_NLRI => ATTR_MP_REACH_NLRI_FLAGS,
        ATTR_MP_UNREACH_NLRI => ATTR_MP_UNREACH_NLRI_FLAGS,
        ATTR_EXTENDED_COMMUNITIES => ATTR_EXTENDED_COMMUNITIES_FLAGS,
        ATTR_AS4_PATH => ATTR_AS4_PATH_FLAGS,
        ATTR_AS4_AGGREGATOR => ATTR_AS4_AGGREGATOR_FLAGS,
        ATTR_LARGE_COMMUNITY => ATTR_LARGE_COMMUNITY_FLAGS,
        _ => BGP_ATTR_FLAG_OPTIONAL,
    }
}

/// Decode one RFC 4271 path attribute from the front of `buf`.
pub fn decode_attribute(buf: &[u8]) -> Result<(BgpPathAttribute, usize)> {
    let (flags, rest) = take(buf, 1, "bgp path attribute flags")?;
    let (type_code, rest) = take(rest, 1, "bgp path attribute type")?;
    let flags = flags[0];
    let type_code = type_code[0];

    let extended = flags & BGP_ATTR_FLAG_EXTENDED_LENGTH != 0;
    let (length, rest, length_len) = if extended {
        let (length, rest) = take(rest, 2, "bgp path attribute length")?;
        (u16::from_be_bytes([length[0], length[1]]) as usize, rest, 2)
    } else {
        let (length, rest) = take(rest, 1, "bgp path attribute length")?;
        (length[0] as usize, rest, 1)
    };
    let (value, _) = take(rest, length, "bgp path attribute value")?;
    let value = match type_code {
        ATTR_ORIGIN => decode_origin_value(value)?,
        ATTR_AS_PATH => decode_as_path_value(value, false)?,
        ATTR_NEXT_HOP => decode_next_hop_value(value)?,
        ATTR_MULTI_EXIT_DISC => decode_multi_exit_disc_value(value)?,
        ATTR_LOCAL_PREF => decode_local_pref_value(value)?,
        ATTR_ATOMIC_AGGREGATE => decode_atomic_aggregate_value(value)?,
        ATTR_AGGREGATOR => decode_aggregator_value(value)?,
        ATTR_COMMUNITIES => decode_communities_value(value)?,
        ATTR_EXTENDED_COMMUNITIES => decode_extended_communities_value(value)?,
        ATTR_LARGE_COMMUNITY => decode_large_communities_value(value)?,
        ATTR_MP_REACH_NLRI => decode_mp_reach_nlri_value(value)?,
        ATTR_MP_UNREACH_NLRI => decode_mp_unreach_nlri_value(value)?,
        _ => BgpAttrValue::Unknown(value.to_vec()),
    };

    Ok((
        BgpPathAttribute {
            flags: Field::user(flags),
            type_code,
            value,
        },
        2 + length_len + length,
    ))
}

fn decode_origin_value(value: &[u8]) -> Result<BgpAttrValue> {
    let (origin, rest) = take(value, 1, "bgp origin attribute value")?;
    if !rest.is_empty() {
        return Err(CrafterError::invalid_field_value(
            "bgp.attribute.origin.length",
            "ORIGIN attribute value must be exactly one octet",
        ));
    }
    Ok(BgpAttrValue::Origin(origin[0]))
}

fn decode_next_hop_value(value: &[u8]) -> Result<BgpAttrValue> {
    let (octets, rest) = take(value, 4, "bgp next_hop attribute value")?;
    if !rest.is_empty() {
        return Err(CrafterError::invalid_field_value(
            "bgp.attribute.next_hop.length",
            "NEXT_HOP attribute value must be exactly four octets",
        ));
    }
    Ok(BgpAttrValue::NextHop(Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    )))
}

fn decode_multi_exit_disc_value(value: &[u8]) -> Result<BgpAttrValue> {
    decode_u32_attribute_value(
        value,
        "bgp multi_exit_disc attribute value",
        "bgp.attribute.multi_exit_disc.length",
        "MULTI_EXIT_DISC attribute value must be exactly four octets",
        BgpAttrValue::MultiExitDisc,
    )
}

fn decode_local_pref_value(value: &[u8]) -> Result<BgpAttrValue> {
    decode_u32_attribute_value(
        value,
        "bgp local_pref attribute value",
        "bgp.attribute.local_pref.length",
        "LOCAL_PREF attribute value must be exactly four octets",
        BgpAttrValue::LocalPref,
    )
}

fn decode_atomic_aggregate_value(value: &[u8]) -> Result<BgpAttrValue> {
    if !value.is_empty() {
        return Err(CrafterError::invalid_field_value(
            "bgp.attribute.atomic_aggregate.length",
            "ATOMIC_AGGREGATE attribute value must be empty",
        ));
    }
    Ok(BgpAttrValue::AtomicAggregate)
}

fn decode_aggregator_value(value: &[u8]) -> Result<BgpAttrValue> {
    let (asn, rest) = take(value, 2, "bgp aggregator attribute asn")?;
    let (addr, rest) = take(rest, 4, "bgp aggregator attribute address")?;
    if !rest.is_empty() {
        return Err(CrafterError::invalid_field_value(
            "bgp.attribute.aggregator.length",
            "AGGREGATOR attribute value must be exactly six octets",
        ));
    }
    Ok(BgpAttrValue::Aggregator {
        asn: u16::from_be_bytes([asn[0], asn[1]]) as u32,
        addr: Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
    })
}

fn decode_communities_value(value: &[u8]) -> Result<BgpAttrValue> {
    if value.len() % 4 != 0 {
        return Err(CrafterError::invalid_field_value(
            "bgp.attribute.communities.length",
            "COMMUNITIES attribute value length must be a multiple of four octets",
        ));
    }

    let communities = value
        .chunks_exact(4)
        .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();
    Ok(BgpAttrValue::Communities(communities))
}

fn decode_extended_communities_value(value: &[u8]) -> Result<BgpAttrValue> {
    if value.len() % 8 != 0 {
        return Err(CrafterError::invalid_field_value(
            "bgp.attribute.extended_communities.length",
            "EXTENDED_COMMUNITIES attribute value length must be a multiple of eight octets",
        ));
    }

    let communities = value
        .chunks_exact(8)
        .map(|chunk| {
            let mut community = [0; 8];
            community.copy_from_slice(chunk);
            community
        })
        .collect();
    Ok(BgpAttrValue::ExtendedCommunities(communities))
}

fn decode_large_communities_value(value: &[u8]) -> Result<BgpAttrValue> {
    if value.len() % 12 != 0 {
        return Err(CrafterError::invalid_field_value(
            "bgp.attribute.large_communities.length",
            "LARGE_COMMUNITIES attribute value length must be a multiple of twelve octets",
        ));
    }

    let communities = value
        .chunks_exact(12)
        .map(|chunk| {
            [
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
                u32::from_be_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]),
            ]
        })
        .collect();
    Ok(BgpAttrValue::LargeCommunities(communities))
}

fn decode_mp_reach_nlri_value(mut value: &[u8]) -> Result<BgpAttrValue> {
    let (afi, rest) = take(value, 2, "bgp mp_reach_nlri afi")?;
    let afi = u16::from_be_bytes([afi[0], afi[1]]);
    let (safi, rest) = take(rest, 1, "bgp mp_reach_nlri safi")?;
    let safi = safi[0];
    let (next_hop_len, rest) = take(rest, 1, "bgp mp_reach_nlri next hop length")?;
    let (next_hop, rest) = take(rest, next_hop_len[0] as usize, "bgp mp_reach_nlri next hop")?;
    let (_reserved, rest) = take(rest, 1, "bgp mp_reach_nlri reserved")?;

    value = rest;
    let mut nlri = Vec::new();
    while !value.is_empty() {
        let (prefix, consumed) = BgpPrefix::decode_prefix_with_max(value, 128)?;
        nlri.push(prefix);
        value = &value[consumed..];
    }

    Ok(BgpAttrValue::MpReachNlri {
        afi,
        safi,
        next_hop: next_hop.to_vec(),
        nlri,
    })
}

fn decode_mp_unreach_nlri_value(mut value: &[u8]) -> Result<BgpAttrValue> {
    let (afi, rest) = take(value, 2, "bgp mp_unreach_nlri afi")?;
    let afi = u16::from_be_bytes([afi[0], afi[1]]);
    let (safi, rest) = take(rest, 1, "bgp mp_unreach_nlri safi")?;
    let safi = safi[0];

    value = rest;
    let mut withdrawn = Vec::new();
    while !value.is_empty() {
        let (prefix, consumed) = BgpPrefix::decode_prefix_with_max(value, 128)?;
        withdrawn.push(prefix);
        value = &value[consumed..];
    }

    Ok(BgpAttrValue::MpUnreachNlri {
        afi,
        safi,
        withdrawn,
    })
}

fn decode_u32_attribute_value(
    value: &[u8],
    context: &'static str,
    field: &'static str,
    message: &'static str,
    build: impl FnOnce(u32) -> BgpAttrValue,
) -> Result<BgpAttrValue> {
    let (octets, rest) = take(value, 4, context)?;
    if !rest.is_empty() {
        return Err(CrafterError::invalid_field_value(field, message));
    }
    Ok(build(u32::from_be_bytes([
        octets[0], octets[1], octets[2], octets[3],
    ])))
}

fn decode_as_path_value(mut value: &[u8], four_octet: bool) -> Result<BgpAttrValue> {
    let as_width = as_path_as_width(four_octet);
    let mut segments = Vec::new();

    while !value.is_empty() {
        let (kind, rest) = take(value, 1, "bgp as_path segment kind")?;
        let (count, rest) = take(rest, 1, "bgp as_path segment count")?;
        let count = count[0] as usize;
        let (asn_bytes, rest) = take(rest, count * as_width, "bgp as_path segment asns")?;

        let mut asns = Vec::with_capacity(count);
        for asn in asn_bytes.chunks_exact(as_width) {
            let asn = if four_octet {
                u32::from_be_bytes([asn[0], asn[1], asn[2], asn[3]])
            } else {
                u16::from_be_bytes([asn[0], asn[1]]) as u32
            };
            asns.push(asn);
        }

        segments.push(AsPathSegment {
            kind: kind[0],
            asns,
        });
        value = rest;
    }

    Ok(BgpAttrValue::AsPath {
        four_octet,
        segments,
    })
}

fn as_path_encoded_len(segments: &[AsPathSegment], four_octet: bool) -> usize {
    let as_width = as_path_as_width(four_octet);
    segments
        .iter()
        .map(|segment| 2 + segment.asns.len() * as_width)
        .sum()
}

fn encode_as_path(segments: &[AsPathSegment], four_octet: bool, out: &mut Vec<u8>) {
    for segment in segments {
        out.push(segment.kind);
        out.push(segment.asns.len() as u8);
        for asn in &segment.asns {
            if four_octet {
                out.extend_from_slice(&asn.to_be_bytes());
            } else {
                out.extend_from_slice(&(*asn as u16).to_be_bytes());
            }
        }
    }
}

fn as_path_as_width(four_octet: bool) -> usize {
    if four_octet {
        4
    } else {
        2
    }
}

fn as_path_summary(segments: &[AsPathSegment]) -> String {
    if segments.is_empty() {
        return "AS_PATH=<empty>".to_string();
    }

    let parts = segments
        .iter()
        .map(|segment| {
            let asns = segment
                .asns
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            match segment.kind {
                BGP_AS_SEGMENT_SET => format!("{{{}}}", asns.replace(' ', ",")),
                BGP_AS_SEGMENT_SEQUENCE => asns,
                other => format!("seg-{other}[{asns}]"),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("AS_PATH={parts}")
}

fn origin_value_name(origin: u8) -> String {
    match origin {
        BGP_ORIGIN_IGP => "IGP".to_string(),
        BGP_ORIGIN_EGP => "EGP".to_string(),
        BGP_ORIGIN_INCOMPLETE => "INCOMPLETE".to_string(),
        other => format!("origin-{other}"),
    }
}

fn communities_summary(communities: &[u32]) -> String {
    if communities.is_empty() {
        return "COMMUNITIES=<empty>".to_string();
    }

    let parts = communities
        .iter()
        .map(|community| community_name(*community))
        .collect::<Vec<_>>()
        .join(" ");
    format!("COMMUNITIES={parts}")
}

fn community_name(community: u32) -> String {
    match community {
        COMMUNITY_NO_EXPORT => "NO_EXPORT".to_string(),
        COMMUNITY_NO_ADVERTISE => "NO_ADVERTISE".to_string(),
        COMMUNITY_NO_EXPORT_SUBCONFED => "NO_EXPORT_SUBCONFED".to_string(),
        other => format!("{}:{}", other >> 16, other & 0xffff),
    }
}

fn extended_communities_summary(communities: &[[u8; 8]]) -> String {
    if communities.is_empty() {
        return "EXTENDED_COMMUNITIES=<empty>".to_string();
    }

    let parts = communities
        .iter()
        .map(|community| {
            format!(
                "type=0x{:02x} value=0x{}",
                community[0],
                hex_bytes(&community[1..])
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("EXTENDED_COMMUNITIES={parts}")
}

fn large_communities_summary(communities: &[[u32; 3]]) -> String {
    if communities.is_empty() {
        return "LARGE_COMMUNITIES=<empty>".to_string();
    }

    let parts = communities
        .iter()
        .map(|[global, local1, local2]| format!("{global}:{local1}:{local2}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("LARGE_COMMUNITIES={parts}")
}

fn mp_reach_summary(afi: u16, safi: u8, next_hop: &[u8], nlri: &[BgpPrefix]) -> String {
    let nlri = nlri
        .iter()
        .map(|prefix| mp_prefix_summary(afi, prefix))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "MP_REACH afi={afi} safi={safi} nh={} nlri=[{nlri}]",
        mp_next_hop_summary(afi, next_hop)
    )
}

fn mp_unreach_summary(afi: u16, safi: u8, withdrawn: &[BgpPrefix]) -> String {
    let withdrawn = withdrawn
        .iter()
        .map(|prefix| mp_prefix_summary(afi, prefix))
        .collect::<Vec<_>>()
        .join(", ");
    format!("MP_UNREACH afi={afi} safi={safi} withdrawn=[{withdrawn}]")
}

fn mp_next_hop_summary(afi: u16, next_hop: &[u8]) -> String {
    match (afi, next_hop) {
        (AFI_IPV4, [a, b, c, d]) => Ipv4Addr::new(*a, *b, *c, *d).to_string(),
        (AFI_IPV6, bytes) if bytes.len() == 16 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(bytes);
            Ipv6Addr::from(octets).to_string()
        }
        _ => format!("0x{}", hex_bytes(next_hop)),
    }
}

fn mp_prefix_summary(afi: u16, prefix: &BgpPrefix) -> String {
    match afi {
        AFI_IPV4 if prefix.length <= 32 && prefix.prefix.len() <= 4 => {
            let mut octets = [0; 4];
            octets[..prefix.prefix.len()].copy_from_slice(&prefix.prefix);
            format!("{}/{}", Ipv4Addr::from(octets), prefix.length)
        }
        AFI_IPV6 if prefix.length <= 128 && prefix.prefix.len() <= 16 => {
            let mut octets = [0; 16];
            octets[..prefix.prefix.len()].copy_from_slice(&prefix.prefix);
            format!("{}/{}", Ipv6Addr::from(octets), prefix.length)
        }
        _ => format!("prefix-{}({}b)", prefix.length, prefix.prefix.len()),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn prefixes_encoded_len(prefixes: &[BgpPrefix]) -> usize {
    prefixes.iter().map(|prefix| 1 + prefix.prefix.len()).sum()
}

/// A BGP network-layer reachability prefix.
///
/// RFC 4271 encodes both UPDATE NLRI and withdrawn routes as one octet of
/// prefix length in bits followed by `ceil(length / 8)` significant prefix
/// octets. MP-BGP uses the same prefix encoding for IPv6 NLRI inside the
/// address-family-specific attributes, so the maximum accepted length is a
/// decoder parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPrefix {
    /// Prefix length in bits.
    pub length: u8,
    /// Exactly `ceil(length / 8)` significant prefix octets.
    pub prefix: Vec<u8>,
}

impl BgpPrefix {
    /// Create an IPv4 BGP prefix, accepting lengths from 0 through 32.
    pub fn from_ipv4(address: Ipv4Addr, length: u8) -> Result<Self> {
        Self::from_address_octets(&address.octets(), length, 32)
    }

    /// Create an IPv6 BGP prefix, accepting lengths from 0 through 128.
    pub fn from_ipv6(address: Ipv6Addr, length: u8) -> Result<Self> {
        Self::from_address_octets(&address.octets(), length, 128)
    }

    /// Number of significant prefix octets encoded on the wire.
    pub fn significant_octets(length: u8) -> usize {
        (length as usize).div_ceil(8)
    }

    /// Append this prefix as `Length | Prefix` bytes.
    pub fn encode_prefix(&self, out: &mut Vec<u8>) {
        out.push(self.length);
        out.extend_from_slice(&self.prefix);
    }

    /// Decode an IPv4 BGP prefix, accepting lengths from 0 through 32.
    pub fn decode_prefix(buf: &[u8]) -> Result<(Self, usize)> {
        Self::decode_prefix_with_max(buf, 32)
    }

    /// Decode a BGP prefix with a caller-supplied maximum length.
    pub fn decode_prefix_with_max(buf: &[u8], max_length: u8) -> Result<(Self, usize)> {
        let (length, rest) = take(buf, 1, "bgp prefix length")?;
        let length = length[0];
        Self::validate_length(length, max_length)?;

        let prefix_len = Self::significant_octets(length);
        let (prefix, _) = take(rest, prefix_len, "bgp prefix")?;

        Ok((
            Self {
                length,
                prefix: prefix.to_vec(),
            },
            1 + prefix_len,
        ))
    }

    fn from_address_octets(octets: &[u8], length: u8, max_length: u8) -> Result<Self> {
        Self::validate_length(length, max_length)?;

        let prefix_len = Self::significant_octets(length);
        let mut prefix = octets[..prefix_len].to_vec();
        if let Some(last) = prefix.last_mut() {
            let remainder = length % 8;
            if remainder != 0 {
                *last &= 0xffu8 << (8 - remainder);
            }
        }

        Ok(Self { length, prefix })
    }

    fn validate_length(length: u8, max_length: u8) -> Result<()> {
        if length > max_length {
            return Err(CrafterError::invalid_field_value(
                "bgp.prefix.length",
                "prefix length exceeds address-family maximum",
            ));
        }
        Ok(())
    }
}

/// Decode an IPv4 BGP prefix, accepting lengths from 0 through 32.
pub fn decode_prefix(buf: &[u8]) -> Result<(BgpPrefix, usize)> {
    BgpPrefix::decode_prefix(buf)
}

/// Decode a BGP prefix with a caller-supplied maximum length.
pub fn decode_prefix_with_max(buf: &[u8], max_length: u8) -> Result<(BgpPrefix, usize)> {
    BgpPrefix::decode_prefix_with_max(buf, max_length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_prefix_encodes_as_length_and_significant_octets() {
        let prefix =
            BgpPrefix::from_ipv4(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid IPv4 prefix");

        let mut encoded = Vec::new();
        prefix.encode_prefix(&mut encoded);

        assert_eq!(prefix.prefix, [0xcb, 0x00, 0x71]);
        assert_eq!(encoded, [0x18, 0xcb, 0x00, 0x71]);
    }

    #[test]
    fn ipv4_prefix_decodes_and_reports_consumed_bytes() {
        let bytes = [0x18, 0xcb, 0x00, 0x71, 0xaa];
        let (prefix, consumed) = BgpPrefix::decode_prefix(&bytes).expect("prefix decodes");

        assert_eq!(
            prefix,
            BgpPrefix {
                length: 24,
                prefix: vec![0xcb, 0x00, 0x71],
            }
        );
        assert_eq!(consumed, 4);
    }

    #[test]
    fn overlong_ipv4_prefix_length_errors() {
        let err = BgpPrefix::decode_prefix(&[33, 0, 0, 0, 0]).expect_err("IPv4 max is 32 bits");

        assert!(matches!(
            err,
            CrafterError::InvalidFieldValue {
                field: "bgp.prefix.length",
                ..
            }
        ));
    }

    #[test]
    fn ipv6_prefix_constructor_allows_128_bits() {
        let prefix = BgpPrefix::from_ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 128)
            .expect("valid IPv6 prefix");

        assert_eq!(prefix.length, 128);
        assert_eq!(prefix.prefix.len(), 16);
    }

    #[test]
    fn origin_attribute_encodes_and_round_trips() {
        let attr = BgpPathAttribute::origin(BGP_ORIGIN_IGP);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(encoded, [ATTR_ORIGIN_FLAGS, ATTR_ORIGIN, 1, BGP_ORIGIN_IGP]);
        assert_eq!(attr.summary(), "ORIGIN=IGP");

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_ORIGIN_FLAGS),
                type_code: ATTR_ORIGIN,
                value: BgpAttrValue::Origin(BGP_ORIGIN_IGP),
            }
        );
        assert_eq!(decoded.summary(), "ORIGIN=IGP");

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn as_sequence_attribute_encodes_and_round_trips() {
        let attr = BgpPathAttribute::as_sequence(&[65000, 65001]);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                ATTR_AS_PATH_FLAGS,
                ATTR_AS_PATH,
                6,
                BGP_AS_SEGMENT_SEQUENCE,
                2,
                0xfd,
                0xe8,
                0xfd,
                0xe9,
            ]
        );
        assert_eq!(attr.summary(), "AS_PATH=65000 65001");

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_AS_PATH_FLAGS),
                type_code: ATTR_AS_PATH,
                value: BgpAttrValue::AsPath {
                    four_octet: false,
                    segments: vec![AsPathSegment {
                        kind: BGP_AS_SEGMENT_SEQUENCE,
                        asns: vec![65000, 65001],
                    }],
                },
            }
        );

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn next_hop_attribute_encodes_and_round_trips() {
        let attr = BgpPathAttribute::next_hop(Ipv4Addr::new(192, 0, 2, 1));
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                ATTR_NEXT_HOP_FLAGS,
                ATTR_NEXT_HOP,
                4,
                0xc0,
                0x00,
                0x02,
                0x01
            ]
        );
        assert_eq!(attr.summary(), "NEXT_HOP=192.0.2.1");

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_NEXT_HOP_FLAGS),
                type_code: ATTR_NEXT_HOP,
                value: BgpAttrValue::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
            }
        );

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn multi_exit_disc_attribute_encodes_and_round_trips() {
        let attr = BgpPathAttribute::multi_exit_disc(100);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                ATTR_MULTI_EXIT_DISC_FLAGS,
                ATTR_MULTI_EXIT_DISC,
                4,
                0,
                0,
                0,
                100
            ]
        );
        assert_eq!(attr.summary(), "MULTI_EXIT_DISC=100");

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_MULTI_EXIT_DISC_FLAGS),
                type_code: ATTR_MULTI_EXIT_DISC,
                value: BgpAttrValue::MultiExitDisc(100),
            }
        );

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn local_pref_attribute_encodes_and_round_trips() {
        let attr = BgpPathAttribute::local_pref(100);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded,
            [ATTR_LOCAL_PREF_FLAGS, ATTR_LOCAL_PREF, 4, 0, 0, 0, 100]
        );
        assert_eq!(attr.summary(), "LOCAL_PREF=100");

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_LOCAL_PREF_FLAGS),
                type_code: ATTR_LOCAL_PREF,
                value: BgpAttrValue::LocalPref(100),
            }
        );

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn atomic_aggregate_attribute_encodes_and_round_trips() {
        let attr = BgpPathAttribute::atomic_aggregate();
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded,
            [ATTR_ATOMIC_AGGREGATE_FLAGS, ATTR_ATOMIC_AGGREGATE, 0]
        );
        assert_eq!(attr.summary(), "ATOMIC_AGGREGATE");

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_ATOMIC_AGGREGATE_FLAGS),
                type_code: ATTR_ATOMIC_AGGREGATE,
                value: BgpAttrValue::AtomicAggregate,
            }
        );

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn aggregator_attribute_encodes_and_round_trips() {
        let attr = BgpPathAttribute::aggregator(65000, Ipv4Addr::new(192, 0, 2, 1));
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                ATTR_AGGREGATOR_FLAGS,
                ATTR_AGGREGATOR,
                6,
                0xfd,
                0xe8,
                0xc0,
                0x00,
                0x02,
                0x01
            ]
        );
        assert_eq!(attr.summary(), "AGGREGATOR=65000 192.0.2.1");

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_AGGREGATOR_FLAGS),
                type_code: ATTR_AGGREGATOR,
                value: BgpAttrValue::Aggregator {
                    asn: 65000,
                    addr: Ipv4Addr::new(192, 0, 2, 1),
                },
            }
        );

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn communities_attribute_encodes_and_round_trips() {
        let communities = [COMMUNITY_NO_EXPORT, 0x_FDE8_0064];
        let attr = BgpPathAttribute::communities(&communities);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                ATTR_COMMUNITIES_FLAGS,
                ATTR_COMMUNITIES,
                8,
                0xff,
                0xff,
                0xff,
                0x01,
                0xfd,
                0xe8,
                0x00,
                0x64
            ]
        );
        assert_eq!(attr.summary(), "COMMUNITIES=NO_EXPORT 65000:100");

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_COMMUNITIES_FLAGS),
                type_code: ATTR_COMMUNITIES,
                value: BgpAttrValue::Communities(communities.to_vec()),
            }
        );
        assert_eq!(decoded.summary(), "COMMUNITIES=NO_EXPORT 65000:100");

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn malformed_communities_length_errors() {
        let err = decode_attribute(&[ATTR_COMMUNITIES_FLAGS, ATTR_COMMUNITIES, 5, 0, 0, 0, 1, 0])
            .expect_err("communities must use four-octet values");

        assert!(matches!(
            err,
            CrafterError::InvalidFieldValue {
                field: "bgp.attribute.communities.length",
                ..
            }
        ));
    }

    #[test]
    fn extended_communities_attribute_encodes_and_round_trips() {
        let communities = [
            [0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            [0x40, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        ];
        let attr = BgpPathAttribute::extended_communities(&communities);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                ATTR_EXTENDED_COMMUNITIES_FLAGS,
                ATTR_EXTENDED_COMMUNITIES,
                16,
                0x00,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x40,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                0x66,
                0x77
            ]
        );
        assert_eq!(
            attr.summary(),
            "EXTENDED_COMMUNITIES=type=0x00 value=0x02030405060708 type=0x40 value=0x11223344556677"
        );

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_EXTENDED_COMMUNITIES_FLAGS),
                type_code: ATTR_EXTENDED_COMMUNITIES,
                value: BgpAttrValue::ExtendedCommunities(communities.to_vec()),
            }
        );
        assert_eq!(decoded.summary(), attr.summary());

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn malformed_extended_communities_length_errors() {
        let err = decode_attribute(&[
            ATTR_EXTENDED_COMMUNITIES_FLAGS,
            ATTR_EXTENDED_COMMUNITIES,
            7,
            0,
            1,
            2,
            3,
            4,
            5,
            6,
        ])
        .expect_err("extended communities must use eight-octet values");

        assert!(matches!(
            err,
            CrafterError::InvalidFieldValue {
                field: "bgp.attribute.extended_communities.length",
                ..
            }
        ));
    }

    #[test]
    fn large_communities_attribute_encodes_and_round_trips() {
        let communities = [[65000, 1, 2]];
        let attr = BgpPathAttribute::large_communities(&communities);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                ATTR_LARGE_COMMUNITY_FLAGS,
                ATTR_LARGE_COMMUNITY,
                12,
                0x00,
                0x00,
                0xfd,
                0xe8,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x02
            ]
        );
        assert_eq!(attr.summary(), "LARGE_COMMUNITIES=65000:1:2");

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_LARGE_COMMUNITY_FLAGS),
                type_code: ATTR_LARGE_COMMUNITY,
                value: BgpAttrValue::LargeCommunities(communities.to_vec()),
            }
        );
        assert_eq!(decoded.summary(), "LARGE_COMMUNITIES=65000:1:2");

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn malformed_large_communities_length_errors() {
        let err = decode_attribute(&[
            ATTR_LARGE_COMMUNITY_FLAGS,
            ATTR_LARGE_COMMUNITY,
            11,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            2,
            0,
            0,
            0,
        ])
        .expect_err("large communities must use twelve-octet values");

        assert!(matches!(
            err,
            CrafterError::InvalidFieldValue {
                field: "bgp.attribute.large_communities.length",
                ..
            }
        ));
    }

    #[test]
    fn mp_reach_ipv6_attribute_encodes_and_round_trips() {
        let nlri = [
            BgpPrefix::from_ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
                .expect("valid IPv6 prefix"),
        ];
        let next_hop = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let attr = BgpPathAttribute::mp_reach_ipv6(next_hop, &nlri);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(encoded[0], 0x80);
        assert_eq!(encoded[1], 0x0e);
        let mut expected = vec![
            ATTR_MP_REACH_NLRI_FLAGS,
            ATTR_MP_REACH_NLRI,
            26,
            0x00,
            0x02,
            0x01,
            16,
        ];
        expected.extend_from_slice(&next_hop.octets());
        expected.extend_from_slice(&[0x00, 32, 0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(encoded, expected);
        assert_eq!(
            attr.summary(),
            "MP_REACH afi=2 safi=1 nh=2001:db8::1 nlri=[2001:db8::/32]"
        );

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_MP_REACH_NLRI_FLAGS),
                type_code: ATTR_MP_REACH_NLRI,
                value: BgpAttrValue::MpReachNlri {
                    afi: AFI_IPV6,
                    safi: SAFI_UNICAST,
                    next_hop: next_hop.octets().to_vec(),
                    nlri: nlri.to_vec(),
                },
            }
        );

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn mp_unreach_ipv6_attribute_encodes_and_round_trips() {
        let withdrawn = [
            BgpPrefix::from_ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
                .expect("valid IPv6 prefix"),
        ];
        let attr = BgpPathAttribute::mp_unreach_ipv6(&withdrawn);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(encoded[0], 0x80);
        assert_eq!(encoded[1], 0x0f);
        assert_eq!(
            encoded,
            [
                ATTR_MP_UNREACH_NLRI_FLAGS,
                ATTR_MP_UNREACH_NLRI,
                8,
                0x00,
                0x02,
                0x01,
                32,
                0x20,
                0x01,
                0x0d,
                0xb8,
            ]
        );
        assert_eq!(
            attr.summary(),
            "MP_UNREACH afi=2 safi=1 withdrawn=[2001:db8::/32]"
        );

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(ATTR_MP_UNREACH_NLRI_FLAGS),
                type_code: ATTR_MP_UNREACH_NLRI,
                value: BgpAttrValue::MpUnreachNlri {
                    afi: AFI_IPV6,
                    safi: SAFI_UNICAST,
                    withdrawn: withdrawn.to_vec(),
                },
            }
        );

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn short_unknown_path_attribute_uses_one_octet_length_and_round_trips() {
        let attr = BgpPathAttribute::unknown(99, vec![0xaa]);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(encoded, [BGP_ATTR_FLAG_OPTIONAL, 99, 1, 0xaa]);

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded,
            BgpPathAttribute {
                flags: Field::user(BGP_ATTR_FLAG_OPTIONAL),
                type_code: 99,
                value: BgpAttrValue::Unknown(vec![0xaa]),
            }
        );

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn long_path_attribute_auto_uses_extended_length_and_round_trips() {
        let value = (0..300).map(|n| n as u8).collect::<Vec<_>>();
        let attr = BgpPathAttribute::unknown(99, value.clone());
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(
            encoded[0],
            BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_EXTENDED_LENGTH
        );
        assert_eq!(encoded[1], 99);
        assert_eq!(&encoded[2..4], &(300u16).to_be_bytes());
        assert_eq!(&encoded[4..], value.as_slice());

        let (decoded, consumed) = decode_attribute(&encoded).expect("attribute decodes");
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded.flags.value(),
            Some(&(BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_EXTENDED_LENGTH))
        );
        assert_eq!(decoded.type_code, 99);
        assert_eq!(decoded.value, BgpAttrValue::Unknown(value));

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn caller_fixed_flags_are_not_extended_automatically() {
        let value = vec![0xaa; 300];
        let attr = BgpPathAttribute::unknown(ATTR_COMMUNITIES, value.clone())
            .with_flags(ATTR_COMMUNITIES_FLAGS);
        let mut encoded = Vec::new();
        attr.encode(&mut encoded);

        assert_eq!(encoded[0], ATTR_COMMUNITIES_FLAGS);
        assert_eq!(encoded[1], ATTR_COMMUNITIES);
        assert_eq!(encoded[2], value.len() as u8);
        assert_eq!(&encoded[3..], value.as_slice());
    }
}
