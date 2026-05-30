//! DNS resource-record data model and its wire codec.

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};

use super::dnssec::DnsTypeBitmaps;
use super::edns::EdnsOption;
use super::name::{decode_dns_name_typed, DnsName};
use super::svcb::SvcParams;
use super::{
    DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_DNSKEY, DNS_TYPE_DS, DNS_TYPE_HTTPS,
    DNS_TYPE_MX, DNS_TYPE_NS, DNS_TYPE_NSEC, DNS_TYPE_NSEC3, DNS_TYPE_OPT, DNS_TYPE_PTR,
    DNS_TYPE_RRSIG, DNS_TYPE_SOA, DNS_TYPE_SRV, DNS_TYPE_SVCB, DNS_TYPE_TXT,
};

/// DNS resource record data for common record types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsRecordData {
    /// IPv4 address data for A records.
    A(Ipv4Addr),
    /// IPv6 address data for AAAA records.
    Aaaa(Ipv6Addr),
    /// Domain name data for NS, CNAME, and PTR records.
    Name(DnsName),
    /// Mail exchanger data.
    Mx {
        /// Preference value.
        preference: u16,
        /// Mail exchanger domain name.
        exchange: DnsName,
    },
    /// Start of authority data (RFC 1035 Section 3.3.13).
    Soa {
        /// MNAME: primary source domain name for this zone.
        mname: DnsName,
        /// RNAME: responsible-person mailbox domain name.
        rname: DnsName,
        /// SERIAL: 32-bit zone version number.
        serial: u32,
        /// REFRESH: 32-bit refresh interval, in seconds.
        refresh: u32,
        /// RETRY: 32-bit retry interval, in seconds.
        retry: u32,
        /// EXPIRE: 32-bit expiry interval, in seconds.
        expire: u32,
        /// MINIMUM: 32-bit minimum TTL, in seconds.
        minimum: u32,
    },
    /// Service location data (RFC 2782): priority, weight, port, target.
    Srv {
        /// Priority of this target host.
        priority: u16,
        /// Relative weight among entries with the same priority.
        weight: u16,
        /// Port of the service on the target host.
        port: u16,
        /// Target host domain name.
        target: DnsName,
    },
    /// TXT strings, each encoded as one DNS character-string.
    Txt(Vec<Vec<u8>>),
    /// EDNS(0) OPT pseudo-record RDATA: a list of {code, length, data} options
    /// (RFC 6891 Section 6.1.2). The OPT CLASS and TTL fields carry the UDP
    /// payload size and the extended RCODE/version/flags rather than ordinary
    /// class and TTL meaning; build with [`DnsRecord::opt`] and inspect with the
    /// `edns_*` accessors on [`DnsRecord`].
    Opt(Vec<EdnsOption>),
    /// Delegation Signer (DS) data (RFC 4034 Section 5.1). Algorithm and digest
    /// type stay raw numeric fields; the digest is opaque wire bytes and is not
    /// cryptographically validated.
    Ds {
        /// Key Tag of the referenced DNSKEY (network byte order).
        key_tag: u16,
        /// DNSSEC algorithm number of the referenced DNSKEY.
        algorithm: u8,
        /// Digest Type identifying the digest algorithm.
        digest_type: u8,
        /// Digest bytes, carried verbatim.
        digest: Vec<u8>,
    },
    /// DNSKEY public-key data (RFC 4034 Section 2.1). Flags and algorithm stay
    /// raw numeric fields; the public key is opaque wire bytes and is not
    /// cryptographically validated.
    Dnskey {
        /// 16-bit Flags field (for example the Zone Key and SEP bits).
        flags: u16,
        /// Protocol field (MUST be 3 per RFC 4034, but carried verbatim).
        protocol: u8,
        /// DNSSEC algorithm number.
        algorithm: u8,
        /// Public key bytes, carried verbatim.
        public_key: Vec<u8>,
    },
    /// Resource Record Signature (RRSIG) data (RFC 4034 Section 3.1). The
    /// signature bytes are opaque and are not cryptographically validated; the
    /// signer's name is emitted uncompressed (Section 3.1.7).
    Rrsig {
        /// RR type covered by this signature.
        type_covered: u16,
        /// DNSSEC algorithm number.
        algorithm: u8,
        /// Number of labels in the original owner name.
        labels: u8,
        /// Original TTL of the covered RRset, in seconds.
        original_ttl: u32,
        /// Signature expiration time (seconds since the Unix epoch).
        signature_expiration: u32,
        /// Signature inception time (seconds since the Unix epoch).
        signature_inception: u32,
        /// Key Tag of the DNSKEY that made the signature.
        key_tag: u16,
        /// Signer's Name (emitted uncompressed per RFC 4034 Section 3.1.7).
        signer_name: DnsName,
        /// Signature bytes, carried verbatim.
        signature: Vec<u8>,
    },
    /// Next Secure (NSEC) data (RFC 4034 Section 4.1). The next domain name is
    /// emitted uncompressed (Section 6.2).
    Nsec {
        /// Next owner name in canonical ordering (emitted uncompressed).
        next_domain_name: DnsName,
        /// Type Bit Maps: the RR types present at the owner name.
        type_bitmaps: DnsTypeBitmaps,
    },
    /// Next Secure v3 (NSEC3) data (RFC 5155 Section 3.2). Hash algorithm and
    /// flags stay raw numeric fields; the salt and next hashed owner name are
    /// opaque wire bytes.
    Nsec3 {
        /// Hash Algorithm number.
        hash_algorithm: u8,
        /// Flags field (the Opt-Out flag is the least significant bit).
        flags: u8,
        /// Iterations: additional hash rounds.
        iterations: u16,
        /// Salt bytes, carried verbatim (may be empty).
        salt: Vec<u8>,
        /// Next Hashed Owner Name: the unmodified binary hash value.
        next_hashed_owner_name: Vec<u8>,
        /// Type Bit Maps: the RR types present at the original owner name.
        type_bitmaps: DnsTypeBitmaps,
    },
    /// SVCB service-binding data (RFC 9460 Section 2.2): SvcPriority, an
    /// uncompressed target name, and an ordered list of SvcParams. SvcParam
    /// values stay opaque wire bytes (their format is determined by the
    /// SvcParamKey); unknown keys are preserved verbatim.
    Svcb {
        /// SvcPriority: 0 selects AliasMode, any other value ServiceMode.
        priority: u16,
        /// TargetName domain name (emitted uncompressed; may be the root `.`).
        target: DnsName,
        /// SvcParams in strictly increasing SvcParamKey order.
        params: SvcParams,
    },
    /// HTTPS service-binding data (RFC 9460 Section 2.2). Shares the SVCB wire
    /// format: SvcPriority, an uncompressed target name, and an ordered list of
    /// SvcParams.
    Https {
        /// SvcPriority: 0 selects AliasMode, any other value ServiceMode.
        priority: u16,
        /// TargetName domain name (emitted uncompressed; may be the root `.`).
        target: DnsName,
        /// SvcParams in strictly increasing SvcParamKey order.
        params: SvcParams,
    },
    /// Unknown or caller-defined record payload bytes.
    Raw(Vec<u8>),
}

impl DnsRecordData {
    /// Create name-like record data.
    pub fn name(name: impl Into<DnsName>) -> Self {
        Self::Name(name.into())
    }

    /// Create TXT record data from one string.
    pub fn txt(text: impl AsRef<[u8]>) -> Self {
        Self::Txt(vec![text.as_ref().to_vec()])
    }

    fn expected_type(&self) -> Option<u16> {
        match self {
            Self::A(_) => Some(DNS_TYPE_A),
            Self::Aaaa(_) => Some(DNS_TYPE_AAAA),
            Self::Mx { .. } => Some(DNS_TYPE_MX),
            Self::Soa { .. } => Some(DNS_TYPE_SOA),
            Self::Srv { .. } => Some(DNS_TYPE_SRV),
            Self::Txt(_) => Some(DNS_TYPE_TXT),
            Self::Opt(_) => Some(DNS_TYPE_OPT),
            Self::Ds { .. } => Some(DNS_TYPE_DS),
            Self::Dnskey { .. } => Some(DNS_TYPE_DNSKEY),
            Self::Rrsig { .. } => Some(DNS_TYPE_RRSIG),
            Self::Nsec { .. } => Some(DNS_TYPE_NSEC),
            Self::Nsec3 { .. } => Some(DNS_TYPE_NSEC3),
            Self::Svcb { .. } => Some(DNS_TYPE_SVCB),
            Self::Https { .. } => Some(DNS_TYPE_HTTPS),
            Self::Name(_) | Self::Raw(_) => None,
        }
    }

    pub(super) fn encoded_len(&self) -> usize {
        match self {
            Self::A(_) => 4,
            Self::Aaaa(_) => 16,
            Self::Name(name) => name.encoded_len(),
            Self::Mx { exchange, .. } => 2 + exchange.encoded_len(),
            Self::Soa { mname, rname, .. } => mname.encoded_len() + rname.encoded_len() + 20,
            Self::Srv { target, .. } => 6 + target.encoded_len(),
            Self::Txt(strings) => strings.iter().map(|value| 1 + value.len()).sum(),
            Self::Opt(options) => options.iter().map(EdnsOption::encoded_len).sum(),
            Self::Ds { digest, .. } => 4 + digest.len(),
            Self::Dnskey { public_key, .. } => 4 + public_key.len(),
            Self::Rrsig {
                signer_name,
                signature,
                ..
            } => 18 + signer_name.encoded_len() + signature.len(),
            Self::Nsec {
                next_domain_name,
                type_bitmaps,
            } => next_domain_name.encoded_len() + type_bitmaps.encoded_len(),
            Self::Nsec3 {
                salt,
                next_hashed_owner_name,
                type_bitmaps,
                ..
            } => 5 + salt.len() + 1 + next_hashed_owner_name.len() + type_bitmaps.encoded_len(),
            Self::Svcb { target, params, .. } | Self::Https { target, params, .. } => {
                2 + target.encoded_len() + params.encoded_len()
            }
            Self::Raw(bytes) => bytes.len(),
        }
    }

    pub(super) fn encode(&self, record_type: u16, out: &mut Vec<u8>) -> Result<()> {
        if let Some(expected) = self.expected_type() {
            if expected != record_type {
                return Err(CrafterError::invalid_field_value(
                    "dns.record.type",
                    "record data does not match record type",
                ));
            }
        }

        match self {
            Self::A(address) => out.extend_from_slice(&address.octets()),
            Self::Aaaa(address) => out.extend_from_slice(&address.octets()),
            Self::Name(name) => name.encode(out)?,
            Self::Mx {
                preference,
                exchange,
            } => {
                out.extend_from_slice(&preference.to_be_bytes());
                exchange.encode(out)?;
            }
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                mname.encode(out)?;
                rname.encode(out)?;
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh.to_be_bytes());
                out.extend_from_slice(&retry.to_be_bytes());
                out.extend_from_slice(&expire.to_be_bytes());
                out.extend_from_slice(&minimum.to_be_bytes());
            }
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                target.encode(out)?;
            }
            Self::Txt(strings) => {
                for text in strings {
                    if text.len() > u8::MAX as usize {
                        return Err(CrafterError::invalid_field_value(
                            "dns.txt",
                            "TXT character-string exceeds 255 bytes",
                        ));
                    }
                    out.push(text.len() as u8);
                    out.extend_from_slice(text);
                }
            }
            Self::Opt(options) => {
                for option in options {
                    option.encode(out)?;
                }
            }
            Self::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                out.extend_from_slice(&key_tag.to_be_bytes());
                out.push(*algorithm);
                out.push(*digest_type);
                out.extend_from_slice(digest);
            }
            Self::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                out.extend_from_slice(&flags.to_be_bytes());
                out.push(*protocol);
                out.push(*algorithm);
                out.extend_from_slice(public_key);
            }
            Self::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                signature,
            } => {
                out.extend_from_slice(&type_covered.to_be_bytes());
                out.push(*algorithm);
                out.push(*labels);
                out.extend_from_slice(&original_ttl.to_be_bytes());
                out.extend_from_slice(&signature_expiration.to_be_bytes());
                out.extend_from_slice(&signature_inception.to_be_bytes());
                out.extend_from_slice(&key_tag.to_be_bytes());
                // RFC 4034 Section 3.1.7: the Signer's Name MUST NOT be
                // compressed, so the deterministic uncompressed encoder is used.
                signer_name.encode(out)?;
                out.extend_from_slice(signature);
            }
            Self::Nsec {
                next_domain_name,
                type_bitmaps,
            } => {
                // RFC 4034 Section 6.2: the Next Domain Name MUST NOT be
                // compressed.
                next_domain_name.encode(out)?;
                type_bitmaps.encode(out);
            }
            Self::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner_name,
                type_bitmaps,
            } => {
                let salt_len = u8::try_from(salt.len()).map_err(|_| {
                    CrafterError::invalid_field_value(
                        "dns.nsec3.salt",
                        "NSEC3 salt exceeds 255 bytes",
                    )
                })?;
                let hash_len = u8::try_from(next_hashed_owner_name.len()).map_err(|_| {
                    CrafterError::invalid_field_value(
                        "dns.nsec3.hash",
                        "NSEC3 next hashed owner name exceeds 255 bytes",
                    )
                })?;
                out.push(*hash_algorithm);
                out.push(*flags);
                out.extend_from_slice(&iterations.to_be_bytes());
                out.push(salt_len);
                out.extend_from_slice(salt);
                out.push(hash_len);
                out.extend_from_slice(next_hashed_owner_name);
                type_bitmaps.encode(out);
            }
            Self::Svcb {
                priority,
                target,
                params,
            }
            | Self::Https {
                priority,
                target,
                params,
            } => {
                out.extend_from_slice(&priority.to_be_bytes());
                // RFC 9460 Section 2.2: the TargetName is uncompressed, so the
                // deterministic uncompressed encoder is used.
                target.encode(out)?;
                params.encode(out)?;
            }
            Self::Raw(bytes) => out.extend_from_slice(bytes),
        }
        Ok(())
    }
}

pub(super) fn decode_record_data(
    record_type: u16,
    message: &[u8],
    rdata_start: usize,
    rdata_end: usize,
) -> Result<DnsRecordData> {
    let rdata = &message[rdata_start..rdata_end];
    match record_type {
        DNS_TYPE_A => {
            if rdata.len() != 4 {
                return Err(CrafterError::invalid_field_value(
                    "dns.a.rdlength",
                    "A records must contain four bytes",
                ));
            }
            Ok(DnsRecordData::A(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            )))
        }
        DNS_TYPE_AAAA => {
            if rdata.len() != 16 {
                return Err(CrafterError::invalid_field_value(
                    "dns.aaaa.rdlength",
                    "AAAA records must contain sixteen bytes",
                ));
            }
            Ok(DnsRecordData::Aaaa(Ipv6Addr::from(
                <[u8; 16]>::try_from(rdata).expect("slice length already checked"),
            )))
        }
        DNS_TYPE_CNAME | DNS_TYPE_NS | DNS_TYPE_PTR => {
            let (name, consumed) = decode_dns_name_typed(message, rdata_start)?;
            ensure_rdata_consumed("dns.name.rdata", consumed, rdata.len())?;
            Ok(DnsRecordData::Name(name))
        }
        DNS_TYPE_MX => {
            if rdata.len() < 3 {
                return Err(CrafterError::buffer_too_short("dns.mx", 3, rdata.len()));
            }
            let preference = read_u16_be(&rdata[0..2])?;
            let (exchange, consumed) = decode_dns_name_typed(message, rdata_start + 2)?;
            ensure_rdata_consumed("dns.mx.exchange", consumed + 2, rdata.len())?;
            Ok(DnsRecordData::Mx {
                preference,
                exchange,
            })
        }
        DNS_TYPE_SOA => {
            // MNAME and RNAME are <domain-name> fields (RFC 1035 Section
            // 3.3.13) followed by five fixed 32-bit fields (20 octets total).
            let (mname, mname_used) = decode_dns_name_typed(message, rdata_start)?;
            let (rname, rname_used) = decode_dns_name_typed(message, rdata_start + mname_used)?;
            let fixed_start = mname_used + rname_used;
            if fixed_start + 20 != rdata.len() {
                return Err(CrafterError::invalid_field_value(
                    "dns.soa.rdlength",
                    "SOA RDATA must end with exactly twenty bytes after MNAME and RNAME",
                ));
            }
            let fixed = &rdata[fixed_start..fixed_start + 20];
            Ok(DnsRecordData::Soa {
                mname,
                rname,
                serial: read_u32_be(&fixed[0..4])?,
                refresh: read_u32_be(&fixed[4..8])?,
                retry: read_u32_be(&fixed[8..12])?,
                expire: read_u32_be(&fixed[12..16])?,
                minimum: read_u32_be(&fixed[16..20])?,
            })
        }
        DNS_TYPE_SRV => {
            // Priority, weight, and port are 16-bit fields, followed by an
            // uncompressed target <domain-name> (RFC 2782).
            if rdata.len() < 7 {
                return Err(CrafterError::buffer_too_short("dns.srv", 7, rdata.len()));
            }
            let priority = read_u16_be(&rdata[0..2])?;
            let weight = read_u16_be(&rdata[2..4])?;
            let port = read_u16_be(&rdata[4..6])?;
            let (target, consumed) = decode_dns_name_typed(message, rdata_start + 6)?;
            ensure_rdata_consumed("dns.srv.target", consumed + 6, rdata.len())?;
            Ok(DnsRecordData::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        DNS_TYPE_TXT => {
            let mut strings = Vec::new();
            let mut offset = 0;
            while offset < rdata.len() {
                let len = rdata[offset] as usize;
                let start = offset + 1;
                let end = start + len;
                if end > rdata.len() {
                    return Err(CrafterError::buffer_too_short("dns.txt", end, rdata.len()));
                }
                strings.push(rdata[start..end].to_vec());
                offset = end;
            }
            Ok(DnsRecordData::Txt(strings))
        }
        DNS_TYPE_OPT => {
            // OPT RDATA is a sequence of {OPTION-CODE (2), OPTION-LENGTH (2),
            // OPTION-DATA (OPTION-LENGTH)} tuples (RFC 6891 Section 6.1.2).
            let mut options = Vec::new();
            let mut offset = 0;
            while offset < rdata.len() {
                if offset + 4 > rdata.len() {
                    // A partial option header (fewer than the four fixed bytes)
                    // is a truncated option.
                    return Err(CrafterError::buffer_too_short(
                        "dns.opt.option",
                        offset + 4,
                        rdata.len(),
                    ));
                }
                let code = read_u16_be(&rdata[offset..offset + 2])?;
                let length = read_u16_be(&rdata[offset + 2..offset + 4])? as usize;
                let data_start = offset + 4;
                let data_end = data_start + length;
                if data_end > rdata.len() {
                    // The declared OPTION-LENGTH runs past the end of the RDATA.
                    return Err(CrafterError::buffer_too_short(
                        "dns.opt.option.data",
                        data_end,
                        rdata.len(),
                    ));
                }
                options.push(EdnsOption::new(code, rdata[data_start..data_end].to_vec()));
                offset = data_end;
            }
            Ok(DnsRecordData::Opt(options))
        }
        DNS_TYPE_DS => {
            // Key Tag (2), Algorithm (1), Digest Type (1), Digest (rest)
            // (RFC 4034 Section 5.1).
            if rdata.len() < 4 {
                return Err(CrafterError::buffer_too_short("dns.ds", 4, rdata.len()));
            }
            Ok(DnsRecordData::Ds {
                key_tag: read_u16_be(&rdata[0..2])?,
                algorithm: rdata[2],
                digest_type: rdata[3],
                digest: rdata[4..].to_vec(),
            })
        }
        DNS_TYPE_DNSKEY => {
            // Flags (2), Protocol (1), Algorithm (1), Public Key (rest)
            // (RFC 4034 Section 2.1).
            if rdata.len() < 4 {
                return Err(CrafterError::buffer_too_short("dns.dnskey", 4, rdata.len()));
            }
            Ok(DnsRecordData::Dnskey {
                flags: read_u16_be(&rdata[0..2])?,
                protocol: rdata[2],
                algorithm: rdata[3],
                public_key: rdata[4..].to_vec(),
            })
        }
        DNS_TYPE_RRSIG => {
            // Eighteen fixed octets, then the uncompressed Signer's Name, then
            // the Signature (RFC 4034 Section 3.1).
            if rdata.len() < 18 {
                return Err(CrafterError::buffer_too_short("dns.rrsig", 18, rdata.len()));
            }
            let type_covered = read_u16_be(&rdata[0..2])?;
            let algorithm = rdata[2];
            let labels = rdata[3];
            let original_ttl = read_u32_be(&rdata[4..8])?;
            let signature_expiration = read_u32_be(&rdata[8..12])?;
            let signature_inception = read_u32_be(&rdata[12..16])?;
            let key_tag = read_u16_be(&rdata[16..18])?;
            // The Signer's Name MUST NOT be compressed (RFC 4034 Section
            // 3.1.7); decode it relative to the RDATA so any stray pointer is
            // still bounds-checked, and require it to stay within the RDATA.
            let (signer_name, name_used) = decode_dns_name_typed(message, rdata_start + 18)?;
            let signature_start = 18 + name_used;
            if signature_start > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.rrsig.signer",
                    signature_start,
                    rdata.len(),
                ));
            }
            Ok(DnsRecordData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                signature: rdata[signature_start..].to_vec(),
            })
        }
        DNS_TYPE_NSEC => {
            // Next Domain Name (uncompressed), then Type Bit Maps (RFC 4034
            // Section 4.1).
            let (next_domain_name, name_used) = decode_dns_name_typed(message, rdata_start)?;
            if name_used > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.nsec.name",
                    name_used,
                    rdata.len(),
                ));
            }
            let type_bitmaps = DnsTypeBitmaps::decode("dns.nsec.bitmap", &rdata[name_used..])?;
            Ok(DnsRecordData::Nsec {
                next_domain_name,
                type_bitmaps,
            })
        }
        DNS_TYPE_NSEC3 => {
            // Hash Alg (1), Flags (1), Iterations (2), Salt Length (1), Salt,
            // Hash Length (1), Next Hashed Owner Name, Type Bit Maps (RFC 5155
            // Section 3.2).
            if rdata.len() < 5 {
                return Err(CrafterError::buffer_too_short("dns.nsec3", 5, rdata.len()));
            }
            let hash_algorithm = rdata[0];
            let flags = rdata[1];
            let iterations = read_u16_be(&rdata[2..4])?;
            let salt_len = rdata[4] as usize;
            let salt_start = 5;
            let salt_end = salt_start + salt_len;
            if salt_end > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.nsec3.salt",
                    salt_end,
                    rdata.len(),
                ));
            }
            let salt = rdata[salt_start..salt_end].to_vec();
            if salt_end + 1 > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.nsec3.hash.length",
                    salt_end + 1,
                    rdata.len(),
                ));
            }
            let hash_len = rdata[salt_end] as usize;
            let hash_start = salt_end + 1;
            let hash_end = hash_start + hash_len;
            if hash_end > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.nsec3.hash",
                    hash_end,
                    rdata.len(),
                ));
            }
            let next_hashed_owner_name = rdata[hash_start..hash_end].to_vec();
            let type_bitmaps = DnsTypeBitmaps::decode("dns.nsec3.bitmap", &rdata[hash_end..])?;
            Ok(DnsRecordData::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner_name,
                type_bitmaps,
            })
        }
        DNS_TYPE_SVCB | DNS_TYPE_HTTPS => {
            // SvcPriority (2), uncompressed TargetName, then SvcParams that
            // consume the remainder of the RDATA (RFC 9460 Section 2.2).
            if rdata.len() < 2 {
                return Err(CrafterError::buffer_too_short("dns.svcb", 2, rdata.len()));
            }
            let priority = read_u16_be(&rdata[0..2])?;
            let (target, target_used) = decode_dns_name_typed(message, rdata_start + 2)?;
            let params_start = 2 + target_used;
            if params_start > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.svcb.target",
                    params_start,
                    rdata.len(),
                ));
            }
            let params = SvcParams::decode("dns.svcb.params", &rdata[params_start..])?;
            if record_type == DNS_TYPE_SVCB {
                Ok(DnsRecordData::Svcb {
                    priority,
                    target,
                    params,
                })
            } else {
                Ok(DnsRecordData::Https {
                    priority,
                    target,
                    params,
                })
            }
        }
        _ => Ok(DnsRecordData::Raw(rdata.to_vec())),
    }
}

fn ensure_rdata_consumed(field: &'static str, consumed: usize, available: usize) -> Result<()> {
    if consumed != available {
        return Err(CrafterError::invalid_field_value(
            field,
            "compressed name did not consume the full RDATA field",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod dns_base_rdata {
    use super::super::{Dns, DnsRecord, DNS_CLASS_IN};
    use super::{decode_record_data, DnsName, DnsRecordData, DNS_TYPE_SOA, DNS_TYPE_SRV};
    use crate::{Ipv4, NetworkLayer, Packet, Udp};
    use core::net::Ipv4Addr;

    /// Build a DNS message carrying one answer, compile it through the packet
    /// stack, decode it back, and return the decoded answer's record data along
    /// with the original compiled bytes and the recompiled bytes for byte-stable
    /// round-trip assertions.
    fn round_trip_answer(answer: DnsRecord) -> (DnsRecordData, Vec<u8>, Vec<u8>) {
        let original = Dns::new().id(0x4242).response(true).answer(answer);
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 53))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(53).dport(53001)
            / original)
            .compile()
            .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let data = decoded.layer::<Dns>().unwrap().answers()[0].data().clone();
        let recompiled = decoded.compile().unwrap();
        (
            data,
            bytes.as_bytes().to_vec(),
            recompiled.as_bytes().to_vec(),
        )
    }

    #[test]
    fn soa_record_round_trips_through_packet_stack() {
        let (data, original, recompiled) = round_trip_answer(DnsRecord::soa(
            "example.com.",
            300,
            "ns1.example.com.",
            "hostmaster.example.com.",
            2024010101,
            7200,
            3600,
            1209600,
            300,
        ));
        assert_eq!(
            data,
            DnsRecordData::Soa {
                mname: DnsName::parse("ns1.example.com.").unwrap(),
                rname: DnsName::parse("hostmaster.example.com.").unwrap(),
                serial: 2024010101,
                refresh: 7200,
                retry: 3600,
                expire: 1209600,
                minimum: 300,
            }
        );
        // Stable wire bytes round trip (no compression emitted by default).
        assert_eq!(recompiled, original);
    }

    #[test]
    fn srv_record_round_trips_through_packet_stack() {
        let (data, original, recompiled) = round_trip_answer(DnsRecord::srv(
            "_sip._tcp.example.com.",
            60,
            10,
            60,
            5060,
            "sip.example.com.",
        ));
        assert_eq!(
            data,
            DnsRecordData::Srv {
                priority: 10,
                weight: 60,
                port: 5060,
                target: DnsName::parse("sip.example.com.").unwrap(),
            }
        );
        // Round-trip is byte-stable.
        assert_eq!(recompiled, original);
    }

    #[test]
    fn soa_too_short_fixed_tail_is_rejected() {
        // MNAME = "a.", RNAME = ".", then only 19 bytes where 20 are required.
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&[1, b'a', 0]); // mname "a."
        rdata.push(0); // rname root
        rdata.extend_from_slice(&[0u8; 19]); // one byte short of the 20-byte tail
        let end = rdata.len();
        assert!(decode_record_data(DNS_TYPE_SOA, &rdata, 0, end).is_err());
    }

    #[test]
    fn soa_trailing_bytes_after_fixed_tail_are_rejected() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&[1, b'a', 0]); // mname "a."
        rdata.push(0); // rname root
        rdata.extend_from_slice(&[0u8; 21]); // one byte too many
        let end = rdata.len();
        assert!(decode_record_data(DNS_TYPE_SOA, &rdata, 0, end).is_err());
    }

    #[test]
    fn srv_too_short_fixed_header_is_rejected() {
        // Fewer than the six fixed bytes (priority/weight/port) plus a name.
        let rdata = [0u8; 5];
        assert!(decode_record_data(DNS_TYPE_SRV, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn srv_trailing_bytes_after_target_are_rejected() {
        // priority/weight/port + root target + one stray trailing byte.
        let rdata = [0u8, 1, 0, 2, 0x13, 0x88, 0, 0xff];
        assert!(decode_record_data(DNS_TYPE_SRV, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn record_data_type_mismatch_is_rejected_on_compile() {
        // A SOA payload under an SRV type must be refused at compile time.
        let record = DnsRecord::new(
            "example.com.",
            DNS_TYPE_SRV,
            DNS_CLASS_IN,
            60,
            DnsRecordData::Soa {
                mname: DnsName::parse("ns1.example.com.").unwrap(),
                rname: DnsName::parse("hostmaster.example.com.").unwrap(),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 5,
            },
        );
        assert!(Packet::from_layer(Dns::new().answer(record))
            .compile()
            .is_err());
    }
}
