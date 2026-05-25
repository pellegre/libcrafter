//! Domain Name System protocol implementation.

use core::any::Any;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::ops::Div;
use core::str;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

/// DNS header length in bytes.
pub const DNS_HEADER_LEN: usize = 12;

/// DNS port.
pub const DNS_PORT: u16 = 53;

/// Standard Internet class.
pub const DNS_CLASS_IN: u16 = 1;

/// DNS A record type.
pub const DNS_TYPE_A: u16 = 1;
/// DNS NS record type.
pub const DNS_TYPE_NS: u16 = 2;
/// DNS CNAME record type.
pub const DNS_TYPE_CNAME: u16 = 5;
/// DNS PTR record type.
pub const DNS_TYPE_PTR: u16 = 12;
/// DNS MX record type.
pub const DNS_TYPE_MX: u16 = 15;
/// DNS TXT record type.
pub const DNS_TYPE_TXT: u16 = 16;
/// DNS AAAA record type.
pub const DNS_TYPE_AAAA: u16 = 28;

/// DNS response flag bit.
pub const DNS_FLAG_QR_RESPONSE: u16 = 0x8000;
/// DNS authoritative-answer flag bit.
pub const DNS_FLAG_AUTHORITATIVE: u16 = 0x0400;
/// DNS truncated flag bit.
pub const DNS_FLAG_TRUNCATED: u16 = 0x0200;
/// DNS recursion-desired flag bit.
pub const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
/// DNS recursion-available flag bit.
pub const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
/// DNS authentic-data flag bit.
pub const DNS_FLAG_AUTHENTIC_DATA: u16 = 0x0020;
/// DNS checking-disabled flag bit.
pub const DNS_FLAG_CHECKING_DISABLED: u16 = 0x0010;

const DNS_NAME_POINTER_MASK: u8 = 0xc0;
const DNS_NAME_POINTER_TAG: u8 = 0xc0;
const DNS_MAX_LABEL_LEN: usize = 63;
const DNS_MAX_NAME_WIRE_LEN: usize = 255;

macro_rules! impl_layer_object {
    ($type:ty) => {
        fn clone_layer(&self) -> Box<dyn Layer> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    };
}

macro_rules! impl_layer_div {
    ($type:ty) => {
        impl<R> Div<R> for $type
        where
            R: IntoPacket,
        {
            type Output = Packet;

            fn div(self, rhs: R) -> Self::Output {
                Packet::from_layer(self).concat(rhs)
            }
        }
    };
}

/// Parsed or constructible DNS question.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    name: String,
    question_type: u16,
    question_class: u16,
}

impl DnsQuestion {
    /// Create a DNS question with an explicit type and IN class.
    pub fn new(name: impl Into<String>, question_type: u16) -> Self {
        Self {
            name: canonical_name(name),
            question_type,
            question_class: DNS_CLASS_IN,
        }
    }

    /// Create an A question.
    pub fn a(name: impl Into<String>) -> Self {
        Self::new(name, DNS_TYPE_A)
    }

    /// Create an AAAA question.
    pub fn aaaa(name: impl Into<String>) -> Self {
        Self::new(name, DNS_TYPE_AAAA)
    }

    /// Set the question class.
    pub fn class(mut self, question_class: u16) -> Self {
        self.question_class = question_class;
        self
    }

    /// Compatibility alias for question type.
    pub fn qtype(mut self, question_type: u16) -> Self {
        self.question_type = question_type;
        self
    }

    /// Compatibility alias for question class.
    pub fn qclass(mut self, question_class: u16) -> Self {
        self.question_class = question_class;
        self
    }

    /// Question name in canonical trailing-dot form.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Question type value.
    pub const fn question_type(&self) -> u16 {
        self.question_type
    }

    /// Question class value.
    pub const fn question_class(&self) -> u16 {
        self.question_class
    }

    fn encoded_len(&self) -> usize {
        encoded_name_len(&self.name) + 4
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_dns_name(&self.name, out)?;
        out.extend_from_slice(&self.question_type.to_be_bytes());
        out.extend_from_slice(&self.question_class.to_be_bytes());
        Ok(())
    }
}

/// DNS resource record data for common record types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsRecordData {
    /// IPv4 address data for A records.
    A(Ipv4Addr),
    /// IPv6 address data for AAAA records.
    Aaaa(Ipv6Addr),
    /// Domain name data for NS, CNAME, and PTR records.
    Name(String),
    /// Mail exchanger data.
    Mx {
        /// Preference value.
        preference: u16,
        /// Mail exchanger domain name.
        exchange: String,
    },
    /// TXT strings, each encoded as one DNS character-string.
    Txt(Vec<Vec<u8>>),
    /// Unknown or caller-defined record payload bytes.
    Raw(Vec<u8>),
}

impl DnsRecordData {
    /// Create name-like record data.
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(canonical_name(name))
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
            Self::Txt(_) => Some(DNS_TYPE_TXT),
            Self::Name(_) | Self::Raw(_) => None,
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::A(_) => 4,
            Self::Aaaa(_) => 16,
            Self::Name(name) => encoded_name_len(name),
            Self::Mx { exchange, .. } => 2 + encoded_name_len(exchange),
            Self::Txt(strings) => strings.iter().map(|value| 1 + value.len()).sum(),
            Self::Raw(bytes) => bytes.len(),
        }
    }

    fn encode(&self, record_type: u16, out: &mut Vec<u8>) -> Result<()> {
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
            Self::Name(name) => encode_dns_name(name, out)?,
            Self::Mx {
                preference,
                exchange,
            } => {
                out.extend_from_slice(&preference.to_be_bytes());
                encode_dns_name(exchange, out)?;
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
            Self::Raw(bytes) => out.extend_from_slice(bytes),
        }
        Ok(())
    }
}

/// DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsRecord {
    name: String,
    record_type: u16,
    class: u16,
    ttl: u32,
    data: DnsRecordData,
}

impl DnsRecord {
    /// Create a DNS resource record.
    pub fn new(
        name: impl Into<String>,
        record_type: u16,
        class: u16,
        ttl: u32,
        data: DnsRecordData,
    ) -> Self {
        Self {
            name: canonical_name(name),
            record_type,
            class,
            ttl,
            data,
        }
    }

    /// Create an A answer.
    pub fn a(name: impl Into<String>, address: Ipv4Addr, ttl: u32) -> Self {
        Self::new(
            name,
            DNS_TYPE_A,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::A(address),
        )
    }

    /// Create an AAAA answer.
    pub fn aaaa(name: impl Into<String>, address: Ipv6Addr, ttl: u32) -> Self {
        Self::new(
            name,
            DNS_TYPE_AAAA,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Aaaa(address),
        )
    }

    /// Create a CNAME answer.
    pub fn cname(name: impl Into<String>, target: impl Into<String>, ttl: u32) -> Self {
        Self::new(
            name,
            DNS_TYPE_CNAME,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::name(target),
        )
    }

    /// Record name in canonical trailing-dot form.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Record type value.
    pub const fn record_type(&self) -> u16 {
        self.record_type
    }

    /// Record class value.
    pub const fn class(&self) -> u16 {
        self.class
    }

    /// Record TTL.
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Record data.
    pub const fn data(&self) -> &DnsRecordData {
        &self.data
    }

    fn encoded_len(&self) -> usize {
        encoded_name_len(&self.name) + 10 + self.data.encoded_len()
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_dns_name(&self.name, out)?;
        out.extend_from_slice(&self.record_type.to_be_bytes());
        out.extend_from_slice(&self.class.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());

        let mut rdata = Vec::with_capacity(self.data.encoded_len());
        self.data.encode(self.record_type, &mut rdata)?;
        let rdlength = u16::try_from(rdata.len()).map_err(|_| {
            CrafterError::invalid_field_value("dns.rdlength", "record data exceeds 65535 bytes")
        })?;
        out.extend_from_slice(&rdlength.to_be_bytes());
        out.extend_from_slice(&rdata);
        Ok(())
    }
}

/// DNS message layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns {
    id: Field<u16>,
    flags: Field<u16>,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additionals: Vec<DnsRecord>,
}

impl Dns {
    /// Create an empty DNS query with recursion desired enabled.
    pub fn new() -> Self {
        Self {
            id: Field::defaulted(0),
            flags: Field::defaulted(DNS_FLAG_RECURSION_DESIRED),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Create a DNS query for a single name and type.
    pub fn query(name: impl Into<String>, question_type: u16) -> Self {
        Self::new().question(DnsQuestion::new(name, question_type))
    }

    /// Create an A query.
    pub fn a_query(name: impl Into<String>) -> Self {
        Self::query(name, DNS_TYPE_A)
    }

    /// Create an AAAA query.
    pub fn aaaa_query(name: impl Into<String>) -> Self {
        Self::query(name, DNS_TYPE_AAAA)
    }

    /// Set the DNS transaction ID.
    pub fn id(mut self, id: u16) -> Self {
        self.id.set_user(id);
        self
    }

    /// Set the raw DNS flags field.
    pub fn flags(mut self, flags: u16) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set or clear the response flag.
    pub fn response(self, enabled: bool) -> Self {
        self.set_flag(DNS_FLAG_QR_RESPONSE, enabled)
    }

    /// Set or clear the authoritative-answer flag.
    pub fn authoritative(self, enabled: bool) -> Self {
        self.set_flag(DNS_FLAG_AUTHORITATIVE, enabled)
    }

    /// Set or clear the recursion-desired flag.
    pub fn recursion_desired(self, enabled: bool) -> Self {
        self.set_flag(DNS_FLAG_RECURSION_DESIRED, enabled)
    }

    /// Compatibility alias for recursion desired.
    pub fn rd(self, enabled: bool) -> Self {
        self.recursion_desired(enabled)
    }

    /// Set or clear the recursion-available flag.
    pub fn recursion_available(self, enabled: bool) -> Self {
        self.set_flag(DNS_FLAG_RECURSION_AVAILABLE, enabled)
    }

    /// Set the four-bit response code.
    pub fn rcode(mut self, rcode: u8) -> Self {
        let flags = (self.flags_value() & !0x000f) | ((rcode as u16) & 0x000f);
        self.flags.set_user(flags);
        self
    }

    /// Append one DNS question.
    pub fn question(mut self, question: DnsQuestion) -> Self {
        self.questions.push(question);
        self
    }

    /// Append one DNS answer record.
    pub fn answer(mut self, answer: DnsRecord) -> Self {
        self.answers.push(answer);
        self
    }

    /// Append one DNS authority record.
    pub fn authority(mut self, authority: DnsRecord) -> Self {
        self.authorities.push(authority);
        self
    }

    /// Append one DNS additional record.
    pub fn additional(mut self, additional: DnsRecord) -> Self {
        self.additionals.push(additional);
        self
    }

    /// DNS transaction ID.
    pub fn id_value(&self) -> u16 {
        value_or_copy(&self.id, 0)
    }

    /// Raw DNS flags.
    pub fn flags_value(&self) -> u16 {
        value_or_copy(&self.flags, DNS_FLAG_RECURSION_DESIRED)
    }

    /// Return true when this message is a response.
    pub fn is_response(&self) -> bool {
        self.flags_value() & DNS_FLAG_QR_RESPONSE != 0
    }

    /// DNS questions.
    pub fn questions(&self) -> &[DnsQuestion] {
        &self.questions
    }

    /// DNS answer records.
    pub fn answers(&self) -> &[DnsRecord] {
        &self.answers
    }

    /// DNS authority records.
    pub fn authorities(&self) -> &[DnsRecord] {
        &self.authorities
    }

    /// DNS additional records.
    pub fn additionals(&self) -> &[DnsRecord] {
        &self.additionals
    }

    fn set_flag(mut self, bit: u16, enabled: bool) -> Self {
        let mut flags = self.flags_value();
        if enabled {
            flags |= bit;
        } else {
            flags &= !bit;
        }
        self.flags.set_user(flags);
        self
    }

    fn encoded_message_len(&self) -> usize {
        DNS_HEADER_LEN
            + self
                .questions
                .iter()
                .map(DnsQuestion::encoded_len)
                .sum::<usize>()
            + self
                .answers
                .iter()
                .map(DnsRecord::encoded_len)
                .sum::<usize>()
            + self
                .authorities
                .iter()
                .map(DnsRecord::encoded_len)
                .sum::<usize>()
            + self
                .additionals
                .iter()
                .map(DnsRecord::encoded_len)
                .sum::<usize>()
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_count("dns.qdcount", self.questions.len())?;
        validate_count("dns.ancount", self.answers.len())?;
        validate_count("dns.nscount", self.authorities.len())?;
        validate_count("dns.arcount", self.additionals.len())?;

        out.extend_from_slice(&self.id_value().to_be_bytes());
        out.extend_from_slice(&self.flags_value().to_be_bytes());
        out.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

        for question in &self.questions {
            question.encode(out)?;
        }
        for answer in &self.answers {
            answer.encode(out)?;
        }
        for authority in &self.authorities {
            authority.encode(out)?;
        }
        for additional in &self.additionals {
            additional.encode(out)?;
        }
        Ok(())
    }
}

impl Default for Dns {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Dns {
    fn name(&self) -> &'static str {
        "Dns"
    }

    fn summary(&self) -> String {
        let direction = if self.is_response() {
            "response"
        } else {
            "query"
        };
        let question = self
            .questions
            .first()
            .map(|question| {
                format!(
                    " {} {}",
                    question.name(),
                    record_type_summary(question.question_type())
                )
            })
            .unwrap_or_default();

        format!(
            "Dns(id=0x{:04x}, {direction}{question}, answers={})",
            self.id_value(),
            self.answers.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("id", format!("0x{:04x}", self.id_value())),
            ("flags", format!("0x{:04x}", self.flags_value())),
            ("qdcount", self.questions.len().to_string()),
            ("ancount", self.answers.len().to_string()),
            ("nscount", self.authorities.len().to_string()),
            ("arcount", self.additionals.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.encoded_message_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.encode(out)
    }

    impl_layer_object!(Dns);
}

impl_layer_div!(Dns);

/// Append a decoded DNS message to an existing packet stack.
pub(crate) fn append_dns_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    Ok(packet.push(decode_dns(bytes)?))
}

/// Decode a DNS name from a full DNS message and byte offset.
///
/// The returned offset is the number of bytes consumed at the original offset,
/// so compressed names return the two-byte pointer length.
pub fn decode_dns_name(message: &[u8], offset: usize) -> Result<(String, usize)> {
    if offset >= message.len() {
        return Err(CrafterError::buffer_too_short(
            "dns.name",
            offset + 1,
            message.len(),
        ));
    }

    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut consumed = None;
    let mut visited = Vec::new();

    loop {
        if cursor >= message.len() {
            return Err(CrafterError::buffer_too_short(
                "dns.name",
                cursor + 1,
                message.len(),
            ));
        }
        if visited.contains(&cursor) {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "compressed name pointer cycle",
            ));
        }
        visited.push(cursor);

        let length = message[cursor];
        match length & DNS_NAME_POINTER_MASK {
            0x00 => {
                if length == 0 {
                    let used = match consumed {
                        Some(consumed) => consumed,
                        None => cursor
                            .checked_add(1)
                            .and_then(|end| end.checked_sub(offset))
                            .ok_or_else(|| {
                                CrafterError::invalid_field_value(
                                    "dns.name",
                                    "name cursor moved before original offset",
                                )
                            })?,
                    };
                    let name = if labels.is_empty() {
                        ".".to_string()
                    } else {
                        format!("{}.", labels.join("."))
                    };
                    return Ok((name, used));
                }

                let label_len = length as usize;
                if label_len > DNS_MAX_LABEL_LEN {
                    return Err(CrafterError::invalid_field_value(
                        "dns.name",
                        "label exceeds 63 bytes",
                    ));
                }
                let label_start = cursor + 1;
                let label_end = label_start + label_len;
                if label_end > message.len() {
                    return Err(CrafterError::buffer_too_short(
                        "dns.name.label",
                        label_end,
                        message.len(),
                    ));
                }
                let label = str::from_utf8(&message[label_start..label_end]).map_err(|_| {
                    CrafterError::invalid_field_value("dns.name", "label is not valid UTF-8")
                })?;
                labels.push(label.to_string());
                cursor = label_end;
            }
            DNS_NAME_POINTER_TAG => {
                if cursor + 1 >= message.len() {
                    return Err(CrafterError::buffer_too_short(
                        "dns.name.pointer",
                        cursor + 2,
                        message.len(),
                    ));
                }
                let pointer = (((length & 0x3f) as usize) << 8) | (message[cursor + 1] as usize);
                if pointer >= message.len() {
                    return Err(CrafterError::invalid_field_value(
                        "dns.name.pointer",
                        "pointer offset is outside the DNS message",
                    ));
                }
                if consumed.is_none() {
                    consumed = Some(cursor + 2 - offset);
                }
                cursor = pointer;
            }
            _ => {
                return Err(CrafterError::invalid_field_value(
                    "dns.name",
                    "reserved label length marker",
                ))
            }
        }
    }
}

fn decode_dns(bytes: &[u8]) -> Result<Dns> {
    if bytes.len() < DNS_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "dns header",
            DNS_HEADER_LEN,
            bytes.len(),
        ));
    }

    let qdcount = read_u16_be(&bytes[4..6])? as usize;
    let ancount = read_u16_be(&bytes[6..8])? as usize;
    let nscount = read_u16_be(&bytes[8..10])? as usize;
    let arcount = read_u16_be(&bytes[10..12])? as usize;

    let mut offset = DNS_HEADER_LEN;
    let mut questions = Vec::with_capacity(qdcount);
    let mut answers = Vec::with_capacity(ancount);
    let mut authorities = Vec::with_capacity(nscount);
    let mut additionals = Vec::with_capacity(arcount);

    for _ in 0..qdcount {
        let (question, next_offset) = decode_question(bytes, offset)?;
        questions.push(question);
        offset = next_offset;
    }
    for _ in 0..ancount {
        let (record, next_offset) = decode_record(bytes, offset)?;
        answers.push(record);
        offset = next_offset;
    }
    for _ in 0..nscount {
        let (record, next_offset) = decode_record(bytes, offset)?;
        authorities.push(record);
        offset = next_offset;
    }
    for _ in 0..arcount {
        let (record, next_offset) = decode_record(bytes, offset)?;
        additionals.push(record);
        offset = next_offset;
    }

    if offset != bytes.len() {
        return Err(CrafterError::invalid_field_value(
            "dns.length",
            "DNS message has trailing bytes after declared records",
        ));
    }

    Ok(Dns {
        id: Field::user(read_u16_be(&bytes[0..2])?),
        flags: Field::user(read_u16_be(&bytes[2..4])?),
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn decode_question(bytes: &[u8], offset: usize) -> Result<(DnsQuestion, usize)> {
    let (name, consumed) = decode_dns_name(bytes, offset)?;
    let fields_offset = offset + consumed;
    if fields_offset + 4 > bytes.len() {
        return Err(CrafterError::buffer_too_short(
            "dns question",
            fields_offset + 4,
            bytes.len(),
        ));
    }

    Ok((
        DnsQuestion {
            name,
            question_type: read_u16_be(&bytes[fields_offset..fields_offset + 2])?,
            question_class: read_u16_be(&bytes[fields_offset + 2..fields_offset + 4])?,
        },
        fields_offset + 4,
    ))
}

fn decode_record(bytes: &[u8], offset: usize) -> Result<(DnsRecord, usize)> {
    let (name, consumed) = decode_dns_name(bytes, offset)?;
    let fields_offset = offset + consumed;
    if fields_offset + 10 > bytes.len() {
        return Err(CrafterError::buffer_too_short(
            "dns record",
            fields_offset + 10,
            bytes.len(),
        ));
    }

    let record_type = read_u16_be(&bytes[fields_offset..fields_offset + 2])?;
    let class = read_u16_be(&bytes[fields_offset + 2..fields_offset + 4])?;
    let ttl = read_u32_be(&bytes[fields_offset + 4..fields_offset + 8])?;
    let rdlength = read_u16_be(&bytes[fields_offset + 8..fields_offset + 10])? as usize;
    let rdata_start = fields_offset + 10;
    let rdata_end = rdata_start + rdlength;
    if rdata_end > bytes.len() {
        return Err(CrafterError::buffer_too_short(
            "dns rdata",
            rdata_end,
            bytes.len(),
        ));
    }

    let data = decode_record_data(record_type, bytes, rdata_start, rdata_end)?;
    Ok((
        DnsRecord {
            name,
            record_type,
            class,
            ttl,
            data,
        },
        rdata_end,
    ))
}

fn decode_record_data(
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
            let (name, consumed) = decode_dns_name(message, rdata_start)?;
            ensure_rdata_consumed("dns.name.rdata", consumed, rdata.len())?;
            Ok(DnsRecordData::Name(name))
        }
        DNS_TYPE_MX => {
            if rdata.len() < 3 {
                return Err(CrafterError::buffer_too_short("dns.mx", 3, rdata.len()));
            }
            let preference = read_u16_be(&rdata[0..2])?;
            let (exchange, consumed) = decode_dns_name(message, rdata_start + 2)?;
            ensure_rdata_consumed("dns.mx.exchange", consumed + 2, rdata.len())?;
            Ok(DnsRecordData::Mx {
                preference,
                exchange,
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

fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> Result<()> {
    if name == "." || name.is_empty() {
        out.push(0);
        return Ok(());
    }

    let mut wire_len = 1usize;
    let stripped = name.strip_suffix('.').unwrap_or(name);
    for label in stripped.split('.') {
        if label.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "empty label inside DNS name",
            ));
        }
        let bytes = label.as_bytes();
        if bytes.len() > DNS_MAX_LABEL_LEN {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "label exceeds 63 bytes",
            ));
        }
        wire_len += 1 + bytes.len();
        if wire_len > DNS_MAX_NAME_WIRE_LEN {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "encoded name exceeds 255 bytes",
            ));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    Ok(())
}

fn encoded_name_len(name: &str) -> usize {
    if name == "." || name.is_empty() {
        1
    } else {
        let stripped = name.strip_suffix('.').unwrap_or(name);
        stripped
            .split('.')
            .map(|label| 1 + label.len())
            .sum::<usize>()
            + 1
    }
}

fn canonical_name(name: impl Into<String>) -> String {
    let name = name.into();
    if name.is_empty() || name == "." || name.ends_with('.') {
        name
    } else {
        format!("{name}.")
    }
}

fn validate_count(field: &'static str, count: usize) -> Result<()> {
    if count > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "DNS section count exceeds 65535",
        ));
    }
    Ok(())
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn record_type_summary(record_type: u16) -> String {
    match record_type {
        DNS_TYPE_A => "A".to_string(),
        DNS_TYPE_NS => "NS".to_string(),
        DNS_TYPE_CNAME => "CNAME".to_string(),
        DNS_TYPE_PTR => "PTR".to_string(),
        DNS_TYPE_MX => "MX".to_string(),
        DNS_TYPE_TXT => "TXT".to_string(),
        DNS_TYPE_AAAA => "AAAA".to_string(),
        value => format!("TYPE{value}"),
    }
}

#[cfg(test)]
mod dns_tests {
    use super::{
        decode_dns_name, Dns, DnsQuestion, DnsRecord, DnsRecordData, DNS_CLASS_IN,
        DNS_FLAG_AUTHORITATIVE, DNS_FLAG_QR_RESPONSE, DNS_FLAG_RECURSION_DESIRED, DNS_TYPE_A,
        DNS_TYPE_AAAA, DNS_TYPE_CNAME,
    };
    use crate::{Ipv4, NetworkLayer, Packet, Udp};
    use core::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn dns_a_query_encodes_header_question_and_udp_payload() {
        let dns = Dns::a_query("example.com").id(0xbeef);
        let packet = Udp::new().sport(53001).dport(53) / dns;
        let compiled = packet.compile().unwrap();
        assert_eq!(&compiled.as_bytes()[8..10], &0xbeefu16.to_be_bytes());
        assert_eq!(
            &compiled.as_bytes()[10..12],
            &DNS_FLAG_RECURSION_DESIRED.to_be_bytes()
        );
        assert_eq!(&compiled.as_bytes()[12..14], &1u16.to_be_bytes());
        assert!(compiled.as_bytes().ends_with(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]));
    }

    #[test]
    fn dns_response_records_roundtrip() {
        let original = Dns::new()
            .id(0x1234)
            .response(true)
            .authoritative(true)
            .question(DnsQuestion::a("example.com."))
            .answer(DnsRecord::a(
                "example.com.",
                Ipv4Addr::new(203, 0, 113, 10),
                60,
            ))
            .answer(DnsRecord::aaaa(
                "example.com.",
                Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                60,
            ))
            .answer(DnsRecord::cname("www.example.com.", "example.com.", 60));

        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 53))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(53).dport(53001)
            / original.clone())
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let dns = decoded.layer::<Dns>().unwrap();

        assert_eq!(dns.id_value(), 0x1234);
        assert_eq!(
            dns.flags_value() & (DNS_FLAG_QR_RESPONSE | DNS_FLAG_AUTHORITATIVE),
            DNS_FLAG_QR_RESPONSE | DNS_FLAG_AUTHORITATIVE
        );
        assert_eq!(dns.questions()[0].name(), "example.com.");
        assert_eq!(dns.answers().len(), 3);
        assert_eq!(
            dns.answers()[0].data(),
            &DnsRecordData::A(Ipv4Addr::new(203, 0, 113, 10))
        );
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn dns_decode_uses_udp_port_context() {
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 53))
            / Udp::new().sport(53001).dport(53)
            / Dns::aaaa_query("example.com").id(0x5678))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let dns = decoded.layer::<Dns>().unwrap();

        assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_AAAA);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn dns_builders_keep_common_values_visible() {
        let query = Dns::new()
            .id(7)
            .rd(false)
            .question(DnsQuestion::new("example.org", DNS_TYPE_A).qclass(DNS_CLASS_IN));

        assert_eq!(query.id_value(), 7);
        assert_eq!(query.flags_value() & DNS_FLAG_RECURSION_DESIRED, 0);
        assert_eq!(query.questions()[0].name(), "example.org.");
        assert_eq!(query.questions()[0].question_class(), DNS_CLASS_IN);
    }

    #[test]
    fn dns_compressed_name_decode_is_exposed() {
        let message = [
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, 4, b'm', b'a', b'i', b'l', 0xc0, 4,
        ];

        assert_eq!(
            decode_dns_name(&message, 0).unwrap(),
            ("www.example.com.".to_string(), 17)
        );
        assert_eq!(
            decode_dns_name(&message, 17).unwrap(),
            ("mail.example.com.".to_string(), 7)
        );
    }

    #[test]
    fn dns_type_mismatch_is_rejected() {
        let record = DnsRecord::new(
            "example.com.",
            DNS_TYPE_CNAME,
            DNS_CLASS_IN,
            60,
            DnsRecordData::A(Ipv4Addr::new(203, 0, 113, 1)),
        );
        assert!(Packet::from_layer(Dns::new().answer(record))
            .compile()
            .is_err());
    }
}

#[cfg(test)]
mod dns_name_decode {
    use super::decode_dns_name;

    #[test]
    fn rejects_truncated_names_and_pointers() {
        assert!(decode_dns_name(&[3, b'w'], 0).is_err());
        assert!(decode_dns_name(&[0xc0], 0).is_err());
        assert!(decode_dns_name(&[0xc0, 0x10], 0).is_err());
    }

    #[test]
    fn rejects_pointer_cycles_and_reserved_markers() {
        assert!(decode_dns_name(&[0xc0, 0x00], 0).is_err());
        assert!(decode_dns_name(&[0x40], 0).is_err());
    }

    #[test]
    fn decodes_root_name() {
        assert_eq!(decode_dns_name(&[0], 0).unwrap(), (".".to_string(), 1));
    }
}

#[cfg(test)]
mod dns_golden_bytes {
    use super::{Dns, DnsQuestion, DNS_TYPE_A};
    use crate::{Ipv4, LinkType, Packet, Udp};
    use core::net::Ipv4Addr;

    const DNS_QUERY_FIXTURE: &[u8] = fixture_bytes!("bytes/ipv4-udp-dns-query-example-com.bin");

    #[test]
    fn dns_query_matches_golden_bytes() {
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 53))
            .id(0x1237)
            .ttl(61)
            / Udp::new().sport(53001).dport(53)
            / Dns::new()
                .id(0xbeef)
                .question(DnsQuestion::new("example.com.", DNS_TYPE_A)))
        .compile()
        .unwrap();

        assert_eq!(bytes.as_bytes(), DNS_QUERY_FIXTURE);
    }

    #[test]
    fn dns_query_fixture_decodes_to_typed_layer() {
        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, DNS_QUERY_FIXTURE).unwrap();
        let dns = decoded.layer::<Dns>().unwrap();

        assert_eq!(dns.id_value(), 0xbeef);
        assert_eq!(dns.questions()[0].name(), "example.com.");
        assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);
        assert_eq!(decoded.compile().unwrap().as_bytes(), DNS_QUERY_FIXTURE);
    }

    #[test]
    fn non_dns_udp_payload_stays_raw_even_when_decoding_from_link() {
        let raw_fixture = fixture_bytes!("bytes/ethernet-vlan-ipv4-udp-raw.bin");
        let decoded = Packet::decode_from_link(LinkType::Ethernet, raw_fixture).unwrap();
        assert!(decoded.layer::<Dns>().is_none());
    }
}
