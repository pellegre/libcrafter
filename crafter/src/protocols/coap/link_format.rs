//! CoRE Link Format packet metadata.
//!
//! The byte-owned model follows RFC 6690 Sections 2 and 3 and the current
//! IANA CoRE Target Attributes registry. Parsing and canonical serialization
//! are separate concerns: this module first keeps link order, repeated
//! attributes, unknown names, and each attribute's syntactic value form
//! inspectable without requiring UTF-8 validation or normalization.

use crate::{
    error::{CrafterError, Result},
    field::{Field, FieldState},
};

use super::{constants::COAP_CONTENT_FORMAT_LINK_FORMAT, message::Coap, option::CoapContentFormat};

const LINK_FORMAT_SYNTAX_FIELD: &str = "coap.link-format.syntax";
const LINK_FORMAT_MAX_INPUT_LEN: usize = u16::MAX as usize;

/// One ordered, lossless `application/link-format` document.
///
/// Typed links are retained independently from an optional exact raw document
/// representation. When raw bytes are present, later serialization uses them
/// as an explicit caller override instead of normalizing the typed view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoapLinkFormat {
    links: Vec<CoapLink>,
    raw: Field<Vec<u8>>,
}

impl CoapLinkFormat {
    /// Build an empty typed link-format document.
    pub const fn new() -> Self {
        Self {
            links: Vec::new(),
            raw: Field::unset(),
        }
    }

    /// Parse one complete RFC 6690 `application/link-format` payload.
    ///
    /// Parsing operates on bytes, retains the complete source payload, and
    /// does not validate or normalize UTF-8. Link order, repeated attributes,
    /// unknown attribute names, quoted-string escapes, and extended values
    /// remain byte-exact. Whitespace outside quoted strings is rejected by
    /// the RFC 6690 grammar rather than silently normalized.
    ///
    /// Syntax failures follow the frozen CoAP error policy and return
    /// [`CrafterError::InvalidFieldValue`] with field
    /// `coap.link-format.syntax` and a stable production-specific reason. The
    /// shared error contract does not expose parser offsets, so callers retain
    /// the original payload when they need to correlate a failure with input.
    pub fn parse(data: &[u8]) -> Result<Self> {
        LinkFormatParser::new(data).parse()
    }

    /// Append one typed link while preserving existing link order.
    pub fn link(mut self, link: CoapLink) -> Self {
        self.links.push(link);
        self
    }

    /// Borrow typed links in their insertion or decoded wire order.
    pub fn links(&self) -> &[CoapLink] {
        &self.links
    }

    /// Pin exact document bytes for lossless serialization.
    ///
    /// The raw representation wins over the typed links and is deliberately
    /// not validated. This keeps unknown extensions and intentionally
    /// malformed caller-selected forms byte-exact. Documents returned by
    /// [`Self::parse`] retain their decoded bytes with `Defaulted` state;
    /// this method records an explicit `User` override.
    pub fn with_raw_bytes(mut self, raw: impl Into<Vec<u8>>) -> Self {
        self.raw.set_user(raw.into());
        self
    }

    /// Return the state of the optional exact raw representation.
    pub const fn raw_state(&self) -> FieldState {
        self.raw.state()
    }

    /// Borrow the exact caller-supplied or decoded document bytes, if present.
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        self.raw.value().map(Vec::as_slice)
    }

    /// Serialize this document as compact CoRE Link Format bytes.
    ///
    /// Retained decoded or caller-supplied raw bytes win for lossless round
    /// trips. Otherwise links and attributes are emitted in model order with
    /// no optional whitespace, using commas and semicolons as the canonical
    /// separators and escaping quoted-string content where required.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.raw.value() {
            Some(raw) => raw.clone(),
            None => serialize_links(&self.links),
        }
    }

    /// Serialize this document as UTF-8 text.
    ///
    /// Byte serialization remains available for deliberately non-UTF-8 raw
    /// forms. This helper reports those forms instead of normalizing or
    /// replacing their bytes.
    pub fn to_string(&self) -> Result<String> {
        String::from_utf8(self.to_bytes())
            .map_err(|_| link_format_syntax_error("serialized document is not valid UTF-8"))
    }

    /// Consume this document and return its serialized payload bytes.
    ///
    /// This is a packet-data conversion only; it does not select a transport
    /// or perform network I/O.
    pub fn into_payload(self) -> Vec<u8> {
        let Self { links, raw } = self;
        match raw.into_value() {
            Some(raw) => raw,
            None => serialize_links(&links),
        }
    }
}

/// Build a Content response carrying one owned CoRE Link Format document.
///
/// The document is serialized into the typed CoAP payload and identified by
/// the assigned `application/link-format` Content-Format. Message type,
/// Message ID, token, and transport remain caller-controlled transaction
/// fields; this helper stores no resource directory and performs no I/O.
pub fn coap_discovery_response(links: CoapLinkFormat) -> Coap {
    Coap::content()
        .content_format(CoapContentFormat::new(COAP_CONTENT_FORMAT_LINK_FORMAT))
        .payload(links.into_payload())
}

fn serialize_links(links: &[CoapLink]) -> Vec<u8> {
    let mut output = Vec::new();

    for (link_index, link) in links.iter().enumerate() {
        if link_index != 0 {
            output.push(b',');
        }

        output.push(b'<');
        output.extend_from_slice(link.target());
        output.push(b'>');

        for attribute in link.attributes() {
            output.push(b';');
            output.extend_from_slice(attribute.name());

            match attribute.value() {
                CoapLinkAttributeValue::Absent => {}
                CoapLinkAttributeValue::Token(value) | CoapLinkAttributeValue::Extended(value) => {
                    output.push(b'=');
                    output.extend_from_slice(value);
                }
                CoapLinkAttributeValue::Quoted(value) => {
                    output.extend_from_slice(b"=\"");
                    serialize_quoted_value(value, &mut output);
                    output.push(b'"');
                }
            }
        }
    }

    output
}

fn serialize_quoted_value(value: &[u8], output: &mut Vec<u8>) {
    let mut offset = 0;
    while let Some(byte) = value.get(offset).copied() {
        if byte == b'\\' {
            match value.get(offset + 1).copied() {
                Some(escaped) if escaped.is_ascii() => {
                    output.extend_from_slice(&[byte, escaped]);
                    offset += 2;
                    continue;
                }
                _ => output.extend_from_slice(b"\\\\"),
            }
        } else if byte == b'"' || !is_quoted_text_byte(byte) {
            output.extend_from_slice(&[b'\\', byte]);
        } else {
            output.push(byte);
        }
        offset += 1;
    }
}

const fn is_quoted_text_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'!' | b'#'..=b'~' | 0x80..=0xff)
}

struct LinkFormatParser<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> LinkFormatParser<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn parse(mut self) -> Result<CoapLinkFormat> {
        if self.data.len() > LINK_FORMAT_MAX_INPUT_LEN {
            return Err(link_format_syntax_error(
                "document exceeds 65535-byte parser limit",
            ));
        }

        let mut links = Vec::new();
        if !self.data.is_empty() {
            loop {
                if self.peek() != Some(b'<') {
                    return Err(link_format_syntax_error(
                        "link value is missing opening angle bracket",
                    ));
                }

                links.push(self.parse_link()?);
                match self.peek() {
                    None => break,
                    Some(b',') => {
                        self.offset += 1;
                        if self.peek().is_none() {
                            return Err(link_format_syntax_error(
                                "link separator is missing a following link value",
                            ));
                        }
                    }
                    Some(_) => {
                        return Err(link_format_syntax_error(
                            "invalid separator after link value",
                        ));
                    }
                }
            }
        }

        Ok(CoapLinkFormat {
            links,
            raw: Field::defaulted(self.data.to_vec()),
        })
    }

    fn parse_link(&mut self) -> Result<CoapLink> {
        debug_assert_eq!(self.peek(), Some(b'<'));
        self.offset += 1;
        let target_start = self.offset;

        while let Some(byte) = self.peek() {
            match byte {
                b'>' => {
                    let target = self.data[target_start..self.offset].to_vec();
                    self.offset += 1;
                    let mut link = CoapLink::new(target);

                    while self.peek() == Some(b';') {
                        self.offset += 1;
                        link.attributes.push(self.parse_attribute()?);
                    }
                    return Ok(link);
                }
                b'%' => {
                    if !self.has_hex_escape() {
                        return Err(link_format_syntax_error(
                            "target URI-reference contains an invalid percent escape",
                        ));
                    }
                    self.offset += 3;
                }
                byte if is_uri_reference_byte(byte) => self.offset += 1,
                _ => {
                    return Err(link_format_syntax_error(
                        "target contains an invalid URI-reference byte",
                    ));
                }
            }
        }

        Err(link_format_syntax_error("unterminated link target"))
    }

    fn parse_attribute(&mut self) -> Result<CoapLinkAttribute> {
        let name_start = self.offset;
        while self.peek().is_some_and(is_attribute_name_byte) {
            self.offset += 1;
        }
        if self.offset == name_start {
            return Err(link_format_syntax_error("missing link attribute name"));
        }

        let extended = self.peek() == Some(b'*');
        if extended {
            self.offset += 1;
        }
        let name = self.data[name_start..self.offset].to_vec();

        match self.peek() {
            Some(b'=') => self.offset += 1,
            _ if extended => {
                return Err(link_format_syntax_error(
                    "extended link attribute is missing a value",
                ));
            }
            None | Some(b';' | b',') => return Ok(CoapLinkAttribute::flag(name)),
            Some(_) => {
                return Err(link_format_syntax_error(
                    "invalid separator after link attribute name",
                ));
            }
        }

        if extended {
            let value = self.parse_extended_value()?;
            return Ok(CoapLinkAttribute::extended(name, value));
        }

        if self.peek() == Some(b'"') {
            let value = self.parse_quoted_value()?;
            Ok(CoapLinkAttribute::quoted(name, value))
        } else {
            let value = self.parse_token_value()?;
            Ok(CoapLinkAttribute::token(name, value))
        }
    }

    fn parse_token_value(&mut self) -> Result<Vec<u8>> {
        let value_start = self.offset;
        while let Some(byte) = self.peek() {
            if matches!(byte, b';' | b',') {
                break;
            }
            if !is_ptoken_byte(byte) {
                return Err(link_format_syntax_error(
                    "unquoted link attribute value is not a ptoken",
                ));
            }
            self.offset += 1;
        }

        if self.offset == value_start {
            return Err(link_format_syntax_error("missing link attribute value"));
        }
        Ok(self.data[value_start..self.offset].to_vec())
    }

    fn parse_quoted_value(&mut self) -> Result<Vec<u8>> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.offset += 1;
        let value_start = self.offset;

        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    let value = self.data[value_start..self.offset].to_vec();
                    self.offset += 1;
                    return Ok(value);
                }
                b'\\' => {
                    let Some(escaped) = self.data.get(self.offset + 1).copied() else {
                        return Err(link_format_syntax_error(
                            "quoted link attribute value ends in an escape",
                        ));
                    };
                    if !escaped.is_ascii() {
                        return Err(link_format_syntax_error(
                            "quoted link attribute value has an invalid escape",
                        ));
                    }
                    self.offset += 2;
                }
                b'\t' | b' '..=b'!' | b'#'..=b'~' | 0x80..=0xff => self.offset += 1,
                _ => {
                    return Err(link_format_syntax_error(
                        "quoted link attribute value contains a control byte",
                    ));
                }
            }
        }

        Err(link_format_syntax_error(
            "unterminated quoted link attribute value",
        ))
    }

    fn parse_extended_value(&mut self) -> Result<Vec<u8>> {
        let value_start = self.offset;
        let charset_start = self.offset;
        while self.peek().is_some_and(is_mime_charset_byte) {
            self.offset += 1;
        }
        if self.offset == charset_start || self.peek() != Some(b'\'') {
            return Err(link_format_syntax_error(
                "extended link attribute value has an invalid charset",
            ));
        }
        self.offset += 1;

        while self.peek().is_some_and(is_language_tag_byte) {
            self.offset += 1;
        }
        if self.peek() != Some(b'\'') {
            return Err(link_format_syntax_error(
                "extended link attribute value is missing its language delimiter",
            ));
        }
        self.offset += 1;

        while let Some(byte) = self.peek() {
            if matches!(byte, b';' | b',') {
                break;
            }
            match byte {
                b'%' if self.has_hex_escape() => self.offset += 3,
                byte if is_extended_value_byte(byte) => self.offset += 1,
                _ => {
                    return Err(link_format_syntax_error(
                        "extended link attribute value has invalid value bytes",
                    ));
                }
            }
        }

        Ok(self.data[value_start..self.offset].to_vec())
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.offset).copied()
    }

    fn has_hex_escape(&self) -> bool {
        self.data
            .get(self.offset + 1..self.offset + 3)
            .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
    }
}

const fn is_attribute_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

const fn is_ptoken_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'<'
                | b'='
                | b'>'
                | b'?'
                | b'@'
                | b'['
                | b']'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

const fn is_mime_charset_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'+'
                | b'-'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'}'
                | b'~'
        )
}

const fn is_language_tag_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

const fn is_extended_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

const fn is_uri_reference_byte(byte: u8) -> bool {
    byte >= 0x80
        || byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b';'
                | b'='
                | b'?'
                | b'@'
                | b'['
                | b']'
                | b'#'
                | b'_'
                | b'~'
        )
}

const fn link_format_syntax_error(reason: &'static str) -> CrafterError {
    CrafterError::invalid_field_value(LINK_FORMAT_SYNTAX_FIELD, reason)
}

/// One CoRE link target and its ordered target attributes.
///
/// The target stores the exact URI-reference bytes found between angle
/// brackets. It is intentionally not restricted to UTF-8, resolved against a
/// base URI, or dereferenced by the packet library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapLink {
    target: Vec<u8>,
    attributes: Vec<CoapLinkAttribute>,
}

impl CoapLink {
    /// Build a link from exact target URI-reference bytes.
    pub fn new(target: impl AsRef<[u8]>) -> Self {
        Self {
            target: target.as_ref().to_vec(),
            attributes: Vec::new(),
        }
    }

    /// Append one attribute while preserving occurrence order and repeats.
    pub fn attribute(mut self, attribute: CoapLinkAttribute) -> Self {
        self.attributes.push(attribute);
        self
    }

    /// Borrow the exact target URI-reference bytes.
    pub fn target(&self) -> &[u8] {
        &self.target
    }

    /// Borrow attributes in their insertion or decoded wire order.
    pub fn attributes(&self) -> &[CoapLinkAttribute] {
        &self.attributes
    }
}

/// The preserved syntactic form of one CoRE link attribute value.
///
/// Value bytes exclude the surrounding `=` and, for [`Self::Quoted`], the
/// surrounding double quotes. Escapes and every byte inside the value remain
/// untouched. [`Self::Extended`] retains an RFC 5987-style `ext-value` used by
/// names such as `title*` and unknown star-suffixed extensions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum CoapLinkAttributeValue {
    /// A flag attribute with no equals sign or value.
    #[default]
    Absent,
    /// An unquoted `ptoken` value.
    Token(Vec<u8>),
    /// Exact bytes inside a quoted-string value.
    Quoted(Vec<u8>),
    /// An unquoted RFC 5987-style extended value.
    Extended(Vec<u8>),
}

impl CoapLinkAttributeValue {
    /// Build a flag attribute value.
    pub const fn absent() -> Self {
        Self::Absent
    }

    /// Build a token value from exact bytes.
    pub fn token(value: impl AsRef<[u8]>) -> Self {
        Self::Token(value.as_ref().to_vec())
    }

    /// Build a quoted value while retaining exact bytes inside the quotes.
    pub fn quoted(value: impl AsRef<[u8]>) -> Self {
        Self::Quoted(value.as_ref().to_vec())
    }

    /// Build an RFC 5987-style extended value from exact bytes.
    pub fn extended(value: impl AsRef<[u8]>) -> Self {
        Self::Extended(value.as_ref().to_vec())
    }

    /// Borrow the exact value bytes, or `None` for a flag attribute.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Absent => None,
            Self::Token(value) | Self::Quoted(value) | Self::Extended(value) => Some(value),
        }
    }

    /// Return whether this is a flag attribute without a value.
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    /// Return whether this is an unquoted token value.
    pub const fn is_token(&self) -> bool {
        matches!(self, Self::Token(_))
    }

    /// Return whether this is a quoted-string value.
    pub const fn is_quoted(&self) -> bool {
        matches!(self, Self::Quoted(_))
    }

    /// Return whether this is an RFC 5987-style extended value.
    pub const fn is_extended(&self) -> bool {
        matches!(self, Self::Extended(_))
    }
}

/// One ordered, lossless CoRE link target attribute.
///
/// Attribute names and values remain open byte strings. Named constructors
/// cover the RFC 6690 grammar and currently registered stable attributes, but
/// registry membership never gates generic construction or equality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoapLinkAttribute {
    name: Vec<u8>,
    value: CoapLinkAttributeValue,
}

impl CoapLinkAttribute {
    /// Build an attribute from its exact name bytes and syntactic value form.
    pub fn new(name: impl AsRef<[u8]>, value: CoapLinkAttributeValue) -> Self {
        Self {
            name: name.as_ref().to_vec(),
            value,
        }
    }

    /// Build an unknown or registered flag attribute.
    pub fn flag(name: impl AsRef<[u8]>) -> Self {
        Self::new(name, CoapLinkAttributeValue::Absent)
    }

    /// Build an unknown or registered token-valued attribute.
    pub fn token(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Self {
        Self::new(name, CoapLinkAttributeValue::token(value))
    }

    /// Build an unknown or registered quoted-string attribute.
    pub fn quoted(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Self {
        Self::new(name, CoapLinkAttributeValue::quoted(value))
    }

    /// Build an unknown star-suffixed extension attribute.
    pub fn extended(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Self {
        Self::new(name, CoapLinkAttributeValue::extended(value))
    }

    /// Build an RFC 6690 `rel` attribute in its safe quoted form.
    pub fn rel(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("rel", value)
    }

    /// Build an RFC 6690 `anchor` attribute.
    pub fn anchor(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("anchor", value)
    }

    /// Build an RFC 6690 `rev` attribute in its safe quoted form.
    pub fn rev(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("rev", value)
    }

    /// Build an RFC 6690 `hreflang` attribute.
    pub fn hreflang(value: impl AsRef<[u8]>) -> Self {
        Self::token("hreflang", value)
    }

    /// Build an RFC 6690 `media` attribute in its safe quoted form.
    pub fn media(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("media", value)
    }

    /// Build an RFC 6690 human-readable `title` attribute.
    pub fn title(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("title", value)
    }

    /// Build an RFC 6690 `title*` extended attribute.
    pub fn title_star(value: impl AsRef<[u8]>) -> Self {
        Self::extended("title*", value)
    }

    /// Build an RFC 6690 Web Linking `type` media-type attribute.
    pub fn media_type(value: impl AsRef<[u8]>) -> Self {
        Self::token("type", value)
    }

    /// Build the RFC 7252 `ct` Content-Format hint attribute.
    pub fn content_type(value: impl AsRef<[u8]>) -> Self {
        Self::token("ct", value)
    }

    /// Build one RFC 7252 `ct` hint from typed Content-Format metadata.
    ///
    /// The numeric identifier remains open to unknown and future registry
    /// values through [`CoapContentFormat`]. Use [`Self::content_type`] when a
    /// link needs multiple space-separated identifiers or deliberately raw
    /// textual bytes.
    pub fn content_format(value: impl Into<CoapContentFormat>) -> Self {
        let value = value.into().value().to_string();
        Self::content_type(value)
    }

    /// Build the RFC 6690 `rt` Resource Type attribute.
    pub fn resource_type(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("rt", value)
    }

    /// Build the RFC 6690 `if` Interface Description attribute.
    pub fn interface_description(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("if", value)
    }

    /// Build the RFC 6690 `sz` maximum-size estimate attribute.
    ///
    /// The textual value is accepted as bytes because RFC 6690 defines no
    /// upper numeric limit and packet construction must preserve deliberately
    /// malformed caller values.
    pub fn size(value: impl AsRef<[u8]>) -> Self {
        Self::token("sz", value)
    }

    /// Build the RFC 7641 `obs` observable-resource flag attribute.
    pub fn observable() -> Self {
        Self::flag("obs")
    }

    /// Build the RFC 8075 `hct` HTTP-to-CoAP URI-template attribute.
    pub fn http_coap_mapping_template(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("hct", value)
    }

    /// Build the RFC 8613 `osc` OSCORE-only flag attribute.
    pub fn oscore_only() -> Self {
        Self::flag("osc")
    }

    /// Build the RFC 9176 `ep` endpoint-name attribute.
    pub fn endpoint_name(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("ep", value)
    }

    /// Build the RFC 9176 `d` sector attribute.
    pub fn sector(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("d", value)
    }

    /// Build the RFC 9176 `base` registration-base-URI attribute.
    pub fn registration_base_uri(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("base", value)
    }

    /// Build the RFC 9176 `et` endpoint-type attribute.
    pub fn endpoint_type(value: impl AsRef<[u8]>) -> Self {
        Self::quoted("et", value)
    }

    /// Build the RFC 9668 `ed-i` EDHOC Initiator-role flag.
    pub fn edhoc_initiator() -> Self {
        Self::flag("ed-i")
    }

    /// Build the RFC 9668 `ed-r` EDHOC Responder-role flag.
    pub fn edhoc_responder() -> Self {
        Self::flag("ed-r")
    }

    /// Build one RFC 9668 `ed-method` occurrence.
    pub fn edhoc_method(value: impl AsRef<[u8]>) -> Self {
        Self::token("ed-method", value)
    }

    /// Build one RFC 9668 `ed-csuite` occurrence.
    pub fn edhoc_cipher_suite(value: impl AsRef<[u8]>) -> Self {
        Self::token("ed-csuite", value)
    }

    /// Build one RFC 9668 `ed-cred-t` occurrence.
    pub fn edhoc_credential_type(value: impl AsRef<[u8]>) -> Self {
        Self::token("ed-cred-t", value)
    }

    /// Build one RFC 9668 `ed-idcred-t` occurrence.
    pub fn edhoc_credential_identifier_type(value: impl AsRef<[u8]>) -> Self {
        Self::token("ed-idcred-t", value)
    }

    /// Build one RFC 9668 `ed-ead` occurrence.
    pub fn edhoc_external_authorization_data(value: impl AsRef<[u8]>) -> Self {
        Self::token("ed-ead", value)
    }

    /// Build the RFC 9668 `ed-comb-req` combined-request flag.
    pub fn edhoc_combined_request() -> Self {
        Self::flag("ed-comb-req")
    }

    /// Borrow the exact, unmodified attribute name bytes.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Borrow the preserved syntactic value form.
    pub const fn value(&self) -> &CoapLinkAttributeValue {
        &self.value
    }

    /// Return whether the name appears in the current IANA Target Attributes
    /// registry snapshot.
    ///
    /// This is inspection metadata only. Matching is ASCII case-insensitive,
    /// as required for ABNF literal names, while the original bytes remain
    /// unchanged. The current provisional `gosc` row is recognized but has no
    /// named stable constructor; callers can preserve it with [`Self::flag`].
    pub fn is_registered_name(&self) -> bool {
        const REGISTERED: &[&[u8]] = &[
            b"href",
            b"anchor",
            b"rel",
            b"rev",
            b"hreflang",
            b"media",
            b"title",
            b"type",
            b"rt",
            b"if",
            b"sz",
            b"ct",
            b"obs",
            b"hct",
            b"osc",
            b"ep",
            b"d",
            b"base",
            b"et",
            b"ed-i",
            b"ed-r",
            b"ed-method",
            b"ed-csuite",
            b"ed-cred-t",
            b"ed-idcred-t",
            b"ed-ead",
            b"ed-comb-req",
            b"gosc",
        ];

        REGISTERED
            .iter()
            .any(|registered| self.name.eq_ignore_ascii_case(registered))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CoapContentFormat, CoapLink, CoapLinkAttribute, CoapLinkAttributeValue, CoapLinkFormat,
        LINK_FORMAT_MAX_INPUT_LEN, LINK_FORMAT_SYNTAX_FIELD,
    };
    use crate::error::CrafterError;
    use crate::field::FieldState;
    use proptest::prelude::*;
    use std::panic::catch_unwind;

    fn assert_syntax_error(data: &[u8], expected_reason: &'static str) {
        let result = catch_unwind(|| CoapLinkFormat::parse(data))
            .expect("link-format syntax parsing must not panic");
        assert_eq!(
            result,
            Err(CrafterError::InvalidFieldValue {
                field: LINK_FORMAT_SYNTAX_FIELD,
                reason: expected_reason,
            })
        );
    }

    fn typed_link_strategy() -> impl Strategy<Value = (String, String, String, Vec<u8>)> {
        (
            "[a-z0-9/_-]{0,24}",
            "[a-z][a-z0-9-]{0,8}",
            "[A-Za-z0-9._~-]{1,16}",
            proptest::collection::vec(
                prop_oneof![
                    Just(b'a'),
                    Just(b' '),
                    Just(b'"'),
                    Just(b'\\'),
                    Just(0x7f),
                    Just(0x80),
                ],
                0..16,
            ),
        )
    }

    #[test]
    fn construction_preserves_link_attribute_order_and_repeated_values() {
        let first_resource_type = CoapLinkAttribute::resource_type("temperature-c");
        let second_resource_type = CoapLinkAttribute::resource_type("outdoor");
        let link = CoapLink::new(b"/sensors/temp")
            .attribute(first_resource_type.clone())
            .attribute(CoapLinkAttribute::interface_description("sensor"))
            .attribute(second_resource_type.clone());
        let document = CoapLinkFormat::new()
            .link(link.clone())
            .link(CoapLink::new(b"/actuators/light"));

        assert_eq!(document.raw_state(), FieldState::Unset);
        assert_eq!(document.raw_bytes(), None);
        assert_eq!(document.links()[0], link);
        assert_eq!(document.links()[0].target(), b"/sensors/temp");
        assert_eq!(
            document.links()[0].attributes(),
            &[
                first_resource_type,
                CoapLinkAttribute::interface_description("sensor"),
                second_resource_type,
            ]
        );
        assert_eq!(document.links()[1].target(), b"/actuators/light");
    }

    #[test]
    fn attribute_value_forms_remain_distinct_and_byte_exact() {
        let flag = CoapLinkAttribute::flag("vendor-flag");
        let token = CoapLinkAttribute::token("vendor-token", [0xff, b'a']);
        let quoted = CoapLinkAttribute::quoted("title", b"Room \\\"A\\\"");
        let extended = CoapLinkAttribute::title_star("UTF-8'en'%E2%82%AC");

        assert!(flag.value().is_absent());
        assert_eq!(flag.value().as_bytes(), None);
        assert!(token.value().is_token());
        assert_eq!(token.value().as_bytes(), Some(&[0xff, b'a'][..]));
        assert!(quoted.value().is_quoted());
        assert_eq!(quoted.value().as_bytes(), Some(&b"Room \\\"A\\\""[..]));
        assert!(extended.value().is_extended());
        assert_eq!(
            extended.value().as_bytes(),
            Some(&b"UTF-8'en'%E2%82%AC"[..])
        );
        assert_ne!(
            CoapLinkAttributeValue::token("same"),
            CoapLinkAttributeValue::quoted("same")
        );
    }

    #[test]
    fn generic_attributes_preserve_unknown_names_and_extension_values() {
        let unknown = CoapLinkAttribute::new(
            [0xfe, b'x'],
            CoapLinkAttributeValue::quoted([0x80, b';', b',']),
        );
        let extension = CoapLinkAttribute::extended("vendor-title*", "UTF-8''raw%20bytes");

        assert_eq!(unknown.name(), &[0xfe, b'x']);
        assert_eq!(unknown.value().as_bytes(), Some(&[0x80, b';', b','][..]));
        assert!(!unknown.is_registered_name());
        assert_eq!(extension.name(), b"vendor-title*");
        assert_eq!(
            extension.value(),
            &CoapLinkAttributeValue::extended("UTF-8''raw%20bytes")
        );
    }

    #[test]
    fn helpers_cover_registered_stable_attribute_forms() {
        let cases = [
            CoapLinkAttribute::rel("hosts"),
            CoapLinkAttribute::anchor("coap://example.test"),
            CoapLinkAttribute::rev("item"),
            CoapLinkAttribute::hreflang("en"),
            CoapLinkAttribute::media("screen"),
            CoapLinkAttribute::title("Temperature"),
            CoapLinkAttribute::media_type("application/json"),
            CoapLinkAttribute::resource_type("temperature-c"),
            CoapLinkAttribute::interface_description("sensor"),
            CoapLinkAttribute::size("11223344556677889900112233445566778899"),
            CoapLinkAttribute::content_type("40"),
            CoapLinkAttribute::observable(),
            CoapLinkAttribute::http_coap_mapping_template("/http/{path}"),
            CoapLinkAttribute::oscore_only(),
            CoapLinkAttribute::endpoint_name("node-1"),
            CoapLinkAttribute::sector("floor-2"),
            CoapLinkAttribute::registration_base_uri("coap://example.test"),
            CoapLinkAttribute::endpoint_type("sensor-node"),
            CoapLinkAttribute::edhoc_initiator(),
            CoapLinkAttribute::edhoc_responder(),
            CoapLinkAttribute::edhoc_method("0"),
            CoapLinkAttribute::edhoc_cipher_suite("2"),
            CoapLinkAttribute::edhoc_credential_type("1"),
            CoapLinkAttribute::edhoc_credential_identifier_type("4"),
            CoapLinkAttribute::edhoc_external_authorization_data("7"),
            CoapLinkAttribute::edhoc_combined_request(),
        ];

        assert!(cases.iter().all(CoapLinkAttribute::is_registered_name));
        assert!(CoapLinkAttribute::flag("GOSC").is_registered_name());
        assert!(!CoapLinkAttribute::title_star("UTF-8''title").is_registered_name());
    }

    #[test]
    fn target_and_attribute_bytes_are_owned_and_equality_is_structural() {
        let mut target = b"/typed".to_vec();
        let mut name = b"vendor".to_vec();
        let mut value = b"one".to_vec();
        let document = CoapLinkFormat::new().link(
            CoapLink::new(&target)
                .attribute(CoapLinkAttribute::token(&name, &value))
                .attribute(CoapLinkAttribute::observable()),
        );
        target[0] = b'!';
        name[0] = b'!';
        value[0] = b'!';

        assert_eq!(document.raw_state(), FieldState::Unset);
        assert_eq!(document.links()[0].target(), b"/typed");
        assert_eq!(document.links()[0].attributes()[0].name(), b"vendor");
        assert_eq!(
            document.links()[0].attributes()[0].value().as_bytes(),
            Some(&b"one"[..])
        );
        assert_eq!(document.clone(), document);
        assert_ne!(
            document,
            CoapLinkFormat::new().link(CoapLink::new("/typed"))
        );
    }

    #[test]
    fn parses_rfc_6690_discovery_examples_in_wire_order() {
        // RFC 6690 Sections 2 and 5: commas separate links, while semicolons
        // introduce ordered attributes and quoted relation values may contain
        // spaces.
        let bytes = b"</sensors/temp>;rt=\"temperature-c\";if=\"sensor\",</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\"";
        let parsed = CoapLinkFormat::parse(bytes).unwrap();

        assert_eq!(parsed.raw_state(), FieldState::Defaulted);
        assert_eq!(parsed.raw_bytes(), Some(bytes.as_slice()));
        assert_eq!(parsed.links().len(), 2);
        assert_eq!(parsed.links()[0].target(), b"/sensors/temp");
        assert_eq!(
            parsed.links()[0].attributes(),
            &[
                CoapLinkAttribute::quoted("rt", "temperature-c"),
                CoapLinkAttribute::quoted("if", "sensor"),
            ]
        );
        assert_eq!(parsed.links()[1].target(), b"/sensors/light");
        assert_eq!(
            parsed.links()[1].attributes()[0],
            CoapLinkAttribute::quoted("rt", "light-lux core.sen-light")
        );
    }

    #[test]
    fn empty_document_flags_empty_quotes_repeats_and_commas_are_supported() {
        let empty = CoapLinkFormat::parse(b"").unwrap();
        assert!(empty.links().is_empty());
        assert_eq!(empty.raw_state(), FieldState::Defaulted);
        assert_eq!(empty.raw_bytes(), Some(&b""[..]));

        let bytes = b"<coap://example.test/a,b>;vendor;empty=\"\";repeat=one;repeat=two";
        let parsed = CoapLinkFormat::parse(bytes).unwrap();
        assert_eq!(parsed.links()[0].target(), b"coap://example.test/a,b");
        assert_eq!(
            parsed.links()[0].attributes(),
            &[
                CoapLinkAttribute::flag("vendor"),
                CoapLinkAttribute::quoted("empty", b""),
                CoapLinkAttribute::token("repeat", "one"),
                CoapLinkAttribute::token("repeat", "two"),
            ]
        );
    }

    #[test]
    fn unknown_quoted_and_extended_forms_preserve_exact_source_bytes() {
        // RFC 6690 Section 2 permits commas and semicolons inside quotes and
        // does not require a decoder to validate UTF-8. RFC 5987 Section 3.2
        // supplies the extended-value spelling retained here.
        let bytes = b"</\x80>;vendor=\"raw\x80,semi;slash\\\\quote\\\"\";vendor-title*=UTF-8'en'%E2%82%AC;empty*=UTF-8''";
        let parsed = CoapLinkFormat::parse(bytes).unwrap();
        let attributes = parsed.links()[0].attributes();

        assert_eq!(parsed.links()[0].target(), b"/\x80");
        assert_eq!(attributes[0].name(), b"vendor");
        assert_eq!(
            attributes[0].value(),
            &CoapLinkAttributeValue::quoted(b"raw\x80,semi;slash\\\\quote\\\"")
        );
        assert_eq!(attributes[1].name(), b"vendor-title*");
        assert_eq!(
            attributes[1].value(),
            &CoapLinkAttributeValue::extended("UTF-8'en'%E2%82%AC")
        );
        assert_eq!(
            attributes[2].value(),
            &CoapLinkAttributeValue::extended("UTF-8''")
        );
        assert_eq!(parsed.raw_bytes(), Some(bytes.as_slice()));
    }

    #[test]
    fn ptoken_and_uri_reference_source_characters_are_accepted() {
        let bytes = b"<coap://[2001:db8::1]/a!$&'()*+,;=:@/?q=x#f>;x=!#$%&'()*+-./:<=>?@[]^_`{|}~";
        let parsed = CoapLinkFormat::parse(bytes).unwrap();

        assert_eq!(
            parsed.links()[0].attributes()[0].value().as_bytes(),
            Some(&b"!#$%&'()*+-./:<=>?@[]^_`{|}~"[..])
        );
    }

    #[test]
    fn serializes_exact_rfc_6690_examples_canonically() {
        // RFC 6690 Section 5 gives these compact forms without the linefeeds
        // inserted in the surrounding prose for readability.
        let cases: Vec<(CoapLinkFormat, &[u8])> = vec![
            (
                CoapLinkFormat::new()
                    .link(
                        CoapLink::new("/sensors/temp")
                            .attribute(CoapLinkAttribute::interface_description("sensor")),
                    )
                    .link(
                        CoapLink::new("/sensors/light")
                            .attribute(CoapLinkAttribute::interface_description("sensor")),
                    ),
                b"</sensors/temp>;if=\"sensor\",</sensors/light>;if=\"sensor\"",
            ),
            (
                CoapLinkFormat::new().link(
                    CoapLink::new("/sensors")
                        .attribute(CoapLinkAttribute::content_format(CoapContentFormat::new(40))),
                ),
                b"</sensors>;ct=40",
            ),
            (
                CoapLinkFormat::new()
                    .link(
                        CoapLink::new("/sensors/temp")
                            .attribute(CoapLinkAttribute::resource_type("temperature-c"))
                            .attribute(CoapLinkAttribute::interface_description("sensor")),
                    )
                    .link(
                        CoapLink::new("/sensors/light")
                            .attribute(CoapLinkAttribute::resource_type("light-lux"))
                            .attribute(CoapLinkAttribute::interface_description("sensor")),
                    ),
                b"</sensors/temp>;rt=\"temperature-c\";if=\"sensor\",</sensors/light>;rt=\"light-lux\";if=\"sensor\"",
            ),
            (
                CoapLinkFormat::new().link(
                    CoapLink::new("/firmware/v2.1")
                        .attribute(CoapLinkAttribute::resource_type("firmware"))
                        .attribute(CoapLinkAttribute::size("262144")),
                ),
                b"</firmware/v2.1>;rt=\"firmware\";sz=262144",
            ),
        ];

        for (document, expected) in cases {
            assert_eq!(document.to_bytes(), expected);
            assert_eq!(document.to_string().unwrap().as_bytes(), expected);
            assert_eq!(document.clone().into_payload(), expected);

            let reparsed = CoapLinkFormat::parse(expected).unwrap();
            assert_eq!(reparsed.links(), document.links());
        }
    }

    #[test]
    fn canonical_serialization_preserves_order_and_escapes_quoted_content() {
        let document = CoapLinkFormat::new().link(
            CoapLink::new("/x")
                .attribute(CoapLinkAttribute::flag("first"))
                .attribute(CoapLinkAttribute::quoted("title", b"a\"b\\"))
                .attribute(CoapLinkAttribute::token("last", "value")),
        );
        let expected = b"</x>;first;title=\"a\\\"b\\\\\";last=value";

        assert_eq!(document.to_bytes(), expected);
        assert_eq!(
            CoapLinkFormat::parse(expected).unwrap().links().len(),
            document.links().len()
        );
    }

    #[test]
    fn retained_and_caller_selected_raw_documents_serialize_losslessly() {
        let decoded_bytes = b"</x>;vendor=one;vendor=two;vendor-title*=UTF-8''raw%20bytes";
        let decoded = CoapLinkFormat::parse(decoded_bytes).unwrap();
        assert_eq!(decoded.raw_state(), FieldState::Defaulted);
        assert_eq!(decoded.to_bytes(), decoded_bytes);
        assert_eq!(decoded.clone().into_payload(), decoded_bytes);

        let caller_bytes = b"caller-selected raw form";
        let caller_selected = CoapLinkFormat::new()
            .link(CoapLink::new("/typed"))
            .with_raw_bytes(caller_bytes.to_vec());
        assert_eq!(caller_selected.raw_state(), FieldState::User);
        assert_eq!(caller_selected.raw_bytes(), Some(caller_bytes.as_slice()));
        assert_eq!(caller_selected.to_bytes(), caller_bytes);
        assert_eq!(caller_selected.into_payload(), caller_bytes);
    }

    #[test]
    fn string_serialization_rejects_non_utf8_without_changing_payload_bytes() {
        let bytes = b"</\x80>;vendor=raw";
        let parsed = CoapLinkFormat::parse(bytes).unwrap();

        assert_eq!(parsed.to_bytes(), bytes);
        assert_eq!(
            parsed.to_string(),
            Err(CrafterError::InvalidFieldValue {
                field: LINK_FORMAT_SYNTAX_FIELD,
                reason: "serialized document is not valid UTF-8",
            })
        );
    }

    #[test]
    fn content_format_metadata_builds_numeric_ct_attributes() {
        let content_format = CoapContentFormat::new(40);
        assert_eq!(
            content_format.registry_meta().label,
            "application/link-format"
        );

        let attribute = CoapLinkAttribute::content_format(content_format);
        assert_eq!(attribute.name(), b"ct");
        assert_eq!(attribute.value(), &CoapLinkAttributeValue::token("40"));
    }

    #[test]
    fn malformed_link_format_corpus_has_stable_context_and_reasons() {
        let cases: &[(&[u8], &str)] = &[
            (b"not-a-link", "link value is missing opening angle bracket"),
            (b"</unterminated", "unterminated link target"),
            (
                b"</bad%escape>",
                "target URI-reference contains an invalid percent escape",
            ),
            (
                b"</bad target>",
                "target contains an invalid URI-reference byte",
            ),
            (b"</ok> ", "invalid separator after link value"),
            (
                b"</ok>,",
                "link separator is missing a following link value",
            ),
            (
                b"</ok>,,</next>",
                "link value is missing opening angle bracket",
            ),
            (b"</ok>;", "missing link attribute name"),
            (b"</ok>;=value", "missing link attribute name"),
            (
                b"</ok>;bad name=value",
                "invalid separator after link attribute name",
            ),
            (b"</ok>;empty=", "missing link attribute value"),
            (
                b"</ok>;token=has space",
                "unquoted link attribute value is not a ptoken",
            ),
            (
                b"</ok>;title=\"unterminated",
                "unterminated quoted link attribute value",
            ),
            (
                b"</ok>;title=\"escape\\",
                "quoted link attribute value ends in an escape",
            ),
            (
                b"</ok>;title=\"escape\\\x80\"",
                "quoted link attribute value has an invalid escape",
            ),
            (
                b"</ok>;title=\"control\x01\"",
                "quoted link attribute value contains a control byte",
            ),
            (
                b"</ok>;title*",
                "extended link attribute is missing a value",
            ),
            (
                b"</ok>;title*=\"quoted\"",
                "extended link attribute value has an invalid charset",
            ),
            (
                b"</ok>;title*='en'value",
                "extended link attribute value has an invalid charset",
            ),
            (
                b"</ok>;title*=UTF-8'en",
                "extended link attribute value is missing its language delimiter",
            ),
            (
                b"</ok>;title*=UTF-8''bad%2",
                "extended link attribute value has invalid value bytes",
            ),
        ];

        for &(data, reason) in cases {
            assert_syntax_error(data, reason);
        }
    }

    #[test]
    fn public_syntax_error_contract_is_stable_at_different_internal_offsets() {
        // The frozen CrafterError contract exposes the grammar context and
        // reason, but no byte offset. Keep the public result identical when
        // the same failed production occurs at different parser positions.
        for data in [&b"not-a-link"[..], &b"</ok>,not-a-link"[..]] {
            assert_syntax_error(data, "link value is missing opening angle bracket");
        }
        for data in [&b"<unterminated"[..], &b"</ok>,<unterminated"[..]] {
            assert_syntax_error(data, "unterminated link target");
        }
    }

    #[test]
    fn parser_limit_accepts_boundary_and_rejects_oversized_input() {
        let mut boundary = Vec::with_capacity(LINK_FORMAT_MAX_INPUT_LEN);
        boundary.push(b'<');
        boundary.resize(LINK_FORMAT_MAX_INPUT_LEN - 1, b'a');
        boundary.push(b'>');
        let parsed = CoapLinkFormat::parse(&boundary).unwrap();
        assert_eq!(
            parsed.links()[0].target().len(),
            LINK_FORMAT_MAX_INPUT_LEN - 2
        );

        let oversized = vec![b'x'; LINK_FORMAT_MAX_INPUT_LEN + 1];
        assert_syntax_error(&oversized, "document exceeds 65535-byte parser limit");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn arbitrary_input_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            prop_assert!(catch_unwind(|| CoapLinkFormat::parse(&data)).is_ok());
        }

        #[test]
        fn parse_serialize_parse_is_stable_for_typed_documents(
            links in proptest::collection::vec(typed_link_strategy(), 0..8)
        ) {
            let mut document = CoapLinkFormat::new();
            for (target, name, token, quoted) in links {
                document = document.link(
                    CoapLink::new(target)
                        .attribute(CoapLinkAttribute::token(name, token))
                        .attribute(CoapLinkAttribute::quoted("title", quoted)),
                );
            }

            let canonical = document.to_bytes();
            let parsed_once = CoapLinkFormat::parse(&canonical).unwrap();
            let serialized = parsed_once.to_bytes();
            let parsed_twice = CoapLinkFormat::parse(&serialized).unwrap();

            prop_assert_eq!(serialized, canonical);
            prop_assert_eq!(parsed_twice, parsed_once);
        }
    }
}
