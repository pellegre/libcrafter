//! CoRE Link Format packet metadata.
//!
//! The byte-owned model follows RFC 6690 Sections 2 and 3 and the current
//! IANA CoRE Target Attributes registry. Parsing and canonical serialization
//! are separate concerns: this module first keeps link order, repeated
//! attributes, unknown names, and each attribute's syntactic value form
//! inspectable without requiring UTF-8 validation or normalization.

use crate::field::{Field, FieldState};

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

    /// Append one typed link while preserving existing link order.
    pub fn link(mut self, link: CoapLink) -> Self {
        self.links.push(link);
        self
    }

    /// Borrow typed links in their insertion or decoded wire order.
    pub fn links(&self) -> &[CoapLink] {
        &self.links
    }

    /// Return the state of the optional exact raw representation.
    pub const fn raw_state(&self) -> FieldState {
        self.raw.state()
    }

    /// Borrow the exact caller-supplied or decoded document bytes, if present.
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        self.raw.value().map(Vec::as_slice)
    }
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
    use super::{CoapLink, CoapLinkAttribute, CoapLinkAttributeValue, CoapLinkFormat};
    use crate::field::FieldState;

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
}
