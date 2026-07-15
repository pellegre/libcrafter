//! Source-backed CoAP group communication wire metadata.
//!
//! RFC 7252 Sections 8.1 and 8.2 define the stable multicast request and
//! unicast response deltas. RFC 7390 Sections 2.2, 2.5, and 2.8 add group
//! request/response guidance and assign `application/coap-group+json`. RFC
//! 9176 Section 9.5 and Appendix A define current Resource Directory group
//! discovery metadata. This module intentionally performs no multicast group
//! joins, endpoint discovery, response scheduling, suppression, or I/O.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Result;
use crate::packet::Packet;
use crate::protocols::ip::{v4::Ipv4, v6::Ipv6};

use super::constants::{COAP_OPTION_ETAG, COAP_OPTION_OBSERVE, COAP_OPTION_OSCORE};
use super::message::{
    coap_request_udp, coap_response_udp, Coap, CoapCode, CoapMessageType, CoapToken,
    CoapValidation, CoapValidationCategory, CoapValidationSeverity,
};
use super::option::{CoapAccept, CoapContentFormat, CoapOption};
use super::oscore::{OscoreError, OscoreOption};

/// RFC 7252's IPv4 "All CoAP Nodes" multicast address.
pub const COAP_ALL_NODES_IPV4_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 187);
/// RFC 7252's link-local IPv6 "All CoAP Nodes" multicast address.
pub const COAP_ALL_NODES_IPV6_LINK_LOCAL_MULTICAST: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fd);
/// RFC 7252's site-local IPv6 "All CoAP Nodes" multicast address.
pub const COAP_ALL_NODES_IPV6_SITE_LOCAL_MULTICAST: Ipv6Addr =
    Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x00fd);

/// RFC 9176's IPv4 "All CoRE Resource Directories" multicast address.
pub const COAP_ALL_RESOURCE_DIRECTORIES_IPV4_MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 190);
/// RFC 9176's link-local IPv6 "All CoRE Resource Directories" address.
pub const COAP_ALL_RESOURCE_DIRECTORIES_IPV6_LINK_LOCAL_MULTICAST: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fe);
/// RFC 9176's site-local IPv6 "All CoRE Resource Directories" address.
pub const COAP_ALL_RESOURCE_DIRECTORIES_IPV6_SITE_LOCAL_MULTICAST: Ipv6Addr =
    Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x00fe);

/// `application/coap-group+json`, assigned Content-Format 256 by RFC 7390.
pub const COAP_CONTENT_FORMAT_GROUP_JSON: u16 = 256;

impl CoapContentFormat {
    /// Build RFC 7390's `application/coap-group+json` Content-Format (256).
    pub fn coap_group_json() -> Self {
        Self::new(COAP_CONTENT_FORMAT_GROUP_JSON)
    }
}

impl CoapAccept {
    /// Build an Accept value for `application/coap-group+json` (256).
    pub fn coap_group_json() -> Self {
        Self::new(COAP_CONTENT_FORMAT_GROUP_JSON)
    }
}

/// Opaque COSE algorithm identifier associated with provisional Group OSCORE metadata.
///
/// No countersignature algorithm is admitted while Group OSCORE remains an
/// Internet-Draft. Numeric identifiers are retained so generated tools can
/// inspect and persist future or unknown assignments without selecting an
/// implementation from model memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupOscoreAlgorithmId(i32);

impl GroupOscoreAlgorithmId {
    /// Preserve an exact numeric COSE algorithm identifier.
    pub const fn new(id: i32) -> Self {
        Self(id)
    }

    /// Return the exact preserved numeric identifier.
    pub const fn id(self) -> i32 {
        self.0
    }

    /// Return whether this crate currently admits the algorithm for Group OSCORE.
    pub const fn is_supported(self) -> bool {
        false
    }

    /// Require countersignature support and return an explicit typed result.
    pub fn require_supported(self) -> std::result::Result<(), OscoreError> {
        Err(OscoreError::UnsupportedCountersignatureAlgorithm { id: self.0 })
    }
}

/// Opaque countersignature-related inputs retained without cryptographic interpretation.
///
/// The current Internet-Draft describes countersignature bytes and External
/// AAD inputs, but the repository source manifest forbids freezing their
/// serializer or algorithm set before publication as a numbered RFC. Debug
/// output therefore exposes lengths and the numeric algorithm only.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupOscoreCountersignature {
    algorithm: GroupOscoreAlgorithmId,
    external_data: Vec<u8>,
    bytes: Vec<u8>,
}

impl GroupOscoreCountersignature {
    /// Preserve caller-supplied algorithm, external data, and countersignature bytes.
    pub fn new(
        algorithm: GroupOscoreAlgorithmId,
        external_data: impl Into<Vec<u8>>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            algorithm,
            external_data: external_data.into(),
            bytes: bytes.into(),
        }
    }

    /// Return the exact opaque COSE algorithm identifier.
    pub const fn algorithm(&self) -> GroupOscoreAlgorithmId {
        self.algorithm
    }

    /// Borrow caller-supplied countersignature external data verbatim.
    pub fn external_data(&self) -> &[u8] {
        &self.external_data
    }

    /// Borrow countersignature bytes verbatim.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the explicit unsupported result for countersignature verification.
    pub fn verify(&self) -> std::result::Result<(), OscoreError> {
        self.algorithm.require_supported()
    }
}

impl fmt::Debug for GroupOscoreCountersignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupOscoreCountersignature")
            .field("algorithm_id", &self.algorithm.id())
            .field("external_data", &"[redacted]")
            .field("external_data_len", &self.external_data.len())
            .field("bytes", &"[redacted]")
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

/// Provisional, lossless inspection metadata for one Group-Flagged CoAP message.
///
/// The complete typed [`Coap`] layer remains authoritative. This view parses
/// only RFC 8613's established Partial IV, KID Context, and KID fields and
/// recognizes IANA's provisional Group Flag. The protected payload and any
/// countersignature material remain opaque; no boundary between ciphertext,
/// tag, and encrypted countersignature is inferred.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupOscoreMetadata {
    message: Coap,
    option: OscoreOption,
    countersignature: GroupOscoreCountersignature,
}

impl GroupOscoreMetadata {
    /// Inspect one Group-Flagged message without normalizing any wire bytes.
    pub fn inspect(
        message: Coap,
        countersignature: GroupOscoreCountersignature,
    ) -> std::result::Result<Self, OscoreError> {
        let mut options = message
            .options_value()
            .iter()
            .filter(|option| option.number().value() == COAP_OPTION_OSCORE);
        let option = options.next().ok_or(OscoreError::MissingContext {
            context: "coap.group-oscore.message.option",
        })?;
        if options.next().is_some() {
            return Err(OscoreError::InvalidFieldValue {
                field: "coap.group-oscore.message.option",
                reason: "OSCORE option must not be repeated",
            });
        }
        let option = OscoreOption::try_from(option)?;
        if !option.has_provisional_group_flag() {
            return Err(OscoreError::InvalidFieldValue {
                field: "coap.group-oscore.option.flags",
                reason: "provisional Group Flag is not set",
            });
        }

        Ok(Self {
            message,
            option,
            countersignature,
        })
    }

    /// Return whether IANA's provisional Group Flag is set.
    pub fn has_group_flag(&self) -> bool {
        self.option.has_provisional_group_flag()
    }

    /// Borrow the exact parsed OSCORE option, including all raw bytes.
    pub const fn oscore_option(&self) -> &OscoreOption {
        &self.option
    }

    /// Borrow the Partial IV parsed by the established RFC 8613 grammar.
    pub fn partial_iv(&self) -> Option<&[u8]> {
        self.option.partial_iv()
    }

    /// Borrow the KID Context, provisionally interpreted as a Group Identifier.
    pub fn group_identifier(&self) -> Option<&[u8]> {
        self.option.kid_context()
    }

    /// Borrow the KID, provisionally interpreted as a Sender ID.
    pub fn sender_id(&self) -> Option<&[u8]> {
        self.option.kid()
    }

    /// Borrow the complete protected payload without guessing field boundaries.
    pub fn protected_payload(&self) -> &[u8] {
        self.message.payload_value()
    }

    /// Borrow the separately retained opaque countersignature metadata.
    pub const fn countersignature(&self) -> &GroupOscoreCountersignature {
        &self.countersignature
    }

    /// Borrow the complete typed CoAP layer.
    pub const fn message(&self) -> &Coap {
        &self.message
    }

    /// Consume the metadata and recover the exact typed CoAP layer.
    pub fn into_message(self) -> Coap {
        self.message
    }

    /// Return the explicit source-boundary error for unavailable protection.
    pub fn require_protection_support(&self) -> std::result::Result<(), OscoreError> {
        Err(OscoreError::UnsupportedGroupOscoreOperation {
            operation: "protect-or-unprotect",
        })
    }
}

impl fmt::Debug for GroupOscoreMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupOscoreMetadata")
            .field("group_flag", &self.has_group_flag())
            .field("option", &"[redacted]")
            .field("option_len", &self.option.as_bytes().len())
            .field("protected_payload", &"[redacted]")
            .field("protected_payload_len", &self.protected_payload().len())
            .field("countersignature", &self.countersignature)
            .finish()
    }
}

/// Owned packet-local metadata for one possible CoAP group datagram.
///
/// Classification deliberately keeps the network endpoints beside the typed
/// [`Coap`] layer: the destination address is what distinguishes a group
/// request from an ordinary request. Unknown option bytes and open code values
/// remain owned by `message` and are never rewritten by this metadata view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapGroupMetadata {
    source: IpAddr,
    destination: IpAddr,
    message: Coap,
}

impl CoapGroupMetadata {
    /// Record explicit source and destination endpoints for one CoAP datagram.
    ///
    /// Mixed address families and role-inappropriate addresses remain
    /// representable for packet crafting. Use [`Self::validate_group_request`]
    /// or [`Self::validate_group_response`] for opt-in semantic checks.
    pub fn new(source: IpAddr, destination: IpAddr, message: Coap) -> Self {
        Self {
            source,
            destination,
            message,
        }
    }

    /// Record IPv4 endpoint metadata without constructing or sending a packet.
    pub fn ipv4(source: Ipv4Addr, destination: Ipv4Addr, message: Coap) -> Self {
        Self::new(source.into(), destination.into(), message)
    }

    /// Record IPv6 endpoint metadata without constructing or sending a packet.
    pub fn ipv6(source: Ipv6Addr, destination: Ipv6Addr, message: Coap) -> Self {
        Self::new(source.into(), destination.into(), message)
    }

    /// Return the exact source IP address supplied by the caller.
    pub const fn source(&self) -> IpAddr {
        self.source
    }

    /// Return the exact destination IP address supplied by the caller.
    pub const fn destination(&self) -> IpAddr {
        self.destination
    }

    /// Borrow the complete typed CoAP layer, including unknown options.
    pub const fn message(&self) -> &Coap {
        &self.message
    }

    /// Consume the metadata and return the complete typed CoAP layer.
    pub fn into_message(self) -> Coap {
        self.message
    }

    /// Return the effective datagram message type.
    pub fn message_type(&self) -> CoapMessageType {
        self.message.message_type_value()
    }

    /// Return the exact open CoAP Code value.
    pub fn code(&self) -> CoapCode {
        self.message.code_value()
    }

    /// Return the effective Message ID.
    pub fn message_id(&self) -> u16 {
        self.message.message_id_value()
    }

    /// Borrow the opaque token used for group-response correlation.
    pub fn token(&self) -> &CoapToken {
        self.message.token_value()
    }

    /// Borrow every known or unknown option in preserved order.
    pub fn options(&self) -> &[CoapOption] {
        self.message.options_value()
    }

    /// Borrow the exact payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.message.payload_value()
    }

    /// Return the first raw-preserving Content-Format occurrence, if present.
    pub fn content_format(&self) -> Option<Result<CoapContentFormat>> {
        self.message.content_format_value()
    }

    /// Return whether the destination is any IPv4 or IPv6 multicast address.
    pub fn has_multicast_destination(&self) -> bool {
        self.destination.is_multicast()
    }

    /// Classify the packet as a group-request candidate.
    ///
    /// This field-level classification requires a request code and multicast
    /// destination, while validation separately reports a Confirmable type,
    /// mixed address families, and multicast-unsafe known options.
    pub fn is_group_request(&self) -> bool {
        self.has_multicast_destination() && self.message.is_request()
    }

    /// Classify the packet as a unicast response candidate.
    ///
    /// A response is known to answer a group request only after comparing it
    /// with [`Self::match_response`].
    pub fn is_unicast_response(&self) -> bool {
        self.message.is_response()
            && is_unicast_endpoint(self.source)
            && is_unicast_endpoint(self.destination)
    }

    /// Validate RFC 7252/RFC 7390 group-request packet metadata.
    ///
    /// The base CoAP validation report is retained and group-specific findings
    /// are appended. Unknown options remain lossless and receive no guessed
    /// multicast semantics.
    pub fn validate_group_request(&self) -> CoapValidation {
        let mut validation = self.message.validate();

        if !same_address_family(self.source, self.destination) {
            validation.push(
                "coap.group.request.address-family",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "group request source and destination must use the same IP address family",
            );
        }
        if !is_unicast_endpoint(self.source) {
            validation.push(
                "coap.group.request.source",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "group request source must be a unicast IP address",
            );
        }
        if !self.destination.is_multicast() {
            validation.push(
                "coap.group.request.destination",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "group request destination must be an IP multicast address",
            );
        }
        if !self.message.is_request() {
            validation.push(
                "coap.group.request.code",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "group request must carry a request code",
            );
        }
        if !self.message.message_type_value().is_non_confirmable() {
            validation.push(
                "coap.group.request.type",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "multicast CoAP requests must be Non-confirmable",
            );
        }

        if self.message.code_value() == CoapCode::get()
            && has_option(&self.message, COAP_OPTION_ETAG)
        {
            validation.push(
                "coap.group.request.options.etag",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "multicast GET requests must not contain ETag",
            );
        }
        if has_option(&self.message, COAP_OPTION_OBSERVE) {
            validation.push(
                "coap.group.request.options.observe",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "Observe does not define multicast group requests",
            );
        }

        validation
    }

    /// Validate packet-local metadata for a unicast response to a group request.
    ///
    /// RFC 7390 recommends a Non-confirmable response. A Confirmable response
    /// is therefore a warning rather than a compile-time rejection; an ACK or
    /// Reset response shape is an error because group requests are NON.
    pub fn validate_group_response(&self) -> CoapValidation {
        let mut validation = self.message.validate();

        if !same_address_family(self.source, self.destination) {
            validation.push(
                "coap.group.response.address-family",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "group response source and destination must use the same IP address family",
            );
        }
        if !is_unicast_endpoint(self.source) {
            validation.push(
                "coap.group.response.source",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "group response source must be a unicast IP address",
            );
        }
        if !is_unicast_endpoint(self.destination) {
            validation.push(
                "coap.group.response.destination",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "group response destination must be a unicast IP address",
            );
        }
        if !self.message.is_response() {
            validation.push(
                "coap.group.response.code",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "group response must carry a response code",
            );
        }

        match self.message.message_type_value() {
            CoapMessageType::NonConfirmable => {}
            CoapMessageType::Confirmable => validation.push(
                "coap.group.response.type",
                CoapValidationSeverity::Warning,
                CoapValidationCategory::GroupCommunication,
                "response to a multicast request should be Non-confirmable",
            ),
            _ => validation.push(
                "coap.group.response.type",
                CoapValidationSeverity::Error,
                CoapValidationCategory::GroupCommunication,
                "response to a multicast request must be a separate unicast response",
            ),
        }

        validation
    }

    /// Compare a unicast response candidate with this group request.
    ///
    /// RFC 7252 Section 8.2 correlates group responses by Token only; Message
    /// IDs and the response source are deliberately not compared for equality
    /// with the original multicast destination.
    pub fn match_response(&self, response: &Self) -> CoapGroupMatch {
        CoapGroupMatch::new(self, response)
    }
}

/// Inspectable stateless correlation result for a group request and response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoapGroupMatch {
    request_is_group: bool,
    request_is_non_confirmable: bool,
    response_is_response: bool,
    response_is_unicast: bool,
    address_family_matches: bool,
    response_destination_matches_request_source: bool,
    token_matches: bool,
}

impl CoapGroupMatch {
    fn new(request: &CoapGroupMetadata, response: &CoapGroupMetadata) -> Self {
        let address_family_matches = same_address_family(request.source, request.destination)
            && same_address_family(response.source, response.destination)
            && same_address_family(request.source, response.source);

        Self {
            request_is_group: request.is_group_request()
                && is_unicast_endpoint(request.source)
                && same_address_family(request.source, request.destination),
            request_is_non_confirmable: request.message.message_type_value().is_non_confirmable(),
            response_is_response: response.message.is_response(),
            response_is_unicast: response.is_unicast_response(),
            address_family_matches,
            response_destination_matches_request_source: response.destination == request.source,
            token_matches: response.message.token_matches(&request.message),
        }
    }

    /// Return whether the request has a unicast source, multicast destination,
    /// one IP family, and a request code.
    pub const fn request_is_group(&self) -> bool {
        self.request_is_group
    }

    /// Return whether the request uses the required NON message type.
    pub const fn request_is_non_confirmable(&self) -> bool {
        self.request_is_non_confirmable
    }

    /// Return whether the candidate carries an open response-class code.
    pub const fn response_is_response(&self) -> bool {
        self.response_is_response
    }

    /// Return whether both response endpoints are unicast addresses.
    pub const fn response_is_unicast(&self) -> bool {
        self.response_is_unicast
    }

    /// Return whether request and response endpoints use one IP family.
    pub const fn address_family_matches(&self) -> bool {
        self.address_family_matches
    }

    /// Return whether the response is addressed back to the request source.
    pub const fn response_destination_matches_request_source(&self) -> bool {
        self.response_destination_matches_request_source
    }

    /// Return the RFC 7252 Token-only correlation result.
    pub const fn token_matches(&self) -> bool {
        self.token_matches
    }

    /// Return whether the candidate is a Token-matching unicast response to a
    /// validly shaped group request.
    ///
    /// Message IDs, response source equality, address-family equality, and
    /// response-destination equality are intentionally absent from the
    /// correlation decision. Their metadata remains separately inspectable;
    /// endpoint state, token lifetime, timing, duplicate suppression, and
    /// security remain caller responsibilities.
    pub const fn is_match(&self) -> bool {
        self.request_is_group
            && self.request_is_non_confirmable
            && self.response_is_response
            && self.response_is_unicast
            && self.token_matches
    }
}

/// Build an IPv4/UDP/CoAP group request packet without sending it.
///
/// `destination` may be a caller-controlled multicast address or
/// [`COAP_ALL_NODES_IPV4_MULTICAST`]. The message is retained exactly so a
/// caller can deliberately construct an invalid Confirmable group request and
/// inspect it with [`CoapGroupMetadata::validate_group_request`].
pub fn coap_ipv4_group_request(source: Ipv4Addr, destination: Ipv4Addr, message: Coap) -> Packet {
    Ipv4::with_addresses(source, destination) / coap_request_udp() / message
}

/// Build an IPv6/UDP/CoAP group request packet without sending it.
pub fn coap_ipv6_group_request(source: Ipv6Addr, destination: Ipv6Addr, message: Coap) -> Packet {
    Ipv6::with_addresses(source, destination) / coap_request_udp() / message
}

/// Build an IPv4 unicast response packet for a group request without sending it.
pub fn coap_ipv4_group_response(source: Ipv4Addr, destination: Ipv4Addr, message: Coap) -> Packet {
    Ipv4::with_addresses(source, destination) / coap_response_udp() / message
}

/// Build an IPv6 unicast response packet for a group request without sending it.
pub fn coap_ipv6_group_response(source: Ipv6Addr, destination: Ipv6Addr, message: Coap) -> Packet {
    Ipv6::with_addresses(source, destination) / coap_response_udp() / message
}

fn has_option(message: &Coap, number: u16) -> bool {
    message
        .options_value()
        .iter()
        .any(|option| option.number().value() == number)
}

fn same_address_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn is_unicast_endpoint(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
        }
        IpAddr::V6(address) => !address.is_unspecified() && !address.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::coap::{CoapRegistryStatus, CoapToken};
    use crate::protocols::transport::Udp;

    const IPV4_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const IPV4_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
    const IPV6_CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10);
    const IPV6_SERVER: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x20);

    fn token() -> CoapToken {
        CoapToken::from_bytes([0xa1, 0xb2])
    }

    #[test]
    fn assigned_group_constants_and_content_format_are_source_backed() {
        assert_eq!(COAP_ALL_NODES_IPV4_MULTICAST, Ipv4Addr::new(224, 0, 1, 187));
        assert_eq!(
            COAP_ALL_NODES_IPV6_LINK_LOCAL_MULTICAST,
            "ff02::fd".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            COAP_ALL_NODES_IPV6_SITE_LOCAL_MULTICAST,
            "ff05::fd".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            COAP_ALL_RESOURCE_DIRECTORIES_IPV4_MULTICAST,
            Ipv4Addr::new(224, 0, 1, 190)
        );
        assert_eq!(
            COAP_ALL_RESOURCE_DIRECTORIES_IPV6_LINK_LOCAL_MULTICAST,
            "ff02::fe".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            COAP_ALL_RESOURCE_DIRECTORIES_IPV6_SITE_LOCAL_MULTICAST,
            "ff05::fe".parse::<Ipv6Addr>().unwrap()
        );

        let format = CoapContentFormat::coap_group_json();
        assert_eq!(format.value(), COAP_CONTENT_FORMAT_GROUP_JSON);
        assert_eq!(format.as_bytes(), [0x01, 0x00]);
        assert_eq!(format.registry_meta().label, "application/coap-group+json");
        assert_eq!(format.registry_meta().status, CoapRegistryStatus::Assigned);
        assert_eq!(CoapAccept::coap_group_json().value(), 256);
    }

    #[test]
    fn ipv4_group_request_packet_and_metadata_preserve_unknown_options() {
        let unknown = CoapOption::new(65_000u16, [0xde, 0xad]);
        let message = Coap::get()
            .non_confirmable()
            .message_id(0x1234)
            .token(token())
            .option(unknown.clone());
        let packet =
            coap_ipv4_group_request(IPV4_CLIENT, COAP_ALL_NODES_IPV4_MULTICAST, message.clone());

        let ipv4 = packet.layer::<Ipv4>().expect("IPv4 layer");
        let udp = packet.layer::<Udp>().expect("UDP layer");
        assert_eq!(ipv4.source(), IPV4_CLIENT);
        assert_eq!(ipv4.destination(), COAP_ALL_NODES_IPV4_MULTICAST);
        assert_eq!(udp.destination_port_value(), 5683);
        assert_eq!(packet.layer::<Coap>(), Some(&message));
        assert!(packet.compile().is_ok());

        let metadata = CoapGroupMetadata::ipv4(IPV4_CLIENT, COAP_ALL_NODES_IPV4_MULTICAST, message);
        assert!(metadata.is_group_request());
        assert!(!metadata.is_unicast_response());
        assert!(metadata.validate_group_request().is_clean());
        assert_eq!(metadata.options(), &[unknown]);
    }

    #[test]
    fn ipv6_group_response_matches_by_token_not_message_id_or_server_address() {
        let request_message = Coap::get()
            .non_confirmable()
            .message_id(0x1111)
            .token(token());
        let response_message = Coap::response(CoapCode::from_parts(2, 30))
            .non_confirmable()
            .message_id(0x9999)
            .token(token())
            .option(CoapOption::new(64_999u16, [0x01]));

        let request = CoapGroupMetadata::ipv6(
            IPV6_CLIENT,
            COAP_ALL_NODES_IPV6_SITE_LOCAL_MULTICAST,
            request_message.clone(),
        );
        let response = CoapGroupMetadata::ipv6(IPV6_SERVER, IPV6_CLIENT, response_message.clone());
        let matched = request.match_response(&response);
        assert!(matched.request_is_group());
        assert!(matched.request_is_non_confirmable());
        assert!(matched.response_is_response());
        assert!(matched.response_is_unicast());
        assert!(matched.address_family_matches());
        assert!(matched.response_destination_matches_request_source());
        assert!(matched.token_matches());
        assert!(matched.is_match());
        assert_ne!(request.message_id(), response.message_id());
        assert!(response.validate_group_response().is_clean());

        let request_packet = coap_ipv6_group_request(
            IPV6_CLIENT,
            COAP_ALL_NODES_IPV6_SITE_LOCAL_MULTICAST,
            request_message,
        );
        let response_packet = coap_ipv6_group_response(IPV6_SERVER, IPV6_CLIENT, response_message);
        assert!(request_packet.compile().is_ok());
        assert!(response_packet.compile().is_ok());
    }

    #[test]
    fn validation_reports_multicast_type_and_known_option_constraints() {
        let malformed = Coap::get()
            .confirmable()
            .message_id(7)
            .token(token())
            .option(CoapOption::new(COAP_OPTION_ETAG, [0x01]))
            .option(CoapOption::new(COAP_OPTION_OBSERVE, []))
            .option(CoapOption::new(65_000u16, [0xff]));
        let metadata =
            CoapGroupMetadata::ipv4(IPV4_CLIENT, COAP_ALL_NODES_IPV4_MULTICAST, malformed);
        let validation = metadata.validate_group_request();
        let fields = validation
            .issues()
            .iter()
            .map(|issue| issue.field())
            .collect::<Vec<_>>();
        assert!(fields.contains(&"coap.group.request.type"));
        assert!(fields.contains(&"coap.group.request.options.etag"));
        assert!(fields.contains(&"coap.group.request.options.observe"));
        assert!(!fields.iter().any(|field| field.contains("65000")));
        assert!(validation.has_errors());

        let wrong_destination =
            CoapGroupMetadata::ipv4(IPV4_CLIENT, IPV4_SERVER, Coap::get().non_confirmable());
        assert!(wrong_destination
            .validate_group_request()
            .issues()
            .iter()
            .any(|issue| issue.field() == "coap.group.request.destination"));
    }

    #[test]
    fn group_response_validation_distinguishes_confirmable_and_ack_shapes() {
        let confirmable = CoapGroupMetadata::ipv4(
            IPV4_SERVER,
            IPV4_CLIENT,
            Coap::content().confirmable().token(token()),
        );
        let warning = confirmable.validate_group_response();
        assert!(!warning.has_errors());
        assert_eq!(warning.len(), 1);
        assert_eq!(
            warning.issues()[0].severity(),
            CoapValidationSeverity::Warning
        );

        let acknowledgement = CoapGroupMetadata::ipv4(
            IPV4_SERVER,
            IPV4_CLIENT,
            Coap::content().acknowledgement().token(token()),
        );
        assert!(acknowledgement.validate_group_response().has_errors());

        let multicast_response = CoapGroupMetadata::ipv4(
            IPV4_SERVER,
            COAP_ALL_NODES_IPV4_MULTICAST,
            Coap::content().non_confirmable().token(token()),
        );
        assert!(multicast_response.validate_group_response().has_errors());

        let request = CoapGroupMetadata::ipv4(
            IPV4_CLIENT,
            COAP_ALL_NODES_IPV4_MULTICAST,
            Coap::get().non_confirmable().token(token()),
        );
        let mismatched = CoapGroupMetadata::ipv4(
            IPV4_SERVER,
            IPV4_CLIENT,
            Coap::content()
                .non_confirmable()
                .token(CoapToken::from_bytes([0xff])),
        );
        let result = request.match_response(&mismatched);
        assert!(!result.token_matches());
        assert!(!result.is_match());
    }

    #[test]
    fn ipv4_group_response_helper_keeps_caller_supplied_documentation_addresses() {
        let message = Coap::content()
            .non_confirmable()
            .content_format(CoapContentFormat::coap_group_json())
            .payload(br#"{"n":"group"}"#.to_vec());
        let packet = coap_ipv4_group_response(IPV4_SERVER, IPV4_CLIENT, message.clone());
        let ipv4 = packet.layer::<Ipv4>().expect("IPv4 layer");
        let udp = packet.layer::<Udp>().expect("UDP layer");
        assert_eq!(ipv4.source(), IPV4_SERVER);
        assert_eq!(ipv4.destination(), IPV4_CLIENT);
        assert_eq!(udp.source_port_value(), 5683);
        assert_eq!(packet.layer::<Coap>(), Some(&message));
        assert!(packet.compile().is_ok());

        let metadata = CoapGroupMetadata::ipv4(IPV4_SERVER, IPV4_CLIENT, message);
        let format = metadata.content_format().unwrap().unwrap();
        assert_eq!(format.value(), COAP_CONTENT_FORMAT_GROUP_JSON);
    }
}
