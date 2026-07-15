//! Constrained Application Protocol (CoAP) packet primitives.
//!
//! Wire behavior in this module is sourced through the evidence manifest at
//! `.agents/docs/coap-rfc-manifest.md`. This namespace is limited to typed,
//! inspectable packet layers and stateless wire transforms; client/server
//! runtimes, transaction state, and transport stream reassembly are outside
//! its scope.

mod block;
mod constants;
mod decode;
mod group;
mod hop_limit;
mod link_format;
mod message;
mod no_response;
mod observe;
mod option;
mod oscore;
mod registry;
mod reliable;

pub use self::block::{CoapBlock, CoapBlockKind, CoapBlockTransport, CoapBlockValidation};
pub(crate) use self::constants::COAP_UDP_PORT;
pub use self::constants::{
    COAPS_PORT, COAP_CODE_CLASS_MASK, COAP_CODE_CLASS_SHIFT, COAP_CODE_DETAIL_MASK,
    COAP_CONTENT_FORMAT_LINK_FORMAT, COAP_HEADER_LEN, COAP_MAX_TOKEN_LEN, COAP_OPTION_ACCEPT,
    COAP_OPTION_BLOCK1, COAP_OPTION_BLOCK2, COAP_OPTION_CONTENT_FORMAT, COAP_OPTION_ECHO,
    COAP_OPTION_ETAG, COAP_OPTION_HOP_LIMIT, COAP_OPTION_IF_MATCH, COAP_OPTION_IF_NONE_MATCH,
    COAP_OPTION_LOCATION_PATH, COAP_OPTION_LOCATION_QUERY, COAP_OPTION_MAX_AGE,
    COAP_OPTION_NO_RESPONSE, COAP_OPTION_OBSERVE, COAP_OPTION_OSCORE, COAP_OPTION_PROXY_SCHEME,
    COAP_OPTION_PROXY_URI, COAP_OPTION_Q_BLOCK1, COAP_OPTION_Q_BLOCK2, COAP_OPTION_REQUEST_TAG,
    COAP_OPTION_SIZE1, COAP_OPTION_SIZE2, COAP_OPTION_URI_HOST, COAP_OPTION_URI_PATH,
    COAP_OPTION_URI_PORT, COAP_OPTION_URI_QUERY, COAP_PAYLOAD_MARKER, COAP_PORT, COAP_TKL_MASK,
    COAP_TYPE_MASK, COAP_TYPE_SHIFT, COAP_VERSION_1, COAP_VERSION_MASK, COAP_VERSION_SHIFT,
};
pub use self::decode::decode_coap;
pub(crate) use self::decode::{append_coap_packet, looks_like_coap_payload};
pub use self::hop_limit::{CoapHopLimit, CoapHopLimitExhausted};
pub use self::link_format::{
    coap_discovery_response, CoapLink, CoapLinkAttribute, CoapLinkAttributeValue, CoapLinkFormat,
};
pub use self::message::{
    coap_discovery_request, coap_ipv4_request, coap_ipv4_response, coap_ipv6_request,
    coap_ipv6_response, coap_request_udp, coap_response_udp, Coap, CoapCode, CoapMessageType,
    CoapOptionOrder, CoapPayloadMarker, CoapToken, CoapTokenLength, CoapValidation,
    CoapValidationCategory, CoapValidationIssue, CoapValidationSeverity, CoapVersion,
};
pub use self::no_response::CoapNoResponse;
pub use self::observe::{CoapObserve, CoapObserveOrdering};
pub use self::option::{
    validate_coap_proxy_options, CoapAccept, CoapContentFormat, CoapEtag, CoapIfMatch,
    CoapIfNoneMatch, CoapLocationPath, CoapLocationQuery, CoapMaxAge, CoapOption,
    CoapOptionEncoding, CoapOptionFormat, CoapOptionNumber, CoapProxyScheme, CoapProxyUri,
    CoapSize1, CoapSize2, CoapUriHost, CoapUriPath, CoapUriPort, CoapUriQuery,
};
pub use self::registry::{
    coap_code_meta, coap_content_format_meta, coap_option_meta, coap_signaling_code_meta,
    coap_signaling_option_meta, CoapRegistryMeta, CoapRegistryStatus,
};

#[cfg(test)]
mod tests {
    #[test]
    fn namespace_compiles() {
        assert!(module_path!().contains("protocols::coap"));
    }
}
