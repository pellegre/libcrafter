//! Simple Service Discovery Protocol (SSDP) packet primitives.
//!
//! SSDP support is source-gated by `.agents/docs/ssdp-source-manifest.md`,
//! `.agents/docs/ssdp-wire-grammar.md`, `.agents/docs/ssdp-codepoints.md`, and
//! `.agents/docs/ssdp-api-design.md`. It provides typed messages, HTTP-like
//! header handling, conservative decoding, registry metadata, and packet
//! composition without introducing a discovery workflow.

mod constants;
pub(crate) mod decode;
mod header;
mod message;
mod registry;

pub use constants::*;
pub use decode::{SsdpParseError, SsdpParseErrorKind, SsdpParseField};
pub use header::{
    SsdpHeader, SsdpHeaderField, SsdpHeaderName, SsdpHeaderNameKind, SsdpHeaderNameParseError,
    SsdpHeaderValue, SsdpHeaders,
};
pub use message::{
    Ssdp, SsdpCacheControl, SsdpLocation, SsdpLocationField, SsdpLocationParseError, SsdpMessage,
    SsdpMethod, SsdpMethodParseError, SsdpReasonPhrase, SsdpRequestLine, SsdpRequestTarget,
    SsdpStartLine, SsdpStartLineField, SsdpStartLineParseError, SsdpStatusCode, SsdpStatusLine,
    SsdpTarget, SsdpUsn, SsdpVersion,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_module_scaffold_names_core_files() {
        let modules = ["constants", "decode", "header", "message", "registry"];
        assert_eq!(modules.len(), 5);
    }

    #[test]
    fn ssdp_public_api_exports_module_surface() {
        fn assert_layer<T: crate::Layer>() {}
        assert_layer::<Ssdp>();

        let message = Ssdp::m_search()
            .with_raw_header(SSDP_HEADER_HOST, SSDP_IPV4_MULTICAST_HOST)
            .expect("HOST header is valid")
            .with_raw_header(SSDP_HEADER_ST, SSDP_ST_ALL)
            .expect("ST header is valid")
            .into_message();
        let headers = message.headers();

        assert_eq!(SSDP_SERVICE_NAME, "ssdp");
        assert_eq!(SSDP_UDP_PORT, 1_900);
        assert_eq!(
            headers
                .get_first(SsdpHeaderNameKind::St)
                .expect("ST value")
                .as_bytes(),
            SSDP_ST_ALL.as_bytes()
        );
        assert!(matches!(
            message.start_line(),
            SsdpStartLine::Request(SsdpRequestLine { .. })
        ));
    }

    #[test]
    fn ssdp_public_api_exports_crate_root_core_and_prelude() {
        fn assert_layer<T: crate::Layer>() {}
        assert_layer::<crate::Ssdp>();
        assert_layer::<crate::core::Ssdp>();
        assert_layer::<crate::prelude::Ssdp>();

        let root_message = crate::Ssdp::notify()
            .with_raw_header(crate::SSDP_HEADER_NT, crate::SSDP_TARGET_ROOTDEVICE)
            .expect("NT header is valid");
        let core_message = crate::core::Ssdp::response_ok()
            .with_raw_header(crate::core::SSDP_HEADER_EXT, "")
            .expect("EXT header is valid");
        let prelude_message = crate::prelude::Ssdp::m_search()
            .with_raw_header(
                crate::prelude::SSDP_HEADER_MAN,
                crate::prelude::SSDP_MAN_DISCOVER,
            )
            .expect("MAN header is valid");

        assert_eq!(crate::SSDP_METHOD_NOTIFY, "NOTIFY");
        assert_eq!(crate::core::SSDP_HTTP_VERSION, "HTTP/1.1");
        assert_eq!(crate::prelude::SSDP_STATUS_OK, 200);
        assert_eq!(root_message.headers().len(), 1);
        assert_eq!(core_message.headers().len(), 1);
        assert_eq!(prelude_message.headers().len(), 1);
    }
}
