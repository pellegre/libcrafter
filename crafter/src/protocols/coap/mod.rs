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
mod link_format;
mod message;
mod observe;
mod option;
mod oscore;
mod registry;
mod reliable;

pub(crate) use self::constants::COAP_UDP_PORT;
pub use self::decode::decode_coap;
pub(crate) use self::decode::{append_coap_packet, looks_like_coap_payload};

#[cfg(test)]
pub(crate) use self::message::Coap;

#[cfg(test)]
mod tests {
    #[test]
    fn namespace_compiles() {
        assert!(module_path!().contains("protocols::coap"));
    }
}
