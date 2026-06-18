//! OSPFv2 packet bodies (RFC 2328 §A.3).
//!
//! The five OSPFv2 packet types (Hello, Database Description, Link State
//! Request, Link State Update, Link State Acknowledgment) follow the shared
//! 24-octet common header. Each body lives inside the [`Ospfv2`](super::Ospfv2)
//! layer as an [`OspfBody`](super::OspfBody) variant (BGP-style enum bodies)
//! rather than as a separate [`Layer`](crate::packet::Layer); the body struct
//! provides `encoded_len()`/`encode()` that the layer's `compile()` routes to.
//!
//! This block adds the Hello body ([`OspfHello`], RFC 2328 §A.3.2) and the
//! Database Description body ([`OspfDatabaseDescription`], RFC 2328 §A.3.3);
//! the other bodies are added by subsequent steps.

pub mod database_description;
pub mod hello;

pub use database_description::OspfDatabaseDescription;
pub use hello::OspfHello;
