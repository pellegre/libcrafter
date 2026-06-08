//! Internet Key Exchange v2 (IKEv2, RFC 7296) message wire format.
//!
//! The IKE header, the generic-payload chain, the standard payload set
//! (including the Encrypted/SK payload), and the header + payload-chain
//! decode path are added by later steps. This is message and payload wire
//! format only — round-trip construction and decoding, not a negotiation
//! state machine.

pub mod payload;
