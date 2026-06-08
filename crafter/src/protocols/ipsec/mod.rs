//! IPSec (RFC 4301/4302/4303/7296) packet support.
//!
//! This module hosts the IPSec wire-level layers — Encapsulating Security
//! Payload (ESP, RFC 4303), Authentication Header (AH, RFC 4302), and the
//! IKEv2 message/payload wire format (RFC 7296) — along with the
//! `SecurityAssociation` per-packet crypto context and the cryptographic
//! transforms that drive ESP/AH/SK confidentiality and integrity.
//!
//! The submodule tree is established here; the typed layers, builders, and
//! decoders are filled in by later steps. Nothing is publicly re-exported yet.

pub mod ah;
pub mod crypto;
pub mod esp;
pub mod ikev2;
pub mod sa;
