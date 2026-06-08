//! Authentication Header (AH, RFC 4302).
//!
//! The `Ah` layer and its builder, the header/payload-length model, the
//! immutable-field canonicalization used to compute the ICV (IPv4 and IPv6),
//! and the opaque/SA-driven verify decode path are added by later steps. AH
//! composes with `/` over IPv4 and IPv6 (IP protocol 51).
