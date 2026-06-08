//! Encapsulating Security Payload (ESP, RFC 4303).
//!
//! The `Esp` layer and its builder, the SPI/sequence header and encrypted
//! trailer model, and the opaque/SA-driven decode path are added by later
//! steps. ESP composes with `/` over IPv4 and IPv6 (IP protocol 50).
