//! SCTP protocol implementation.
//!
//! SCTP layers compose with the same packet builder surface as other transports:
//! `Ipv4 / Sctp / ...`, `compile()`, direct L3 decode, `summary()`, and typed
//! layer inspection all stay offline until a caller chooses an explicit live
//! wire path.
//!
//! ```rust
//! use crafter::prelude::*;
//! use std::net::Ipv4Addr;
//!
//! # fn main() -> crafter::Result<()> {
//! let packet = Ipv4::new()
//!     .src(Ipv4Addr::new(192, 0, 2, 94))
//!     .dst(Ipv4Addr::new(198, 51, 100, 94))
//!     / Sctp::data(
//!         0x0102_0394,
//!         1,
//!         1,
//!         SCTP_PPID_WEBRTC_STRING,
//!         b"hello-sctp".to_vec(),
//!     )
//!     .sport(21_094)
//!     .dport(21_095)
//!     .vtag(0x1122_3394);
//!
//! let compiled = packet.compile()?;
//! let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
//! let sctp = decoded.layer::<Sctp>().expect("SCTP layer");
//!
//! assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
//! assert_eq!(sctp.chunk_count(), 1);
//! assert!(decoded.summary().contains("Ipv4("));
//! assert!(decoded.summary().contains("Sctp("));
//! assert!(decoded.summary().contains("chunks=1[DATA]"));
//! # Ok(())
//! # }
//! ```
//!
//! Explicit field overrides survive compilation, including intentionally wrong
//! SCTP checksums for negative testing.
//!
//! ```rust
//! use crafter::prelude::*;
//! use std::net::Ipv4Addr;
//!
//! # fn main() -> crafter::Result<()> {
//! let packet = Ipv4::new()
//!     .src(Ipv4Addr::new(192, 0, 2, 95))
//!     .dst(Ipv4Addr::new(198, 51, 100, 95))
//!     / Sctp::data(0x0102_0395, 2, 1, SCTP_PPID_WEBRTC_STRING, b"override".to_vec())
//!         .sport(21_096)
//!         .dport(21_097)
//!         .vtag(0x1122_3395)
//!         .checksum(0x0102_0304);
//!
//! let compiled = packet.compile()?;
//! let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
//! let sctp = decoded.layer::<Sctp>().expect("SCTP layer");
//!
//! assert_eq!(sctp.checksum_value(), Some(0x0102_0304));
//! assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Invalid);
//! assert!(decoded.summary().contains("checksum=0x01020304"));
//! assert!(decoded.summary().contains("checksum_status=invalid"));
//! # Ok(())
//! # }
//! ```

mod cause;
mod checksum;
mod chunk;
mod constants;
mod decode;
mod packet;
mod parameter;

#[allow(unused_imports)]
pub use self::cause::*;
#[allow(unused_imports)]
pub use self::checksum::SctpChecksumStatus;
#[allow(unused_imports)]
pub(crate) use self::checksum::{sctp_crc32c, sctp_packet_crc32c};
#[allow(unused_imports)]
pub use self::chunk::*;
#[allow(unused_imports)]
pub use self::constants::*;
#[allow(unused_imports)]
pub(crate) use self::decode::append_sctp_packet_with_registry;
#[allow(unused_imports)]
pub use self::decode::{
    looks_like_sctp_payload, looks_like_sctp_udp_encapsulation,
    looks_like_udp_encapsulated_sctp_payload,
};
#[allow(unused_imports)]
pub use self::packet::{sctp_data, sctp_heartbeat, sctp_init, sctp_sack, sctp_shutdown, Sctp};
#[allow(unused_imports)]
pub use self::parameter::*;
