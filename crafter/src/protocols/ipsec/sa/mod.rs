//! IPSec Security Association.
//!
//! A lightweight per-packet crypto context carrying the SPI, mode,
//! encryption/integrity algorithms, keys, salt, and ESN flag that drive
//! ESP/AH and IKEv2 SK crypto. It is not a policy database (SAD/SPD).
//! The `SecurityAssociation` value type, algorithm enums, and the
//! seal/open crypto driver are added by later steps.
