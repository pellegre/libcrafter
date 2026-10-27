//! HT20 receive, transmit, signaling, training, coding, and aggregation.

pub(super) mod ldpc;
pub(super) mod rx;
mod signal;
pub(super) mod stbc;
mod training;
pub(in crate::radio) mod tx;

pub use signal::{HtSignalError, HtSignalFields};
pub use tx::{
    HtCoding, HtFormat, HtGuardInterval, HtMcs, HtSignalBits, HtTransmission, HtTxConfig,
};

pub(in crate::radio) use signal::crc;

pub(super) use signal::{decode_iq, decode_iq_at};
pub(super) use training::{train_single_stream, train_stbc_second};
