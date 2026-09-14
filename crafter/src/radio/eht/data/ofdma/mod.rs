//! EHT20 downlink OFDMA DATA recovery by independently decodable resource.

mod receiver;
#[cfg(test)]
mod tests;

pub(in crate::radio) use receiver::{Admission, Receiver, Recovered};
