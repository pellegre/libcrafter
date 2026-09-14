//! EHT PHY signaling defined by IEEE 802.11be.
//! Source and edition limitations: docs/wifi-phy-evidence.json.

pub(in crate::radio) mod iq;
mod sig;
#[cfg(test)]
mod test_support;
mod usig;

pub(in crate::radio) use sig::iq::{Error as SignalIqError, Receiver as SignalReceiver};
pub use sig::{
    EhtLtfMode, EhtMuMimoUser, EhtNonMuUser, EhtNonOfdmaCommon, EhtNonOfdmaSignal,
    EhtNonOfdmaUsers, EhtOfdmaCommon, EhtOfdmaSignal, EhtOfdmaUser, EhtOfdmaUserKind,
    EhtRuAllocation20, EhtSigError,
};
pub use usig::{
    EhtMuPpduType, EhtMuUsigFields, EhtSigMcs, EhtTbUsigFields, EhtUsigError, EhtUsigFields,
    EhtUsigFormat,
};
