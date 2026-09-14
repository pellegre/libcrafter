//! EHT PHY signaling defined by IEEE 802.11be.
//! Source and edition limitations: docs/wifi-phy-evidence.json.

pub(in crate::radio) mod data;
pub(in crate::radio) mod iq;
mod sig;
pub(in crate::radio) mod tb;
#[cfg(test)]
mod test_support;
pub(in crate::radio) mod training;
mod usig;

pub(in crate::radio) use sig::iq::{
    Error as SignalIqError, Fields as ReceivedSignal, Receiver as SignalReceiver, SignalFields,
};
pub use sig::{
    EhtLtfMode, EhtMuMimoUser, EhtNonMuUser, EhtNonOfdmaCommon, EhtNonOfdmaSignal,
    EhtNonOfdmaUsers, EhtOfdmaCommon, EhtOfdmaSignal, EhtOfdmaUser, EhtOfdmaUserKind,
    EhtResourceUnit, EhtRuAllocation20, EhtRuComponent, EhtRuSize, EhtSigError,
};
pub use usig::{
    EhtMuPpduType, EhtMuUsigFields, EhtSigMcs, EhtTbUsigFields, EhtUsigError, EhtUsigFields,
    EhtUsigFormat,
};
