//! EHT PHY signaling defined by IEEE 802.11be.
//! Source and edition limitations: docs/wifi-phy-evidence.json.

mod usig;

pub use usig::{
    EhtMuPpduType, EhtMuUsigFields, EhtSigMcs, EhtTbUsigFields, EhtUsigError, EhtUsigFields,
    EhtUsigFormat,
};
