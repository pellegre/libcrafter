//! IEEE 802.11 MAC layer scaffolding.

mod a_control;
mod codec;
mod constants;
mod element;
mod fixed_fields;
mod frame_control;
mod frame_type;
mod header;
mod labels;
mod layer;
mod qos_control;
mod sequence_control;
mod subtype;
mod trigger;
mod util;

pub use self::a_control::Dot11TrsControl;
pub(crate) use self::codec::decode_dot11_with_registry;
pub(crate) use self::codec::decode_dot11_with_registry_fcs;
use self::codec::{read_mac_at, read_u16_le_at};
pub use self::constants::*;
pub use self::element::Dot11TaggedParameter;
pub use self::fixed_fields::{
    Dot11ActionFixedFields, Dot11AssociationRequestFixedFields,
    Dot11AssociationResponseFixedFields, Dot11AuthenticationFixedFields, Dot11BeaconFixedFields,
    Dot11ManagementFixedFields, Dot11ReasonCodeFixedFields, Dot11ReassociationRequestFixedFields,
};
pub use self::frame_control::Dot11FrameControl;
pub use self::frame_type::Dot11FrameType;
pub use self::labels::*;
pub use self::layer::Dot11;
pub use self::qos_control::Dot11QosControl;
pub use self::sequence_control::Dot11SequenceControl;
pub use self::subtype::{Dot11ControlSubtype, Dot11DataSubtype, Dot11ManagementSubtype};
pub use self::trigger::{
    Dot11Trigger, Dot11TriggerCommonFields, Dot11TriggerRemainder, Dot11TriggerUser,
    Dot11TriggerUserFields,
};

#[cfg(test)]
mod tests;
