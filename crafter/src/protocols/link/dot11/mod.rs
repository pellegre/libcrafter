//! IEEE 802.11 MAC layer scaffolding.

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
mod util;

pub(crate) use self::codec::decode_dot11_with_registry;
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

#[cfg(test)]
mod tests;
