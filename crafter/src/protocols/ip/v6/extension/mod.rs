//! IPv6 extension header layer implementations.

macro_rules! impl_ipv6_extension_layer_object {
    ($type:ty) => {
        fn clone_layer(&self) -> Box<dyn crate::packet::Layer> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn core::any::Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
            self
        }

        fn into_any(self: Box<Self>) -> Box<dyn core::any::Any> {
            self
        }
    };
}

macro_rules! impl_ipv6_extension_layer_div {
    ($type:ty) => {
        impl<R> core::ops::Div<R> for $type
        where
            R: crate::packet::IntoPacket,
        {
            type Output = crate::packet::Packet;

            fn div(self, rhs: R) -> Self::Output {
                crate::packet::Packet::from_layer(self).concat(rhs)
            }
        }
    };
}

mod destination;
mod fragment;
mod hop_by_hop;
mod mobile;
mod routing;
mod segment;

use crate::error::{CrafterError, Result};

use super::constants::{IPV6_EXTENSION_MIN_LEN, IPV6_MAX_HEADER_EXT_LEN};

pub(super) use destination::decode_destination_options_header;
pub(super) use hop_by_hop::decode_hop_by_hop_header;
pub(super) use mobile::decode_mobile_routing_header;

pub use destination::Ipv6DestinationOptionsHeader;
pub use fragment::{Ipv6FragmentHeader, Ipv6FragmentHeaderStatus};
pub use hop_by_hop::Ipv6HopByHopOptionsHeader;
pub use mobile::{Ipv6MobileRoutingHeader, Ipv6MobileRoutingHeaderStatus};
pub use routing::{Ipv6RoutingHeader, Ipv6RoutingTypeStatus};
pub use segment::Ipv6SegmentRoutingHeader;

pub(super) fn decode_extension_total_len(context: &'static str, bytes: &[u8]) -> Result<usize> {
    if bytes.len() < IPV6_EXTENSION_MIN_LEN {
        return Err(CrafterError::buffer_too_short(
            context,
            IPV6_EXTENSION_MIN_LEN,
            bytes.len(),
        ));
    }

    let total_len = IPV6_EXTENSION_MIN_LEN + bytes[1] as usize * 8;
    if bytes.len() < total_len {
        return Err(CrafterError::buffer_too_short(
            context,
            total_len,
            bytes.len(),
        ));
    }
    Ok(total_len)
}

pub(super) fn validate_extension_total_len(field: &'static str, total_len: usize) -> Result<()> {
    if total_len < IPV6_EXTENSION_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            field,
            "IPv6 extension header must be at least 8 bytes",
        ));
    }
    if total_len > IPV6_MAX_HEADER_EXT_LEN {
        return Err(CrafterError::invalid_field_value(
            field,
            "IPv6 extension header length exceeds the 8-bit header length field",
        ));
    }
    if total_len % 8 != 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "IPv6 extension header length must be a multiple of 8 bytes",
        ));
    }
    Ok(())
}

pub(super) fn header_ext_len_from_total(field: &'static str, total_len: usize) -> Result<u8> {
    validate_extension_total_len(field, total_len)?;
    u8::try_from((total_len - IPV6_EXTENSION_MIN_LEN) / 8)
        .map_err(|_| CrafterError::invalid_field_value(field, "header extension length overflow"))
}

pub(super) fn round_up_to_8(len: usize) -> usize {
    (len + 7) & !7
}
