//! Shared transport protocol helpers.

use crate::error::Result;
use crate::field::Field;
use crate::packet::{LayerContext, TransportChecksumContext};

macro_rules! impl_layer_object {
    ($type:ty) => {
        fn clone_layer(&self) -> Box<dyn $crate::packet::Layer> {
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

macro_rules! impl_layer_div {
    ($type:ty) => {
        impl<R> core::ops::Div<R> for $type
        where
            R: $crate::packet::IntoPacket,
        {
            type Output = $crate::packet::Packet;

            fn div(self, rhs: R) -> Self::Output {
                $crate::packet::Packet::from_layer(self).concat(rhs)
            }
        }
    };
}

pub(crate) use impl_layer_div;
pub(crate) use impl_layer_object;

pub(crate) fn payload_bytes_after(ctx: LayerContext<'_>) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for (index, layer) in ctx.packet().iter().enumerate().skip(ctx.index() + 1) {
        let layer_ctx = LayerContext::new(ctx.packet(), index);
        layer.compile(&layer_ctx, &mut payload)?;
    }
    Ok(payload)
}

pub(super) fn transport_checksum_context(
    ctx: LayerContext<'_>,
    transport_protocol: u8,
) -> Option<TransportChecksumContext> {
    (0..ctx.index()).rev().find_map(|index| {
        ctx.packet()
            .get(index)
            .and_then(|layer| layer.transport_checksum_context(transport_protocol))
    })
}

pub(super) fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}
