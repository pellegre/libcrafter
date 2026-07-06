//! Outgoing packet mutation hooks for repeated flow iterations.

use crate::{PacketContext, Result};

type MutateFn = dyn FnMut(crafter::Packet, u64, &mut PacketContext) -> Result<crafter::Packet>;

/// Mutates an outgoing packet immediately before the runner sends it.
pub trait Mutator {
    /// Return the packet to send for this iteration.
    fn mutate(
        &mut self,
        packet: crafter::Packet,
        iteration: u64,
        ctx: &mut PacketContext,
    ) -> Result<crafter::Packet>;

    /// Human-readable mutator name for reports.
    fn name(&self) -> &str;
}

impl Mutator for Box<dyn Mutator> {
    fn mutate(
        &mut self,
        packet: crafter::Packet,
        iteration: u64,
        ctx: &mut PacketContext,
    ) -> Result<crafter::Packet> {
        self.as_mut().mutate(packet, iteration, ctx)
    }

    fn name(&self) -> &str {
        self.as_ref().name()
    }
}

/// Mutator that leaves outgoing packets unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Identity;

impl Mutator for Identity {
    fn mutate(
        &mut self,
        packet: crafter::Packet,
        _iteration: u64,
        _ctx: &mut PacketContext,
    ) -> Result<crafter::Packet> {
        Ok(packet)
    }

    fn name(&self) -> &str {
        "identity"
    }
}

/// Mutator backed by a caller-provided closure.
pub struct FnMutator {
    name: String,
    mutate: Box<MutateFn>,
}

impl FnMutator {
    /// Create a named mutator from a closure.
    pub fn new(
        name: impl Into<String>,
        mutate: impl FnMut(crafter::Packet, u64, &mut PacketContext) -> Result<crafter::Packet>
            + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            mutate: Box::new(mutate),
        }
    }
}

impl Mutator for FnMutator {
    fn mutate(
        &mut self,
        packet: crafter::Packet,
        iteration: u64,
        ctx: &mut PacketContext,
    ) -> Result<crafter::Packet> {
        (self.mutate)(packet, iteration, ctx)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::{FnMutator, Identity, Mutator};
    use crate::PacketContext;
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn mutator_identity_returns_same_packet_summary() {
        let packet =
            crafter::Packet::decode_raw([0xde, 0xad, 0xbe, 0xef]).expect("raw packet decodes");
        let expected_summary = packet.summary();
        let mut context = PacketContext::new();
        let mut mutator: Box<dyn Mutator> = Box::new(Identity);

        let mutated = mutator
            .mutate(packet, 17, &mut context)
            .expect("identity mutation succeeds");

        assert_eq!(mutator.name(), "identity");
        assert_eq!(mutated.summary(), expected_summary);
    }

    #[test]
    fn mutator_fn_mutator_appends_raw_payload_and_receives_iteration() {
        let seen_iteration = Rc::new(Cell::new(None));
        let seen_iteration_for_mutator = Rc::clone(&seen_iteration);
        let mut context = PacketContext::new();
        let packet = crafter::Packet::decode_raw([0xde]).expect("raw packet decodes");
        let original_summary = packet.summary();
        let mut mutator: Box<dyn Mutator> = Box::new(FnMutator::new(
            "append-iteration-payload",
            move |packet, iteration, ctx| {
                seen_iteration_for_mutator.set(Some(iteration));
                ctx.set_transaction_id(iteration as u32);
                Ok(packet / crafter::Raw::from_bytes([0xca, 0xfe]))
            },
        ));

        let mutated = mutator
            .mutate(packet, 42, &mut context)
            .expect("closure mutation succeeds");

        assert_eq!(mutator.name(), "append-iteration-payload");
        assert_ne!(mutated.summary(), original_summary);
        assert!(mutated.summary().contains("Raw(len=2)"));
        assert_eq!(seen_iteration.get(), Some(42));
        assert_eq!(context.get_transaction_id(), Some(42));
    }
}
