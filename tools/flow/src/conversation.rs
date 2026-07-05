//! Persistent send and receive position for one flow run.

use crafter::net::PacketSender;

use crate::{Binding, CaptureSource, FlowError, MemoryCaptureSource, Result};

/// A single flow execution position with one send half and one capture source.
pub struct Conversation {
    binding: Binding,
    sender: Option<PacketSender>,
    source: Box<dyn CaptureSource>,
}

impl Conversation {
    /// Open a conversation for the binding using an empty offline capture source.
    pub fn open(binding: &Binding) -> Result<Self> {
        Self::open_with_source(binding, MemoryCaptureSource::default())
    }

    /// Open a conversation for the binding using the provided capture source.
    pub fn open_with_source<S>(binding: &Binding, source: S) -> Result<Self>
    where
        S: CaptureSource + 'static,
    {
        let sender = if binding.is_live() {
            Some(
                PacketSender::open(binding.send_options())
                    .map_err(|error| FlowError::Send(error.to_string()))?,
            )
        } else {
            None
        };

        Ok(Self {
            binding: binding.clone(),
            sender,
            source: Box::new(source),
        })
    }

    /// Returns true when this conversation is offline and holds no live sender.
    pub fn is_dry_run(&self) -> bool {
        self.binding.is_dry_run()
    }

    /// Borrow the binding used to open this conversation.
    pub const fn binding(&self) -> &Binding {
        &self.binding
    }

    /// Return an inspectable one-line description of this conversation.
    pub fn describe(&self) -> String {
        let sender = if self.sender.is_some() {
            "open sender"
        } else {
            "no sender"
        };

        format!(
            "Conversation({:?}, {:?}, {:?}, {}, {})",
            self.binding.mode(),
            self.binding.target(),
            self.binding.send_class(),
            sender,
            self.source.describe()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Conversation;
    use crate::{Binding, MemoryCaptureSource};
    use std::time::Duration;

    fn raw_packet(bytes: impl AsRef<[u8]>) -> crafter::Packet {
        crafter::Packet::decode_raw(bytes).expect("raw packet decodes")
    }

    #[test]
    fn conversation_open_default_is_dry_run_without_sender() {
        let binding = Binding::default();
        let conversation = Conversation::open(&binding).expect("dry-run conversation opens");

        assert!(conversation.is_dry_run());
        assert_eq!(conversation.binding(), &binding);
        assert!(conversation.sender.is_none());
        assert!(conversation.describe().contains("DryRun"));
        assert!(conversation.describe().contains("no sender"));
    }

    #[test]
    fn conversation_open_with_source_accepts_memory_capture_source() {
        let binding = Binding::default();
        let packet = raw_packet([0xde, 0xad]);
        let mut conversation =
            Conversation::open_with_source(&binding, MemoryCaptureSource::new(vec![packet]))
                .expect("conversation opens with injected source");

        assert!(conversation.is_dry_run());
        assert!(conversation.sender.is_none());
        assert!(conversation.describe().contains("memory capture source"));
        assert!(conversation
            .source
            .next_packet(Duration::from_millis(1))
            .expect("capture succeeds")
            .is_some());
    }
}
