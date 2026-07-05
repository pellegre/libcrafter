//! Flow runner ownership scaffold.

use crate::{Binding, CaptureSource, Conversation, MemoryCaptureSource, Result, RunOptions};

/// Owns the run options and single conversation for one flow run.
pub struct Runner {
    options: RunOptions,
    conversation: Conversation,
}

impl Runner {
    /// Create a runner from a binding and default run options.
    pub fn bind(binding: Binding) -> Result<Self> {
        Self::with_options(RunOptions::default().binding(binding))
    }

    /// Create a runner using an empty offline capture source.
    pub fn with_options(options: RunOptions) -> Result<Self> {
        Self::with_source(options, MemoryCaptureSource::default())
    }

    /// Create a runner with an injected capture source.
    pub fn with_source<S>(options: RunOptions, source: S) -> Result<Self>
    where
        S: CaptureSource + 'static,
    {
        let conversation = Conversation::open_with_source(&options.binding, source)?;

        Ok(Self {
            options,
            conversation,
        })
    }

    /// Borrow the options used to construct this runner.
    pub const fn options(&self) -> &RunOptions {
        &self.options
    }

    /// Returns true when this runner was opened for offline dry-run operation.
    pub fn is_dry_run(&self) -> bool {
        self.conversation.is_dry_run()
    }
}

#[cfg(test)]
mod tests {
    use super::Runner;
    use crate::{Binding, MemoryCaptureSource, RunOptions};

    #[test]
    fn runner_bind_default_succeeds_and_reports_dry_run() {
        let runner = Runner::bind(Binding::default()).expect("runner binds default dry-run");

        assert!(runner.is_dry_run());
        assert_eq!(runner.options().binding, Binding::default());
    }

    #[test]
    fn runner_with_source_accepts_injected_capture_source() {
        let packet = crafter::Packet::decode_raw([0xde, 0xad]).expect("raw packet decodes");
        let options = RunOptions::default();
        let runner = Runner::with_source(options.clone(), MemoryCaptureSource::new(vec![packet]))
            .expect("runner opens with injected source");

        assert!(runner.is_dry_run());
        assert_eq!(runner.options(), &options);
    }
}
