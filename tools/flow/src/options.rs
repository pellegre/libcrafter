//! Per-run options for flow execution.

use std::time::Duration;

use crate::{Binding, Bound};

/// Bundles the binding, loop bound, timeout, and retry knobs for one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub binding: Binding,
    pub bound: Bound,
    pub step_timeout: Duration,
    pub retries: u32,
}

impl RunOptions {
    /// Set the execution binding.
    pub fn binding(mut self, binding: Binding) -> Self {
        self.binding = binding;
        self
    }

    /// Set the loop bound.
    pub fn bound(mut self, bound: Bound) -> Self {
        self.bound = bound;
        self
    }

    /// Set the timeout used for each receive step.
    pub fn step_timeout(mut self, step_timeout: Duration) -> Self {
        self.step_timeout = step_timeout;
        self
    }

    /// Set the number of retry attempts.
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            binding: Binding::default(),
            bound: Bound::default(),
            step_timeout: Duration::from_millis(250),
            retries: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RunOptions;
    use crate::{Binding, Bound};
    use std::time::Duration;

    #[test]
    fn run_options_defaults_are_safe_and_bounded() {
        let options = RunOptions::default();

        assert_eq!(options.binding, Binding::default());
        assert_eq!(options.bound, Bound::default());
        assert_eq!(options.step_timeout, Duration::from_millis(250));
        assert_eq!(options.retries, 1);
    }

    #[test]
    fn run_options_builder_updates_binding() {
        let binding = Binding::interface("eth0").live().link_layer();
        let options = RunOptions::default().binding(binding.clone());

        assert_eq!(options.binding, binding);
    }

    #[test]
    fn run_options_builder_updates_bound() {
        let bound = Bound::Duration(Duration::from_secs(2));
        let options = RunOptions::default().bound(bound);

        assert_eq!(options.bound, bound);
    }

    #[test]
    fn run_options_builder_updates_step_timeout() {
        let timeout = Duration::from_millis(75);
        let options = RunOptions::default().step_timeout(timeout);

        assert_eq!(options.step_timeout, timeout);
    }

    #[test]
    fn run_options_builder_updates_retries() {
        let options = RunOptions::default().retries(3);

        assert_eq!(options.retries, 3);
    }
}
