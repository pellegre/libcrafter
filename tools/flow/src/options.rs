//! Per-run options for flow execution.

use std::time::Duration;

use crate::{Binding, Bound};

/// Bounded repeat policy for each outgoing packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendRepeat {
    count: u32,
    interval: Duration,
}

impl SendRepeat {
    /// Create a repeat policy with at least one send.
    pub fn new(count: u32, interval: Duration) -> Self {
        Self {
            count: count.max(1),
            interval,
        }
    }

    /// Number of copies to send for each outgoing packet.
    pub const fn count(self) -> u32 {
        self.count
    }

    /// Delay between repeated copies.
    pub const fn interval(self) -> Duration {
        self.interval
    }
}

impl Default for SendRepeat {
    fn default() -> Self {
        Self::new(1, Duration::ZERO)
    }
}

/// Bundles the binding, loop bound, timeout, and retry knobs for one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub binding: Binding,
    pub bound: Bound,
    pub step_timeout: Duration,
    pub run_timeout: Option<Duration>,
    pub send_repeat: SendRepeat,
    pub retries: u32,
    pub capture_filter: Option<String>,
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

    /// Set an optional deadline for the whole run.
    pub fn run_timeout(mut self, run_timeout: Duration) -> Self {
        self.run_timeout = Some(run_timeout);
        self
    }

    /// Set the repeat policy used for every outgoing packet.
    pub fn send_repeat(mut self, count: u32, interval: Duration) -> Self {
        self.send_repeat = SendRepeat::new(count, interval);
        self
    }

    /// Set the number of retry attempts.
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Set the live capture BPF filter.
    ///
    /// Empty and whitespace-only filters clear the filter so callers can pass
    /// the result of advisory filter derivation directly.
    pub fn capture_filter(mut self, capture_filter: impl Into<String>) -> Self {
        let capture_filter = capture_filter.into();
        self.capture_filter = normalize_capture_filter(&capture_filter);
        self
    }

    /// Clear any configured live capture BPF filter.
    pub fn clear_capture_filter(mut self) -> Self {
        self.capture_filter = None;
        self
    }
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            binding: Binding::default(),
            bound: Bound::default(),
            step_timeout: Duration::from_millis(250),
            run_timeout: None,
            send_repeat: SendRepeat::default(),
            retries: 1,
            capture_filter: None,
        }
    }
}

fn normalize_capture_filter(capture_filter: &str) -> Option<String> {
    let capture_filter = capture_filter.trim();
    if capture_filter.is_empty() {
        None
    } else {
        Some(capture_filter.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{RunOptions, SendRepeat};
    use crate::{Binding, Bound};
    use std::time::Duration;

    #[test]
    fn run_options_defaults_are_safe_and_bounded() {
        let options = RunOptions::default();

        assert_eq!(options.binding, Binding::default());
        assert_eq!(options.bound, Bound::default());
        assert_eq!(options.step_timeout, Duration::from_millis(250));
        assert_eq!(options.run_timeout, None);
        assert_eq!(options.send_repeat, SendRepeat::default());
        assert_eq!(options.retries, 1);
        assert_eq!(options.capture_filter, None);
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
    fn run_options_builder_updates_run_timeout() {
        let timeout = Duration::from_secs(2);
        let options = RunOptions::default().run_timeout(timeout);

        assert_eq!(options.run_timeout, Some(timeout));
    }

    #[test]
    fn run_options_builder_updates_send_repeat() {
        let interval = Duration::from_millis(25);
        let options = RunOptions::default().send_repeat(3, interval);

        assert_eq!(options.send_repeat.count(), 3);
        assert_eq!(options.send_repeat.interval(), interval);
    }

    #[test]
    fn send_repeat_keeps_at_least_one_copy() {
        let repeat = SendRepeat::new(0, Duration::from_millis(1));

        assert_eq!(repeat.count(), 1);
    }

    #[test]
    fn run_options_builder_updates_retries() {
        let options = RunOptions::default().retries(3);

        assert_eq!(options.retries, 3);
    }

    #[test]
    fn run_options_builder_updates_capture_filter() {
        let options = RunOptions::default().capture_filter(" arp ");

        assert_eq!(options.capture_filter.as_deref(), Some("arp"));
    }

    #[test]
    fn run_options_empty_capture_filter_clears_filter() {
        let options = RunOptions::default()
            .capture_filter("arp")
            .capture_filter("   ");

        assert_eq!(options.capture_filter, None);
    }
}
