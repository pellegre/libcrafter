//! Loop bounds for protocol flows.

use std::time::Duration;

/// Controls how long a looping flow may continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// Stop after the given number of completed iterations.
    Count(u64),
    /// Stop once the given elapsed duration has been reached.
    Duration(Duration),
    /// Continue without a built-in limit.
    ///
    /// This is an explicit opt-in. Flows that can exhaust a peer resource must
    /// not use an unbounded run by default.
    Unbounded,
}

impl Bound {
    /// Returns whether a flow should continue for the current progress.
    pub fn should_continue(&self, iterations: u64, elapsed: Duration) -> bool {
        match self {
            Self::Count(limit) => iterations < *limit,
            Self::Duration(limit) => elapsed < *limit,
            Self::Unbounded => true,
        }
    }
}

impl Default for Bound {
    fn default() -> Self {
        Self::Count(1)
    }
}

#[cfg(test)]
mod tests {
    use super::Bound;
    use std::time::Duration;

    #[test]
    fn bound_default_is_single_count() {
        assert_eq!(Bound::default(), Bound::Count(1));
    }

    #[test]
    fn bound_count_stops_before_fourth_iteration() {
        let bound = Bound::Count(3);

        assert!(bound.should_continue(0, Duration::ZERO));
        assert!(bound.should_continue(1, Duration::ZERO));
        assert!(bound.should_continue(2, Duration::ZERO));
        assert!(!bound.should_continue(3, Duration::ZERO));
    }

    #[test]
    fn bound_unbounded_never_stops_on_count() {
        let bound = Bound::Unbounded;

        assert!(bound.should_continue(0, Duration::ZERO));
        assert!(bound.should_continue(u64::MAX, Duration::MAX));
    }
}
