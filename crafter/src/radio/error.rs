use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RadioError {
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    Limit {
        context: &'static str,
        limit: u64,
        actual: u64,
    },
    Overflow {
        context: &'static str,
    },
    Source(String),
}

impl fmt::Display for RadioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RadioError {}

pub type RadioResult<T> = Result<T, RadioError>;
