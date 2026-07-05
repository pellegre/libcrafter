//! Common imports for flow tools.
//!
//! Later engine types (`Binding`, `Bound`, `PacketContext`, `Matcher`,
//! `Transition`, `FlowState`, `Flow`, `Runner`, and `FlowReport`) are added here
//! as they are implemented.
//!
//! ```
//! use crafter_flow::prelude::*;
//!
//! let error = FlowError::Unsupported("pending engine type".to_string());
//! assert!(error.to_string().contains("unsupported flow feature"));
//! ```

pub use crate::error::{FlowError, Result};
pub use crate::docaddr;
pub use crate::Role;

#[cfg(test)]
mod tests {
    use crate as crafter_flow;

    #[test]
    fn prelude_exports_flow_error() {
        use crafter_flow::prelude::*;

        let error = FlowError::Unsupported("pending engine type".to_string());
        assert!(error.to_string().contains("unsupported flow feature"));
    }
}
