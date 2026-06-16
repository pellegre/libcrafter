//! RIP message-level types.
//!
//! The first octet of every RIP message is the command (RFC 1058 §3.1),
//! extended by the demand/triggered-RIP commands of RFC 2091 §3.2. This module
//! models that octet as the [`RipCommand`] enum, which maps to and from the
//! wire value while preserving any unrecognized command as `Other(code)` rather
//! than rejecting or rewriting it, consistent with the crate's
//! preserve-don't-reject policy for unknown codepoints.

use super::registry::rip_command_name;

/// A RIP message command (the first header octet).
///
/// Source: RFC 1058 §3.1 (1 Request, 2 Response) and RFC 2091 §3.2
/// (9 Update Request, 10 Update Response, 11 Update Acknowledge). Any other
/// command value is preserved verbatim as [`RipCommand::Other`] so unknown
/// commands round-trip instead of being rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RipCommand {
    /// Request (command 1) — ask a neighbor for all or part of its table.
    /// Source: RFC 1058 §3.1.
    Request,
    /// Response (command 2) — carry route entries to a neighbor.
    /// Source: RFC 1058 §3.1.
    Response,
    /// Update Request (command 9) — demand/triggered RIP.
    /// Source: RFC 2091 §3.2.
    UpdateRequest,
    /// Update Response (command 10) — demand/triggered RIP.
    /// Source: RFC 2091 §3.2.
    UpdateResponse,
    /// Update Acknowledge (command 11) — demand/triggered RIP.
    /// Source: RFC 2091 §3.2.
    UpdateAcknowledge,
    /// Any other command value, preserved verbatim.
    Other(u8),
}

impl RipCommand {
    /// Map a wire command octet to a [`RipCommand`].
    ///
    /// Recognizes 1/2 (RFC 1058 §3.1) and 9/10/11 (RFC 2091 §3.2); every other
    /// value is preserved as [`RipCommand::Other`].
    pub const fn from_code(code: u8) -> RipCommand {
        match code {
            1 => RipCommand::Request,
            2 => RipCommand::Response,
            9 => RipCommand::UpdateRequest,
            10 => RipCommand::UpdateResponse,
            11 => RipCommand::UpdateAcknowledge,
            other => RipCommand::Other(other),
        }
    }

    /// The wire command octet for this [`RipCommand`].
    ///
    /// Reverse of [`RipCommand::from_code`]: the named variants map to their
    /// RFC codepoints and [`RipCommand::Other`] returns its preserved value.
    pub const fn code(self) -> u8 {
        match self {
            RipCommand::Request => 1,
            RipCommand::Response => 2,
            RipCommand::UpdateRequest => 9,
            RipCommand::UpdateResponse => 10,
            RipCommand::UpdateAcknowledge => 11,
            RipCommand::Other(code) => code,
        }
    }

    /// Short name for this command.
    ///
    /// Delegates to [`rip_command_name`] for the command's wire codepoint,
    /// falling back to `"Unassigned"` for codes the governing RFCs do not name.
    pub fn name(self) -> &'static str {
        rip_command_name(self.code()).unwrap_or("Unassigned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rip_command_roundtrips_known_and_unknown() {
        // RFC 1058 §3.1 core commands.
        assert_eq!(RipCommand::from_code(1), RipCommand::Request);
        assert_eq!(RipCommand::Request.code(), 1);
        assert_eq!(RipCommand::from_code(2), RipCommand::Response);
        assert_eq!(RipCommand::Response.code(), 2);

        // RFC 2091 §3.2 demand/triggered RIP commands.
        assert_eq!(RipCommand::from_code(9), RipCommand::UpdateRequest);
        assert_eq!(RipCommand::UpdateRequest.code(), 9);
        assert_eq!(RipCommand::from_code(10), RipCommand::UpdateResponse);
        assert_eq!(RipCommand::UpdateResponse.code(), 10);
        assert_eq!(RipCommand::from_code(11), RipCommand::UpdateAcknowledge);
        assert_eq!(RipCommand::UpdateAcknowledge.code(), 11);

        // An unknown command round-trips through Other(code).
        assert_eq!(RipCommand::from_code(200), RipCommand::Other(200));
        assert_eq!(RipCommand::Other(200).code(), 200);
        assert_eq!(
            RipCommand::from_code(RipCommand::Other(200).code()),
            RipCommand::Other(200)
        );

        // Named variants expose their registry names; unknowns fall back.
        assert_eq!(RipCommand::Request.name(), "Request");
        assert_eq!(RipCommand::UpdateAcknowledge.name(), "Update Acknowledge");
        assert_eq!(RipCommand::Other(200).name(), "Unassigned");
    }
}
