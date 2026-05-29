//! Explicit raw/malformed DHCPv4 construction hooks.
//!
//! The normal [`Dhcp`](super::Dhcp) builder is protocol-correct by default and
//! refuses to compile structurally invalid packets (oversized fixed fields,
//! oversized option payloads, options without an end marker). Generated tools
//! that need to exercise a DHCP stack with deliberately malformed input cannot
//! use that path, so this module exposes a separate, visibly-named builder.
//!
//! [`DhcpMalformed`] emits raw DHCP bytes and bypasses the normal validation in
//! [`Dhcp::compile`](super::Dhcp). Because the type name carries the word
//! "malformed", a caller can never reach this surface by accident: the typed
//! [`Dhcp`](super::Dhcp) builder stays valid by default, and any intentionally
//! invalid packet is opt-in through this API.
//!
//! Source: RFC 2131 section 2 fixed BOOTP header layout (op, htype, hlen, hops,
//! xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr[16], sname[64],
//! file[128]) followed by the 4-byte magic cookie (RFC 2131 section 3) and the
//! options area (RFC 2132). Each malformation knob below names the RFC field or
//! structural rule it violates.

use core::any::Any;
use core::ops::Div;

use crate::error::Result;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::constants::{
    DHCP_CHADDR_LEN, DHCP_FILE_LEN, DHCP_FIXED_HEADER_LEN, DHCP_MAGIC_COOKIE, DHCP_MIN_LEN,
    DHCP_OPTION_END, DHCP_SNAME_LEN,
};
use super::Dhcp;

/// Explicit raw/malformed DHCPv4 byte builder.
///
/// This builder produces raw on-the-wire bytes and intentionally skips the
/// structural validation the normal [`Dhcp`](super::Dhcp) builder enforces. It
/// exists so generated tools can craft invalid packets (bad magic cookie,
/// malformed option lengths, missing end markers, oversized fields) to exercise
/// a peer's parser without weakening the protocol-correct defaults of the typed
/// builder.
///
/// Start from [`DhcpMalformed::from_valid`] with a well-formed [`Dhcp`] and then
/// apply the malformation knobs you need. The resulting bytes can be inspected
/// directly with [`DhcpMalformed::to_bytes`] or composed into a packet stack
/// with `/`; it compiles as an opaque DHCP payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMalformed {
    base: Dhcp,
    magic_cookie_override: Option<u32>,
    raw_chaddr: Option<Vec<u8>>,
    raw_sname: Option<Vec<u8>>,
    raw_file: Option<Vec<u8>>,
    raw_options: Option<Vec<u8>>,
    append_end: bool,
}

impl DhcpMalformed {
    /// Wrap a valid [`Dhcp`] so it can be mutated into a malformed packet.
    ///
    /// The base packet supplies all fixed-field values and options; the
    /// malformation knobs below override individual pieces with raw bytes.
    pub fn from_valid(base: Dhcp) -> Self {
        Self {
            base,
            magic_cookie_override: None,
            raw_chaddr: None,
            raw_sname: None,
            raw_file: None,
            raw_options: None,
            append_end: true,
        }
    }

    /// Start from the default DHCP request fixed header.
    pub fn new() -> Self {
        Self::from_valid(Dhcp::new())
    }

    /// Override the 4-byte magic cookie with an arbitrary value.
    ///
    /// RFC 2131 section 3 fixes the cookie at `0x63825363`; any other value is a
    /// malformed DHCP packet. The normal decoder rejects it as
    /// `dhcp.magic_cookie`.
    pub fn invalid_magic_cookie(mut self, cookie: u32) -> Self {
        self.magic_cookie_override = Some(cookie);
        self
    }

    /// Replace the `chaddr` fixed field with raw bytes of any length.
    ///
    /// RFC 2131 section 2 bounds `chaddr` to 16 octets; the typed builder
    /// rejects longer values. This knob writes the bytes verbatim without the
    /// 16-octet bound so callers can overflow or underfill the field.
    pub fn raw_chaddr(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.raw_chaddr = Some(bytes.into());
        self
    }

    /// Replace the `sname` fixed field with raw bytes of any length.
    ///
    /// RFC 2131 section 2 bounds `sname` to 64 octets; this knob ignores the
    /// bound and writes the bytes verbatim.
    pub fn raw_sname(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.raw_sname = Some(bytes.into());
        self
    }

    /// Replace the `file` fixed field with raw bytes of any length.
    ///
    /// RFC 2131 section 2 bounds `file` to 128 octets; this knob ignores the
    /// bound and writes the bytes verbatim.
    pub fn raw_file(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.raw_file = Some(bytes.into());
        self
    }

    /// Replace the entire options area with raw bytes.
    ///
    /// The bytes are emitted exactly as supplied after the magic cookie. This is
    /// the lowest-level malformation hook: callers control option codes, length
    /// bytes, end markers, and any trailing junk. No end marker is appended.
    pub fn raw_options(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.raw_options = Some(bytes.into());
        self.append_end = false;
        self
    }

    /// Build a single malformed option segment with an explicit length byte.
    ///
    /// The declared length is written verbatim; it does not have to match the
    /// number of data bytes, letting callers craft a length that overruns or
    /// underruns the payload. The segment replaces the options area and no end
    /// marker is appended.
    pub fn option_with_declared_len(
        self,
        code: u8,
        declared_len: u8,
        data: impl AsRef<[u8]>,
    ) -> Self {
        let data = data.as_ref();
        let mut bytes = Vec::with_capacity(2 + data.len());
        bytes.push(code);
        bytes.push(declared_len);
        bytes.extend_from_slice(data);
        self.raw_options(bytes)
    }

    /// Build an option whose payload exceeds the 255-byte length limit.
    ///
    /// A single DHCP option length byte cannot describe more than 255 octets
    /// (RFC 2132 section 2); RFC 3396 splitting handles longer logical values.
    /// This emits one oversized segment with a truncated (`len % 256`) length
    /// byte followed by the full payload, which the decoder cannot reassemble.
    pub fn oversized_option_payload(self, code: u8, data: impl AsRef<[u8]>) -> Self {
        let data = data.as_ref();
        let declared = (data.len() % 256) as u8;
        self.option_with_declared_len(code, declared, data)
    }

    /// Emit the options area without the trailing end marker.
    ///
    /// RFC 2132 section 2 requires options to be terminated by the end option
    /// (code 255). This drops it so the decoder reports `dhcp.options`.
    pub fn without_end_marker(mut self) -> Self {
        self.append_end = false;
        self
    }

    /// Append raw bytes after the end marker.
    ///
    /// Only padding may follow the end option; any other trailing byte is a
    /// malformed stream the decoder rejects as `dhcp.option.end`. The supplied
    /// bytes are appended verbatim after the normally-encoded options (including
    /// their end marker).
    pub fn trailing_after_end(mut self, bytes: impl AsRef<[u8]>) -> Self {
        let mut options = self.encoded_options();
        if self.append_end && !ends_with_end_marker(&options) {
            options.push(DHCP_OPTION_END);
        }
        options.extend_from_slice(bytes.as_ref());
        self.raw_options = Some(options);
        self.append_end = false;
        self
    }

    /// Encode the raw DHCP bytes, skipping the normal structural validation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DHCP_MIN_LEN);
        out.push(self.base.op_value());
        out.push(self.base.hardware_type_value());
        out.push(self.base.hardware_len_value());
        out.push(self.base.hops_value());
        out.extend_from_slice(&self.base.transaction_id_value().to_be_bytes());
        out.extend_from_slice(&self.base.seconds_value().to_be_bytes());
        out.extend_from_slice(&self.base.flags_value().to_be_bytes());
        out.extend_from_slice(&self.base.client_ip_address_value().octets());
        out.extend_from_slice(&self.base.your_ip_address_value().octets());
        out.extend_from_slice(&self.base.server_ip_address_value().octets());
        out.extend_from_slice(&self.base.gateway_ip_address_value().octets());

        write_fixed_field(
            &mut out,
            self.raw_chaddr.as_deref(),
            self.base.chaddr_bytes(),
            DHCP_CHADDR_LEN,
        );
        write_fixed_field(
            &mut out,
            self.raw_sname.as_deref(),
            self.base.sname_raw(),
            DHCP_SNAME_LEN,
        );
        write_fixed_field(
            &mut out,
            self.raw_file.as_deref(),
            self.base.file_raw(),
            DHCP_FILE_LEN,
        );

        let cookie = self
            .magic_cookie_override
            .unwrap_or_else(|| self.base.magic_cookie_value());
        out.extend_from_slice(&cookie.to_be_bytes());

        out.extend_from_slice(&self.encoded_options());
        out
    }

    fn encoded_options(&self) -> Vec<u8> {
        if let Some(raw) = &self.raw_options {
            return raw.clone();
        }
        // Fall back to the typed encoder for the base options. The base packet
        // was constructed through the valid builder, so this cannot fail; if it
        // somehow does, drop to an empty options area rather than panicking.
        match self.base.encoded_options() {
            Ok(mut bytes) => {
                if !self.append_end {
                    strip_trailing_end(&mut bytes);
                }
                bytes
            }
            Err(_) => Vec::new(),
        }
    }
}

impl Default for DhcpMalformed {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for DhcpMalformed {
    fn name(&self) -> &'static str {
        "DhcpMalformed"
    }

    fn summary(&self) -> String {
        let bytes = self.to_bytes();
        let cookie = self.magic_cookie_override.unwrap_or(DHCP_MAGIC_COOKIE);
        format!("DhcpMalformed(len={}, magic=0x{:08x})", bytes.len(), cookie)
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let bytes = self.to_bytes();
        vec![
            ("len", bytes.len().to_string()),
            (
                "magic_cookie",
                format!(
                    "0x{:08x}",
                    self.magic_cookie_override
                        .unwrap_or_else(|| self.base.magic_cookie_value())
                ),
            ),
            ("fixed_header_len", DHCP_FIXED_HEADER_LEN.to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.to_bytes().len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.to_bytes());
        Ok(())
    }

    fn clone_layer(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<R> Div<R> for DhcpMalformed
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

fn write_fixed_field(out: &mut Vec<u8>, raw: Option<&[u8]>, base: &[u8], padded_len: usize) {
    match raw {
        // Raw override: write bytes verbatim with no length bound or padding so
        // callers can over- or under-fill the field on purpose.
        Some(bytes) => out.extend_from_slice(bytes),
        // No override: reproduce the normal fixed-field encoding (truncate to
        // the field length and zero-pad to it).
        None => {
            let copy_len = base.len().min(padded_len);
            out.extend_from_slice(&base[..copy_len]);
            out.resize(out.len() + (padded_len - copy_len), 0);
        }
    }
}

fn ends_with_end_marker(options: &[u8]) -> bool {
    matches!(options.last(), Some(&DHCP_OPTION_END))
}

fn strip_trailing_end(options: &mut Vec<u8>) {
    if ends_with_end_marker(options) {
        options.pop();
    }
}
