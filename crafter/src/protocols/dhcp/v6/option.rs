//! DHCPv6 generic option model.
//!
//! DHCPv6 options are 16-bit code, 16-bit length, variable payload TLVs. This
//! module starts with the raw-preserving data model; the serial codec and IANA
//! registry classification live in later modules.

use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};

use super::constants::{
    DHCPV6_OPTION_CLIENTID, DHCPV6_OPTION_ELAPSED_TIME, DHCPV6_OPTION_HEADER_LEN,
    DHCPV6_OPTION_ORO, DHCPV6_OPTION_PREFERENCE, DHCPV6_OPTION_RAPID_COMMIT,
    DHCPV6_OPTION_SERVERID,
};

/// DHCPv6 option codepoint.
///
/// Every 16-bit value is representable so packets can preserve registered,
/// obsolete, unassigned, private, or future codepoints without requiring typed
/// support in the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dhcpv6OptionCode(u16);

impl Dhcpv6OptionCode {
    /// Create an option codepoint from its raw wire value.
    pub const fn from_code(code: u16) -> Self {
        Self(code)
    }

    /// Raw wire codepoint.
    pub const fn code(self) -> u16 {
        self.0
    }
}

impl From<u16> for Dhcpv6OptionCode {
    fn from(code: u16) -> Self {
        Self::from_code(code)
    }
}

impl From<Dhcpv6OptionCode> for u16 {
    fn from(code: Dhcpv6OptionCode) -> Self {
        code.code()
    }
}

/// Reusable DHCPv6 option payload format family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dhcpv6OptionFormat {
    /// Zero-length payload.
    Empty,
    /// Opaque payload bytes preserved verbatim.
    Raw,
}

/// Raw-preserving DHCPv6 option payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Dhcpv6OptionValue {
    /// Zero-length payload.
    Empty,
    /// Opaque payload bytes preserved verbatim.
    Raw(Vec<u8>),
}

impl Dhcpv6OptionValue {
    /// View this option value as payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Raw(bytes) => bytes,
        }
    }

    /// Consume this value into payload bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::Raw(bytes) => bytes,
        }
    }

    /// Payload length in bytes.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// True when the payload has zero bytes.
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Payload format family.
    pub const fn format(&self) -> Dhcpv6OptionFormat {
        match self {
            Self::Empty => Dhcpv6OptionFormat::Empty,
            Self::Raw(_) => Dhcpv6OptionFormat::Raw,
        }
    }
}

impl From<Vec<u8>> for Dhcpv6OptionValue {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Raw(bytes)
    }
}

impl From<&[u8]> for Dhcpv6OptionValue {
    fn from(bytes: &[u8]) -> Self {
        Self::Raw(bytes.to_vec())
    }
}

/// DHCPv6 option TLV.
///
/// The payload is kept as a [`Dhcpv6OptionValue`] so unknown and unsupported
/// options can round-trip through later codecs without losing bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dhcpv6Option {
    code: Dhcpv6OptionCode,
    value: Dhcpv6OptionValue,
}

impl Dhcpv6Option {
    /// Create an option from a codepoint and raw payload bytes.
    pub fn raw(code: impl Into<Dhcpv6OptionCode>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            code: code.into(),
            value: Dhcpv6OptionValue::Raw(payload.into()),
        }
    }

    /// Create a zero-length option.
    pub fn empty(code: impl Into<Dhcpv6OptionCode>) -> Self {
        Self {
            code: code.into(),
            value: Dhcpv6OptionValue::Empty,
        }
    }

    /// Create an option from a codepoint and typed payload value.
    pub fn typed(code: impl Into<Dhcpv6OptionCode>, value: Dhcpv6OptionValue) -> Self {
        Self {
            code: code.into(),
            value,
        }
    }

    /// Create an OPTION_CLIENTID option carrying DUID bytes.
    pub fn client_id(duid: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_CLIENTID, duid)
    }

    /// Create an OPTION_SERVERID option carrying DUID bytes.
    pub fn server_id(duid: impl Into<Vec<u8>>) -> Self {
        Self::raw(DHCPV6_OPTION_SERVERID, duid)
    }

    /// Create an OPTION_ORO option from requested option codepoints.
    pub fn oro<I, C>(codes: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<Dhcpv6OptionCode>,
    {
        let mut payload = Vec::new();
        for code in codes {
            append_u16_be(&mut payload, code.into().code());
        }
        Self::raw(DHCPV6_OPTION_ORO, payload)
    }

    /// Create an OPTION_PREFERENCE option.
    pub fn preference(preference: u8) -> Self {
        Self::raw(DHCPV6_OPTION_PREFERENCE, vec![preference])
    }

    /// Create an OPTION_ELAPSED_TIME option in hundredths of a second.
    pub fn elapsed_time(centiseconds: u16) -> Self {
        Self::raw(
            DHCPV6_OPTION_ELAPSED_TIME,
            centiseconds.to_be_bytes().to_vec(),
        )
    }

    /// Create an OPTION_RAPID_COMMIT option.
    pub fn rapid_commit() -> Self {
        Self::empty(DHCPV6_OPTION_RAPID_COMMIT)
    }

    /// Option codepoint.
    pub const fn code(&self) -> Dhcpv6OptionCode {
        self.code
    }

    /// Raw option codepoint.
    pub const fn codepoint(&self) -> u16 {
        self.code.code()
    }

    /// Option payload value.
    pub const fn value(&self) -> &Dhcpv6OptionValue {
        &self.value
    }

    /// Mutable option payload value.
    pub fn value_mut(&mut self) -> &mut Dhcpv6OptionValue {
        &mut self.value
    }

    /// View this option's payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.value.as_bytes()
    }

    /// Alias for [`Dhcpv6Option::payload`].
    pub fn as_bytes(&self) -> &[u8] {
        self.payload()
    }

    /// Payload length in bytes.
    pub fn payload_len(&self) -> usize {
        self.value.len()
    }

    /// True when the payload has zero bytes.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Payload format family.
    pub const fn format(&self) -> Dhcpv6OptionFormat {
        self.value.format()
    }

    /// Consume this option into its codepoint and payload value.
    pub fn into_parts(self) -> (Dhcpv6OptionCode, Dhcpv6OptionValue) {
        (self.code, self.value)
    }

    /// Return OPTION_CLIENTID DUID bytes when this option is Client ID.
    pub fn client_id_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_CLIENTID)
    }

    /// Return OPTION_SERVERID DUID bytes when this option is Server ID.
    pub fn server_id_value(&self) -> Option<&[u8]> {
        self.payload_if_code(DHCPV6_OPTION_SERVERID)
    }

    /// Decode OPTION_ORO requested option codepoints.
    pub fn oro_value(&self) -> Result<Option<Vec<Dhcpv6OptionCode>>> {
        let Some(payload) = self.payload_if_code(DHCPV6_OPTION_ORO) else {
            return Ok(None);
        };
        if payload.len() % 2 != 0 {
            return Err(CrafterError::invalid_field_value(
                "dhcpv6.option.oro",
                "payload length must be a multiple of 2 bytes",
            ));
        }

        let mut codes = Vec::with_capacity(payload.len() / 2);
        for chunk in payload.chunks_exact(2) {
            codes.push(Dhcpv6OptionCode::from_code(read_u16_be(chunk)?));
        }
        Ok(Some(codes))
    }

    /// Decode OPTION_PREFERENCE.
    pub fn preference_value(&self) -> Result<Option<u8>> {
        Ok(self
            .exact_payload_if_code(DHCPV6_OPTION_PREFERENCE, 1, "dhcpv6.option.preference")?
            .map(|payload| payload[0]))
    }

    /// Decode OPTION_ELAPSED_TIME.
    pub fn elapsed_time_value(&self) -> Result<Option<u16>> {
        Ok(self
            .exact_payload_if_code(DHCPV6_OPTION_ELAPSED_TIME, 2, "dhcpv6.option.elapsed_time")?
            .map(|payload| u16::from_be_bytes([payload[0], payload[1]])))
    }

    /// Return true when this is a valid zero-length OPTION_RAPID_COMMIT.
    pub fn rapid_commit_present(&self) -> Result<bool> {
        Ok(self
            .exact_payload_if_code(DHCPV6_OPTION_RAPID_COMMIT, 0, "dhcpv6.option.rapid_commit")?
            .is_some())
    }

    /// Encode this option to its DHCPv6 TLV wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(DHCPV6_OPTION_HEADER_LEN + self.payload_len());
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Append this option's DHCPv6 TLV wire bytes to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        let payload_len = u16::try_from(self.payload_len()).map_err(|_| {
            CrafterError::invalid_field_value("dhcpv6.option.length", "payload exceeds 65535 bytes")
        })?;

        append_u16_be(out, self.codepoint());
        append_u16_be(out, payload_len);
        out.extend_from_slice(self.payload());
        Ok(())
    }

    /// Encode a serial list of DHCPv6 options.
    pub fn encode_all(options: &[Self]) -> Result<Vec<u8>> {
        let total_len = options
            .iter()
            .map(|option| DHCPV6_OPTION_HEADER_LEN + option.payload_len())
            .sum();
        let mut out = Vec::with_capacity(total_len);
        for option in options {
            option.encode_into(&mut out)?;
        }
        Ok(out)
    }

    /// Decode a serial DHCPv6 option list.
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>> {
        let mut options = Vec::new();
        let mut offset = 0usize;

        while offset < bytes.len() {
            let code = read_option_code(bytes, offset)?;
            let payload_len = read_option_len(bytes, offset)? as usize;
            let payload_start = offset + DHCPV6_OPTION_HEADER_LEN;
            let payload_end = payload_start + payload_len;
            ensure_available(bytes, payload_end, "dhcpv6.option.payload")?;

            let payload = &bytes[payload_start..payload_end];
            let value = if payload.is_empty() {
                Dhcpv6OptionValue::Empty
            } else {
                Dhcpv6OptionValue::Raw(payload.to_vec())
            };
            options.push(Self::typed(code, value));
            offset = payload_end;
        }

        Ok(options)
    }

    fn payload_if_code(&self, code: u16) -> Option<&[u8]> {
        (self.codepoint() == code).then(|| self.payload())
    }

    fn exact_payload_if_code(
        &self,
        code: u16,
        expected_len: usize,
        context: &'static str,
    ) -> Result<Option<&[u8]>> {
        let Some(payload) = self.payload_if_code(code) else {
            return Ok(None);
        };
        if payload.len() != expected_len {
            return Err(CrafterError::invalid_field_value(
                context,
                "payload length does not match option format",
            ));
        }
        Ok(Some(payload))
    }
}

fn append_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_option_code(bytes: &[u8], offset: usize) -> Result<u16> {
    ensure_available(bytes, offset + 2, "dhcpv6.option.code")?;
    read_u16_be(&bytes[offset..offset + 2])
}

fn read_option_len(bytes: &[u8], offset: usize) -> Result<u16> {
    ensure_available(
        bytes,
        offset + DHCPV6_OPTION_HEADER_LEN,
        "dhcpv6.option.length",
    )?;
    read_u16_be(&bytes[offset + 2..offset + DHCPV6_OPTION_HEADER_LEN])
}

fn ensure_available(bytes: &[u8], required: usize, context: &'static str) -> Result<()> {
    if bytes.len() < required {
        Err(CrafterError::buffer_too_short(
            context,
            required,
            bytes.len(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod dhcpv6_option_model_tests {
    use super::{Dhcpv6Option, Dhcpv6OptionCode, Dhcpv6OptionFormat, Dhcpv6OptionValue};

    #[test]
    fn dhcpv6_option_model_raw_option_preserves_code_and_payload() {
        let option = Dhcpv6Option::raw(23u16, vec![0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(option.code(), Dhcpv6OptionCode::from_code(23));
        assert_eq!(option.codepoint(), 23);
        assert_eq!(option.payload(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(option.as_bytes(), option.payload());
        assert_eq!(option.payload_len(), 4);
        assert_eq!(option.format(), Dhcpv6OptionFormat::Raw);
        assert!(!option.is_empty());
    }

    #[test]
    fn dhcpv6_option_model_empty_option_has_empty_payload() {
        let option = Dhcpv6Option::empty(14u16);

        assert_eq!(option.codepoint(), 14);
        assert_eq!(option.payload(), &[]);
        assert_eq!(option.payload_len(), 0);
        assert_eq!(option.format(), Dhcpv6OptionFormat::Empty);
        assert!(option.is_empty());
    }

    #[test]
    fn dhcpv6_option_model_unknown_codes_are_ordinary_codepoints() {
        let code = Dhcpv6OptionCode::from_code(65_000);
        let option = Dhcpv6Option::raw(code, [1, 2, 3].as_slice());

        assert_eq!(u16::from(option.code()), 65_000);
        assert_eq!(option.payload(), &[1, 2, 3]);
    }

    #[test]
    fn dhcpv6_option_model_value_bytes_are_lossless() {
        let mut option =
            Dhcpv6Option::typed(1u16, Dhcpv6OptionValue::Raw(vec![0x00, 0xff, 0x7e, 0x80]));
        assert_eq!(option.value().as_bytes(), &[0x00, 0xff, 0x7e, 0x80]);

        *option.value_mut() = Dhcpv6OptionValue::Empty;
        let (code, value) = option.into_parts();
        assert_eq!(code.code(), 1);
        assert_eq!(value.into_bytes(), Vec::<u8>::new());
    }
}

#[cfg(test)]
mod dhcpv6_option_codec_tests {
    use super::Dhcpv6Option;
    use crate::error::CrafterError;

    #[test]
    fn dhcpv6_option_codec_encodes_zero_length_options() {
        let option = Dhcpv6Option::empty(14u16);

        assert_eq!(option.encode().unwrap(), vec![0x00, 0x0e, 0x00, 0x00]);
        let decoded = Dhcpv6Option::decode_all(&[0x00, 0x0e, 0x00, 0x00]).unwrap();
        assert_eq!(decoded, vec![option]);
        assert!(decoded[0].is_empty());
    }

    #[test]
    fn dhcpv6_option_codec_decodes_multiple_options() {
        let bytes = [0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x17, 0x00, 0x00];
        let decoded = Dhcpv6Option::decode_all(&bytes).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].codepoint(), 1);
        assert_eq!(decoded[0].payload(), &[0xaa, 0xbb]);
        assert_eq!(decoded[1].codepoint(), 23);
        assert_eq!(decoded[1].payload(), &[]);
        assert_eq!(Dhcpv6Option::encode_all(&decoded).unwrap(), bytes);
    }

    #[test]
    fn dhcpv6_option_codec_unknown_options_roundtrip() {
        let option = Dhcpv6Option::raw(65_000u16, [0xde, 0xad, 0xbe, 0xef].as_slice());
        let encoded = option.encode().unwrap();

        assert_eq!(
            encoded,
            vec![0xfd, 0xe8, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(Dhcpv6Option::decode_all(&encoded).unwrap(), vec![option]);
    }

    #[test]
    fn dhcpv6_option_codec_truncated_code_length_and_payload_are_structured() {
        assert_eq!(
            Dhcpv6Option::decode_all(&[0x00]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.code", 2, 1),
        );

        assert_eq!(
            Dhcpv6Option::decode_all(&[0x00, 0x01, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.length", 4, 3),
        );

        assert_eq!(
            Dhcpv6Option::decode_all(&[0x00, 0x01, 0x00, 0x04, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("dhcpv6.option.payload", 8, 5),
        );
    }
}

#[cfg(test)]
mod dhcpv6_basic_options_tests {
    use super::{Dhcpv6Option, Dhcpv6OptionCode};
    use crate::error::CrafterError;
    use crate::protocols::dhcp::v6::{
        DHCPV6_OPTION_CLIENTID, DHCPV6_OPTION_ELAPSED_TIME, DHCPV6_OPTION_ORO,
        DHCPV6_OPTION_PREFERENCE, DHCPV6_OPTION_RAPID_COMMIT, DHCPV6_OPTION_SERVERID,
    };

    #[test]
    fn dhcpv6_basic_options_constructors_encode_core_tlvs() {
        let client_id = Dhcpv6Option::client_id([0x00, 0x03, 0xaa, 0xbb]);
        let server_id = Dhcpv6Option::server_id([0x00, 0x01, 0xcc, 0xdd]);
        let oro = Dhcpv6Option::oro([23u16, 24u16]);
        let preference = Dhcpv6Option::preference(200);
        let elapsed_time = Dhcpv6Option::elapsed_time(37);
        let rapid_commit = Dhcpv6Option::rapid_commit();

        assert_eq!(client_id.codepoint(), DHCPV6_OPTION_CLIENTID);
        assert_eq!(
            client_id.client_id_value(),
            Some(&[0x00, 0x03, 0xaa, 0xbb][..])
        );
        assert_eq!(server_id.codepoint(), DHCPV6_OPTION_SERVERID);
        assert_eq!(
            server_id.server_id_value(),
            Some(&[0x00, 0x01, 0xcc, 0xdd][..])
        );
        assert_eq!(oro.codepoint(), DHCPV6_OPTION_ORO);
        assert_eq!(
            oro.oro_value().unwrap(),
            Some(vec![
                Dhcpv6OptionCode::from_code(23),
                Dhcpv6OptionCode::from_code(24),
            ]),
        );
        assert_eq!(preference.codepoint(), DHCPV6_OPTION_PREFERENCE);
        assert_eq!(preference.preference_value().unwrap(), Some(200));
        assert_eq!(elapsed_time.codepoint(), DHCPV6_OPTION_ELAPSED_TIME);
        assert_eq!(elapsed_time.elapsed_time_value().unwrap(), Some(37));
        assert_eq!(rapid_commit.codepoint(), DHCPV6_OPTION_RAPID_COMMIT);
        assert!(rapid_commit.rapid_commit_present().unwrap());

        assert_eq!(
            Dhcpv6Option::encode_all(&[
                client_id,
                server_id,
                oro,
                preference,
                elapsed_time,
                rapid_commit,
            ])
            .unwrap(),
            vec![
                0x00, 0x01, 0x00, 0x04, 0x00, 0x03, 0xaa, 0xbb, 0x00, 0x02, 0x00, 0x04, 0x00, 0x01,
                0xcc, 0xdd, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18, 0x00, 0x07, 0x00, 0x01,
                200, 0x00, 0x08, 0x00, 0x02, 0x00, 37, 0x00, 0x0e, 0x00, 0x00,
            ],
        );
    }

    #[test]
    fn dhcpv6_basic_options_value_decoders_validate_fixed_lengths() {
        let decoded = Dhcpv6Option::decode_all(&[
            0x00, 0x07, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x08, 0x00, 0x01, 0xcc, 0x00, 0x0e, 0x00,
            0x01, 0xdd, 0x00, 0x06, 0x00, 0x03, 0x00, 0x17, 0xff,
        ])
        .unwrap();

        assert_eq!(
            decoded[0].preference_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.preference",
                "payload length does not match option format",
            ),
        );
        assert_eq!(decoded[0].payload(), &[0xaa, 0xbb]);

        assert_eq!(
            decoded[1].elapsed_time_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.elapsed_time",
                "payload length does not match option format",
            ),
        );
        assert_eq!(decoded[1].payload(), &[0xcc]);

        assert_eq!(
            decoded[2].rapid_commit_present().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.rapid_commit",
                "payload length does not match option format",
            ),
        );
        assert_eq!(decoded[2].payload(), &[0xdd]);

        assert_eq!(
            decoded[3].oro_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "dhcpv6.option.oro",
                "payload length must be a multiple of 2 bytes",
            ),
        );
        assert_eq!(decoded[3].payload(), &[0x00, 0x17, 0xff]);
    }
}
