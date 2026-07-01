//! TLS supported group helpers.
//!
//! TLS `NamedGroup` values are raw two-octet registry codepoints used by
//! supported_groups and key_share. The model keeps every caller-supplied or
//! decoded value intact, including unknown, GREASE, private-use, and legacy
//! explicit-curve values.

use core::fmt;

use super::constants::{self, TlsCodepointStatus};
use crate::{CrafterError, Result};

/// TLS NamedGroup codepoint width in bytes.
pub const TLS_NAMED_GROUP_LEN: usize = 2;
/// TLS supported_groups vector length-prefix width in bytes.
pub const TLS_NAMED_GROUP_LIST_PREFIX_LEN: usize = 2;

/// A raw-preserving TLS `NamedGroup` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsNamedGroup {
    raw: u16,
}

impl TlsNamedGroup {
    /// Reserved NamedGroup zero value.
    pub const RESERVED: Self = Self::new(constants::TLS_NAMED_GROUP_RESERVED);
    /// TLS NamedGroup `secp256r1`.
    pub const SECP256R1: Self = Self::new(constants::TLS_NAMED_GROUP_SECP256R1);
    /// TLS NamedGroup `secp384r1`.
    pub const SECP384R1: Self = Self::new(constants::TLS_NAMED_GROUP_SECP384R1);
    /// TLS NamedGroup `secp521r1`.
    pub const SECP521R1: Self = Self::new(constants::TLS_NAMED_GROUP_SECP521R1);
    /// TLS NamedGroup `x25519`.
    pub const X25519: Self = Self::new(constants::TLS_NAMED_GROUP_X25519);
    /// TLS NamedGroup `x448`.
    pub const X448: Self = Self::new(constants::TLS_NAMED_GROUP_X448);
    /// TLS NamedGroup `ffdhe2048`.
    pub const FFDHE2048: Self = Self::new(constants::TLS_NAMED_GROUP_FFDHE2048);
    /// TLS NamedGroup `ffdhe3072`.
    pub const FFDHE3072: Self = Self::new(constants::TLS_NAMED_GROUP_FFDHE3072);
    /// TLS NamedGroup `ffdhe4096`.
    pub const FFDHE4096: Self = Self::new(constants::TLS_NAMED_GROUP_FFDHE4096);
    /// TLS NamedGroup `ffdhe6144`.
    pub const FFDHE6144: Self = Self::new(constants::TLS_NAMED_GROUP_FFDHE6144);
    /// TLS NamedGroup `ffdhe8192`.
    pub const FFDHE8192: Self = Self::new(constants::TLS_NAMED_GROUP_FFDHE8192);
    /// Draft-backed NamedGroup `X25519MLKEM768`, preserve-only in this bootstrap.
    pub const X25519MLKEM768: Self = Self::new(constants::TLS_NAMED_GROUP_X25519MLKEM768);
    /// Legacy explicit-prime curve indicator.
    pub const ARBITRARY_EXPLICIT_PRIME_CURVES: Self =
        Self::new(constants::TLS_NAMED_GROUP_ARBITRARY_EXPLICIT_PRIME_CURVES);
    /// Legacy explicit-char2 curve indicator.
    pub const ARBITRARY_EXPLICIT_CHAR2_CURVES: Self =
        Self::new(constants::TLS_NAMED_GROUP_ARBITRARY_EXPLICIT_CHAR2_CURVES);

    /// Preserve a caller-supplied raw two-octet named group value.
    pub const fn new(raw: u16) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw two-octet named group value.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Decode a big-endian TLS named group value from exactly two bytes.
    pub const fn from_be_bytes(bytes: [u8; TLS_NAMED_GROUP_LEN]) -> Self {
        Self::new(u16::from_be_bytes(bytes))
    }

    /// TLS NamedGroup `secp256r1` constructor.
    pub const fn secp256r1() -> Self {
        Self::SECP256R1
    }

    /// TLS NamedGroup `secp384r1` constructor.
    pub const fn secp384r1() -> Self {
        Self::SECP384R1
    }

    /// TLS NamedGroup `secp521r1` constructor.
    pub const fn secp521r1() -> Self {
        Self::SECP521R1
    }

    /// TLS NamedGroup `x25519` constructor.
    pub const fn x25519() -> Self {
        Self::X25519
    }

    /// TLS NamedGroup `x448` constructor.
    pub const fn x448() -> Self {
        Self::X448
    }

    /// TLS NamedGroup `ffdhe2048` constructor.
    pub const fn ffdhe2048() -> Self {
        Self::FFDHE2048
    }

    /// Return the preserved raw two-octet wire value.
    pub const fn raw(self) -> u16 {
        self.raw
    }

    /// Return the preserved raw two-octet wire value.
    pub const fn as_u16(self) -> u16 {
        self.raw
    }

    /// Return the big-endian two-byte wire encoding.
    pub const fn to_be_bytes(self) -> [u8; TLS_NAMED_GROUP_LEN] {
        self.raw.to_be_bytes()
    }

    /// Append the two-byte wire encoding to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    /// Return the two-byte wire encoding as a vector.
    pub fn encode_to_vec(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    /// Decode a TLS named group from the first two bytes of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (group, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(group)
    }

    /// Decode a TLS named group from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_NAMED_GROUP_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.named_group",
                TLS_NAMED_GROUP_LEN,
                bytes.len(),
            ));
        }

        Ok((
            Self::from_be_bytes([bytes[0], bytes[1]]),
            &bytes[TLS_NAMED_GROUP_LEN..],
        ))
    }

    /// Return the source-backed named group name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        constants::tls_named_group_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        constants::tls_named_group_status(self.raw)
    }

    /// Return true when this group has a selected source-backed name.
    pub const fn is_known(self) -> bool {
        self.name().is_some()
    }

    /// Return true for groups selected for default TLS builders.
    pub const fn is_default_eligible(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::DefaultEligible)
    }

    /// Return true for RFC 8701 sparse GREASE named group values.
    pub const fn is_grease(self) -> bool {
        constants::is_tls_grease_u16(self.raw)
    }

    /// Return true for IANA private-use named group values.
    pub const fn is_private_use(self) -> bool {
        matches!(self.raw, 0xfe00..=0xfeff)
    }

    /// Return true for FFDHE groups selected in the codepoint notes.
    pub const fn is_ffdhe(self) -> bool {
        matches!(
            self.raw,
            constants::TLS_NAMED_GROUP_FFDHE2048
                | constants::TLS_NAMED_GROUP_FFDHE3072
                | constants::TLS_NAMED_GROUP_FFDHE4096
                | constants::TLS_NAMED_GROUP_FFDHE6144
                | constants::TLS_NAMED_GROUP_FFDHE8192
        )
    }

    /// Return true for legacy explicit-curve indicators selected in the notes.
    pub const fn is_legacy_explicit_curve(self) -> bool {
        matches!(
            self.raw,
            constants::TLS_NAMED_GROUP_ARBITRARY_EXPLICIT_PRIME_CURVES
                | constants::TLS_NAMED_GROUP_ARBITRARY_EXPLICIT_CHAR2_CURVES
        )
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        constants::tls_named_group_label(self.raw)
    }

    /// Stable one-line summary with raw value and source-backed status.
    pub fn summary(self) -> String {
        format!(
            "{} raw=0x{:04x} status={}",
            self.label(),
            self.raw,
            self.status().label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("named_group", self.label()),
            ("named_group_raw", format!("0x{:04x}", self.raw)),
            ("named_group_status", self.status().label().to_string()),
            ("grease", self.is_grease().to_string()),
            ("private_use", self.is_private_use().to_string()),
            ("ffdhe", self.is_ffdhe().to_string()),
            (
                "legacy_explicit_curve",
                self.is_legacy_explicit_curve().to_string(),
            ),
        ]
    }
}

impl From<u16> for TlsNamedGroup {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<TlsNamedGroup> for u16 {
    fn from(value: TlsNamedGroup) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsNamedGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Ordered TLS supported_groups vector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsNamedGroupList {
    groups: Vec<TlsNamedGroup>,
}

impl TlsNamedGroupList {
    /// Create an ordered named group list.
    pub fn new(groups: impl Into<Vec<TlsNamedGroup>>) -> Self {
        Self {
            groups: groups.into(),
        }
    }

    /// Create an empty ordered named group list.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create an ordered list from raw two-octet values.
    pub fn from_raws(raws: impl IntoIterator<Item = u16>) -> Self {
        Self::new(
            raws.into_iter()
                .map(TlsNamedGroup::from_u16)
                .collect::<Vec<_>>(),
        )
    }

    /// Borrow the ordered named group values.
    pub fn groups(&self) -> &[TlsNamedGroup] {
        &self.groups
    }

    /// Return the ordered raw named group values.
    pub fn raw_values(&self) -> Vec<u16> {
        self.groups.iter().map(|group| group.raw()).collect()
    }

    /// Return labels in wire order.
    pub fn labels(&self) -> Vec<String> {
        self.groups.iter().map(|group| group.label()).collect()
    }

    /// Consume the list and return the ordered values.
    pub fn into_vec(self) -> Vec<TlsNamedGroup> {
        self.groups
    }

    /// Append a group to the ordered list.
    pub fn push(&mut self, group: TlsNamedGroup) {
        self.groups.push(group);
    }

    /// Number of named group values in the list.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Return true when the list carries no named group values.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Number of bytes occupied by the vector body, excluding the length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        self.groups
            .len()
            .checked_mul(TLS_NAMED_GROUP_LEN)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.named_groups.length", "length overflow")
            })
    }

    /// Number of bytes occupied by the complete encoded vector.
    pub fn encoded_len(&self) -> Result<usize> {
        self.byte_len()?
            .checked_add(TLS_NAMED_GROUP_LIST_PREFIX_LEN)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.named_groups.length", "length overflow")
            })
    }

    /// Append the uint16 length-prefixed supported_groups vector.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        let encoded_len = u16::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.named_groups.length",
                "length must fit in two bytes",
            )
        })?;

        out.extend_from_slice(&encoded_len.to_be_bytes());
        for group in &self.groups {
            group.encode(out);
        }
        Ok(())
    }

    /// Return the uint16 length-prefixed supported_groups vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a uint16 length-prefixed supported_groups vector.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (list, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(list)
    }

    /// Decode a uint16 length-prefixed supported_groups vector from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_NAMED_GROUP_LIST_PREFIX_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.named_groups.length",
                TLS_NAMED_GROUP_LIST_PREFIX_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let required = TLS_NAMED_GROUP_LIST_PREFIX_LEN + byte_len;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.named_groups",
                required,
                bytes.len(),
            ));
        }

        if byte_len % TLS_NAMED_GROUP_LEN != 0 {
            return Err(CrafterError::invalid_field_value(
                "tls.named_groups.length",
                "named group vector length must be even",
            ));
        }

        let body = &bytes[TLS_NAMED_GROUP_LIST_PREFIX_LEN..required];
        let groups = body
            .chunks_exact(TLS_NAMED_GROUP_LEN)
            .map(|chunk| TlsNamedGroup::from_be_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();

        Ok((Self::new(groups), &bytes[required..]))
    }

    /// Stable one-line summary preserving order.
    pub fn summary(&self) -> String {
        let values = self.labels().join(",");
        format!(
            "named_groups count={} bytes={} values={}",
            self.len(),
            self.groups.len() * TLS_NAMED_GROUP_LEN,
            values
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("named_groups_count", self.len().to_string()),
            (
                "named_groups_bytes",
                (self.groups.len() * TLS_NAMED_GROUP_LEN).to_string(),
            ),
            ("named_groups", self.labels().join(",")),
        ]
    }
}

impl From<Vec<TlsNamedGroup>> for TlsNamedGroupList {
    fn from(groups: Vec<TlsNamedGroup>) -> Self {
        Self::new(groups)
    }
}

impl<const N: usize> From<[TlsNamedGroup; N]> for TlsNamedGroupList {
    fn from(groups: [TlsNamedGroup; N]) -> Self {
        Self::new(Vec::from(groups))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_groups_signatures_named_group_known_constructors_expose_raw_values() {
        assert_eq!(
            TlsNamedGroup::secp256r1().raw(),
            constants::TLS_NAMED_GROUP_SECP256R1
        );
        assert_eq!(
            TlsNamedGroup::secp384r1().raw(),
            constants::TLS_NAMED_GROUP_SECP384R1
        );
        assert_eq!(
            TlsNamedGroup::secp521r1().raw(),
            constants::TLS_NAMED_GROUP_SECP521R1
        );
        assert_eq!(
            TlsNamedGroup::x25519().raw(),
            constants::TLS_NAMED_GROUP_X25519
        );
        assert_eq!(TlsNamedGroup::x448().raw(), constants::TLS_NAMED_GROUP_X448);
        assert_eq!(
            TlsNamedGroup::ffdhe2048().raw(),
            constants::TLS_NAMED_GROUP_FFDHE2048
        );
        assert_eq!(
            TlsNamedGroup::from_be_bytes([0x00, 0x1d]),
            TlsNamedGroup::X25519
        );
        assert_eq!(TlsNamedGroup::X25519.to_be_bytes(), [0x00, 0x1d]);
    }

    #[test]
    fn tls_groups_signatures_named_group_labels_statuses_and_ranges_reuse_constants() {
        let x25519 = TlsNamedGroup::X25519;
        let ffdhe = TlsNamedGroup::FFDHE2048;
        let explicit = TlsNamedGroup::ARBITRARY_EXPLICIT_PRIME_CURVES;
        let grease = TlsNamedGroup::from_u16(0x0a0a);
        let private = TlsNamedGroup::from_u16(0xfe00);
        let unknown = TlsNamedGroup::from_u16(0xbeef);

        assert_eq!(x25519.name(), Some("x25519"));
        assert_eq!(x25519.status(), TlsCodepointStatus::DefaultEligible);
        assert_eq!(x25519.label(), "x25519");
        assert_eq!(x25519.to_string(), "x25519");
        assert!(x25519.is_known());
        assert!(x25519.is_default_eligible());

        assert_eq!(ffdhe.status(), TlsCodepointStatus::PreserveOnly);
        assert_eq!(ffdhe.label(), "ffdhe2048");
        assert!(ffdhe.is_ffdhe());
        assert!(!ffdhe.is_default_eligible());

        assert_eq!(explicit.status(), TlsCodepointStatus::PreserveOnly);
        assert!(explicit.is_legacy_explicit_curve());

        assert_eq!(grease.name(), None);
        assert_eq!(grease.status(), TlsCodepointStatus::ReservedGrease);
        assert_eq!(grease.label(), "reserved grease named group 0x0a0a");
        assert!(grease.is_grease());

        assert_eq!(private.status(), TlsCodepointStatus::PrivateUse);
        assert_eq!(private.label(), "private-use named group 0xfe00");
        assert!(private.is_private_use());

        assert_eq!(unknown.status(), TlsCodepointStatus::Unknown);
        assert_eq!(unknown.label(), "unknown named group 0xbeef");
        assert!(!unknown.is_known());
    }

    #[test]
    fn tls_groups_signatures_named_group_encode_decode_preserves_raw_values_and_tail() {
        let group = TlsNamedGroup::from_u16(0xbeef);
        let mut encoded = Vec::new();
        group.encode(&mut encoded);

        assert_eq!(encoded, [0xbe, 0xef]);
        assert_eq!(group.encode_to_vec(), vec![0xbe, 0xef]);
        assert_eq!(TlsNamedGroup::decode(&encoded).unwrap(), group);
        assert_eq!(
            TlsNamedGroup::decode_prefix(&[0xbe, 0xef, 0xaa]).unwrap(),
            (group, &[0xaa][..])
        );
        assert_eq!(u16::from(group), 0xbeef);
        assert_eq!(TlsNamedGroup::from(0xbeef).as_u16(), 0xbeef);
    }

    #[test]
    fn tls_groups_signatures_named_group_inspection_includes_raw_status_and_ranges() {
        let grease = TlsNamedGroup::from_u16(0x1a1a);

        assert_eq!(
            grease.summary(),
            "reserved grease named group 0x1a1a raw=0x1a1a status=reserved-grease"
        );

        let fields = grease.inspection_fields();
        assert!(fields.contains(&(
            "named_group",
            "reserved grease named group 0x1a1a".to_string()
        )));
        assert!(fields.contains(&("named_group_raw", "0x1a1a".to_string())));
        assert!(fields.contains(&("named_group_status", "reserved-grease".to_string())));
        assert!(fields.contains(&("grease", "true".to_string())));
        assert!(fields.contains(&("private_use", "false".to_string())));
        assert!(fields.contains(&("ffdhe", "false".to_string())));
        assert!(fields.contains(&("legacy_explicit_curve", "false".to_string())));
    }

    #[test]
    fn tls_groups_signatures_named_group_list_encodes_decodes_and_preserves_order() {
        let list = TlsNamedGroupList::new(vec![
            TlsNamedGroup::X25519,
            TlsNamedGroup::from_u16(0x0a0a),
            TlsNamedGroup::FFDHE2048,
            TlsNamedGroup::from_u16(0xfe00),
            TlsNamedGroup::from_u16(0xbeef),
        ]);

        let encoded = list.encode_to_vec().unwrap();
        assert_eq!(
            encoded,
            [0x00, 0x0a, 0x00, 0x1d, 0x0a, 0x0a, 0x01, 0x00, 0xfe, 0x00, 0xbe, 0xef]
        );

        let encoded_with_tail = [encoded.as_slice(), &[0xaa][..]].concat();
        let (decoded, tail) = TlsNamedGroupList::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded, list);
        assert_eq!(
            decoded.raw_values(),
            vec![0x001d, 0x0a0a, 0x0100, 0xfe00, 0xbeef]
        );
        assert_eq!(
            decoded.labels(),
            vec![
                "x25519".to_string(),
                "reserved grease named group 0x0a0a".to_string(),
                "ffdhe2048".to_string(),
                "private-use named group 0xfe00".to_string(),
                "unknown named group 0xbeef".to_string(),
            ]
        );
        assert_eq!(
            decoded.summary(),
            "named_groups count=5 bytes=10 values=x25519,reserved grease named group 0x0a0a,ffdhe2048,private-use named group 0xfe00,unknown named group 0xbeef"
        );

        let fields = decoded.inspection_fields();
        assert!(fields.contains(&("named_groups_count", "5".to_string())));
        assert!(fields.contains(&("named_groups_bytes", "10".to_string())));
    }

    #[test]
    fn tls_groups_signatures_named_group_list_supports_empty_and_incremental_building() {
        let mut list = TlsNamedGroupList::empty();
        assert!(list.is_empty());
        assert_eq!(list.encode_to_vec().unwrap(), [0x00, 0x00]);
        assert_eq!(
            TlsNamedGroupList::decode([0x00, 0x00]).unwrap().groups(),
            &[]
        );

        list.push(TlsNamedGroup::SECP256R1);
        assert_eq!(list.len(), 1);
        assert_eq!(list.byte_len().unwrap(), 2);
        assert_eq!(list.encoded_len().unwrap(), 4);
        assert_eq!(list.encode_to_vec().unwrap(), [0x00, 0x02, 0x00, 0x17]);

        let from_raws = TlsNamedGroupList::from_raws([0x001d, 0xfe00]);
        assert_eq!(from_raws.raw_values(), vec![0x001d, 0xfe00]);
        assert_eq!(
            TlsNamedGroupList::from([TlsNamedGroup::X25519]).raw_values(),
            vec![0x001d]
        );
    }

    #[test]
    fn tls_groups_signatures_named_group_list_reports_structured_decode_errors() {
        assert_eq!(
            TlsNamedGroup::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.named_group", TLS_NAMED_GROUP_LEN, 1)
        );
        assert_eq!(
            TlsNamedGroupList::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.named_groups.length",
                TLS_NAMED_GROUP_LIST_PREFIX_LEN,
                1,
            )
        );
        assert_eq!(
            TlsNamedGroupList::decode([0x00, 0x04, 0x00, 0x1d]).unwrap_err(),
            CrafterError::buffer_too_short("tls.named_groups", 6, 4)
        );
        assert_eq!(
            TlsNamedGroupList::decode([0x00, 0x03, 0x00, 0x1d, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.named_groups.length",
                "named group vector length must be even"
            )
        );
    }

    #[test]
    fn tls_groups_signatures_named_group_list_rejects_encoded_body_too_large_for_u16_prefix() {
        let groups = vec![TlsNamedGroup::X25519; 32768];
        let list = TlsNamedGroupList::new(groups);

        assert_eq!(list.byte_len().unwrap(), 65536);
        assert_eq!(
            list.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.named_groups.length",
                "length must fit in two bytes"
            )
        );
    }
}
