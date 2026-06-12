//! BGP-4 (RFC 4271) message layers.

use std::net::Ipv4Addr;

use crate::field::Field;

use super::attribute::{BgpPathAttribute, BgpPrefix};
use super::capability::{
    decode_capabilities, encode_capabilities, BgpCapability, BgpOptParam,
    BGP_OPT_PARAM_CAPABILITIES,
};
use super::constants::{self, BGP_HEADER_LEN, BGP_MARKER_LEN, BGP_VERSION};

/// The shared 19-octet BGP message header (RFC 4271 §4.1).
///
/// Every BGP message begins with this fixed header: a 16-octet Marker (all
/// ones by default), a 2-octet Length covering the whole message, and a
/// 1-octet Type. Each field uses [`Field`] so that `compile()` can auto-fill
/// values the caller left unset while preserving anything the caller set
/// explicitly, including wrong-on-purpose values used to build malformed
/// messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BgpHeader {
    /// 16-octet Marker. Defaults to all ones (`[0xFF; 16]`).
    marker: Field<[u8; BGP_MARKER_LEN]>,
    /// 2-octet total message Length. Left unset so it is auto-filled.
    length: Field<u16>,
    /// 1-octet message Type code.
    message_type: Field<u8>,
}

impl BgpHeader {
    /// Create a header for the given message type with builder defaults:
    /// the marker defaults to all ones and the length is left unset so
    /// `compile()` fills it from the body size.
    pub(crate) fn new(message_type: u8) -> Self {
        Self {
            marker: Field::defaulted([0xFF; BGP_MARKER_LEN]),
            length: Field::unset(),
            message_type: Field::defaulted(message_type),
        }
    }

    /// Construct a header from decoded wire fields, marking every field as
    /// caller-supplied so auto-fill leaves them untouched.
    #[allow(dead_code)]
    pub(crate) fn from_decoded_parts(
        marker: [u8; BGP_MARKER_LEN],
        length: u16,
        message_type: u8,
    ) -> Self {
        Self {
            marker: Field::user(marker),
            length: Field::user(length),
            message_type: Field::user(message_type),
        }
    }

    /// Force a specific marker, overriding the default. Allows building
    /// malformed messages with a non-all-ones marker.
    #[allow(dead_code)]
    pub(crate) fn set_marker(&mut self, marker: [u8; BGP_MARKER_LEN]) {
        self.marker.set_user(marker);
    }

    /// Force a specific Length, overriding auto-fill. Allows building
    /// malformed messages whose declared length disagrees with the body.
    #[allow(dead_code)]
    pub(crate) fn set_length(&mut self, length: u16) {
        self.length.set_user(length);
    }

    /// Force a specific message Type, overriding the default.
    #[allow(dead_code)]
    pub(crate) fn set_type(&mut self, message_type: u8) {
        self.message_type.set_user(message_type);
    }

    /// The Marker to emit: the caller/default value if set, else all ones.
    pub(crate) fn effective_marker(&self) -> [u8; BGP_MARKER_LEN] {
        self.marker
            .value()
            .copied()
            .unwrap_or([0xFF; BGP_MARKER_LEN])
    }

    /// The Length to emit: the caller value if set, otherwise the header
    /// length plus `body_len` (the full on-wire message length).
    pub(crate) fn effective_length(&self, body_len: usize) -> u16 {
        match self.length.value() {
            Some(&length) => length,
            None => (BGP_HEADER_LEN + body_len) as u16,
        }
    }

    /// The message Type to emit: the caller/default value if set, else 0.
    pub(crate) fn effective_type(&self) -> u8 {
        self.message_type.value().copied().unwrap_or(0)
    }

    /// Append the 19-octet header to `out`: the 16-octet marker, the 2-octet
    /// big-endian length, and the 1-octet type. `body_len` is the length of
    /// the message body that follows the header.
    pub(crate) fn write_header(&self, body_len: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.effective_marker());
        out.extend_from_slice(&self.effective_length(body_len).to_be_bytes());
        out.push(self.effective_type());
    }
}

/// BGP OPEN message body (RFC 4271 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpOpen {
    /// Protocol version. Defaults to BGP-4.
    pub(crate) version: Field<u8>,
    /// Peer's 2-octet AS number.
    pub(crate) my_as: Field<u16>,
    /// Hold time in seconds.
    pub(crate) hold_time: Field<u16>,
    /// BGP identifier carried as an IPv4 address.
    pub(crate) bgp_id: Field<Ipv4Addr>,
    /// Length of the encoded optional-parameters bytes.
    pub(crate) opt_params_len: Field<u8>,
    /// OPEN optional parameters.
    pub(crate) params: Vec<BgpOptParam>,
    /// Decoded capabilities collected from type-2 optional parameters.
    pub(crate) capabilities: Vec<BgpCapability>,
}

impl BgpOpen {
    /// Create an OPEN body with BGP-4 as the default version and no optional
    /// parameters.
    pub(crate) fn new() -> Self {
        Self {
            version: Field::defaulted(BGP_VERSION),
            my_as: Field::unset(),
            hold_time: Field::unset(),
            bgp_id: Field::unset(),
            opt_params_len: Field::unset(),
            params: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    /// Construct an OPEN body from decoded wire fields, marking scalar fields as
    /// user-supplied so re-compilation preserves the decoded values.
    pub(crate) fn from_decoded_parts(
        version: u8,
        my_as: u16,
        hold_time: u16,
        bgp_id: Ipv4Addr,
        opt_params_len: u8,
        params: Vec<BgpOptParam>,
        capabilities: Vec<BgpCapability>,
    ) -> Self {
        Self {
            version: Field::user(version),
            my_as: Field::user(my_as),
            hold_time: Field::user(hold_time),
            bgp_id: Field::user(bgp_id),
            opt_params_len: Field::user(opt_params_len),
            params,
            capabilities,
        }
    }

    /// Append a typed optional parameter to this OPEN body.
    pub fn push_param(&mut self, param: BgpOptParam) {
        if param.param_type == BGP_OPT_PARAM_CAPABILITIES {
            if let Ok(capabilities) = decode_capabilities(&param.value) {
                self.capabilities.extend(capabilities);
            }
        }
        self.params.push(param);
    }

    /// Append an optional parameter with a raw type code and value.
    pub fn raw_param(&mut self, param_type: u8, value: Vec<u8>) {
        self.push_param(BgpOptParam::raw(param_type, value));
    }

    /// Append one RFC 5492 capabilities optional parameter.
    pub fn capabilities(&mut self, capabilities: impl IntoIterator<Item = BgpCapability>) {
        let capabilities = capabilities.into_iter().collect::<Vec<_>>();
        self.push_param(BgpOptParam::capabilities(encode_capabilities(
            &capabilities,
        )));
    }

    /// Encoded length of all optional parameters.
    pub(crate) fn params_len(&self) -> usize {
        self.params.iter().map(BgpOptParam::encoded_len).sum()
    }

    /// The on-wire OPEN body length, excluding the shared BGP header.
    pub(crate) fn body_len(&self) -> usize {
        10 + self.params_len()
    }

    /// The optional-parameters length to emit.
    pub(crate) fn effective_opt_params_len(&self) -> u8 {
        self.opt_params_len
            .value()
            .copied()
            .unwrap_or(self.params_len() as u8)
    }

    /// Append the RFC 4271 §4.2 OPEN body to `out`.
    pub(crate) fn write_body(&self, out: &mut Vec<u8>) {
        out.push(self.version.value().copied().unwrap_or(BGP_VERSION));
        out.extend_from_slice(&self.my_as.value().copied().unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.hold_time.value().copied().unwrap_or(0).to_be_bytes());
        out.extend_from_slice(
            &self
                .bgp_id
                .value()
                .copied()
                .unwrap_or(Ipv4Addr::UNSPECIFIED)
                .octets(),
        );
        out.push(self.effective_opt_params_len());
        for param in &self.params {
            param.encode(out);
        }
    }
}

/// BGP UPDATE message body (RFC 4271 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpUpdate {
    /// Withdrawn Routes, encoded as BGP prefixes.
    pub(crate) withdrawn: Vec<BgpPrefix>,
    /// Withdrawn Routes Length field.
    pub(crate) withdrawn_len: Field<u16>,
    /// Path Attributes.
    pub(crate) attributes: Vec<BgpPathAttribute>,
    /// Total Path Attribute Length field.
    pub(crate) attr_len: Field<u16>,
    /// Network Layer Reachability Information.
    pub(crate) nlri: Vec<BgpPrefix>,
}

impl BgpUpdate {
    /// Create an empty UPDATE body.
    pub(crate) fn new() -> Self {
        Self {
            withdrawn: Vec::new(),
            withdrawn_len: Field::unset(),
            attributes: Vec::new(),
            attr_len: Field::unset(),
            nlri: Vec::new(),
        }
    }

    /// Construct an UPDATE body from decoded wire fields, preserving the
    /// declared sub-length fields exactly for byte-for-byte re-compilation.
    pub(crate) fn from_decoded_parts(
        withdrawn: Vec<BgpPrefix>,
        withdrawn_len: u16,
        attributes: Vec<BgpPathAttribute>,
        attr_len: u16,
        nlri: Vec<BgpPrefix>,
    ) -> Self {
        Self {
            withdrawn,
            withdrawn_len: Field::user(withdrawn_len),
            attributes,
            attr_len: Field::user(attr_len),
            nlri,
        }
    }

    /// The encoded Withdrawn Routes byte length.
    pub(crate) fn withdrawn_len(&self) -> usize {
        prefixes_len(&self.withdrawn)
    }

    /// The encoded Path Attributes byte length.
    pub(crate) fn attributes_len(&self) -> usize {
        self.attributes
            .iter()
            .map(BgpPathAttribute::encoded_len)
            .sum()
    }

    /// The encoded NLRI byte length.
    pub(crate) fn nlri_len(&self) -> usize {
        prefixes_len(&self.nlri)
    }

    /// The on-wire UPDATE body length, excluding the shared BGP header.
    pub(crate) fn encoded_len(&self) -> usize {
        2 + self.withdrawn_len() + 2 + self.attributes_len() + self.nlri_len()
    }

    /// The Withdrawn Routes Length value to emit.
    pub(crate) fn effective_withdrawn_len(&self, encoded_len: usize) -> u16 {
        self.withdrawn_len
            .value()
            .copied()
            .unwrap_or(encoded_len as u16)
    }

    /// The Total Path Attribute Length value to emit.
    pub(crate) fn effective_attr_len(&self, encoded_len: usize) -> u16 {
        self.attr_len.value().copied().unwrap_or(encoded_len as u16)
    }

    /// Append the RFC 4271 §4.3 UPDATE body to `out`.
    pub(crate) fn write_body(&self, out: &mut Vec<u8>) {
        let mut withdrawn = Vec::new();
        for prefix in &self.withdrawn {
            prefix.encode_prefix(&mut withdrawn);
        }

        let mut attributes = Vec::new();
        for attribute in &self.attributes {
            attribute.encode(&mut attributes);
        }

        out.extend_from_slice(&self.effective_withdrawn_len(withdrawn.len()).to_be_bytes());
        out.extend_from_slice(&withdrawn);
        out.extend_from_slice(&self.effective_attr_len(attributes.len()).to_be_bytes());
        out.extend_from_slice(&attributes);
        for prefix in &self.nlri {
            prefix.encode_prefix(out);
        }
    }
}

fn prefixes_len(prefixes: &[BgpPrefix]) -> usize {
    prefixes.iter().map(|prefix| 1 + prefix.prefix.len()).sum()
}

/// BGP NOTIFICATION message body (RFC 4271 §4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpNotification {
    /// NOTIFICATION Error Code.
    pub(crate) error_code: Field<u8>,
    /// NOTIFICATION Error Subcode.
    pub(crate) error_subcode: Field<u8>,
    /// Optional diagnostic data carried after the code/subcode pair.
    pub(crate) data: Vec<u8>,
}

impl BgpNotification {
    /// Create a NOTIFICATION body with caller-supplied code and subcode.
    pub(crate) fn new(error_code: u8, error_subcode: u8) -> Self {
        Self {
            error_code: Field::user(error_code),
            error_subcode: Field::user(error_subcode),
            data: Vec::new(),
        }
    }

    /// The on-wire NOTIFICATION body length, excluding the shared BGP header.
    pub(crate) fn body_len(&self) -> usize {
        2 + self.data.len()
    }

    /// Append the RFC 4271 §4.5 NOTIFICATION body to `out`.
    pub(crate) fn write_body(&self, out: &mut Vec<u8>) {
        out.push(self.error_code.value().copied().unwrap_or(0));
        out.push(self.error_subcode.value().copied().unwrap_or(0));
        out.extend_from_slice(&self.data);
    }
}

/// BGP ROUTE-REFRESH message body (RFC 2918).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpRouteRefresh {
    /// Address Family Identifier.
    pub(crate) afi: Field<u16>,
    /// Reserved byte in RFC 2918, used as subtype by RFC 7313.
    pub(crate) subtype: Field<u8>,
    /// Subsequent Address Family Identifier.
    pub(crate) safi: Field<u8>,
}

impl BgpRouteRefresh {
    /// Create a ROUTE-REFRESH body for the given AFI/SAFI pair.
    pub(crate) fn new(afi: u16, safi: u8) -> Self {
        Self {
            afi: Field::user(afi),
            subtype: Field::defaulted(0),
            safi: Field::user(safi),
        }
    }

    /// Construct a ROUTE-REFRESH body from decoded wire fields, preserving the
    /// RFC 2918 reserved / RFC 7313 subtype byte exactly.
    pub(crate) fn from_decoded_parts(afi: u16, subtype: u8, safi: u8) -> Self {
        Self {
            afi: Field::user(afi),
            subtype: Field::user(subtype),
            safi: Field::user(safi),
        }
    }

    /// The on-wire ROUTE-REFRESH body length, excluding the shared BGP header.
    pub(crate) fn body_len(&self) -> usize {
        4
    }

    /// Append the RFC 2918 ROUTE-REFRESH body to `out`.
    pub(crate) fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.afi.value().copied().unwrap_or(0).to_be_bytes());
        out.push(self.subtype.value().copied().unwrap_or(0));
        out.push(self.safi.value().copied().unwrap_or(0));
    }
}

#[allow(dead_code)]
pub(crate) fn notification_name(code: u8, subcode: u8) -> String {
    let Some(code_name) = notification_code_name(code) else {
        return unknown_notification_name(code, subcode);
    };
    let Some(subcode_name) = notification_subcode_name(code, subcode) else {
        return unknown_notification_name(code, subcode);
    };

    format!("{code_name}/{subcode_name}")
}

fn unknown_notification_name(code: u8, subcode: u8) -> String {
    format!("code-{code}/subcode-{subcode}")
}

fn notification_code_name(code: u8) -> Option<&'static str> {
    const CODES: &[(u8, &str)] = &[
        (constants::NOTIFY_MESSAGE_HEADER_ERROR, "MessageHeaderError"),
        (constants::NOTIFY_OPEN_MESSAGE_ERROR, "OpenMessageError"),
        (constants::NOTIFY_UPDATE_MESSAGE_ERROR, "UpdateMessageError"),
        (constants::NOTIFY_HOLD_TIMER_EXPIRED, "HoldTimerExpired"),
        (constants::NOTIFY_FSM_ERROR, "FSMError"),
        (constants::NOTIFY_CEASE, "Cease"),
        (
            constants::NOTIFY_ROUTE_REFRESH_MESSAGE_ERROR,
            "RouteRefreshMessageError",
        ),
        (
            constants::NOTIFY_SEND_HOLD_TIMER_EXPIRED,
            "SendHoldTimerExpired",
        ),
        (constants::NOTIFY_LOSS_OF_LSDB_SYNC, "LossOfLSDBSync"),
    ];

    lookup_name(CODES, code)
}

fn notification_subcode_name(code: u8, subcode: u8) -> Option<&'static str> {
    const MESSAGE_HEADER_ERROR_SUBCODES: &[(u8, &str)] = &[
        (
            constants::MSG_HEADER_ERR_CONNECTION_NOT_SYNCHRONIZED,
            "ConnectionNotSynchronized",
        ),
        (
            constants::MSG_HEADER_ERR_BAD_MESSAGE_LENGTH,
            "BadMessageLength",
        ),
        (constants::MSG_HEADER_ERR_BAD_MESSAGE_TYPE, "BadMessageType"),
    ];
    const OPEN_MESSAGE_ERROR_SUBCODES: &[(u8, &str)] = &[
        (
            constants::OPEN_ERR_UNSUPPORTED_VERSION_NUMBER,
            "UnsupportedVersionNumber",
        ),
        (constants::OPEN_ERR_BAD_PEER_AS, "BadPeerAS"),
        (constants::OPEN_ERR_BAD_BGP_IDENTIFIER, "BadBgpIdentifier"),
        (
            constants::OPEN_ERR_UNSUPPORTED_OPTIONAL_PARAMETER,
            "UnsupportedOptionalParameter",
        ),
        (
            constants::OPEN_ERR_UNACCEPTABLE_HOLD_TIME,
            "UnacceptableHoldTime",
        ),
        (
            constants::OPEN_ERR_UNSUPPORTED_CAPABILITY,
            "UnsupportedCapability",
        ),
        (constants::OPEN_ERR_ROLE_MISMATCH, "RoleMismatch"),
    ];
    const UPDATE_MESSAGE_ERROR_SUBCODES: &[(u8, &str)] = &[
        (
            constants::UPDATE_ERR_MALFORMED_ATTRIBUTE_LIST,
            "MalformedAttributeList",
        ),
        (
            constants::UPDATE_ERR_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE,
            "UnrecognizedWellKnownAttribute",
        ),
        (
            constants::UPDATE_ERR_MISSING_WELL_KNOWN_ATTRIBUTE,
            "MissingWellKnownAttribute",
        ),
        (
            constants::UPDATE_ERR_ATTRIBUTE_FLAGS_ERROR,
            "AttributeFlagsError",
        ),
        (
            constants::UPDATE_ERR_ATTRIBUTE_LENGTH_ERROR,
            "AttributeLengthError",
        ),
        (
            constants::UPDATE_ERR_INVALID_ORIGIN_ATTRIBUTE,
            "InvalidOriginAttribute",
        ),
        (
            constants::UPDATE_ERR_INVALID_NEXT_HOP_ATTRIBUTE,
            "InvalidNextHopAttribute",
        ),
        (
            constants::UPDATE_ERR_OPTIONAL_ATTRIBUTE_ERROR,
            "OptionalAttributeError",
        ),
        (
            constants::UPDATE_ERR_INVALID_NETWORK_FIELD,
            "InvalidNetworkField",
        ),
        (constants::UPDATE_ERR_MALFORMED_AS_PATH, "MalformedAsPath"),
    ];
    const FSM_ERROR_SUBCODES: &[(u8, &str)] = &[
        (constants::FSM_ERR_UNSPECIFIED, "Unspecified"),
        (
            constants::FSM_ERR_UNEXPECTED_MESSAGE_IN_OPENSENT,
            "UnexpectedMessageInOpenSent",
        ),
        (
            constants::FSM_ERR_UNEXPECTED_MESSAGE_IN_OPENCONFIRM,
            "UnexpectedMessageInOpenConfirm",
        ),
        (
            constants::FSM_ERR_UNEXPECTED_MESSAGE_IN_ESTABLISHED,
            "UnexpectedMessageInEstablished",
        ),
    ];
    const CEASE_SUBCODES: &[(u8, &str)] = &[
        (
            constants::CEASE_MAX_PREFIXES_REACHED,
            "MaximumPrefixesReached",
        ),
        (
            constants::CEASE_ADMINISTRATIVE_SHUTDOWN,
            "AdministrativeShutdown",
        ),
        (constants::CEASE_PEER_DECONFIGURED, "PeerDeconfigured"),
        (constants::CEASE_ADMINISTRATIVE_RESET, "AdministrativeReset"),
        (constants::CEASE_CONNECTION_REJECTED, "ConnectionRejected"),
        (
            constants::CEASE_OTHER_CONFIGURATION_CHANGE,
            "OtherConfigurationChange",
        ),
        (
            constants::CEASE_CONNECTION_COLLISION_RESOLUTION,
            "ConnectionCollisionResolution",
        ),
        (constants::CEASE_OUT_OF_RESOURCES, "OutOfResources"),
        (constants::CEASE_HARD_RESET, "HardReset"),
        (constants::CEASE_BFD_DOWN, "BfdDown"),
    ];
    const ROUTE_REFRESH_ERROR_SUBCODES: &[(u8, &str)] = &[(
        constants::ROUTE_REFRESH_ERR_INVALID_MESSAGE_LENGTH,
        "InvalidMessageLength",
    )];

    let subcodes = match code {
        constants::NOTIFY_MESSAGE_HEADER_ERROR => MESSAGE_HEADER_ERROR_SUBCODES,
        constants::NOTIFY_OPEN_MESSAGE_ERROR => OPEN_MESSAGE_ERROR_SUBCODES,
        constants::NOTIFY_UPDATE_MESSAGE_ERROR => UPDATE_MESSAGE_ERROR_SUBCODES,
        constants::NOTIFY_FSM_ERROR => FSM_ERROR_SUBCODES,
        constants::NOTIFY_CEASE => CEASE_SUBCODES,
        constants::NOTIFY_ROUTE_REFRESH_MESSAGE_ERROR => ROUTE_REFRESH_ERROR_SUBCODES,
        _ => return None,
    };

    lookup_name(subcodes, subcode)
}

fn lookup_name(table: &[(u8, &'static str)], value: u8) -> Option<&'static str> {
    table
        .iter()
        .find_map(|(code, name)| (*code == value).then_some(*name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::bgp::constants::BGP_TYPE_KEEPALIVE;

    #[test]
    fn unset_length_is_header_plus_body() {
        let header = BgpHeader::new(BGP_TYPE_KEEPALIVE);

        assert_eq!(header.effective_length(0), BGP_HEADER_LEN as u16);
        assert_eq!(header.effective_length(10), (BGP_HEADER_LEN + 10) as u16);
    }

    #[test]
    fn user_set_length_is_preserved_verbatim() {
        let mut header = BgpHeader::new(BGP_TYPE_KEEPALIVE);
        header.set_length(4096);

        // Body size is ignored once the caller forces a length, even when the
        // forced value disagrees with the body (malformed-on-purpose).
        assert_eq!(header.effective_length(0), 4096);
        assert_eq!(header.effective_length(99), 4096);
    }

    #[test]
    fn default_marker_is_all_ones() {
        let header = BgpHeader::new(BGP_TYPE_KEEPALIVE);

        assert_eq!(header.effective_marker(), [0xFF; BGP_MARKER_LEN]);
    }

    #[test]
    fn set_marker_overrides_default() {
        let mut header = BgpHeader::new(BGP_TYPE_KEEPALIVE);
        header.set_marker([0x00; BGP_MARKER_LEN]);

        assert_eq!(header.effective_marker(), [0x00; BGP_MARKER_LEN]);
    }

    #[test]
    fn effective_type_reflects_constructor_and_override() {
        let mut header = BgpHeader::new(BGP_TYPE_KEEPALIVE);
        assert_eq!(header.effective_type(), BGP_TYPE_KEEPALIVE);

        header.set_type(99);
        assert_eq!(header.effective_type(), 99);
    }

    #[test]
    fn write_header_emits_marker_length_type() {
        let header = BgpHeader::new(BGP_TYPE_KEEPALIVE);
        let mut out = Vec::new();
        header.write_header(0, &mut out);

        assert_eq!(out.len(), BGP_HEADER_LEN);
        assert_eq!(&out[..BGP_MARKER_LEN], &[0xFF; BGP_MARKER_LEN]);
        // Length = 19 + 0, big-endian.
        assert_eq!(&out[BGP_MARKER_LEN..BGP_MARKER_LEN + 2], &[0x00, 0x13]);
        assert_eq!(out[BGP_MARKER_LEN + 2], BGP_TYPE_KEEPALIVE);
    }

    #[test]
    fn from_decoded_parts_marks_fields_user_set() {
        let header = BgpHeader::from_decoded_parts([0xAB; BGP_MARKER_LEN], 23, 2);

        assert_eq!(header.effective_marker(), [0xAB; BGP_MARKER_LEN]);
        // User-set length ignores body size.
        assert_eq!(header.effective_length(1000), 23);
        assert_eq!(header.effective_type(), 2);
    }

    #[test]
    fn notification_name_maps_known_pair() {
        assert_eq!(
            notification_name(
                constants::NOTIFY_CEASE,
                constants::CEASE_ADMINISTRATIVE_SHUTDOWN
            ),
            "Cease/AdministrativeShutdown"
        );
    }

    #[test]
    fn notification_name_preserves_unknown_pair_as_codes() {
        assert_eq!(
            notification_name(constants::NOTIFY_CEASE, 200),
            "code-6/subcode-200"
        );
    }
}
