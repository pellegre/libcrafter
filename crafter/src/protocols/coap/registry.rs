//! CoAP registry metadata.
//!
//! Labels and status classes are frozen by the reviewed IANA snapshot in
//! `.agents/docs/coap-codepoints.md`. Registry lookup is inspection metadata,
//! never a parser gate: every caller-supplied numeric value is returned in the
//! metadata and unknown values receive deterministic numeric fallback labels.

/// Source-backed assignment status for a CoAP registry value.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoapRegistryStatus {
    /// Value has a current stable assignment.
    Assigned,
    /// Value has a time-limited IANA assignment.
    Temporary,
    /// Value has no current registry assignment.
    Unassigned,
    /// Value is reserved and unavailable for ordinary use.
    Reserved,
    /// Value is reserved for examples and documentation.
    Documentation,
    /// Value is reserved for experimental use.
    Experimental,
    /// Value is assigned, but its semantic reference is not a final RFC.
    DraftBacked,
    /// Value is outside the source-backed registry domain.
    Unknown,
}

impl CoapRegistryStatus {
    /// Return whether the value has a current assignment of any maturity.
    pub const fn is_assigned(self) -> bool {
        matches!(self, Self::Assigned | Self::Temporary | Self::DraftBacked)
    }

    /// Stable lowercase label for summaries and show output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Temporary => "temporary",
            Self::Unassigned => "unassigned",
            Self::Reserved => "reserved",
            Self::Documentation => "documentation",
            Self::Experimental => "experimental",
            Self::DraftBacked => "draft-backed",
            Self::Unknown => "unknown",
        }
    }
}

/// Inspectable metadata for a numeric CoAP registry value.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoapRegistryMeta {
    /// Raw numeric value supplied by the caller or parsed from the packet.
    pub value: u64,
    /// Registered label or deterministic numeric fallback label.
    pub label: String,
    /// Source-backed assignment status.
    pub status: CoapRegistryStatus,
    /// Stable source reference from the reviewed registry snapshot, if known.
    pub reference: Option<&'static str>,
}

/// Return registry metadata for a one-octet CoAP Code value.
///
/// This is base-datagram metadata. Class-7 values remain reserved here; use
/// [`coap_signaling_code_meta`] when inspecting a reliable CoAP frame.
pub fn coap_code_meta(code: u8) -> CoapRegistryMeta {
    let assigned = match code {
        0x00 => Some(("Empty", "RFC 7252 Section 4.1")),
        0x01 => Some(("GET", "RFC 7252")),
        0x02 => Some(("POST", "RFC 7252")),
        0x03 => Some(("PUT", "RFC 7252")),
        0x04 => Some(("DELETE", "RFC 7252")),
        0x05 => Some(("FETCH", "RFC 8132")),
        0x06 => Some(("PATCH", "RFC 8132")),
        0x07 => Some(("iPATCH", "RFC 8132")),
        0x41 => Some(("Created", "RFC 7252")),
        0x42 => Some(("Deleted", "RFC 7252")),
        0x43 => Some(("Valid", "RFC 7252")),
        0x44 => Some(("Changed", "RFC 7252")),
        0x45 => Some(("Content", "RFC 7252")),
        0x5f => Some(("Continue", "RFC 7959")),
        0x80 => Some(("Bad Request", "RFC 7252")),
        0x81 => Some(("Unauthorized", "RFC 7252")),
        0x82 => Some(("Bad Option", "RFC 7252")),
        0x83 => Some(("Forbidden", "RFC 7252")),
        0x84 => Some(("Not Found", "RFC 7252")),
        0x85 => Some(("Method Not Allowed", "RFC 7252")),
        0x86 => Some(("Not Acceptable", "RFC 7252")),
        0x88 => Some(("Request Entity Incomplete", "RFC 7959")),
        0x89 => Some(("Conflict", "RFC 8132")),
        0x8c => Some(("Precondition Failed", "RFC 7252")),
        0x8d => Some(("Request Entity Too Large", "RFC 7252; RFC 7959")),
        0x8f => Some(("Unsupported Content-Format", "RFC 7252")),
        0x96 => Some(("Unprocessable Entity", "RFC 8132")),
        0x9d => Some(("Too Many Requests", "RFC 8516")),
        0xa0 => Some(("Internal Server Error", "RFC 7252")),
        0xa1 => Some(("Not Implemented", "RFC 7252")),
        0xa2 => Some(("Bad Gateway", "RFC 7252")),
        0xa3 => Some(("Service Unavailable", "RFC 7252")),
        0xa4 => Some(("Gateway Timeout", "RFC 7252")),
        0xa5 => Some(("Proxying Not Supported", "RFC 7252")),
        0xa8 => Some(("Hop Limit Reached", "RFC 8768")),
        _ => None,
    };

    if let Some((label, reference)) = assigned {
        return meta(code.into(), label, CoapRegistryStatus::Assigned, reference);
    }

    let class = code >> 5;
    let status = match class {
        0 | 2 | 4 | 5 => CoapRegistryStatus::Unassigned,
        1 | 3 | 6 | 7 => CoapRegistryStatus::Reserved,
        _ => unreachable!("a CoAP code class is three bits"),
    };
    fallback_meta(
        code.into(),
        format!("code-{class}.{:02}", code & 0x1f),
        status,
        "IANA CoRE Parameters; RFC 7252",
    )
}

/// Return registry metadata for a datagram CoAP Option Number.
pub fn coap_option_meta(number: u16) -> CoapRegistryMeta {
    let row = match number {
        1 => Some((
            "If-Match",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        3 => Some((
            "Uri-Host",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        4 => Some(("ETag", CoapRegistryStatus::Assigned, "RFC 7252; RFC 8613")),
        5 => Some((
            "If-None-Match",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        6 => Some((
            "Observe",
            CoapRegistryStatus::Assigned,
            "RFC 7641; RFC 8613",
        )),
        7 => Some((
            "Uri-Port",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        8 => Some((
            "Location-Path",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        9 => Some(("OSCORE", CoapRegistryStatus::Assigned, "RFC 8613")),
        11 => Some((
            "Uri-Path",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        12 => Some((
            "Content-Format",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        14 => Some((
            "Max-Age",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8516; RFC 8613",
        )),
        15 => Some((
            "Uri-Query",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        16 => Some(("Hop-Limit", CoapRegistryStatus::Assigned, "RFC 8768")),
        17 => Some(("Accept", CoapRegistryStatus::Assigned, "RFC 7252; RFC 8613")),
        19 => Some(("Q-Block1", CoapRegistryStatus::Assigned, "RFC 9177")),
        20 => Some((
            "Location-Query",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        21 => Some(("EDHOC", CoapRegistryStatus::Assigned, "RFC 9668")),
        23 => Some((
            "Block2",
            CoapRegistryStatus::Assigned,
            "RFC 7959; RFC 8323; RFC 8613",
        )),
        27 => Some((
            "Block1",
            CoapRegistryStatus::Assigned,
            "RFC 7959; RFC 8323; RFC 8613",
        )),
        28 => Some(("Size2", CoapRegistryStatus::Assigned, "RFC 7959; RFC 8613")),
        31 => Some(("Q-Block2", CoapRegistryStatus::Assigned, "RFC 9177")),
        35 => Some((
            "Proxy-Uri",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        39 => Some((
            "Proxy-Scheme",
            CoapRegistryStatus::Assigned,
            "RFC 7252; RFC 8613",
        )),
        60 => Some(("Size1", CoapRegistryStatus::Assigned, "RFC 7252; RFC 8613")),
        235 => Some((
            "Proxy-Cri",
            CoapRegistryStatus::DraftBacked,
            "RFC-ietf-core-href-29",
        )),
        239 => Some((
            "Proxy-Scheme-Number",
            CoapRegistryStatus::DraftBacked,
            "RFC-ietf-core-href-29",
        )),
        252 => Some(("Echo", CoapRegistryStatus::Assigned, "RFC 9175")),
        258 => Some((
            "No-Response",
            CoapRegistryStatus::Assigned,
            "RFC 7967; RFC 8613",
        )),
        292 => Some(("Request-Tag", CoapRegistryStatus::Assigned, "RFC 9175")),
        2049 => Some((
            "OCF-Accept-Content-Format-Version",
            CoapRegistryStatus::Assigned,
            "IANA CoRE Parameters",
        )),
        2053 => Some((
            "OCF-Content-Format-Version",
            CoapRegistryStatus::Assigned,
            "IANA CoRE Parameters",
        )),
        2055 => Some((
            "SCP82-Params",
            CoapRegistryStatus::Assigned,
            "GlobalPlatform GPC SPE 207",
        )),
        2056 => Some((
            "X-Admin-Protocol",
            CoapRegistryStatus::Assigned,
            "GSMA SGP.32 v1.3",
        )),
        _ => None,
    };

    if let Some((label, status, reference)) = row {
        return meta(number.into(), label, status, reference);
    }

    let status = match number {
        0 | 128 | 132 | 136 | 140 => CoapRegistryStatus::Reserved,
        65000..=u16::MAX => CoapRegistryStatus::Experimental,
        _ => CoapRegistryStatus::Unassigned,
    };
    fallback_meta(
        number.into(),
        format!("option-{number}"),
        status,
        "IANA CoRE Parameters; RFC 7252 Section 12.2",
    )
}

/// Whether an option is critical, derived from option-number bit zero.
pub const fn coap_option_is_critical(number: u16) -> bool {
    number & 1 != 0
}

/// Whether an option is unsafe to forward, derived from bit one.
pub const fn coap_option_is_unsafe(number: u16) -> bool {
    number & 2 != 0
}

/// Whether an option is safe to forward, derived from bit one.
pub const fn coap_option_is_safe_to_forward(number: u16) -> bool {
    !coap_option_is_unsafe(number)
}

/// Whether a safe-to-forward option is excluded from the cache key.
///
/// RFC 7252 Section 5.4.6 defines this directly from bits 1 through 4, so the
/// result applies equally to assigned, unassigned, and future option numbers.
pub const fn coap_option_is_no_cache_key(number: u16) -> bool {
    number & 0x1e == 0x1c
}

/// Return registry metadata for a CoAP Content-Format identifier.
///
/// Values above the 16-bit IANA registry domain remain inspectable with
/// `Unknown` status instead of being truncated or rejected.
pub fn coap_content_format_meta(value: u64) -> CoapRegistryMeta {
    if let Ok(index) = CONTENT_FORMAT_ROWS.binary_search_by_key(&value, |row| row.value) {
        let row = CONTENT_FORMAT_ROWS[index];
        return meta(row.value, row.label, row.status, row.reference);
    }

    let status = match value {
        1542..=1543 => CoapRegistryStatus::Reserved,
        0..=64997 => CoapRegistryStatus::Unassigned,
        64998..=64999 => CoapRegistryStatus::Documentation,
        65000..=65535 => CoapRegistryStatus::Experimental,
        _ => CoapRegistryStatus::Unknown,
    };
    let reference = if value <= 65535 {
        "IANA CoRE Parameters; RFC 9876"
    } else {
        "CoAP Content-Format registry domain is 0..=65535"
    };
    fallback_meta(value, format!("content-format-{value}"), status, reference)
}

/// Return registry metadata for a reliable-transport CoAP signaling Code.
pub fn coap_signaling_code_meta(code: u8) -> CoapRegistryMeta {
    let assigned = match code {
        0xe1 => Some(("CSM", "RFC 8323")),
        0xe2 => Some(("Ping", "RFC 8323")),
        0xe3 => Some(("Pong", "RFC 8323")),
        0xe4 => Some(("Release", "RFC 8323")),
        0xe5 => Some(("Abort", "RFC 8323")),
        _ => None,
    };
    if let Some((label, reference)) = assigned {
        return meta(code.into(), label, CoapRegistryStatus::Assigned, reference);
    }

    let class = code >> 5;
    let status = if class == 7 {
        CoapRegistryStatus::Unassigned
    } else {
        CoapRegistryStatus::Unknown
    };
    fallback_meta(
        code.into(),
        format!("signaling-{class}.{:02}", code & 0x1f),
        status,
        "IANA CoRE Parameters; RFC 8323",
    )
}

/// Return contextual registry metadata for a reliable CoAP signaling option.
///
/// Ordinary datagram option labels are deliberately not reused: the key is
/// the pair of the enclosing signaling Code byte and option number.
pub fn coap_signaling_option_meta(code: u8, number: u16) -> CoapRegistryMeta {
    let assigned = match (code, number) {
        (0xe1, 2) => Some(("Max-Message-Size", "RFC 8323")),
        (0xe1, 4) => Some(("Block-Wise-Transfer", "RFC 8323")),
        (0xe1, 6) => Some(("Extended-Token-Length", "RFC 8974")),
        (0xe2 | 0xe3, 2) => Some(("Custody", "RFC 8323")),
        (0xe4, 2) => Some(("Alternative-Address", "RFC 8323")),
        (0xe4, 4) => Some(("Hold-Off", "RFC 8323")),
        (0xe5, 2) => Some(("Bad-CSM-Option", "RFC 8323")),
        (0xe0..=0xff, 9) => Some(("OSCORE", "RFC 8613")),
        _ => None,
    };
    if let Some((label, reference)) = assigned {
        return meta(
            number.into(),
            label,
            CoapRegistryStatus::Assigned,
            reference,
        );
    }

    let status = if code >> 5 != 7 {
        CoapRegistryStatus::Unknown
    } else if number >= 65000 {
        CoapRegistryStatus::Experimental
    } else {
        CoapRegistryStatus::Unassigned
    };
    fallback_meta(
        number.into(),
        format!("signaling-option-{number}"),
        status,
        "IANA CoRE Parameters; RFC 8323",
    )
}

#[derive(Clone, Copy)]
struct RegistryRow {
    value: u64,
    label: &'static str,
    status: CoapRegistryStatus,
    reference: &'static str,
}

macro_rules! content_format_rows {
    ($(($value:literal, $label:literal, $status:ident, $reference:literal)),+ $(,)?) => {
        &[
            $(RegistryRow {
                value: $value,
                label: $label,
                status: CoapRegistryStatus::$status,
                reference: $reference,
            }),+
        ]
    };
}

// Sorted by numeric identifier for binary search. Media-type parameters and
// content codings are part of the display identity when IANA registers them.
const CONTENT_FORMAT_ROWS: &[RegistryRow] = content_format_rows![
    (
        0,
        "text/plain; charset=utf-8",
        Assigned,
        "RFC 2046; RFC 3676; RFC 5147"
    ),
    (
        16,
        "application/cose; cose-type=\"cose-encrypt0\"",
        Assigned,
        "RFC 9052"
    ),
    (
        17,
        "application/cose; cose-type=\"cose-mac0\"",
        Assigned,
        "RFC 9052"
    ),
    (
        18,
        "application/cose; cose-type=\"cose-sign1\"",
        Assigned,
        "RFC 9052"
    ),
    (19, "application/ace+cbor", Assigned, "RFC 9200"),
    (21, "image/gif", Assigned, "W3C GIF89a"),
    (22, "image/jpeg", Assigned, "ISO/IEC 10918-5"),
    (23, "image/png", Assigned, "W3C PNG"),
    (40, "application/link-format", Assigned, "RFC 6690"),
    (41, "application/xml", Assigned, "RFC 3023"),
    (
        42,
        "application/octet-stream",
        Assigned,
        "RFC 2045; RFC 2046"
    ),
    (
        47,
        "application/exi",
        Assigned,
        "W3C EXI 1.0 Second Edition"
    ),
    (50, "application/json", Assigned, "RFC 8259"),
    (51, "application/json-patch+json", Assigned, "RFC 6902"),
    (52, "application/merge-patch+json", Assigned, "RFC 7396"),
    (60, "application/cbor", Assigned, "RFC 8949"),
    (61, "application/cwt", Assigned, "RFC 8392"),
    (62, "application/multipart-core", Assigned, "RFC 8710"),
    (63, "application/cbor-seq", Assigned, "RFC 8742"),
    (64, "application/edhoc+cbor-seq", Assigned, "RFC 9528"),
    (65, "application/cid-edhoc+cbor-seq", Assigned, "RFC 9528"),
    (
        96,
        "application/cose; cose-type=\"cose-encrypt\"",
        Assigned,
        "RFC 9052"
    ),
    (
        97,
        "application/cose; cose-type=\"cose-mac\"",
        Assigned,
        "RFC 9052"
    ),
    (
        98,
        "application/cose; cose-type=\"cose-sign\"",
        Assigned,
        "RFC 9052"
    ),
    (101, "application/cose-key", Assigned, "RFC 9052"),
    (102, "application/cose-key-set", Assigned, "RFC 9052"),
    (110, "application/senml+json", Assigned, "RFC 8428"),
    (111, "application/sensml+json", Assigned, "RFC 8428"),
    (112, "application/senml+cbor", Assigned, "RFC 8428"),
    (113, "application/sensml+cbor", Assigned, "RFC 8428"),
    (114, "application/senml-exi", Assigned, "RFC 8428"),
    (115, "application/sensml-exi", Assigned, "RFC 8428"),
    (
        140,
        "application/yang-data+cbor; id=sid",
        Assigned,
        "RFC 9254"
    ),
    (256, "application/coap-group+json", Assigned, "RFC 7390"),
    (
        257,
        "application/concise-problem-details+cbor",
        Assigned,
        "RFC 9290"
    ),
    (258, "application/swid+cbor", Assigned, "RFC 9393"),
    (259, "application/pkixcmp", Assigned, "RFC 9482; RFC 9811"),
    (260, "application/yang-sid+json", Assigned, "RFC 9595"),
    (261, "application/ace-groupcomm+cbor", Assigned, "RFC 9594"),
    (262, "application/ace-trl+cbor", Assigned, "RFC 9770"),
    (263, "application/eat+cwt", Assigned, "RFC 9782"),
    (264, "application/eat+jwt", Assigned, "RFC 9782"),
    (265, "application/eat-bun+cbor", Assigned, "RFC 9782"),
    (266, "application/eat-bun+json", Assigned, "RFC 9782"),
    (267, "application/eat-ucs+cbor", Assigned, "RFC 9782"),
    (268, "application/eat-ucs+json", Assigned, "RFC 9782"),
    (269, "application/coap-eap", Assigned, "RFC 9820"),
    (
        270,
        "application/suit-report+cose",
        DraftBacked,
        "RFC-ietf-suit-report-19"
    ),
    (271, "application/dots+cbor", Assigned, "RFC 9132"),
    (
        272,
        "application/missing-blocks+cbor-seq",
        Assigned,
        "RFC 9177"
    ),
    (
        273,
        "application/cmw+cbor",
        DraftBacked,
        "RFC-ietf-rats-msg-wrap-22"
    ),
    (
        274,
        "application/cmw+json",
        DraftBacked,
        "RFC-ietf-rats-msg-wrap-22"
    ),
    (
        275,
        "application/cmw+cose",
        DraftBacked,
        "RFC-ietf-rats-msg-wrap-22"
    ),
    (
        276,
        "application/cmw+jws",
        DraftBacked,
        "RFC-ietf-rats-msg-wrap-22"
    ),
    (
        277,
        "application/scitt-statement+cose",
        Assigned,
        "RFC 9943"
    ),
    (278, "application/scitt-receipt+cose", Assigned, "RFC 9943"),
    (
        279,
        "application/statuslist+cwt",
        DraftBacked,
        "RFC-ietf-oauth-status-list-21"
    ),
    (
        280,
        "application/pkcs7-mime; smime-type=server-generated-key",
        Assigned,
        "RFC 7030; RFC 8551; RFC 9148"
    ),
    (
        281,
        "application/pkcs7-mime; smime-type=certs-only",
        Assigned,
        "RFC 8551; RFC 9148"
    ),
    (
        284,
        "application/pkcs8",
        Assigned,
        "RFC 5958; RFC 8551; RFC 9148"
    ),
    (285, "application/csrattrs", Assigned, "RFC 7030; RFC 9148"),
    (
        286,
        "application/pkcs10",
        Assigned,
        "RFC 5967; RFC 8551; RFC 9148"
    ),
    (287, "application/pkix-cert", Assigned, "RFC 2585; RFC 9148"),
    (290, "application/aif+cbor", Assigned, "RFC 9237"),
    (291, "application/aif+json", Assigned, "RFC 9237"),
    (
        292,
        "application/aif+cbor; toid=CRI-local-part",
        DraftBacked,
        "RFC-ietf-core-href-29"
    ),
    (
        293,
        "application/sd-cwt",
        Temporary,
        "draft-ietf-spice-sd-cwt-06; expires 2026-12-08"
    ),
    (
        294,
        "application/kb+cwt",
        Temporary,
        "draft-ietf-spice-sd-cwt-06; expires 2026-12-08"
    ),
    (
        295,
        "application/measured-component+cbor",
        DraftBacked,
        "RFC-ietf-rats-eat-measured-component-12"
    ),
    (
        296,
        "application/measured-component+json",
        DraftBacked,
        "RFC-ietf-rats-eat-measured-component-12"
    ),
    (
        297,
        "application/aif+cbor; toid=oscore-gname; tperm=oscore-gperm",
        DraftBacked,
        "RFC-ietf-ace-key-groupcomm-oscore-21"
    ),
    (
        298,
        "application/aif+json; toid=oscore-gname; tperm=oscore-gperm",
        DraftBacked,
        "RFC-ietf-ace-key-groupcomm-oscore-21"
    ),
    (310, "application/senml+xml", Assigned, "RFC 8428"),
    (311, "application/sensml+xml", Assigned, "RFC 8428"),
    (320, "application/senml-etch+json", Assigned, "RFC 8790"),
    (322, "application/senml-etch+cbor", Assigned, "RFC 8790"),
    (340, "application/yang-data+cbor", Assigned, "RFC 9254"),
    (
        341,
        "application/yang-data+cbor; id=name",
        Assigned,
        "RFC 9254"
    ),
    (
        432,
        "application/td+json",
        Assigned,
        "W3C WoT Thing Description 1.1"
    ),
    (
        433,
        "application/tm+json",
        Assigned,
        "W3C WoT Thing Description 1.1"
    ),
    (434, "application/sdf+json", Assigned, "RFC 9880"),
    (
        553,
        "application/dns-message",
        Assigned,
        "RFC 8484; RFC 9953"
    ),
    (601, "application/uccs+cbor", Assigned, "RFC 9781"),
    (
        836,
        "application/voucher+cose",
        Temporary,
        "draft-ietf-anima-constrained-voucher-23; expires 2027-04-12"
    ),
    (
        10000,
        "application/vnd.ocf+cbor",
        Assigned,
        "IANA CoRE Parameters"
    ),
    (10001, "application/oscore", Assigned, "RFC 8613"),
    (10002, "application/javascript", Assigned, "RFC 4329"),
    (
        10003,
        "application/eat+cwt; eat_profile=\"tag:psacertified.org,2023:psa#tfm\"",
        Assigned,
        "RFC 9783"
    ),
    (
        10004,
        "application/eat+cwt; eat_profile=\"tag:psacertified.org,2019:psa#legacy\"",
        Assigned,
        "RFC 9783"
    ),
    (
        10005,
        "application/eat+cwt; eat_profile=2.16.840.1.113741.1.16.1",
        Assigned,
        "RFC 9782; draft-cds-rats-intel-corim-profile-05"
    ),
    (
        10006,
        "application/vnd.oms.cellular-cose-content+cbor",
        Assigned,
        "OMS Group"
    ),
    (
        10007,
        "application/syslog-msg",
        Assigned,
        "IANA Media Types registration"
    ),
    (
        10570,
        "application/toc+cbor",
        Assigned,
        "TCG CE-Binding Section 6.3.1"
    ),
    (
        10571,
        "application/ce+cbor",
        Assigned,
        "TCG CE-Binding Section 6.3.2"
    ),
    (
        10572,
        "application/toc+cbor; profile=2.16.840.1.113741.1.16.1",
        Assigned,
        "TCG DICE Concise Evidence Binding for SPDM"
    ),
    (
        10573,
        "application/ce+cbor; profile=2.16.840.1.113741.1.16.1",
        Assigned,
        "TCG DICE Concise Evidence Binding for SPDM"
    ),
    (
        11050,
        "application/json; content-coding=deflate",
        Assigned,
        "RFC 8259; RFC 9110"
    ),
    (
        11060,
        "application/cbor; content-coding=deflate",
        Assigned,
        "RFC 8949; RFC 9110"
    ),
    (
        11542,
        "application/vnd.oma.lwm2m+tlv",
        Assigned,
        "OMA LightweightM2M 1.0"
    ),
    (
        11543,
        "application/vnd.oma.lwm2m+json",
        Assigned,
        "OMA LightweightM2M 1.0"
    ),
    (
        11544,
        "application/vnd.oma.lwm2m+cbor",
        Assigned,
        "OMA LightweightM2M 1.2"
    ),
    (
        12000,
        "text/plain;charset=utf-8; content-coding=zstd",
        Assigned,
        "IANA CoRE Parameters"
    ),
    (
        12041,
        "application/xml; content-coding=zstd",
        Assigned,
        "IANA CoRE Parameters"
    ),
    (
        12050,
        "application/json; content-coding=zstd",
        Assigned,
        "IANA CoRE Parameters"
    ),
    (20000, "text/css", Assigned, "RFC 2318"),
    (
        20001,
        "application/vnd.as207960.vas.config+jer",
        Assigned,
        "IANA CoRE Parameters"
    ),
    (
        20002,
        "application/vnd.as207960.vas.config+uper",
        Assigned,
        "IANA CoRE Parameters"
    ),
    (
        20003,
        "application/vnd.as207960.vas.tap+jer",
        Assigned,
        "IANA CoRE Parameters"
    ),
    (
        20004,
        "application/vnd.as207960.vas.tap+uper",
        Assigned,
        "IANA CoRE Parameters"
    ),
    (
        30000,
        "image/svg+xml",
        Assigned,
        "W3C SVG media-type registration"
    ),
];

fn meta(
    value: u64,
    label: &'static str,
    status: CoapRegistryStatus,
    reference: &'static str,
) -> CoapRegistryMeta {
    CoapRegistryMeta {
        value,
        label: label.to_owned(),
        status,
        reference: Some(reference),
    }
}

fn fallback_meta(
    value: u64,
    label: String,
    status: CoapRegistryStatus,
    reference: &'static str,
) -> CoapRegistryMeta {
    CoapRegistryMeta {
        value,
        label,
        status,
        reference: Some(reference),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_metadata_is_stable_and_non_rejecting() {
        let cases = [
            (CoapRegistryStatus::Assigned, "assigned", true),
            (CoapRegistryStatus::Temporary, "temporary", true),
            (CoapRegistryStatus::Unassigned, "unassigned", false),
            (CoapRegistryStatus::Reserved, "reserved", false),
            (CoapRegistryStatus::Documentation, "documentation", false),
            (CoapRegistryStatus::Experimental, "experimental", false),
            (CoapRegistryStatus::DraftBacked, "draft-backed", true),
            (CoapRegistryStatus::Unknown, "unknown", false),
        ];

        for (status, label, assigned) in cases {
            assert_eq!(status.label(), label);
            assert_eq!(status.is_assigned(), assigned);
        }
    }

    #[test]
    fn code_registry_covers_assignments_gaps_and_reserved_boundaries() {
        let cases = [
            (0x00, "Empty", CoapRegistryStatus::Assigned),
            (0x01, "GET", CoapRegistryStatus::Assigned),
            (0x07, "iPATCH", CoapRegistryStatus::Assigned),
            (0x08, "code-0.08", CoapRegistryStatus::Unassigned),
            (0x1f, "code-0.31", CoapRegistryStatus::Unassigned),
            (0x20, "code-1.00", CoapRegistryStatus::Reserved),
            (0x3f, "code-1.31", CoapRegistryStatus::Reserved),
            (0x40, "code-2.00", CoapRegistryStatus::Unassigned),
            (0x41, "Created", CoapRegistryStatus::Assigned),
            (0x5f, "Continue", CoapRegistryStatus::Assigned),
            (0x60, "code-3.00", CoapRegistryStatus::Reserved),
            (0x87, "code-4.07", CoapRegistryStatus::Unassigned),
            (0x9d, "Too Many Requests", CoapRegistryStatus::Assigned),
            (0xa8, "Hop Limit Reached", CoapRegistryStatus::Assigned),
            (0xbf, "code-5.31", CoapRegistryStatus::Unassigned),
            (0xe1, "code-7.01", CoapRegistryStatus::Reserved),
            (0xff, "code-7.31", CoapRegistryStatus::Reserved),
        ];

        for (value, label, status) in cases {
            let metadata = coap_code_meta(value);
            assert_eq!(metadata.value, u64::from(value));
            assert_eq!(metadata.label, label);
            assert_eq!(metadata.status, status);
        }
    }

    #[test]
    fn option_registry_covers_rows_and_allocation_boundaries() {
        let cases = [
            (0, "option-0", CoapRegistryStatus::Reserved),
            (1, "If-Match", CoapRegistryStatus::Assigned),
            (2, "option-2", CoapRegistryStatus::Unassigned),
            (9, "OSCORE", CoapRegistryStatus::Assigned),
            (128, "option-128", CoapRegistryStatus::Reserved),
            (235, "Proxy-Cri", CoapRegistryStatus::DraftBacked),
            (292, "Request-Tag", CoapRegistryStatus::Assigned),
            (
                2049,
                "OCF-Accept-Content-Format-Version",
                CoapRegistryStatus::Assigned,
            ),
            (64999, "option-64999", CoapRegistryStatus::Unassigned),
            (65000, "option-65000", CoapRegistryStatus::Experimental),
            (u16::MAX, "option-65535", CoapRegistryStatus::Experimental),
        ];

        for (value, label, status) in cases {
            let metadata = coap_option_meta(value);
            assert_eq!(metadata.value, u64::from(value));
            assert_eq!(metadata.label, label);
            assert_eq!(metadata.status, status);
        }
    }

    #[test]
    fn option_properties_are_derived_for_known_and_future_numbers() {
        let cases = [
            (12, false, false, true, false),
            (13, true, false, true, false),
            (14, false, true, false, false),
            (15, true, true, false, false),
            (28, false, false, true, true),
            (29, true, false, true, true),
            (65021, true, false, true, true),
        ];

        for (number, critical, unsafe_to_forward, safe_to_forward, no_cache_key) in cases {
            assert_eq!(coap_option_is_critical(number), critical);
            assert_eq!(coap_option_is_unsafe(number), unsafe_to_forward);
            assert_eq!(coap_option_is_safe_to_forward(number), safe_to_forward);
            assert_eq!(coap_option_is_no_cache_key(number), no_cache_key);
        }
    }

    #[test]
    fn content_format_registry_covers_maturity_and_range_boundaries() {
        let cases = [
            (0, "text/plain; charset=utf-8", CoapRegistryStatus::Assigned),
            (1, "content-format-1", CoapRegistryStatus::Unassigned),
            (40, "application/link-format", CoapRegistryStatus::Assigned),
            (
                270,
                "application/suit-report+cose",
                CoapRegistryStatus::DraftBacked,
            ),
            (293, "application/sd-cwt", CoapRegistryStatus::Temporary),
            (
                836,
                "application/voucher+cose",
                CoapRegistryStatus::Temporary,
            ),
            (1542, "content-format-1542", CoapRegistryStatus::Reserved),
            (10001, "application/oscore", CoapRegistryStatus::Assigned),
            (
                64997,
                "content-format-64997",
                CoapRegistryStatus::Unassigned,
            ),
            (
                64998,
                "content-format-64998",
                CoapRegistryStatus::Documentation,
            ),
            (
                65000,
                "content-format-65000",
                CoapRegistryStatus::Experimental,
            ),
            (
                65535,
                "content-format-65535",
                CoapRegistryStatus::Experimental,
            ),
            (65536, "content-format-65536", CoapRegistryStatus::Unknown),
        ];

        for (value, label, status) in cases {
            let metadata = coap_content_format_meta(value);
            assert_eq!(metadata.value, value);
            assert_eq!(metadata.label, label);
            assert_eq!(metadata.status, status);
        }
    }

    #[test]
    fn signaling_registries_are_contextual_and_lossless() {
        let code_cases = [
            (0xe0, "signaling-7.00", CoapRegistryStatus::Unassigned),
            (0xe1, "CSM", CoapRegistryStatus::Assigned),
            (0xe5, "Abort", CoapRegistryStatus::Assigned),
            (0xe6, "signaling-7.06", CoapRegistryStatus::Unassigned),
            (0xff, "signaling-7.31", CoapRegistryStatus::Unassigned),
            (0x01, "signaling-0.01", CoapRegistryStatus::Unknown),
        ];
        for (value, label, status) in code_cases {
            let metadata = coap_signaling_code_meta(value);
            assert_eq!(metadata.value, u64::from(value));
            assert_eq!(metadata.label, label);
            assert_eq!(metadata.status, status);
        }

        let option_cases = [
            (0xe1, 2, "Max-Message-Size", CoapRegistryStatus::Assigned),
            (0xe1, 4, "Block-Wise-Transfer", CoapRegistryStatus::Assigned),
            (
                0xe1,
                6,
                "Extended-Token-Length",
                CoapRegistryStatus::Assigned,
            ),
            (0xe2, 2, "Custody", CoapRegistryStatus::Assigned),
            (0xe3, 2, "Custody", CoapRegistryStatus::Assigned),
            (0xe4, 2, "Alternative-Address", CoapRegistryStatus::Assigned),
            (0xe4, 4, "Hold-Off", CoapRegistryStatus::Assigned),
            (0xe5, 2, "Bad-CSM-Option", CoapRegistryStatus::Assigned),
            (0xe3, 9, "OSCORE", CoapRegistryStatus::Assigned),
            (
                0xe2,
                4,
                "signaling-option-4",
                CoapRegistryStatus::Unassigned,
            ),
            (
                0xe1,
                65000,
                "signaling-option-65000",
                CoapRegistryStatus::Experimental,
            ),
            (0x01, 2, "signaling-option-2", CoapRegistryStatus::Unknown),
        ];
        for (code, number, label, status) in option_cases {
            let metadata = coap_signaling_option_meta(code, number);
            assert_eq!(metadata.value, u64::from(number));
            assert_eq!(metadata.label, label);
            assert_eq!(metadata.status, status);
        }

        // Signaling number 2 has four different contextual meanings and must
        // never inherit an ordinary CoAP option label.
        assert_eq!(
            coap_signaling_option_meta(0xe1, 2).label,
            "Max-Message-Size"
        );
        assert_eq!(coap_signaling_option_meta(0xe2, 2).label, "Custody");
        assert_eq!(
            coap_signaling_option_meta(0xe4, 2).label,
            "Alternative-Address"
        );
        assert_eq!(coap_signaling_option_meta(0xe5, 2).label, "Bad-CSM-Option");
        assert_ne!(coap_option_meta(2).label, "Max-Message-Size");
    }
}
