//! SSDP registry metadata.
//!
//! Source-gated by `.agents/docs/ssdp-source-manifest.md` and
//! `.agents/docs/ssdp-codepoints.md`. This module is metadata only: it names
//! source-backed SSDP values, keeps unknown values inspectable with stable
//! fallback labels, and records excluded or ambiguous values without rejecting
//! them.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use super::constants::{
    SSDP_HEADER_BOOTID, SSDP_HEADER_CACHE_CONTROL, SSDP_HEADER_CONFIGID, SSDP_HEADER_CPFN,
    SSDP_HEADER_CPUUID, SSDP_HEADER_DATE, SSDP_HEADER_EXT, SSDP_HEADER_HOST, SSDP_HEADER_LOCATION,
    SSDP_HEADER_MAN, SSDP_HEADER_MX, SSDP_HEADER_NEXTBOOTID, SSDP_HEADER_NLS_SUFFIX,
    SSDP_HEADER_NT, SSDP_HEADER_NTS, SSDP_HEADER_OPT, SSDP_HEADER_SEARCHPORT,
    SSDP_HEADER_SECURELOCATION, SSDP_HEADER_SERVER, SSDP_HEADER_ST, SSDP_HEADER_TCPPORT,
    SSDP_HEADER_USER_AGENT, SSDP_HEADER_USN, SSDP_IPV4_MULTICAST, SSDP_IPV4_MULTICAST_HOST,
    SSDP_IPV6_LINK_LOCAL_HOST, SSDP_IPV6_LINK_LOCAL_MULTICAST, SSDP_IPV6_MULTICAST_PATTERN,
    SSDP_IPV6_SITE_LOCAL_HOST, SSDP_IPV6_SITE_LOCAL_MULTICAST, SSDP_METHOD_M_SEARCH,
    SSDP_METHOD_NOTIFY, SSDP_REASON_OK, SSDP_SERVICE_NAME, SSDP_STATUS_OK, SSDP_UDP_PORT,
};

const METHOD_HTTP_SEARCH: &str = "SEARCH";
const HEADER_SVCID: &str = "SVCID";
const HEADER_SEQ: &str = "SEQ";
const HEADER_LVL: &str = "LVL";
const HEADER_CONTENT_LENGTH: &str = "CONTENT-LENGTH";
const HEADER_CONTENT_TYPE: &str = "CONTENT-TYPE";
const SSDP_CONFIGID_RESERVED_FIRST: u32 = 16_777_216;
const SSDP_IPV6_GLOBAL_MULTICAST: &str = "ff0e::c";
const SSDP_IPV6_GLOBAL_HOST: &str = "[ff0e::c]:1900";
const SSDP_IPV6_ORG_LOCAL_MULTICAST: &str = "ff08::c";

const ASSIGNED_HEADER_NAMES: &[&str] = &[
    SSDP_HEADER_HOST,
    SSDP_HEADER_CACHE_CONTROL,
    SSDP_HEADER_LOCATION,
    SSDP_HEADER_NT,
    SSDP_HEADER_NTS,
    SSDP_HEADER_SERVER,
    SSDP_HEADER_USN,
    SSDP_HEADER_BOOTID,
    SSDP_HEADER_CONFIGID,
    SSDP_HEADER_SEARCHPORT,
    SSDP_HEADER_NEXTBOOTID,
    SSDP_HEADER_SECURELOCATION,
    SSDP_HEADER_MAN,
    SSDP_HEADER_MX,
    SSDP_HEADER_ST,
    SSDP_HEADER_USER_AGENT,
    SSDP_HEADER_TCPPORT,
    SSDP_HEADER_CPFN,
    SSDP_HEADER_CPUUID,
    SSDP_HEADER_DATE,
    SSDP_HEADER_EXT,
    SSDP_HEADER_OPT,
];

const EXCLUDED_EVENTING_HEADERS: &[&str] = &[
    HEADER_SVCID,
    HEADER_SEQ,
    HEADER_LVL,
    HEADER_CONTENT_LENGTH,
    HEADER_CONTENT_TYPE,
];

/// Source-backed SSDP registry assignment status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum SsdpRegistryStatus {
    /// Assigned by the reviewed UPnP/IANA sources for SSDP discovery.
    Assigned,
    /// Source-backed extension form, but not a fixed full codepoint.
    Extension,
    /// Not named by the reviewed SSDP sources; preserve verbatim.
    Unknown,
    /// Reserved by a reviewed SSDP source.
    Reserved,
    /// Historical value superseded by current SSDP source guidance.
    Obsolete,
    /// Source evidence exists but is not enough for a default helper.
    Ambiguous,
    /// Source-backed value that is deliberately outside SSDP discovery helpers.
    Excluded,
}

impl SsdpRegistryStatus {
    /// Stable lowercase status label.
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Extension => "extension",
            Self::Unknown => "unknown",
            Self::Reserved => "reserved",
            Self::Obsolete => "obsolete",
            Self::Ambiguous => "ambiguous",
            Self::Excluded => "excluded",
        }
    }
}

impl fmt::Display for SsdpRegistryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// SSDP method metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SsdpMethodMeta {
    /// Preserved method token.
    pub(super) token: String,
    /// Stable diagnostic label.
    pub(super) label: String,
    /// Registry status.
    pub(super) status: SsdpRegistryStatus,
}

/// Return metadata for an SSDP method token.
///
/// `NOTIFY` and `M-SEARCH` are UPnP-defined SSDP methods. The registered HTTP
/// `SEARCH` method is explicitly not an SSDP alias; every other token receives
/// a stable unknown fallback label and remains preservable.
pub(super) fn ssdp_method_meta(token: &str) -> SsdpMethodMeta {
    let (label, status) = match token {
        SSDP_METHOD_NOTIFY => (SSDP_METHOD_NOTIFY.to_string(), SsdpRegistryStatus::Assigned),
        SSDP_METHOD_M_SEARCH => (
            SSDP_METHOD_M_SEARCH.to_string(),
            SsdpRegistryStatus::Assigned,
        ),
        METHOD_HTTP_SEARCH => (
            format!("excluded-http-method:{METHOD_HTTP_SEARCH}"),
            SsdpRegistryStatus::Excluded,
        ),
        _ => (
            format!("unknown-method:{token}"),
            SsdpRegistryStatus::Unknown,
        ),
    };

    SsdpMethodMeta {
        token: token.to_string(),
        label,
        status,
    }
}

/// Return a stable SSDP method label.
pub(super) fn ssdp_method_label(token: &str) -> String {
    ssdp_method_meta(token).label
}

/// SSDP status-code metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SsdpStatusMeta {
    /// Preserved status code.
    pub(super) code: u16,
    /// Stable diagnostic label.
    pub(super) label: String,
    /// Registry status.
    pub(super) status: SsdpRegistryStatus,
}

/// Return metadata for an SSDP status code.
///
/// `200 OK` is the only UPnP discovery response status helper. Generic HTTP
/// error statuses are classified as excluded instead of promoted to SSDP
/// helpers; every other three-digit value receives a stable unknown label.
pub(super) fn ssdp_status_meta(code: u16) -> SsdpStatusMeta {
    let (label, status) = match code {
        SSDP_STATUS_OK => (
            format!("{SSDP_STATUS_OK} {SSDP_REASON_OK}"),
            SsdpRegistryStatus::Assigned,
        ),
        400..=599 => (
            format!("excluded-http-error-status:{code:03}"),
            SsdpRegistryStatus::Excluded,
        ),
        0..=999 => (
            format!("unknown-status:{code:03}"),
            SsdpRegistryStatus::Unknown,
        ),
        _ => (
            format!("unknown-status:{code}"),
            SsdpRegistryStatus::Unknown,
        ),
    };

    SsdpStatusMeta {
        code,
        label,
        status,
    }
}

/// Return a stable SSDP status-code label.
pub(super) fn ssdp_status_label(code: u16) -> String {
    ssdp_status_meta(code).label
}

/// SSDP header-name metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SsdpHeaderNameMeta {
    /// Preserved header-name spelling.
    pub(super) name: String,
    /// Stable diagnostic label.
    pub(super) label: String,
    /// Registry status.
    pub(super) status: SsdpRegistryStatus,
}

/// Return metadata for an SSDP header field name.
///
/// Fixed UPnP discovery headers are matched case-insensitively. Namespace
/// prefixed `*-NLS` fields are recognized as source-backed extension fields.
/// Eventing-only HTTP-like headers are excluded from SSDP discovery helpers;
/// vendor and unknown fields remain preservable unknown metadata.
pub(super) fn ssdp_header_name_meta(name: &str) -> SsdpHeaderNameMeta {
    let (label, status) = if let Some(canonical) = assigned_header_name(name) {
        (canonical.to_string(), SsdpRegistryStatus::Assigned)
    } else if let Some(namespace) = nls_namespace_prefix(name) {
        (
            format!("nls-extension-header:{namespace}"),
            SsdpRegistryStatus::Extension,
        )
    } else if let Some(canonical) = excluded_eventing_header_name(name) {
        (
            format!("excluded-eventing-header:{canonical}"),
            SsdpRegistryStatus::Excluded,
        )
    } else {
        let fallback_name = name.to_ascii_lowercase();
        let prefix = if name.contains('.') {
            "vendor-header"
        } else {
            "unknown-header"
        };
        (
            format!("{prefix}:{fallback_name}"),
            SsdpRegistryStatus::Unknown,
        )
    };

    SsdpHeaderNameMeta {
        name: name.to_string(),
        label,
        status,
    }
}

/// Return a stable SSDP header-name label.
pub(super) fn ssdp_header_name_label(name: &str) -> String {
    ssdp_header_name_meta(name).label
}

/// SSDP `CONFIGID.UPNP.ORG` value metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SsdpConfigIdMeta {
    /// Preserved numeric value.
    pub(super) value: u32,
    /// Stable diagnostic label.
    pub(super) label: String,
    /// Registry status.
    pub(super) status: SsdpRegistryStatus,
}

/// Return metadata for a `CONFIGID.UPNP.ORG` value.
///
/// UPnP reserves values above `16777215` for future Technical Committee
/// assignment. The packet layer records that fact without rejecting the value.
pub(super) fn ssdp_config_id_meta(value: u32) -> SsdpConfigIdMeta {
    let (label, status) = if value < SSDP_CONFIGID_RESERVED_FIRST {
        (format!("configid:{value}"), SsdpRegistryStatus::Assigned)
    } else {
        (
            format!("reserved-configid:{value}"),
            SsdpRegistryStatus::Reserved,
        )
    };

    SsdpConfigIdMeta {
        value,
        label,
        status,
    }
}

/// Return a stable SSDP `CONFIGID.UPNP.ORG` value label.
pub(super) fn ssdp_config_id_label(value: u32) -> String {
    ssdp_config_id_meta(value).label
}

/// Transport protocol for SSDP service metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum SsdpServiceTransport {
    /// UDP transport.
    Udp,
    /// TCP transport.
    Tcp,
}

impl SsdpServiceTransport {
    const fn label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// SSDP service-port metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SsdpServiceMeta {
    /// Transport protocol.
    pub(super) transport: SsdpServiceTransport,
    /// Preserved port number.
    pub(super) port: u16,
    /// Stable diagnostic label.
    pub(super) label: String,
    /// Registry status.
    pub(super) status: SsdpRegistryStatus,
}

/// Return metadata for an SSDP-related service port.
///
/// The packet layer admits only `ssdp/udp` port 1900 as an SSDP service
/// helper. IANA's `ssdp/tcp` registration is recorded as excluded here because
/// this module does not provide a TCP SSDP surface.
pub(super) fn ssdp_service_meta(transport: SsdpServiceTransport, port: u16) -> SsdpServiceMeta {
    let (label, status) = match (transport, port) {
        (SsdpServiceTransport::Udp, SSDP_UDP_PORT) => (
            format!("{SSDP_SERVICE_NAME}/{}:{SSDP_UDP_PORT}", transport.label()),
            SsdpRegistryStatus::Assigned,
        ),
        (SsdpServiceTransport::Tcp, SSDP_UDP_PORT) => (
            format!(
                "excluded-{SSDP_SERVICE_NAME}/{}:{SSDP_UDP_PORT}",
                transport.label()
            ),
            SsdpRegistryStatus::Excluded,
        ),
        _ => (
            format!("unknown-{}-service:{port}", transport.label()),
            SsdpRegistryStatus::Unknown,
        ),
    };

    SsdpServiceMeta {
        transport,
        port,
        label,
        status,
    }
}

/// Return a stable SSDP service-port label.
pub(super) fn ssdp_service_label(transport: SsdpServiceTransport, port: u16) -> String {
    ssdp_service_meta(transport, port).label
}

/// SSDP multicast destination metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SsdpMulticastMeta {
    /// Preserved multicast destination spelling.
    pub(super) value: String,
    /// Stable diagnostic label.
    pub(super) label: String,
    /// Registry status.
    pub(super) status: SsdpRegistryStatus,
}

/// Return metadata for an SSDP multicast destination or HOST literal.
///
/// Link-local and site-local IPv6 groups are source-backed SSDP helpers.
/// Global-scope SSDP multicast is preserved as obsolete because later UPnP
/// guidance prohibits Global scoped multicast messages. Other concrete IPv6
/// scopes under the IANA SSDP pattern stay ambiguous instead of becoming
/// defaults.
pub(super) fn ssdp_multicast_meta(value: &str) -> SsdpMulticastMeta {
    let lower = value.to_ascii_lowercase();
    let (label, status) = match lower.as_str() {
        SSDP_IPV4_MULTICAST => (
            "ssdp-ipv4-multicast".to_string(),
            SsdpRegistryStatus::Assigned,
        ),
        SSDP_IPV4_MULTICAST_HOST => (
            "ssdp-ipv4-multicast-host".to_string(),
            SsdpRegistryStatus::Assigned,
        ),
        SSDP_IPV6_LINK_LOCAL_MULTICAST => (
            "ssdp-ipv6-link-local-multicast".to_string(),
            SsdpRegistryStatus::Assigned,
        ),
        SSDP_IPV6_LINK_LOCAL_HOST => (
            "ssdp-ipv6-link-local-host".to_string(),
            SsdpRegistryStatus::Assigned,
        ),
        SSDP_IPV6_SITE_LOCAL_MULTICAST => (
            "ssdp-ipv6-site-local-multicast".to_string(),
            SsdpRegistryStatus::Assigned,
        ),
        SSDP_IPV6_SITE_LOCAL_HOST => (
            "ssdp-ipv6-site-local-host".to_string(),
            SsdpRegistryStatus::Assigned,
        ),
        SSDP_IPV6_MULTICAST_PATTERN => (
            "ssdp-ipv6-multicast-pattern".to_string(),
            SsdpRegistryStatus::Assigned,
        ),
        SSDP_IPV6_GLOBAL_MULTICAST | SSDP_IPV6_GLOBAL_HOST => (
            "obsolete-ipv6-global-ssdp-multicast".to_string(),
            SsdpRegistryStatus::Obsolete,
        ),
        SSDP_IPV6_ORG_LOCAL_MULTICAST => (
            format!("ambiguous-ipv6-ssdp-scope:{SSDP_IPV6_ORG_LOCAL_MULTICAST}"),
            SsdpRegistryStatus::Ambiguous,
        ),
        _ => (
            format!("unknown-multicast:{lower}"),
            SsdpRegistryStatus::Unknown,
        ),
    };

    SsdpMulticastMeta {
        value: value.to_string(),
        label,
        status,
    }
}

/// Return a stable SSDP multicast label.
pub(super) fn ssdp_multicast_label(value: &str) -> String {
    ssdp_multicast_meta(value).label
}

fn assigned_header_name(name: &str) -> Option<&'static str> {
    ASSIGNED_HEADER_NAMES
        .iter()
        .copied()
        .find(|candidate| candidate.eq_ignore_ascii_case(name))
}

fn excluded_eventing_header_name(name: &str) -> Option<&'static str> {
    EXCLUDED_EVENTING_HEADERS
        .iter()
        .copied()
        .find(|candidate| candidate.eq_ignore_ascii_case(name))
}

fn nls_namespace_prefix(name: &str) -> Option<&str> {
    let suffix = format!("-{SSDP_HEADER_NLS_SUFFIX}");
    if name.len() > suffix.len()
        && name
            .to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase())
    {
        return Some(&name[..name.len() - suffix.len()]);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_registry_labels_method_assigned_unknown_and_excluded() {
        let notify = ssdp_method_meta("NOTIFY");
        assert_eq!(notify.token, "NOTIFY");
        assert_eq!(notify.label, "NOTIFY");
        assert_eq!(notify.status, SsdpRegistryStatus::Assigned);
        assert_eq!(ssdp_method_label("M-SEARCH"), "M-SEARCH");

        let search = ssdp_method_meta("SEARCH");
        assert_eq!(search.label, "excluded-http-method:SEARCH");
        assert_eq!(search.status, SsdpRegistryStatus::Excluded);

        let unknown = ssdp_method_meta("X-SEARCH");
        assert_eq!(unknown.label, "unknown-method:X-SEARCH");
        assert_eq!(unknown.status, SsdpRegistryStatus::Unknown);
        assert_eq!(ssdp_method_label("X-SEARCH"), unknown.label);
    }

    #[test]
    fn ssdp_registry_labels_status_assigned_unknown_and_http_errors() {
        let ok = ssdp_status_meta(200);
        assert_eq!(ok.code, 200);
        assert_eq!(ok.label, "200 OK");
        assert_eq!(ok.status, SsdpRegistryStatus::Assigned);

        let unknown = ssdp_status_meta(299);
        assert_eq!(unknown.label, "unknown-status:299");
        assert_eq!(unknown.status, SsdpRegistryStatus::Unknown);
        assert_eq!(ssdp_status_label(7), "unknown-status:007");

        let error = ssdp_status_meta(404);
        assert_eq!(error.label, "excluded-http-error-status:404");
        assert_eq!(error.status, SsdpRegistryStatus::Excluded);
    }

    #[test]
    fn ssdp_registry_labels_header_names_assigned_extension_unknown_and_excluded() {
        let host = ssdp_header_name_meta("host");
        assert_eq!(host.name, "host");
        assert_eq!(host.label, "HOST");
        assert_eq!(host.status, SsdpRegistryStatus::Assigned);

        let nls = ssdp_header_name_meta("01-NLS");
        assert_eq!(nls.label, "nls-extension-header:01");
        assert_eq!(nls.status, SsdpRegistryStatus::Extension);

        let vendor = ssdp_header_name_meta("X-DEVICE.UPNP.ORG");
        assert_eq!(vendor.label, "vendor-header:x-device.upnp.org");
        assert_eq!(vendor.status, SsdpRegistryStatus::Unknown);

        let unknown = ssdp_header_name_meta("X_VENDOR");
        assert_eq!(unknown.label, "unknown-header:x_vendor");
        assert_eq!(unknown.status, SsdpRegistryStatus::Unknown);
        assert_eq!(ssdp_header_name_label("X_VENDOR"), unknown.label);

        for header in ["SVCID", "SEQ", "LVL", "CONTENT-LENGTH", "CONTENT-TYPE"] {
            let meta = ssdp_header_name_meta(header);
            assert_eq!(meta.label, format!("excluded-eventing-header:{header}"));
            assert_eq!(meta.status, SsdpRegistryStatus::Excluded);
        }
    }

    #[test]
    fn ssdp_registry_labels_configid_reserved_values_are_metadata_only() {
        let assigned = ssdp_config_id_meta(16_777_215);
        assert_eq!(assigned.value, 16_777_215);
        assert_eq!(assigned.label, "configid:16777215");
        assert_eq!(assigned.status, SsdpRegistryStatus::Assigned);

        let reserved = ssdp_config_id_meta(16_777_216);
        assert_eq!(reserved.label, "reserved-configid:16777216");
        assert_eq!(reserved.status, SsdpRegistryStatus::Reserved);
        assert_eq!(ssdp_config_id_label(16_777_216), reserved.label);
    }

    #[test]
    fn ssdp_registry_labels_service_ports_assigned_unknown_and_excluded_tcp() {
        let udp = ssdp_service_meta(SsdpServiceTransport::Udp, 1_900);
        assert_eq!(udp.transport, SsdpServiceTransport::Udp);
        assert_eq!(udp.port, 1_900);
        assert_eq!(udp.label, "ssdp/udp:1900");
        assert_eq!(udp.status, SsdpRegistryStatus::Assigned);

        let tcp = ssdp_service_meta(SsdpServiceTransport::Tcp, 1_900);
        assert_eq!(tcp.label, "excluded-ssdp/tcp:1900");
        assert_eq!(tcp.status, SsdpRegistryStatus::Excluded);

        let unknown = ssdp_service_meta(SsdpServiceTransport::Udp, 49_152);
        assert_eq!(unknown.label, "unknown-udp-service:49152");
        assert_eq!(unknown.status, SsdpRegistryStatus::Unknown);
        assert_eq!(
            ssdp_service_label(SsdpServiceTransport::Udp, 49_152),
            unknown.label
        );
    }

    #[test]
    fn ssdp_registry_labels_multicast_assigned_unknown_obsolete_and_ambiguous() {
        let ipv4 = ssdp_multicast_meta("239.255.255.250");
        assert_eq!(ipv4.value, "239.255.255.250");
        assert_eq!(ipv4.label, "ssdp-ipv4-multicast");
        assert_eq!(ipv4.status, SsdpRegistryStatus::Assigned);

        let link = ssdp_multicast_meta("FF02::C");
        assert_eq!(link.label, "ssdp-ipv6-link-local-multicast");
        assert_eq!(link.status, SsdpRegistryStatus::Assigned);

        let site_host = ssdp_multicast_meta("[ff05::c]:1900");
        assert_eq!(site_host.label, "ssdp-ipv6-site-local-host");
        assert_eq!(site_host.status, SsdpRegistryStatus::Assigned);

        let global = ssdp_multicast_meta("ff0e::c");
        assert_eq!(global.label, "obsolete-ipv6-global-ssdp-multicast");
        assert_eq!(global.status, SsdpRegistryStatus::Obsolete);

        let ambiguous = ssdp_multicast_meta("ff08::c");
        assert_eq!(ambiguous.label, "ambiguous-ipv6-ssdp-scope:ff08::c");
        assert_eq!(ambiguous.status, SsdpRegistryStatus::Ambiguous);

        let unknown = ssdp_multicast_meta("239.255.255.251");
        assert_eq!(unknown.label, "unknown-multicast:239.255.255.251");
        assert_eq!(unknown.status, SsdpRegistryStatus::Unknown);
        assert_eq!(ssdp_multicast_label("239.255.255.251"), unknown.label);
    }

    #[test]
    fn ssdp_registry_labels_status_labels_are_stable() {
        for (status, label) in [
            (SsdpRegistryStatus::Assigned, "assigned"),
            (SsdpRegistryStatus::Extension, "extension"),
            (SsdpRegistryStatus::Unknown, "unknown"),
            (SsdpRegistryStatus::Reserved, "reserved"),
            (SsdpRegistryStatus::Obsolete, "obsolete"),
            (SsdpRegistryStatus::Ambiguous, "ambiguous"),
            (SsdpRegistryStatus::Excluded, "excluded"),
        ] {
            assert_eq!(status.label(), label);
            assert_eq!(status.to_string(), label);
        }
    }
}
