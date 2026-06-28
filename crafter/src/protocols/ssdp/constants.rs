//! Source-backed SSDP constants.

pub const SSDP_SERVICE_NAME: &str = "ssdp";
pub const SSDP_UDP_PORT: u16 = 1_900;
pub const SSDP_IPV4_MULTICAST: &str = "239.255.255.250";
pub const SSDP_IPV4_MULTICAST_HOST: &str = "239.255.255.250:1900";
pub const SSDP_IPV6_MULTICAST_PATTERN: &str = "ff0x::c";
pub const SSDP_IPV6_LINK_LOCAL_MULTICAST: &str = "ff02::c";
pub const SSDP_IPV6_SITE_LOCAL_MULTICAST: &str = "ff05::c";
pub const SSDP_IPV6_LINK_LOCAL_HOST: &str = "[ff02::c]:1900";
pub const SSDP_IPV6_SITE_LOCAL_HOST: &str = "[ff05::c]:1900";

pub const SSDP_METHOD_NOTIFY: &str = "NOTIFY";
pub const SSDP_METHOD_M_SEARCH: &str = "M-SEARCH";
pub const SSDP_HTTP_VERSION: &str = "HTTP/1.1";
pub const SSDP_STATUS_OK: u16 = 200;
pub const SSDP_REASON_OK: &str = "OK";

pub const SSDP_NTS_ALIVE: &str = "ssdp:alive";
pub const SSDP_NTS_BYEBYE: &str = "ssdp:byebye";
pub const SSDP_NTS_UPDATE: &str = "ssdp:update";
pub const SSDP_MAN_DISCOVER: &str = "\"ssdp:discover\"";
pub const SSDP_ST_ALL: &str = "ssdp:all";
pub const SSDP_TARGET_ROOTDEVICE: &str = "upnp:rootdevice";

pub const SSDP_HEADER_HOST: &str = "HOST";
pub const SSDP_HEADER_CACHE_CONTROL: &str = "CACHE-CONTROL";
pub const SSDP_HEADER_LOCATION: &str = "LOCATION";
pub const SSDP_HEADER_NT: &str = "NT";
pub const SSDP_HEADER_NTS: &str = "NTS";
pub const SSDP_HEADER_SERVER: &str = "SERVER";
pub const SSDP_HEADER_USN: &str = "USN";
pub const SSDP_HEADER_BOOTID: &str = "BOOTID.UPNP.ORG";
pub const SSDP_HEADER_CONFIGID: &str = "CONFIGID.UPNP.ORG";
pub const SSDP_HEADER_SEARCHPORT: &str = "SEARCHPORT.UPNP.ORG";
pub const SSDP_HEADER_NEXTBOOTID: &str = "NEXTBOOTID.UPNP.ORG";
pub const SSDP_HEADER_SECURELOCATION: &str = "SECURELOCATION.UPNP.ORG";
pub const SSDP_HEADER_MAN: &str = "MAN";
pub const SSDP_HEADER_MX: &str = "MX";
pub const SSDP_HEADER_ST: &str = "ST";
pub const SSDP_HEADER_USER_AGENT: &str = "USER-AGENT";
pub const SSDP_HEADER_TCPPORT: &str = "TCPPORT.UPNP.ORG";
pub const SSDP_HEADER_CPFN: &str = "CPFN.UPNP.ORG";
pub const SSDP_HEADER_CPUUID: &str = "CPUUID.UPNP.ORG";
pub const SSDP_HEADER_DATE: &str = "DATE";
pub const SSDP_HEADER_EXT: &str = "EXT";
pub const SSDP_HEADER_OPT: &str = "OPT";
pub const SSDP_HEADER_NLS_SUFFIX: &str = "NLS";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_constants_transport_and_multicast_values() {
        assert_eq!(SSDP_SERVICE_NAME, "ssdp");
        assert_eq!(SSDP_UDP_PORT, 1_900);
        assert_eq!(SSDP_IPV4_MULTICAST, "239.255.255.250");
        assert_eq!(SSDP_IPV4_MULTICAST_HOST, "239.255.255.250:1900");
        assert_eq!(SSDP_IPV6_MULTICAST_PATTERN, "ff0x::c");
        assert_eq!(SSDP_IPV6_LINK_LOCAL_MULTICAST, "ff02::c");
        assert_eq!(SSDP_IPV6_SITE_LOCAL_MULTICAST, "ff05::c");
        assert_eq!(SSDP_IPV6_LINK_LOCAL_HOST, "[ff02::c]:1900");
        assert_eq!(SSDP_IPV6_SITE_LOCAL_HOST, "[ff05::c]:1900");
    }

    #[test]
    fn ssdp_constants_start_line_values() {
        assert_eq!(SSDP_METHOD_NOTIFY, "NOTIFY");
        assert_eq!(SSDP_METHOD_M_SEARCH, "M-SEARCH");
        assert_eq!(SSDP_HTTP_VERSION, "HTTP/1.1");
        assert_eq!(SSDP_STATUS_OK, 200);
        assert_eq!(SSDP_REASON_OK, "OK");
    }

    #[test]
    fn ssdp_constants_notification_and_target_values() {
        assert_eq!(SSDP_NTS_ALIVE, "ssdp:alive");
        assert_eq!(SSDP_NTS_BYEBYE, "ssdp:byebye");
        assert_eq!(SSDP_NTS_UPDATE, "ssdp:update");
        assert_eq!(SSDP_MAN_DISCOVER, "\"ssdp:discover\"");
        assert_eq!(SSDP_ST_ALL, "ssdp:all");
        assert_eq!(SSDP_TARGET_ROOTDEVICE, "upnp:rootdevice");
    }

    #[test]
    fn ssdp_constants_header_name_values() {
        let headers = [
            (SSDP_HEADER_HOST, "HOST"),
            (SSDP_HEADER_CACHE_CONTROL, "CACHE-CONTROL"),
            (SSDP_HEADER_LOCATION, "LOCATION"),
            (SSDP_HEADER_NT, "NT"),
            (SSDP_HEADER_NTS, "NTS"),
            (SSDP_HEADER_SERVER, "SERVER"),
            (SSDP_HEADER_USN, "USN"),
            (SSDP_HEADER_BOOTID, "BOOTID.UPNP.ORG"),
            (SSDP_HEADER_CONFIGID, "CONFIGID.UPNP.ORG"),
            (SSDP_HEADER_SEARCHPORT, "SEARCHPORT.UPNP.ORG"),
            (SSDP_HEADER_NEXTBOOTID, "NEXTBOOTID.UPNP.ORG"),
            (SSDP_HEADER_SECURELOCATION, "SECURELOCATION.UPNP.ORG"),
            (SSDP_HEADER_MAN, "MAN"),
            (SSDP_HEADER_MX, "MX"),
            (SSDP_HEADER_ST, "ST"),
            (SSDP_HEADER_USER_AGENT, "USER-AGENT"),
            (SSDP_HEADER_TCPPORT, "TCPPORT.UPNP.ORG"),
            (SSDP_HEADER_CPFN, "CPFN.UPNP.ORG"),
            (SSDP_HEADER_CPUUID, "CPUUID.UPNP.ORG"),
            (SSDP_HEADER_DATE, "DATE"),
            (SSDP_HEADER_EXT, "EXT"),
            (SSDP_HEADER_OPT, "OPT"),
            (SSDP_HEADER_NLS_SUFFIX, "NLS"),
        ];

        for (actual, expected) in headers {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn ssdp_constants_excluded_values_are_not_named_defaults() {
        let named_methods = [SSDP_METHOD_NOTIFY, SSDP_METHOD_M_SEARCH];
        assert!(!named_methods.contains(&"SEARCH"));

        let named_multicast_values = [
            SSDP_IPV4_MULTICAST,
            SSDP_IPV4_MULTICAST_HOST,
            SSDP_IPV6_MULTICAST_PATTERN,
            SSDP_IPV6_LINK_LOCAL_MULTICAST,
            SSDP_IPV6_SITE_LOCAL_MULTICAST,
            SSDP_IPV6_LINK_LOCAL_HOST,
            SSDP_IPV6_SITE_LOCAL_HOST,
        ];
        assert!(!named_multicast_values.contains(&"ff0e::c"));
        assert!(!named_multicast_values.contains(&"[ff0e::c]:1900"));
        assert!(!named_multicast_values.contains(&"[ff0x::130]:7900"));

        let named_values = [
            SSDP_NTS_ALIVE,
            SSDP_NTS_BYEBYE,
            SSDP_NTS_UPDATE,
            SSDP_MAN_DISCOVER,
            SSDP_ST_ALL,
            SSDP_TARGET_ROOTDEVICE,
        ];
        assert!(!named_values.contains(&"upnp:event"));
        assert!(!named_values.contains(&"upnp:propchange"));

        let named_headers = [
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
            SSDP_HEADER_NLS_SUFFIX,
        ];
        for excluded in ["SVCID", "SEQ", "LVL", "CONTENT-LENGTH", "CONTENT-TYPE"] {
            assert!(!named_headers.contains(&excluded));
        }
    }
}
