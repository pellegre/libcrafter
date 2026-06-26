//! Source-backed DHCPv4 option-code metadata.
//!
//! Source: IANA "Dynamic Host Configuration Protocol (DHCP) and Bootstrap
//! Protocol (BOOTP) Parameters" registry, sub-registry "BOOTP Vendor
//! Extensions and DHCP Options" (registry last updated 2026-02-02), reconciled
//! against RFC 2132. Each entry records the registered short name and the
//! assignment status so that decoders can preserve unknown, private-use,
//! removed/unassigned, and ambiguous codepoints instead of pretending every
//! code has a single authoritative typed interpretation.
//!
//! This table is intentionally metadata only: it names codepoints and ranges.
//! The wire-format codec for each option lives with [`super::option`]. Codes
//! whose registry rows carry multiple historical or vendor-specific meanings
//! are marked [`DhcpOptionStatus::Ambiguous`] so callers do not assume a single
//! decode.

/// Registry assignment status for a DHCPv4 option codepoint.
///
/// Source: IANA "BOOTP Vendor Extensions and DHCP Options" registry status
/// column and RFC 3942 / RFC 3679 reclassifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhcpOptionStatus {
    /// Assigned to a single registered option by an RFC.
    Assigned,
    /// Registered but carrying multiple historical or vendor-specific meanings
    /// (for example PXE codes 128-135 and 150), so no single typed decode is
    /// authoritative.
    Ambiguous,
    /// Reserved for private use (codes 224-254 per the registry).
    PrivateUse,
    /// Removed or unassigned by the registry (for example RFC 3679 / RFC 3942).
    RemovedOrUnassigned,
    /// Not present in the registry table the crate was built against.
    Unknown,
}

/// One source-backed DHCPv4 option-code registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DhcpOptionMeta {
    /// Wire codepoint.
    pub code: u8,
    /// Registered short name, or a range/status label for non-assigned codes.
    pub name: &'static str,
    /// Registry assignment status.
    pub status: DhcpOptionStatus,
}

/// Lowest private-use DHCPv4 option code (inclusive).
///
/// Source: IANA registry rows "224-254 Reserved (Private Use)".
pub const DHCP_OPTION_PRIVATE_USE_START: u8 = 224;
/// Highest private-use DHCPv4 option code (inclusive).
pub const DHCP_OPTION_PRIVATE_USE_END: u8 = 254;

/// Return the registry metadata for a DHCPv4 option code.
///
/// Unknown codes fall through to a generated [`DhcpOptionStatus`] derived from
/// the registry's range rules so private-use and unassigned ranges still carry
/// useful diagnostics.
pub const fn option_meta(code: u8) -> DhcpOptionMeta {
    if let Some(meta) = assigned_meta(code) {
        return meta;
    }
    if code >= DHCP_OPTION_PRIVATE_USE_START && code <= DHCP_OPTION_PRIVATE_USE_END {
        return DhcpOptionMeta {
            code,
            name: "Reserved (Private Use)",
            status: DhcpOptionStatus::PrivateUse,
        };
    }
    DhcpOptionMeta {
        code,
        name: "Unassigned",
        status: DhcpOptionStatus::RemovedOrUnassigned,
    }
}

/// Registry status for a DHCPv4 option code.
pub const fn option_status(code: u8) -> DhcpOptionStatus {
    option_meta(code).status
}

/// Registered short name for a DHCPv4 option code, when assigned.
pub const fn option_name(code: u8) -> Option<&'static str> {
    match assigned_meta(code) {
        Some(meta) => Some(meta.name),
        None => None,
    }
}

const fn entry(code: u8, name: &'static str, status: DhcpOptionStatus) -> DhcpOptionMeta {
    DhcpOptionMeta { code, name, status }
}

const A: DhcpOptionStatus = DhcpOptionStatus::Assigned;
const AMB: DhcpOptionStatus = DhcpOptionStatus::Ambiguous;
const REM: DhcpOptionStatus = DhcpOptionStatus::RemovedOrUnassigned;

/// Look up an explicitly listed registry row for a code.
///
/// Source: IANA "BOOTP Vendor Extensions and DHCP Options" registry rows
/// (updated 2026-02-02), reconciled with RFC 2132. Codes covered only by the
/// private-use or unassigned range rules are intentionally absent here and
/// handled by [`option_meta`].
const fn assigned_meta(code: u8) -> Option<DhcpOptionMeta> {
    let meta = match code {
        0 => entry(0, "Pad", A),
        1 => entry(1, "Subnet Mask", A),
        2 => entry(2, "Time Offset", A),
        3 => entry(3, "Router", A),
        4 => entry(4, "Time Server", A),
        5 => entry(5, "Name Server", A),
        6 => entry(6, "Domain Server", A),
        7 => entry(7, "Log Server", A),
        8 => entry(8, "Quotes Server", A),
        9 => entry(9, "LPR Server", A),
        10 => entry(10, "Impress Server", A),
        11 => entry(11, "RLP Server", A),
        12 => entry(12, "Hostname", A),
        13 => entry(13, "Boot File Size", A),
        14 => entry(14, "Merit Dump File", A),
        15 => entry(15, "Domain Name", A),
        16 => entry(16, "Swap Server", A),
        17 => entry(17, "Root Path", A),
        18 => entry(18, "Extension File", A),
        19 => entry(19, "Forward On/Off", A),
        20 => entry(20, "SrcRte On/Off", A),
        21 => entry(21, "Policy Filter", A),
        22 => entry(22, "Max DG Assembly", A),
        23 => entry(23, "Default IP TTL", A),
        24 => entry(24, "MTU Timeout", A),
        25 => entry(25, "MTU Plateau", A),
        26 => entry(26, "MTU Interface", A),
        27 => entry(27, "MTU Subnet", A),
        28 => entry(28, "Broadcast Address", A),
        29 => entry(29, "Mask Discovery", A),
        30 => entry(30, "Mask Supplier", A),
        31 => entry(31, "Router Discovery", A),
        32 => entry(32, "Router Request", A),
        33 => entry(33, "Static Route", A),
        34 => entry(34, "Trailers", A),
        35 => entry(35, "ARP Timeout", A),
        36 => entry(36, "Ethernet", A),
        37 => entry(37, "Default TCP TTL", A),
        38 => entry(38, "Keepalive Time", A),
        39 => entry(39, "Keepalive Data", A),
        40 => entry(40, "NIS Domain", A),
        41 => entry(41, "NIS Servers", A),
        42 => entry(42, "NTP Servers", A),
        43 => entry(43, "Vendor Specific", A),
        44 => entry(44, "NETBIOS Name Srv", A),
        45 => entry(45, "NETBIOS Dist Srv", A),
        46 => entry(46, "NETBIOS Node Type", A),
        47 => entry(47, "NETBIOS Scope", A),
        48 => entry(48, "X Window Font", A),
        49 => entry(49, "X Window Manager", A),
        50 => entry(50, "Address Request", A),
        51 => entry(51, "Address Time", A),
        52 => entry(52, "Overload", A),
        53 => entry(53, "DHCP Msg Type", A),
        54 => entry(54, "DHCP Server Id", A),
        55 => entry(55, "Parameter List", A),
        56 => entry(56, "DHCP Message", A),
        57 => entry(57, "DHCP Max Msg Size", A),
        58 => entry(58, "Renewal Time", A),
        59 => entry(59, "Rebinding Time", A),
        60 => entry(60, "Class Id", A),
        61 => entry(61, "Client Id", A),
        62 => entry(62, "NetWare/IP Domain", A),
        63 => entry(63, "NetWare/IP Option", A),
        64 => entry(64, "NIS-Domain-Name", A),
        65 => entry(65, "NIS-Server-Addr", A),
        66 => entry(66, "Server-Name", A),
        67 => entry(67, "Bootfile-Name", A),
        68 => entry(68, "Home-Agent-Addrs", A),
        69 => entry(69, "SMTP-Server", A),
        70 => entry(70, "POP3-Server", A),
        71 => entry(71, "NNTP-Server", A),
        72 => entry(72, "WWW-Server", A),
        73 => entry(73, "Finger-Server", A),
        74 => entry(74, "IRC-Server", A),
        75 => entry(75, "StreetTalk-Server", A),
        76 => entry(76, "STDA-Server", A),
        77 => entry(77, "User-Class", A),
        78 => entry(78, "Directory Agent", A),
        79 => entry(79, "Service Scope", A),
        80 => entry(80, "Rapid Commit", A),
        81 => entry(81, "Client FQDN", A),
        82 => entry(82, "Relay Agent Information", A),
        83 => entry(83, "iSNS", A),
        84 => entry(84, "REMOVED/Unassigned", REM),
        85 => entry(85, "NDS Servers", A),
        86 => entry(86, "NDS Tree Name", A),
        87 => entry(87, "NDS Context", A),
        88 => entry(88, "BCMCS Controller Domain Name list", A),
        89 => entry(89, "BCMCS Controller IPv4 address option", A),
        90 => entry(90, "Authentication", A),
        91 => entry(91, "client-last-transaction-time option", A),
        92 => entry(92, "associated-ip option", A),
        93 => entry(93, "Client System", A),
        94 => entry(94, "Client NDI", A),
        95 => entry(95, "LDAP", A),
        96 => entry(96, "REMOVED/Unassigned", REM),
        97 => entry(97, "UUID/GUID", A),
        98 => entry(98, "User-Auth", A),
        99 => entry(99, "GEOCONF_CIVIC", A),
        100 => entry(100, "PCode", A),
        101 => entry(101, "TCode", A),
        102..=107 => entry(code, "REMOVED/Unassigned", REM),
        108 => entry(108, "IPv6-Only Preferred", A),
        109 => entry(109, "OPTION_DHCP4O6_S46_SADDR", A),
        110 => entry(110, "REMOVED/Unassigned", REM),
        111 => entry(111, "Unassigned", REM),
        112 => entry(112, "Netinfo Address", A),
        113 => entry(113, "Netinfo Tag", A),
        114 => entry(114, "DHCP Captive-Portal", A),
        115 => entry(115, "REMOVED/Unassigned", REM),
        116 => entry(116, "Auto-Config", A),
        117 => entry(117, "Name Service Search", A),
        118 => entry(118, "Subnet Selection Option", A),
        119 => entry(119, "Domain Search", A),
        120 => entry(120, "SIP Servers DHCP Option", A),
        121 => entry(121, "Classless Static Route Option", A),
        122 => entry(122, "CCC", A),
        123 => entry(123, "GeoConf Option", A),
        124 => entry(124, "V-I Vendor Class", A),
        125 => entry(125, "V-I Vendor-Specific Information", A),
        126 => entry(126, "Removed/Unassigned", REM),
        127 => entry(127, "Removed/Unassigned", REM),
        // Codes 128-135 carry both an RFC 4578 PXE meaning and several vendor
        // meanings in the registry; treat them as ambiguous, not single-typed.
        128..=135 => entry(code, "PXE / vendor specific (ambiguous)", AMB),
        136 => entry(136, "OPTION_PANA_AGENT", A),
        137 => entry(137, "OPTION_V4_LOST", A),
        138 => entry(138, "OPTION_CAPWAP_AC_V4", A),
        139 => entry(139, "OPTION-IPv4_Address-MoS", A),
        140 => entry(140, "OPTION-IPv4_FQDN-MoS", A),
        141 => entry(141, "SIP UA Configuration Service Domains", A),
        142 => entry(142, "OPTION-IPv4_Address-ANDSF", A),
        143 => entry(143, "OPTION_V4_SZTP_REDIRECT", A),
        144 => entry(144, "GeoLoc", A),
        145 => entry(145, "FORCERENEW_NONCE_CAPABLE", A),
        146 => entry(146, "RDNSS Selection", A),
        147 => entry(147, "OPTION_V4_DOTS_RI", A),
        148 => entry(148, "OPTION_V4_DOTS_ADDRESS", A),
        149 => entry(149, "Unassigned", REM),
        // Code 150 is the well-known TFTP/Etherboot/GRUB ambiguous codepoint.
        150 => entry(150, "TFTP server / Etherboot / GRUB (ambiguous)", AMB),
        151 => entry(151, "status-code", A),
        152 => entry(152, "base-time", A),
        153 => entry(153, "start-time-of-state", A),
        154 => entry(154, "query-start-time", A),
        155 => entry(155, "query-end-time", A),
        156 => entry(156, "dhcp-state", A),
        157 => entry(157, "data-source", A),
        158 => entry(158, "OPTION_V4_PCP_SERVER", A),
        159 => entry(159, "OPTION_V4_PORTPARAMS", A),
        160 => entry(160, "Unassigned", REM),
        161 => entry(161, "OPTION_MUD_URL_V4", A),
        162 => entry(162, "OPTION_V4_DNR", A),
        163..=174 => entry(code, "Unassigned", REM),
        // Codes 175-177 are tentatively assigned / replaced and ambiguous.
        175..=177 => entry(code, "Tentatively assigned / vendor (ambiguous)", AMB),
        178..=207 => entry(code, "Unassigned", REM),
        208 => entry(208, "PXELINUX Magic", A),
        209 => entry(209, "Configuration File", A),
        210 => entry(210, "Path Prefix", A),
        211 => entry(211, "Reboot Time", A),
        212 => entry(212, "OPTION_6RD", A),
        213 => entry(213, "OPTION_V4_ACCESS_DOMAIN", A),
        214..=219 => entry(code, "Unassigned", REM),
        220 => entry(220, "Subnet Allocation Option", A),
        221 => entry(221, "Virtual Subnet Selection (VSS) Option", A),
        222..=223 => entry(code, "Unassigned", REM),
        255 => entry(255, "End", A),
        _ => return None,
    };
    Some(meta)
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn dhcp_option_registry_classifies_known_ranges() {
        // RFC 2132 assigned codes.
        assert_eq!(option_status(0), DhcpOptionStatus::Assigned);
        assert_eq!(option_name(53), Some("DHCP Msg Type"));
        assert_eq!(option_status(255), DhcpOptionStatus::Assigned);

        // Relay agent and authentication are assigned.
        assert_eq!(option_name(82), Some("Relay Agent Information"));
        assert_eq!(option_name(90), Some("Authentication"));

        // Ambiguous historical codes are flagged, not single-typed.
        assert_eq!(option_status(128), DhcpOptionStatus::Ambiguous);
        assert_eq!(option_status(150), DhcpOptionStatus::Ambiguous);

        // Removed/unassigned codes from RFC 3679 / RFC 3942.
        assert_eq!(option_status(84), DhcpOptionStatus::RemovedOrUnassigned);
        assert_eq!(option_status(102), DhcpOptionStatus::RemovedOrUnassigned);
        assert_eq!(option_status(163), DhcpOptionStatus::RemovedOrUnassigned);

        // Private use range 224-254.
        assert_eq!(option_status(224), DhcpOptionStatus::PrivateUse);
        assert_eq!(option_status(240), DhcpOptionStatus::PrivateUse);
        assert_eq!(option_status(254), DhcpOptionStatus::PrivateUse);
        assert_eq!(option_name(240), None);
    }

    #[test]
    fn dhcp_option_registry_covers_every_codepoint_without_panic() {
        for code in 0u8..=255 {
            let meta = option_meta(code);
            assert_eq!(meta.code, code);
            // Names are never empty.
            assert!(!meta.name.is_empty());
            // option_name agrees with assigned_meta.
            match meta.status {
                DhcpOptionStatus::Assigned | DhcpOptionStatus::Ambiguous => {
                    assert_eq!(option_name(code), Some(meta.name));
                }
                DhcpOptionStatus::PrivateUse | DhcpOptionStatus::RemovedOrUnassigned => {}
                DhcpOptionStatus::Unknown => panic!("range table should not yield Unknown"),
            }
        }
    }

    /// Checked-in snapshot of every individually assigned DHCPv4 option code in
    /// the IANA "BOOTP Vendor Extensions and DHCP Options" registry.
    ///
    /// Source: IANA "Dynamic Host Configuration Protocol (DHCP) and Bootstrap
    /// Protocol (BOOTP) Parameters", sub-registry "BOOTP Vendor Extensions and
    /// DHCP Options" (DHCP Option Codes table), retrieved 2026-05-29. This is the
    /// list of codepoints whose registry row names a specific option (status
    /// Assigned) or names several historical/vendor meanings for one code
    /// (status Ambiguous, e.g. PXE codes 128-135, code 150, and the tentatively
    /// assigned codes 175-177). Codes covered only by the registry's range rules
    /// ("REMOVED/Unassigned", "Unassigned", "Reserved (Private Use)") are
    /// intentionally absent: they have no single registered name and the codec
    /// preserves them as raw bytes.
    ///
    /// The snapshot is deliberately checked in so the completeness test runs
    /// fully offline; refresh it from the IANA registry when extending coverage.
    const IANA_ASSIGNED_OPTION_CODES: &[u8] = &[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
        71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94,
        95, 97, 98, 99, 100, 101, 108, 109, 112, 113, 114, 116, 117, 118, 119, 120, 121, 122, 123,
        124, 125, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
        144, 145, 146, 147, 148, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 161, 162, 175,
        176, 177, 208, 209, 210, 211, 212, 213, 220, 221, 255,
    ];

    #[test]
    fn dhcp_iana_option_registry_snapshot_is_covered() {
        // Every individually assigned IANA option code must be known to the
        // local metadata table: it must carry a registered name and an Assigned
        // or Ambiguous status, never a generated "Unassigned"/"Private Use"
        // fallback. This is the registry-completeness guard the plan asks for;
        // it fails loudly if a future IANA assignment is added to the snapshot
        // but not reflected in `assigned_meta`.
        for &code in IANA_ASSIGNED_OPTION_CODES {
            let meta = option_meta(code);
            assert_eq!(meta.code, code);
            assert!(
                matches!(
                    meta.status,
                    DhcpOptionStatus::Assigned | DhcpOptionStatus::Ambiguous
                ),
                "IANA-assigned option code {code} is missing from local metadata \
                 (got status {:?}, name {:?})",
                meta.status,
                meta.name,
            );
            assert_eq!(
                option_name(code),
                Some(meta.name),
                "assigned option code {code} must expose its registered name",
            );
            assert!(
                !meta.name.is_empty(),
                "assigned option code {code} must have a non-empty name",
            );
            // The named, registry-classified codepoint must also surface a
            // typed codepoint classification rather than the raw fallback. Pad
            // (0) and End (255) are the two single-octet framing codes carried
            // as their own classified variants.
            assert!(
                matches!(
                    super::super::DhcpOptionCode::from_code(code),
                    super::super::DhcpOptionCode::Assigned(_)
                        | super::super::DhcpOptionCode::Ambiguous(_)
                        | super::super::DhcpOptionCode::Pad
                        | super::super::DhcpOptionCode::End
                ),
                "assigned option code {code} must classify as Assigned/Ambiguous",
            );
        }

        // Codes outside the snapshot that fall in the private-use or
        // removed/unassigned ranges are still classified (and preserved raw),
        // never silently mislabeled as assigned.
        use std::collections::HashSet;
        let assigned: HashSet<u8> = IANA_ASSIGNED_OPTION_CODES.iter().copied().collect();
        for code in 0u8..=255 {
            if assigned.contains(&code) {
                continue;
            }
            assert!(
                matches!(
                    option_status(code),
                    DhcpOptionStatus::PrivateUse | DhcpOptionStatus::RemovedOrUnassigned
                ),
                "unassigned/private code {code} must not be reported as assigned",
            );
        }
    }
}
