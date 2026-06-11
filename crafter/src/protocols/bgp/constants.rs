//! BGP-4 (RFC 4271) wire constants.
//!
//! Codepoints copied verbatim (name and value) from the codepoint authority
//! table, `.agents/docs/bgp-codepoints.md`, which is itself derived from and
//! kept in sync with `.agents/docs/bgp-manifest.md` (the full RFC/IANA
//! evidence record). Each constant cites its defining RFC in a line comment.
//! On any disagreement, the authority table — not this file — is the source of
//! truth.
//!
//! Message-type and attribute-flag codepoints carry the `BGP_TYPE_*` and
//! `BGP_ATTR_FLAG_*` names used by the builder, decode, and spec steps;
//! path-attribute type codes keep the authority's `ATTR_*` prefix.

// ---------------------------------------------------------------------------
// Fixed protocol constants (RFC 4271 §4.1, §4.2)
// ---------------------------------------------------------------------------

/// BGP TCP listen port. RFC 4271 §1 / IANA service registry.
pub const BGP_PORT: u16 = 179;
/// BGP protocol version carried in OPEN. RFC 4271 §4.2.
pub const BGP_VERSION: u8 = 4;
/// BGP message header Marker field length, in octets. RFC 4271 §4.1.
pub const BGP_MARKER_LEN: usize = 16;
/// BGP message header length (Marker + Length + Type), in octets. RFC 4271 §4.1.
pub const BGP_HEADER_LEN: usize = 19;
/// Maximum BGP message length, in octets. RFC 4271 §4.1.
pub const BGP_MAX_MESSAGE_LEN: usize = 4096;
/// Reserved 2-octet AS number signalling a 4-octet AS in AS4 attributes. RFC 6793 §9.
pub const AS_TRANS: u16 = 23456;
/// Minimum OPEN message length, in octets. RFC 4271 §4.2.
pub const BGP_MIN_OPEN_LEN: usize = 29;
/// Minimum UPDATE message length, in octets. RFC 4271 §4.3.
pub const BGP_MIN_UPDATE_LEN: usize = 23;
/// Minimum NOTIFICATION message length, in octets. RFC 4271 §4.5.
pub const BGP_MIN_NOTIFICATION_LEN: usize = 21;
/// KEEPALIVE message length (header only), in octets. RFC 4271 §4.4.
pub const BGP_KEEPALIVE_LEN: usize = 19;

// ---------------------------------------------------------------------------
// Message types (IANA `bgp-parameters-1`)
// ---------------------------------------------------------------------------

/// OPEN message type. RFC 4271.
pub const BGP_TYPE_OPEN: u8 = 1;
/// UPDATE message type. RFC 4271.
pub const BGP_TYPE_UPDATE: u8 = 2;
/// NOTIFICATION message type. RFC 4271.
pub const BGP_TYPE_NOTIFICATION: u8 = 3;
/// KEEPALIVE message type. RFC 4271.
pub const BGP_TYPE_KEEPALIVE: u8 = 4;
/// ROUTE-REFRESH message type. RFC 2918.
pub const BGP_TYPE_ROUTE_REFRESH: u8 = 5;

// ---------------------------------------------------------------------------
// OPEN optional parameter types (IANA `bgp-parameters-11`)
// ---------------------------------------------------------------------------

/// Authentication optional parameter type (deprecated). RFC 4271 / RFC 5492.
pub const OPT_PARAM_AUTHENTICATION: u8 = 1;
/// Capabilities optional parameter type. RFC 5492.
pub const OPT_PARAM_CAPABILITIES: u8 = 2;
/// Extended optional-parameters-length marker. RFC 9072.
pub const OPT_PARAM_EXTENDED_LENGTH: u8 = 255;

// ---------------------------------------------------------------------------
// Capability codes (IANA `capability-codes-2`)
// ---------------------------------------------------------------------------

/// Multiprotocol Extensions capability. RFC 2858 (obsoleted by RFC 4760).
pub const CAP_MULTIPROTOCOL: u8 = 1;
/// Route Refresh capability. RFC 2918.
pub const CAP_ROUTE_REFRESH: u8 = 2;
/// Graceful Restart capability. RFC 4724.
pub const CAP_GRACEFUL_RESTART: u8 = 64;
/// Four-octet AS Number capability. RFC 6793.
pub const CAP_FOUR_OCTET_AS: u8 = 65;
/// ADD-PATH capability. RFC 7911.
pub const CAP_ADD_PATH: u8 = 69;
/// Enhanced Route Refresh capability (preserve only). RFC 7313.
pub const CAP_ENHANCED_ROUTE_REFRESH: u8 = 70;
/// Prestandard Route Refresh capability (deprecated; preserve only). RFC 8810.
pub const CAP_ROUTE_REFRESH_OLD: u8 = 128;

// ---------------------------------------------------------------------------
// Path attribute type codes (IANA `bgp-parameters-2`)
// ---------------------------------------------------------------------------

/// ORIGIN path attribute. RFC 4271.
pub const ATTR_ORIGIN: u8 = 1;
/// AS_PATH path attribute. RFC 4271.
pub const ATTR_AS_PATH: u8 = 2;
/// NEXT_HOP path attribute. RFC 4271.
pub const ATTR_NEXT_HOP: u8 = 3;
/// MULTI_EXIT_DISC path attribute. RFC 4271.
pub const ATTR_MULTI_EXIT_DISC: u8 = 4;
/// LOCAL_PREF path attribute. RFC 4271.
pub const ATTR_LOCAL_PREF: u8 = 5;
/// ATOMIC_AGGREGATE path attribute. RFC 4271.
pub const ATTR_ATOMIC_AGGREGATE: u8 = 6;
/// AGGREGATOR path attribute. RFC 4271.
pub const ATTR_AGGREGATOR: u8 = 7;
/// COMMUNITIES path attribute. RFC 1997.
pub const ATTR_COMMUNITIES: u8 = 8;
/// ORIGINATOR_ID path attribute (preserve only). RFC 4456.
pub const ATTR_ORIGINATOR_ID: u8 = 9;
/// CLUSTER_LIST path attribute (preserve only). RFC 4456.
pub const ATTR_CLUSTER_LIST: u8 = 10;
/// MP_REACH_NLRI path attribute. RFC 4760.
pub const ATTR_MP_REACH_NLRI: u8 = 14;
/// MP_UNREACH_NLRI path attribute. RFC 4760.
pub const ATTR_MP_UNREACH_NLRI: u8 = 15;
/// EXTENDED COMMUNITIES path attribute. RFC 4360.
pub const ATTR_EXTENDED_COMMUNITIES: u8 = 16;
/// AS4_PATH path attribute. RFC 6793.
pub const ATTR_AS4_PATH: u8 = 17;
/// AS4_AGGREGATOR path attribute. RFC 6793.
pub const ATTR_AS4_AGGREGATOR: u8 = 18;
/// LARGE COMMUNITY path attribute. RFC 8092.
pub const ATTR_LARGE_COMMUNITY: u8 = 32;

// ---------------------------------------------------------------------------
// Attribute flags octet (RFC 4271 §4.3)
// ---------------------------------------------------------------------------

/// Optional bit: 1 = optional, 0 = well-known. RFC 4271 §4.3.
pub const BGP_ATTR_FLAG_OPTIONAL: u8 = 0x80;
/// Transitive bit: 1 = transitive; well-known MUST be 1. RFC 4271 §4.3.
pub const BGP_ATTR_FLAG_TRANSITIVE: u8 = 0x40;
/// Partial bit: 1 = partial, 0 = complete. RFC 4271 §4.3.
pub const BGP_ATTR_FLAG_PARTIAL: u8 = 0x20;
/// Extended-Length bit: 1 = 2-octet length, 0 = 1-octet. RFC 4271 §4.3.
pub const BGP_ATTR_FLAG_EXTENDED_LENGTH: u8 = 0x10;

// Well-known flag defaults per in-scope attribute (Optional/Transitive/Partial/
// Extended-Length bits; Partial = 0 and Extended-Length = 0 by default).

/// Default ORIGIN flags: well-known mandatory (transitive). RFC 4271 §4.3.
pub const ATTR_ORIGIN_FLAGS: u8 = 0x40;
/// Default AS_PATH flags: well-known mandatory (transitive). RFC 4271 §4.3.
pub const ATTR_AS_PATH_FLAGS: u8 = 0x40;
/// Default NEXT_HOP flags: well-known mandatory (transitive). RFC 4271 §4.3.
pub const ATTR_NEXT_HOP_FLAGS: u8 = 0x40;
/// Default MULTI_EXIT_DISC flags: optional non-transitive. RFC 4271 §4.3.
pub const ATTR_MULTI_EXIT_DISC_FLAGS: u8 = 0x80;
/// Default LOCAL_PREF flags: well-known discretionary (transitive). RFC 4271 §4.3.
pub const ATTR_LOCAL_PREF_FLAGS: u8 = 0x40;
/// Default ATOMIC_AGGREGATE flags: well-known discretionary (transitive). RFC 4271 §4.3.
pub const ATTR_ATOMIC_AGGREGATE_FLAGS: u8 = 0x40;
/// Default AGGREGATOR flags: optional transitive. RFC 4271 §4.3.
pub const ATTR_AGGREGATOR_FLAGS: u8 = 0xC0;
/// Default COMMUNITIES flags: optional transitive. RFC 1997.
pub const ATTR_COMMUNITIES_FLAGS: u8 = 0xC0;
/// Default MP_REACH_NLRI flags: optional non-transitive. RFC 4760 §3.
pub const ATTR_MP_REACH_NLRI_FLAGS: u8 = 0x80;
/// Default MP_UNREACH_NLRI flags: optional non-transitive. RFC 4760 §4.
pub const ATTR_MP_UNREACH_NLRI_FLAGS: u8 = 0x80;
/// Default EXTENDED COMMUNITIES flags: optional transitive. RFC 4360.
pub const ATTR_EXTENDED_COMMUNITIES_FLAGS: u8 = 0xC0;
/// Default AS4_PATH flags: optional transitive. RFC 6793 §3.
pub const ATTR_AS4_PATH_FLAGS: u8 = 0xC0;
/// Default AS4_AGGREGATOR flags: optional transitive. RFC 6793 §3.
pub const ATTR_AS4_AGGREGATOR_FLAGS: u8 = 0xC0;
/// Default LARGE COMMUNITY flags: optional transitive. RFC 8092.
pub const ATTR_LARGE_COMMUNITY_FLAGS: u8 = 0xC0;

// ---------------------------------------------------------------------------
// ORIGIN values (attribute type 1, RFC 4271 §5.1.1)
// ---------------------------------------------------------------------------

/// ORIGIN = IGP. RFC 4271 §5.1.1.
pub const ORIGIN_IGP: u8 = 0;
/// ORIGIN = EGP. RFC 4271 §5.1.1.
pub const ORIGIN_EGP: u8 = 1;
/// ORIGIN = INCOMPLETE. RFC 4271 §5.1.1.
pub const ORIGIN_INCOMPLETE: u8 = 2;

// ---------------------------------------------------------------------------
// AS_PATH segment types (attribute type 2, RFC 4271 §5.1.2)
// ---------------------------------------------------------------------------

/// AS_SET segment type. RFC 4271 §4.3.
pub const AS_PATH_SEG_AS_SET: u8 = 1;
/// AS_SEQUENCE segment type. RFC 4271 §4.3.
pub const AS_PATH_SEG_AS_SEQUENCE: u8 = 2;
/// AS_CONFED_SEQUENCE segment type. RFC 5065.
pub const AS_PATH_SEG_AS_CONFED_SEQUENCE: u8 = 3;
/// AS_CONFED_SET segment type. RFC 5065.
pub const AS_PATH_SEG_AS_CONFED_SET: u8 = 4;

// ---------------------------------------------------------------------------
// Well-known COMMUNITIES (attribute type 8, RFC 1997)
// ---------------------------------------------------------------------------

/// NO_EXPORT well-known community. RFC 1997.
pub const COMMUNITY_NO_EXPORT: u32 = 0xFFFF_FF01;
/// NO_ADVERTISE well-known community. RFC 1997.
pub const COMMUNITY_NO_ADVERTISE: u32 = 0xFFFF_FF02;
/// NO_EXPORT_SUBCONFED well-known community. RFC 1997.
pub const COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFF_FF03;

// ---------------------------------------------------------------------------
// NOTIFICATION error codes (IANA `bgp-parameters-3`, RFC 4271 §6)
// ---------------------------------------------------------------------------

/// Message Header Error. RFC 4271.
pub const NOTIFY_MESSAGE_HEADER_ERROR: u8 = 1;
/// OPEN Message Error. RFC 4271.
pub const NOTIFY_OPEN_MESSAGE_ERROR: u8 = 2;
/// UPDATE Message Error. RFC 4271.
pub const NOTIFY_UPDATE_MESSAGE_ERROR: u8 = 3;
/// Hold Timer Expired. RFC 4271.
pub const NOTIFY_HOLD_TIMER_EXPIRED: u8 = 4;
/// Finite State Machine Error. RFC 4271.
pub const NOTIFY_FSM_ERROR: u8 = 5;
/// Cease. RFC 4271.
pub const NOTIFY_CEASE: u8 = 6;
/// ROUTE-REFRESH Message Error. RFC 7313.
pub const NOTIFY_ROUTE_REFRESH_MESSAGE_ERROR: u8 = 7;
/// Send Hold Timer Expired. RFC 9687.
pub const NOTIFY_SEND_HOLD_TIMER_EXPIRED: u8 = 8;
/// Loss of LSDB Sync. RFC 9815.
pub const NOTIFY_LOSS_OF_LSDB_SYNC: u8 = 9;

// Message Header Error subcodes (error code 1, IANA `bgp-parameters-5`, RFC 4271 §6.1)

/// Connection Not Synchronized. RFC 4271.
pub const MSG_HEADER_ERR_CONNECTION_NOT_SYNCHRONIZED: u8 = 1;
/// Bad Message Length. RFC 4271.
pub const MSG_HEADER_ERR_BAD_MESSAGE_LENGTH: u8 = 2;
/// Bad Message Type. RFC 4271.
pub const MSG_HEADER_ERR_BAD_MESSAGE_TYPE: u8 = 3;

// OPEN Message Error subcodes (error code 2, IANA `bgp-parameters-6`, RFC 4271 §6.2)

/// Unsupported Version Number. RFC 4271.
pub const OPEN_ERR_UNSUPPORTED_VERSION_NUMBER: u8 = 1;
/// Bad Peer AS. RFC 4271.
pub const OPEN_ERR_BAD_PEER_AS: u8 = 2;
/// Bad BGP Identifier. RFC 4271.
pub const OPEN_ERR_BAD_BGP_IDENTIFIER: u8 = 3;
/// Unsupported Optional Parameter. RFC 4271.
pub const OPEN_ERR_UNSUPPORTED_OPTIONAL_PARAMETER: u8 = 4;
/// Unacceptable Hold Time. RFC 4271.
pub const OPEN_ERR_UNACCEPTABLE_HOLD_TIME: u8 = 6;
/// Unsupported Capability. RFC 5492.
pub const OPEN_ERR_UNSUPPORTED_CAPABILITY: u8 = 7;
/// Role Mismatch. RFC 9234.
pub const OPEN_ERR_ROLE_MISMATCH: u8 = 11;

// UPDATE Message Error subcodes (error code 3, IANA `bgp-parameters-7`, RFC 4271 §6.3)

/// Malformed Attribute List. RFC 4271.
pub const UPDATE_ERR_MALFORMED_ATTRIBUTE_LIST: u8 = 1;
/// Unrecognized Well-known Attribute. RFC 4271.
pub const UPDATE_ERR_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE: u8 = 2;
/// Missing Well-known Attribute. RFC 4271.
pub const UPDATE_ERR_MISSING_WELL_KNOWN_ATTRIBUTE: u8 = 3;
/// Attribute Flags Error. RFC 4271.
pub const UPDATE_ERR_ATTRIBUTE_FLAGS_ERROR: u8 = 4;
/// Attribute Length Error. RFC 4271.
pub const UPDATE_ERR_ATTRIBUTE_LENGTH_ERROR: u8 = 5;
/// Invalid ORIGIN Attribute. RFC 4271.
pub const UPDATE_ERR_INVALID_ORIGIN_ATTRIBUTE: u8 = 6;
/// Invalid NEXT_HOP Attribute. RFC 4271.
pub const UPDATE_ERR_INVALID_NEXT_HOP_ATTRIBUTE: u8 = 8;
/// Optional Attribute Error. RFC 4271.
pub const UPDATE_ERR_OPTIONAL_ATTRIBUTE_ERROR: u8 = 9;
/// Invalid Network Field. RFC 4271.
pub const UPDATE_ERR_INVALID_NETWORK_FIELD: u8 = 10;
/// Malformed AS_PATH. RFC 4271.
pub const UPDATE_ERR_MALFORMED_AS_PATH: u8 = 11;

// Finite State Machine Error subcodes (error code 5, IANA `bgp-finite-state-machine-error-subcodes`)

/// Unspecified Error. RFC 6608.
pub const FSM_ERR_UNSPECIFIED: u8 = 0;
/// Receive Unexpected Message in OpenSent State. RFC 6608.
pub const FSM_ERR_UNEXPECTED_MESSAGE_IN_OPENSENT: u8 = 1;
/// Receive Unexpected Message in OpenConfirm State. RFC 6608.
pub const FSM_ERR_UNEXPECTED_MESSAGE_IN_OPENCONFIRM: u8 = 2;
/// Receive Unexpected Message in Established State. RFC 6608.
pub const FSM_ERR_UNEXPECTED_MESSAGE_IN_ESTABLISHED: u8 = 3;

// Cease subcodes (error code 6, IANA `bgp-parameters-8`)

/// Maximum Number of Prefixes Reached. RFC 4486.
pub const CEASE_MAX_PREFIXES_REACHED: u8 = 1;
/// Administrative Shutdown. RFC 4486 (RFC 9003).
pub const CEASE_ADMINISTRATIVE_SHUTDOWN: u8 = 2;
/// Peer De-configured. RFC 4486.
pub const CEASE_PEER_DECONFIGURED: u8 = 3;
/// Administrative Reset. RFC 4486 (RFC 9003).
pub const CEASE_ADMINISTRATIVE_RESET: u8 = 4;
/// Connection Rejected. RFC 4486.
pub const CEASE_CONNECTION_REJECTED: u8 = 5;
/// Other Configuration Change. RFC 4486.
pub const CEASE_OTHER_CONFIGURATION_CHANGE: u8 = 6;
/// Connection Collision Resolution. RFC 4486.
pub const CEASE_CONNECTION_COLLISION_RESOLUTION: u8 = 7;
/// Out of Resources. RFC 4486.
pub const CEASE_OUT_OF_RESOURCES: u8 = 8;
/// Hard Reset. RFC 8538.
pub const CEASE_HARD_RESET: u8 = 9;
/// BFD Down. RFC 9384.
pub const CEASE_BFD_DOWN: u8 = 10;

// ROUTE-REFRESH Message Error subcodes (error code 7, IANA `route-refresh-error-subcodes`)

/// Invalid Message Length. RFC 7313.
pub const ROUTE_REFRESH_ERR_INVALID_MESSAGE_LENGTH: u8 = 1;

// ---------------------------------------------------------------------------
// ROUTE-REFRESH message subtypes (type 5 body, RFC 2918 / RFC 7313)
// ---------------------------------------------------------------------------

/// Normal route refresh. RFC 2918 (also RFC 5291).
pub const ROUTE_REFRESH_SUBTYPE_NORMAL: u8 = 0;
/// Begin-of-RIB (BoRR). RFC 7313.
pub const ROUTE_REFRESH_SUBTYPE_BORR: u8 = 1;
/// End-of-RIB (EoRR). RFC 7313.
pub const ROUTE_REFRESH_SUBTYPE_EORR: u8 = 2;

// ---------------------------------------------------------------------------
// AFI values (IANA `address-family-numbers-2`)
// ---------------------------------------------------------------------------

/// IPv4 address family. IANA Address Family Numbers.
pub const AFI_IPV4: u16 = 1;
/// IPv6 address family. IANA Address Family Numbers.
pub const AFI_IPV6: u16 = 2;

// ---------------------------------------------------------------------------
// SAFI values (IANA `safi-namespace-2`)
// ---------------------------------------------------------------------------

/// Unicast forwarding. RFC 4760.
pub const SAFI_UNICAST: u8 = 1;
/// Multicast forwarding. RFC 4760.
pub const SAFI_MULTICAST: u8 = 2;
