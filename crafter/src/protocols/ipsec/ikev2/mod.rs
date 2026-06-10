//! Internet Key Exchange v2 (IKEv2, RFC 7296) message wire format.
//!
//! The IKE header, the generic-payload chain, the standard payload set
//! (including the Encrypted/SK payload), and the header + payload-chain decode
//! path live here. This is message and payload wire format only — round-trip
//! construction and decoding, not a negotiation state machine.
//!
//! The [`IkeHeader`] layer, the [`PayloadType`] codepoint enum, every concrete
//! payload layer (SA, KE, Nonce, Notify, Delete, ID, AUTH, TS, CERT, CERTREQ,
//! Vendor ID, Configuration, EAP, and the Encrypted/SK payload) with their
//! field enums, and the IKEv2 codepoint constants generated tools reach for are
//! re-exported here, and on up through `ipsec`, `protocols`, the crate root,
//! `core`, and the `prelude`, so a tool building from `crafter::prelude::*` can
//! assemble an `IKE_SA_INIT` message over UDP/500 without reaching into the
//! module tree.

pub mod decode;

pub mod header;

pub mod payload;

pub use header::{
    IkeHeader, CREATE_CHILD_SA, IKE_AUTH, IKE_FLAG_INITIATOR, IKE_FLAG_RESPONSE, IKE_FLAG_VERSION,
    IKE_HEADER_LEN, IKE_SA_INIT, IKE_VERSION_2, INFORMATIONAL, NO_NEXT_PAYLOAD,
};

pub use payload::{
    following_ike_payload_type, following_next_payload, payload_type_for_layer_name,
    write_generic_payload_header, AuthMethod, CertEncoding, CfgType, ConfigAttribute, DecodedSk,
    IdRole, IdType, IkeAuthPayload, IkeCertPayload, IkeCertReqPayload, IkeConfigPayload,
    IkeDeletePayload, IkeEapPayload, IkeEncryptedPayload, IkeIdPayload, IkeKePayload,
    IkeNoncePayload, IkeNotifyPayload, IkePayload, IkeSaPayload, IkeTsPayload, IkeVendorIdPayload,
    NotifyType, PayloadHeaderFields, PayloadType, Proposal, TrafficSelector, Transform,
    TransformAttribute, TsRole, GENERIC_PAYLOAD_HEADER_LEN, PAYLOAD_AUTH, PAYLOAD_CERT,
    PAYLOAD_CERTREQ, PAYLOAD_CP, PAYLOAD_CRITICAL_BIT, PAYLOAD_DELETE, PAYLOAD_EAP, PAYLOAD_IDI,
    PAYLOAD_IDR, PAYLOAD_KE, PAYLOAD_NONCE, PAYLOAD_NONE, PAYLOAD_NOTIFY, PAYLOAD_SA, PAYLOAD_SK,
    PAYLOAD_TSI, PAYLOAD_TSR, PAYLOAD_TYPE_NONE, PAYLOAD_VENDOR_ID,
};

pub use payload::auth::{
    AUTH_DIGITAL_SIGNATURE, AUTH_DSS_DIGITAL_SIGNATURE, AUTH_RSA_DIGITAL_SIGNATURE,
    AUTH_SHARED_KEY_MIC,
};
pub use payload::cert::{
    CERT_ENCODING_DNS_SIGNED_KEY, CERT_ENCODING_HASH_URL_X509, CERT_ENCODING_HASH_URL_X509_BUNDLE,
    CERT_ENCODING_PKCS7_X509, CERT_ENCODING_X509_SIGNATURE,
};
pub use payload::config::{CFG_ACK, CFG_REPLY, CFG_REQUEST, CFG_SET};
pub use payload::delete::{DELETE_PROTOCOL_AH, DELETE_PROTOCOL_ESP, DELETE_PROTOCOL_IKE};
pub use payload::id::{ID_FQDN, ID_IPV4_ADDR, ID_IPV6_ADDR, ID_KEY_ID, ID_RFC822_ADDR};
pub use payload::ke::{
    DH_GROUP_CURVE25519, DH_GROUP_ECP_256, DH_GROUP_MODP_1024, DH_GROUP_MODP_2048,
};
pub use payload::notify::{
    NOTIFY_ADDITIONAL_TS_POSSIBLE, NOTIFY_AUTHENTICATION_FAILED, NOTIFY_COOKIE,
    NOTIFY_INITIAL_CONTACT, NOTIFY_INVALID_KE_PAYLOAD, NOTIFY_INVALID_SYNTAX,
    NOTIFY_IPCOMP_SUPPORTED, NOTIFY_NAT_DETECTION_DESTINATION_IP, NOTIFY_NAT_DETECTION_SOURCE_IP,
    NOTIFY_NO_PROPOSAL_CHOSEN, NOTIFY_PROTOCOL_AH, NOTIFY_PROTOCOL_ESP, NOTIFY_PROTOCOL_IKE,
    NOTIFY_PROTOCOL_NONE, NOTIFY_REKEY_SA, NOTIFY_SET_WINDOW_SIZE,
    NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD, NOTIFY_USE_TRANSPORT_MODE,
};
pub use payload::sa::{
    PROTOCOL_ID_AH, PROTOCOL_ID_ESP, PROTOCOL_ID_IKE, TRANSFORM_TYPE_DH, TRANSFORM_TYPE_ENCR,
    TRANSFORM_TYPE_ESN, TRANSFORM_TYPE_INTEG, TRANSFORM_TYPE_PRF,
};
pub use payload::ts::{TS_IPV4_ADDR_RANGE, TS_IPV6_ADDR_RANGE};
