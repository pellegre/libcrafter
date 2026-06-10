//! IPSec (RFC 4301/4302/4303/7296) packet support.
//!
//! This module hosts the IPSec wire-level layers — Encapsulating Security
//! Payload (ESP, RFC 4303), Authentication Header (AH, RFC 4302), and the
//! IKEv2 message/payload wire format (RFC 7296) — along with the
//! `SecurityAssociation` per-packet crypto context and the cryptographic
//! transforms that drive ESP/AH/SK confidentiality and integrity.
//!
//! The submodule tree is established here; the typed layers, builders, and
//! decoders are filled in by later steps. The ESP and AH layers, the
//! `SecurityAssociation` crypto context, and the algorithm-identifier enums are
//! re-exported here (and on up through `protocols`, the crate root, `core`, and
//! the `prelude`) so generated tools reach them with `crafter::prelude::*`.

pub mod ah;
pub mod crypto;
pub mod esp;
pub mod ikev2;
pub mod natt;
pub mod sa;

pub use ah::header::{
    AH_FIXED_LEN, AH_HIGH_SEQUENCE_LEN, AH_LENGTH_UNIT, AH_NEXT_HEADER_LEN,
    AH_PAYLOAD_LEN_FIELD_LEN, AH_PAYLOAD_LEN_OFFSET, AH_RESERVED_LEN, AH_SEQUENCE_LEN, AH_SPI_LEN,
};
pub use ah::Ah;
pub use esp::header::{
    ESP_HEADER_LEN, ESP_HIGH_SEQUENCE_LEN, ESP_MAX_PAD_LEN, ESP_NEXT_HEADER_FIELD_LEN,
    ESP_PAD_LENGTH_FIELD_LEN,
};
pub use esp::Esp;
pub use ikev2::{
    following_ike_payload_type, following_next_payload, payload_type_for_layer_name,
    write_generic_payload_header, AuthMethod, CertEncoding, CfgType, ConfigAttribute, DecodedSk,
    IdRole, IdType, IkeAuthPayload, IkeCertPayload, IkeCertReqPayload, IkeConfigPayload,
    IkeDeletePayload, IkeEapPayload, IkeEncryptedPayload, IkeHeader, IkeIdPayload, IkeKePayload,
    IkeNoncePayload, IkeNotifyPayload, IkePayload, IkeSaPayload, IkeTsPayload, IkeVendorIdPayload,
    NotifyType, PayloadHeaderFields, PayloadType, Proposal, TrafficSelector, Transform,
    TransformAttribute, TsRole, AUTH_DIGITAL_SIGNATURE, AUTH_DSS_DIGITAL_SIGNATURE,
    AUTH_RSA_DIGITAL_SIGNATURE, AUTH_SHARED_KEY_MIC, CERT_ENCODING_DNS_SIGNED_KEY,
    CERT_ENCODING_HASH_URL_X509, CERT_ENCODING_HASH_URL_X509_BUNDLE, CERT_ENCODING_PKCS7_X509,
    CERT_ENCODING_X509_SIGNATURE, CFG_ACK, CFG_REPLY, CFG_REQUEST, CFG_SET, CREATE_CHILD_SA,
    DELETE_PROTOCOL_AH, DELETE_PROTOCOL_ESP, DELETE_PROTOCOL_IKE, DH_GROUP_CURVE25519,
    DH_GROUP_ECP_256, DH_GROUP_MODP_1024, DH_GROUP_MODP_2048, GENERIC_PAYLOAD_HEADER_LEN, ID_FQDN,
    ID_IPV4_ADDR, ID_IPV6_ADDR, ID_KEY_ID, ID_RFC822_ADDR, IKE_AUTH, IKE_FLAG_INITIATOR,
    IKE_FLAG_RESPONSE, IKE_FLAG_VERSION, IKE_HEADER_LEN, IKE_SA_INIT, IKE_VERSION_2, INFORMATIONAL,
    NOTIFY_ADDITIONAL_TS_POSSIBLE, NOTIFY_AUTHENTICATION_FAILED, NOTIFY_COOKIE,
    NOTIFY_INITIAL_CONTACT, NOTIFY_INVALID_KE_PAYLOAD, NOTIFY_INVALID_SYNTAX,
    NOTIFY_IPCOMP_SUPPORTED, NOTIFY_NAT_DETECTION_DESTINATION_IP, NOTIFY_NAT_DETECTION_SOURCE_IP,
    NOTIFY_NO_PROPOSAL_CHOSEN, NOTIFY_PROTOCOL_AH, NOTIFY_PROTOCOL_ESP, NOTIFY_PROTOCOL_IKE,
    NOTIFY_PROTOCOL_NONE, NOTIFY_REKEY_SA, NOTIFY_SET_WINDOW_SIZE,
    NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD, NOTIFY_USE_TRANSPORT_MODE, NO_NEXT_PAYLOAD, PAYLOAD_AUTH,
    PAYLOAD_CERT, PAYLOAD_CERTREQ, PAYLOAD_CP, PAYLOAD_CRITICAL_BIT, PAYLOAD_DELETE, PAYLOAD_EAP,
    PAYLOAD_IDI, PAYLOAD_IDR, PAYLOAD_KE, PAYLOAD_NONCE, PAYLOAD_NONE, PAYLOAD_NOTIFY, PAYLOAD_SA,
    PAYLOAD_SK, PAYLOAD_TSI, PAYLOAD_TSR, PAYLOAD_TYPE_NONE, PAYLOAD_VENDOR_ID, PROTOCOL_ID_AH,
    PROTOCOL_ID_ESP, PROTOCOL_ID_IKE, TRANSFORM_TYPE_DH, TRANSFORM_TYPE_ENCR, TRANSFORM_TYPE_ESN,
    TRANSFORM_TYPE_INTEG, TRANSFORM_TYPE_PRF, TS_IPV4_ADDR_RANGE, TS_IPV6_ADDR_RANGE,
};
pub use natt::{
    is_non_esp_marker, non_esp_marker, NatTraversal, NON_ESP_MARKER, NON_ESP_MARKER_LEN,
};
pub use sa::{EncryptionAlgorithm, IntegrityAlgorithm, IpsecMode, SecurityAssociation};
