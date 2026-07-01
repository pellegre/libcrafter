//! TLS packet-layer module.
//!
//! Source-backed steps add typed record, handshake, extension, and codepoint
//! behavior while preserving unknown or encrypted bytes as raw payloads.

pub mod alert;
pub mod cipher_suite;
pub mod constants;
pub mod content_type;
pub(crate) mod decode;
pub mod extension;
pub mod handshake;
pub mod layer;
pub mod named_group;
pub mod record;
pub mod signature_scheme;
pub mod vector;
pub mod vectors;
pub mod version;

pub use alert::{TlsAlert, TlsAlertDescription, TlsAlertLevel, TLS_ALERT_LEN};
pub use cipher_suite::{TlsCipherSuite, TlsCipherSuiteList};
pub use content_type::TlsContentType;
pub use extension::{
    TlsAlpnProtocol, TlsAlpnProtocols, TlsExtensionListContext, TlsExtensionType, TlsExtensions,
    TlsKeyShare, TlsKeyShareContext, TlsKeyShareEntry, TlsPreSharedKey, TlsPreSharedKeyContext,
    TlsPskBinderEntry, TlsPskBinders, TlsPskIdentities, TlsPskIdentity, TlsPskKeyExchangeMode,
    TlsPskKeyExchangeModes, TlsRawExtension, TlsServerName, TlsServerNameList, TlsServerNameType,
    TlsSignatureAlgorithms, TlsSignatureAlgorithmsCert, TlsSupportedGroups, TlsSupportedVersions,
    TlsSupportedVersionsContext, TLS_ALPN_PROTOCOL_NAME_LENGTH_LEN,
    TLS_ALPN_PROTOCOL_NAME_LIST_LENGTH_LEN, TLS_EXTENSION_HEADER_LEN, TLS_EXTENSION_LENGTH_LEN,
    TLS_EXTENSION_LIST_LENGTH_LEN, TLS_EXTENSION_TYPE_LEN, TLS_KEY_SHARE_CLIENT_SHARES_LENGTH_LEN,
    TLS_KEY_SHARE_ENTRY_HEADER_LEN, TLS_KEY_SHARE_GROUP_LEN, TLS_KEY_SHARE_KEY_EXCHANGE_LENGTH_LEN,
    TLS_PRE_SHARED_KEY_SELECTED_IDENTITY_LEN, TLS_PSK_BINDERS_LENGTH_LEN,
    TLS_PSK_BINDER_LENGTH_LEN, TLS_PSK_IDENTITIES_LENGTH_LEN, TLS_PSK_IDENTITY_HEADER_LEN,
    TLS_PSK_IDENTITY_LENGTH_LEN, TLS_PSK_IDENTITY_OBFUSCATED_TICKET_AGE_LEN,
    TLS_PSK_KEY_EXCHANGE_MODES_LENGTH_LEN, TLS_PSK_KEY_EXCHANGE_MODE_LEN,
    TLS_PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE, TLS_PSK_KEY_EXCHANGE_MODE_PSK_KE,
    TLS_SERVER_NAME_HEADER_LEN, TLS_SERVER_NAME_LENGTH_LEN, TLS_SERVER_NAME_LIST_LENGTH_LEN,
    TLS_SERVER_NAME_TYPE_HOST_NAME, TLS_SERVER_NAME_TYPE_LEN,
    TLS_SIGNATURE_ALGORITHMS_LIST_LENGTH_LEN, TLS_SIGNATURE_ALGORITHM_LEN,
    TLS_SUPPORTED_GROUPS_LIST_LENGTH_LEN, TLS_SUPPORTED_GROUP_LEN,
    TLS_SUPPORTED_VERSIONS_CLIENT_LENGTH_LEN, TLS_SUPPORTED_VERSION_LEN,
};
pub use handshake::{
    TlsClientHello, TlsClientHelloBody, TlsHandshake, TlsHandshakeBody, TlsHandshakeHeader,
    TlsHandshakeType, TlsServerHello, TlsServerHelloBody, TLS_CLIENT_HELLO_FIXED_LEN,
    TLS_CLIENT_HELLO_LEGACY_VERSION_LEN, TLS_CLIENT_HELLO_RANDOM_LEN, TLS_COMPRESSION_METHOD_NULL,
    TLS_HANDSHAKE_HEADER_LEN, TLS_HANDSHAKE_LENGTH_LEN, TLS_HANDSHAKE_MAX_LENGTH,
    TLS_HANDSHAKE_TYPE_LEN, TLS_SERVER_HELLO_FIXED_LEN, TLS_SERVER_HELLO_LEGACY_VERSION_LEN,
    TLS_SERVER_HELLO_RANDOM_LEN,
};
pub use layer::Tls;
pub use named_group::{TlsNamedGroup, TlsNamedGroupList};
pub use record::{
    TlsHandshakeRecordBody, TlsRecord, TlsRecordBody, TlsRecordHeader, TLS_RECORD_CONTENT_TYPE_LEN,
    TLS_RECORD_HEADER_LEN, TLS_RECORD_LENGTH_LEN, TLS_RECORD_VERSION_LEN,
};
pub use signature_scheme::{TlsSignatureScheme, TlsSignatureSchemeList};
pub use version::{TlsVersion, TlsVersionField};

#[cfg(test)]
mod tests;
