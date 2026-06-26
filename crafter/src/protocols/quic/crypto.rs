//! QUIC packet-protection helpers.
//!
//! This module stays utility-level: it exposes source-backed helpers for
//! explicit caller-supplied inputs and fixed vectors, but it never implies
//! ownership of TLS session state or a complete QUIC endpoint.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::constants::{QUIC_VERSION_1, QUIC_VERSION_2};
use crate::error::{CrafterError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Length of a QUIC Initial secret derived with SHA-256.
pub const QUIC_INITIAL_SECRET_LEN: usize = 32;
/// Length of the AES-128 packet-protection key used by Initial vectors.
pub const QUIC_INITIAL_AES_128_KEY_LEN: usize = 16;
/// Length of the Initial packet-protection IV.
pub const QUIC_INITIAL_IV_LEN: usize = 12;
/// Length of the AES header-protection key used by Initial vectors.
pub const QUIC_INITIAL_HP_KEY_LEN: usize = 16;

/// RFC 9001 QUIC v1 Initial salt.
pub const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9369 QUIC v2 Initial salt.
pub const QUIC_V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Placeholder context for future higher-level packet-protection helpers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicCryptoContext;

impl QuicCryptoContext {
    /// Create an empty context.
    pub const fn new() -> Self {
        Self
    }

    /// Non-panicking placeholder that reports deferred automatic protection.
    pub fn protect_placeholder(self, _packet: &[u8]) -> Result<Vec<u8>> {
        Err(CrafterError::invalid_field_value(
            "quic.crypto",
            "automatic QUIC packet protection is not implemented; use explicit helpers",
        ))
    }
}

/// QUIC Initial secrets for one version and destination connection ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialSecrets {
    version: u32,
    initial_secret: [u8; QUIC_INITIAL_SECRET_LEN],
    client_initial_secret: [u8; QUIC_INITIAL_SECRET_LEN],
    server_initial_secret: [u8; QUIC_INITIAL_SECRET_LEN],
}

impl QuicInitialSecrets {
    /// Return the QUIC version used to select salt and packet-protection labels.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Return the common Initial PRK from HKDF-Extract.
    pub const fn initial_secret(&self) -> &[u8; QUIC_INITIAL_SECRET_LEN] {
        &self.initial_secret
    }

    /// Return the client Initial traffic secret.
    pub const fn client_initial_secret(&self) -> &[u8; QUIC_INITIAL_SECRET_LEN] {
        &self.client_initial_secret
    }

    /// Return the server Initial traffic secret.
    pub const fn server_initial_secret(&self) -> &[u8; QUIC_INITIAL_SECRET_LEN] {
        &self.server_initial_secret
    }

    /// Derive client Initial AES-128 key, IV, and header-protection key.
    pub fn client_packet_keys(&self) -> Result<QuicInitialPacketKeys> {
        derive_initial_packet_keys(self.version, &self.client_initial_secret)
    }

    /// Derive server Initial AES-128 key, IV, and header-protection key.
    pub fn server_packet_keys(&self) -> Result<QuicInitialPacketKeys> {
        derive_initial_packet_keys(self.version, &self.server_initial_secret)
    }
}

/// QUIC Initial packet-protection material for deterministic vector checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialPacketKeys {
    key: [u8; QUIC_INITIAL_AES_128_KEY_LEN],
    iv: [u8; QUIC_INITIAL_IV_LEN],
    header_protection_key: [u8; QUIC_INITIAL_HP_KEY_LEN],
}

impl QuicInitialPacketKeys {
    /// Return the AES-128 packet-protection key.
    pub const fn key(&self) -> &[u8; QUIC_INITIAL_AES_128_KEY_LEN] {
        &self.key
    }

    /// Return the packet-protection IV.
    pub const fn iv(&self) -> &[u8; QUIC_INITIAL_IV_LEN] {
        &self.iv
    }

    /// Return the AES header-protection key.
    pub const fn header_protection_key(&self) -> &[u8; QUIC_INITIAL_HP_KEY_LEN] {
        &self.header_protection_key
    }
}

/// Return the source-backed QUIC Initial salt for supported versions.
pub fn quic_initial_salt(version: u32) -> Result<&'static [u8; 20]> {
    match version {
        QUIC_VERSION_1 => Ok(&QUIC_V1_INITIAL_SALT),
        QUIC_VERSION_2 => Ok(&QUIC_V2_INITIAL_SALT),
        _ => Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.version",
            "unsupported QUIC Initial salt version",
        )),
    }
}

/// Derive QUIC Initial secrets from a destination connection ID.
///
/// This is the RFC 9001 / RFC 9369 Initial-only path. It does not derive
/// Handshake, 0-RTT, 1-RTT, update, or TLS transcript secrets.
pub fn derive_quic_initial_secrets(
    version: u32,
    destination_connection_id: impl AsRef<[u8]>,
) -> Result<QuicInitialSecrets> {
    let initial_secret = hkdf_extract_sha256(
        quic_initial_salt(version)?,
        destination_connection_id.as_ref(),
    )?;
    let client_initial_secret = hkdf_expand_label_sha256_array(
        &initial_secret,
        "client in",
        QUIC_INITIAL_SECRET_LEN,
        "quic.crypto.initial.client_initial_secret",
    )?;
    let server_initial_secret = hkdf_expand_label_sha256_array(
        &initial_secret,
        "server in",
        QUIC_INITIAL_SECRET_LEN,
        "quic.crypto.initial.server_initial_secret",
    )?;
    Ok(QuicInitialSecrets {
        version,
        initial_secret,
        client_initial_secret,
        server_initial_secret,
    })
}

fn derive_initial_packet_keys(version: u32, secret: &[u8]) -> Result<QuicInitialPacketKeys> {
    Ok(QuicInitialPacketKeys {
        key: hkdf_expand_label_sha256_array(
            secret,
            packet_key_label(version)?,
            QUIC_INITIAL_AES_128_KEY_LEN,
            "quic.crypto.initial.key",
        )?,
        iv: hkdf_expand_label_sha256_array(
            secret,
            packet_iv_label(version)?,
            QUIC_INITIAL_IV_LEN,
            "quic.crypto.initial.iv",
        )?,
        header_protection_key: hkdf_expand_label_sha256_array(
            secret,
            packet_hp_label(version)?,
            QUIC_INITIAL_HP_KEY_LEN,
            "quic.crypto.initial.hp",
        )?,
    })
}

fn packet_key_label(version: u32) -> Result<&'static str> {
    match version {
        QUIC_VERSION_1 => Ok("quic key"),
        QUIC_VERSION_2 => Ok("quicv2 key"),
        _ => Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.version",
            "unsupported QUIC packet-protection key label version",
        )),
    }
}

fn packet_iv_label(version: u32) -> Result<&'static str> {
    match version {
        QUIC_VERSION_1 => Ok("quic iv"),
        QUIC_VERSION_2 => Ok("quicv2 iv"),
        _ => Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.version",
            "unsupported QUIC packet-protection IV label version",
        )),
    }
}

fn packet_hp_label(version: u32) -> Result<&'static str> {
    match version {
        QUIC_VERSION_1 => Ok("quic hp"),
        QUIC_VERSION_2 => Ok("quicv2 hp"),
        _ => Err(CrafterError::invalid_field_value(
            "quic.crypto.initial.version",
            "unsupported QUIC header-protection label version",
        )),
    }
}

fn hkdf_extract_sha256(salt: &[u8], input_keying_material: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).map_err(|_| {
        CrafterError::invalid_field_value("quic.crypto.hkdf.salt", "invalid HKDF salt length")
    })?;
    mac.update(input_keying_material);
    let output = mac.finalize().into_bytes();
    let mut extracted = [0u8; 32];
    extracted.copy_from_slice(&output);
    Ok(extracted)
}

fn hkdf_expand_label_sha256_array<const N: usize>(
    secret: &[u8],
    label: &str,
    len: usize,
    field: &'static str,
) -> Result<[u8; N]> {
    if len != N {
        return Err(CrafterError::invalid_field_value(
            field,
            "requested HKDF output length does not match fixed output",
        ));
    }
    let expanded = hkdf_expand_label_sha256(secret, label.as_bytes(), &[], len, field)?;
    let mut output = [0u8; N];
    output.copy_from_slice(&expanded);
    Ok(output)
}

fn hkdf_expand_label_sha256(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    let info = tls13_hkdf_label(label, context, len, field)?;
    hkdf_expand_sha256(secret, &info, len, field)
}

fn tls13_hkdf_label(
    label: &[u8],
    context: &[u8],
    len: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "HKDF output length exceeds TLS 1.3 label limit",
        ));
    }
    let label_len = 6usize
        .checked_add(label.len())
        .ok_or_else(|| CrafterError::invalid_field_value(field, "HKDF label length overflow"))?;
    if label_len > u8::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "HKDF label exceeds TLS 1.3 label length limit",
        ));
    }
    if context.len() > u8::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "HKDF context exceeds TLS 1.3 context length limit",
        ));
    }

    let mut encoded = Vec::with_capacity(2 + 1 + label_len + 1 + context.len());
    encoded.extend_from_slice(&(len as u16).to_be_bytes());
    encoded.push(label_len as u8);
    encoded.extend_from_slice(b"tls13 ");
    encoded.extend_from_slice(label);
    encoded.push(context.len() as u8);
    encoded.extend_from_slice(context);
    Ok(encoded)
}

fn hkdf_expand_sha256(
    pseudo_random_key: &[u8],
    info: &[u8],
    len: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    if len > 255 * 32 {
        return Err(CrafterError::invalid_field_value(
            field,
            "HKDF output length exceeds RFC 5869 limit",
        ));
    }

    let mut output = Vec::with_capacity(len);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while output.len() < len {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(pseudo_random_key).map_err(|_| {
            CrafterError::invalid_field_value("quic.crypto.hkdf.prk", "invalid HKDF PRK length")
        })?;
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();

        let remaining = len - output.len();
        output.extend_from_slice(&previous[..remaining.min(previous.len())]);
        if output.len() < len {
            counter = counter.checked_add(1).ok_or_else(|| {
                CrafterError::invalid_field_value(field, "HKDF block counter overflow")
            })?;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    #[test]
    fn quic_initial_secret_derivation_matches_rfc9001_v1_vectors() -> Result<()> {
        let secrets = derive_quic_initial_secrets(QUIC_VERSION_1, TEST_DCID)?;
        assert_eq!(secrets.version(), QUIC_VERSION_1);
        assert_eq!(quic_initial_salt(QUIC_VERSION_1)?, &QUIC_V1_INITIAL_SALT);
        assert_eq!(
            secrets.initial_secret(),
            &hex_array::<32>("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
        );
        assert_eq!(
            secrets.client_initial_secret(),
            &hex_array::<32>("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            secrets.server_initial_secret(),
            &hex_array::<32>("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );

        let client_keys = secrets.client_packet_keys()?;
        assert_eq!(
            client_keys.key(),
            &hex_array::<16>("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(
            client_keys.iv(),
            &hex_array::<12>("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            client_keys.header_protection_key(),
            &hex_array::<16>("9f50449e04a0e810283a1e9933adedd2")
        );

        let server_keys = secrets.server_packet_keys()?;
        assert_eq!(
            server_keys.key(),
            &hex_array::<16>("cf3a5331653c364c88f0f379b6067e37")
        );
        assert_eq!(
            server_keys.iv(),
            &hex_array::<12>("0ac1493ca1905853b0bba03e")
        );
        assert_eq!(
            server_keys.header_protection_key(),
            &hex_array::<16>("c206b8d9b9f0f37644430b490eeaa314")
        );

        Ok(())
    }

    #[test]
    fn quic_initial_secret_derivation_matches_rfc9369_v2_vectors() -> Result<()> {
        let secrets = derive_quic_initial_secrets(QUIC_VERSION_2, TEST_DCID)?;
        assert_eq!(secrets.version(), QUIC_VERSION_2);
        assert_eq!(quic_initial_salt(QUIC_VERSION_2)?, &QUIC_V2_INITIAL_SALT);
        assert_eq!(
            secrets.initial_secret(),
            &hex_array::<32>("2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba")
        );
        assert_eq!(
            secrets.client_initial_secret(),
            &hex_array::<32>("14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b")
        );
        assert_eq!(
            secrets.server_initial_secret(),
            &hex_array::<32>("0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1")
        );

        let client_keys = secrets.client_packet_keys()?;
        assert_eq!(
            client_keys.key(),
            &hex_array::<16>("8b1a0bc121284290a29e0971b5cd045d")
        );
        assert_eq!(
            client_keys.iv(),
            &hex_array::<12>("91f73e2351d8fa91660e909f")
        );
        assert_eq!(
            client_keys.header_protection_key(),
            &hex_array::<16>("45b95e15235d6f45a6b19cbcb0294ba9")
        );

        let server_keys = secrets.server_packet_keys()?;
        assert_eq!(
            server_keys.key(),
            &hex_array::<16>("82db637861d55e1d011f19ea71d5d2a7")
        );
        assert_eq!(
            server_keys.iv(),
            &hex_array::<12>("dd13c276499c0249d3310652")
        );
        assert_eq!(
            server_keys.header_protection_key(),
            &hex_array::<16>("edf6d05c83121201b436e16877593c3a")
        );

        Ok(())
    }

    #[test]
    fn quic_initial_secret_derivation_rejects_unsupported_versions() {
        assert_eq!(
            derive_quic_initial_secrets(0xface_feed, TEST_DCID).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.crypto.initial.version",
                "unsupported QUIC Initial salt version"
            )
        );
    }

    #[test]
    fn quic_initial_secret_derivation_encodes_tls13_labels() -> Result<()> {
        assert_eq!(
            tls13_hkdf_label(b"client in", &[], 32, "test")?,
            hex_vec("00200f746c73313320636c69656e7420696e00")
        );
        assert_eq!(
            tls13_hkdf_label(b"server in", &[], 32, "test")?,
            hex_vec("00200f746c7331332073657276657220696e00")
        );
        assert_eq!(
            tls13_hkdf_label(b"quic key", &[], 16, "test")?,
            hex_vec("00100e746c7331332071756963206b657900")
        );
        assert_eq!(
            tls13_hkdf_label(b"quicv2 hp", &[], 16, "test")?,
            hex_vec("00100f746c7331332071756963763220687000")
        );
        Ok(())
    }

    fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex_vec(hex);
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    fn hex_vec(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        hex.as_bytes()
            .chunks_exact(2)
            .map(|byte| {
                let byte = std::str::from_utf8(byte).expect("hex is UTF-8");
                u8::from_str_radix(byte, 16).expect("valid hex")
            })
            .collect()
    }
}
