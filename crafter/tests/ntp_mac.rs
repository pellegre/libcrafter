use crafter::prelude::*;

const KEY_ID: u32 = 0x0102_0304;
const DIGEST: [u8; 16] = [
    0xde, 0xad, 0xbe, 0xef, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
];

fn ntp_mac_tail_payload() -> crafter::Result<Vec<u8>> {
    Ok(Packet::from_layer(
        Ntp::client().legacy_mac(NtpLegacyMac::from_key_id_and_digest(KEY_ID, DIGEST)),
    )
    .compile()?
    .into_bytes())
}

#[test]
fn ntp_mac_tail_direct_decode_exposes_metadata_and_redacts_summary() -> crafter::Result<()> {
    let bytes = ntp_mac_tail_payload()?;

    assert_eq!(bytes.len(), NTP_FIXED_HEADER_LEN + 4 + DIGEST.len());
    assert_eq!(bytes[0], 0x23);
    assert_eq!(
        &bytes[NTP_FIXED_HEADER_LEN..NTP_FIXED_HEADER_LEN + 4],
        &[1, 2, 3, 4]
    );
    assert_eq!(&bytes[NTP_FIXED_HEADER_LEN + 4..], DIGEST.as_slice());

    let decoded = Ntp::decode(&bytes)?;
    let legacy_mac = decoded.legacy_mac_value().expect("decoded legacy MAC tail");

    assert_eq!(legacy_mac.key_id(), Some(KEY_ID));
    assert_eq!(legacy_mac.digest().len(), DIGEST.len());
    assert_eq!(legacy_mac.len(), 4 + DIGEST.len());

    let summary = decoded.summary();
    let lower_summary = summary.to_ascii_lowercase();
    assert!(summary.contains("tail=legacy-mac"), "{summary}");
    assert!(!lower_summary.contains("01020304"), "{summary}");
    assert!(!lower_summary.contains("deadbeef"), "{summary}");
    assert!(!lower_summary.contains("abababab"), "{summary}");

    Ok(())
}

#[test]
fn ntp_mac_tail_recompile_preserves_original_bytes_exactly() -> crafter::Result<()> {
    let original = ntp_mac_tail_payload()?;
    let decoded = Ntp::decode(&original)?;
    let recompiled = Packet::from_layer(decoded).compile()?;

    assert_eq!(recompiled.as_bytes(), original.as_slice());

    Ok(())
}
