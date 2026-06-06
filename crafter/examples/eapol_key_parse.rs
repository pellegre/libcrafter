mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;

const STA_MAC: MacAddr = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x21]);
const AP_MAC: MacAddr = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x22]);

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example eapol_key_parse --\n\nDecode a synthetic Dot11/LlcSnap/Eapol-Key byte sequence offline.",
    ) {
        return Ok(());
    }

    let bytes = synthetic_eapol_key_frame()?.into_bytes();
    let decoded = Packet::decode_from_link(LinkType::Ieee80211, &bytes)?;

    println!("mode: offline");
    println!("summary: {}", decoded.summary());
    println!("show:\n{}", decoded.show());
    if let Some(key) = decoded.layer::<EapolKey>() {
        println!(
            "Eapol key descriptor: {}",
            key.descriptor_type_kind().label()
        );
        println!("Eapol key handshake: {:?}", key.rsn_handshake_message());
        println!("Eapol key data bytes: {}", key.key_data_bytes().len());
    }
    println!("hexdump:\n{}", hexdump(&bytes));

    Ok(())
}

fn synthetic_eapol_key_frame() -> crafter::Result<CompiledPacket> {
    let dot11 = Dot11::data();
    let from_ds = dot11.frame_control_value().with_from_ds(true);
    let key_information = EapolKeyInformation::new()
        .with_descriptor_version(2)
        .with_key_type(true)
        .with_install(true)
        .with_key_ack(true)
        .with_key_mic(true)
        .with_secure(true);

    let packet = dot11
        .frame_control(from_ds)
        .addr1(STA_MAC)
        .addr2(AP_MAC)
        .addr3(AP_MAC)
        .sequence_number(9)
        / LlcSnap::new().ethertype(ETHERTYPE_EAPOL)
        / Eapol::key()
        / EapolKey::new()
            .key_information(key_information)
            .key_length(16)
            .replay_counter(1)
            .nonce(ascending::<32>(0x10))
            .iv(ascending::<16>(0xa0))
            .rsc(ascending::<8>(0xb0))
            .id(ascending::<8>(0xc0))
            .mic(ascending::<16>(0xd0))
            .key_data([DOT11_TAG_RSN, 2, 1, 0]);

    packet.compile()
}

fn ascending<const N: usize>(start: u8) -> [u8; N] {
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = start.wrapping_add(index as u8);
    }
    bytes
}
