use crafter::prelude::*;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let flags = AdStructure::flags_general_disc();
    let packet = BleRadio::advertising(37)
        / BleLlAdv::adv_ind()
            .adv_a_str("C0:FF:EE:11:22:33")?
            .push_ad(flags)
            .push_ad(complete_local_name("libcrafter-ble"))
            .push_ad(manufacturer_data(
                0xFFFF,
                &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE],
            ));

    let compiled = packet.compile()?;

    println!("mode: offline");
    println!("hex bytes: {}", hex_bytes(compiled.as_bytes()));
    println!("summary: {}", packet.summary());
    println!("show:\n{}", packet.show());

    #[cfg(feature = "whad")]
    print_whad_dry_run_plan(packet.clone())?;

    Ok(())
}

fn complete_local_name(name: &str) -> AdStructure {
    AdStructure::complete_local_name(name)
}

fn manufacturer_data(company_id: u16, data: &[u8]) -> AdStructure {
    AdStructure::manufacturer_data(company_id, data)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(feature = "whad")]
fn print_whad_dry_run_plan(packet: Packet) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use crafter::wire::packet_wire::WhadMockChannel;

    let channel = WhadMockChannel::new();
    let wire = PacketWire::whad_serial("/dev/ttyACM0")
        .ble_inject()
        .with_mock_channel(channel.clone())
        .open()?;
    let mut writer = wire.writer()?;
    let report = writer.write_record(&PacketRecord::new(packet))?;

    println!("whad mode: dry-run");
    println!("whad target: /dev/ttyACM0");
    if let Some(details) = report.target_details() {
        println!("whad plan: {details}");
    }
    println!("whad transmitted bytes: {}", channel.written_bytes().len());

    Ok(())
}
