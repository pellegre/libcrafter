use crafter::prelude::*;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Lab-safe documentation values: 2.4 GHz channel 15, PAN 0x1234, and short
    // (16-bit) addresses. The stack is Dot15d4Radio / Dot15d4 / ZigbeeNwk /
    // ZigbeeAps, composed with `/` like every other crafter packet.
    let packet = Dot15d4Radio::on_channel(15)
        / Dot15d4::data()
            .dest_short(0x1234, 0x0000)
            .src_short(0x1234, 0xABCD)
            .seq(1)
        / ZigbeeNwk::data().dest(0x0000).src(0xABCD).radius(30)
        / ZigbeeAps::data()
            .cluster(0x0006)
            .profile(0x0104)
            .payload(&[0x01]);

    let compiled = packet.compile()?;

    println!("mode: offline");
    println!("hex bytes: {}", hex_bytes(compiled.as_bytes()));
    println!("summary: {}", packet.summary());
    println!("show:\n{}", packet.show());

    #[cfg(feature = "whad")]
    print_whad_dry_run_plan(packet.clone())?;

    Ok(())
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

    // Dry-run inject: no `.live()`, so the builder never touches the serial port
    // and transmits nothing. The mock channel proves the plan is produced
    // offline.
    let channel = WhadMockChannel::new();
    let wire = PacketWire::whad_serial("/dev/ttyACM0")
        .dot15d4_send()
        .channel(15)
        .with_mock_channel(channel.clone())
        .open()?;
    let mut writer = wire.writer()?;
    let report = writer.write_record(&PacketRecord::new(packet))?;

    println!("whad mode: dry-run");
    println!("whad target: /dev/ttyACM0");
    if let Some(details) = report.target_details() {
        println!("whad plan: {details}");
    }
    println!("whad bytes requested: {}", report.bytes_requested());
    println!("whad transmitted bytes: {}", channel.written_bytes().len());

    Ok(())
}
