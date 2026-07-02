use crafter::prelude::*;

#[test]
fn ntp_timestamp_raw_accessors_cover_zero_max_and_fraction() {
    let zero = NtpTimestamp::zero();
    assert_eq!(zero.raw(), 0);
    assert_eq!(zero.seconds(), 0);
    assert_eq!(zero.fraction(), 0);
    assert!(zero.is_zero());
    assert_eq!(zero.as_seconds(), 0.0);

    let half = NtpTimestamp::from_parts(1, 0x8000_0000);
    assert_eq!(half.raw(), 0x0000_0001_8000_0000);
    assert_eq!(half.seconds(), 1);
    assert_eq!(half.fraction(), 0x8000_0000);
    assert_eq!(half.as_seconds(), 1.5);

    let max = NtpTimestamp::from_raw(u64::MAX);
    assert_eq!(max.seconds(), u32::MAX);
    assert_eq!(max.fraction(), u32::MAX);
    assert_eq!(max.raw(), u64::MAX);
    assert!(!max.is_zero());
}

#[test]
fn ntp_timestamp_era_safe_raw_preservation_roundtrips_through_packet() -> crafter::Result<()> {
    let reference = NtpTimestamp::zero();
    let origin = NtpTimestamp::from_raw(0xffff_ffff_ffff_ffff);
    let receive = NtpTimestamp::from_parts(0x83aa_7e80, 0x8000_0000);
    let transmit = NtpTimestamp::from_raw(0x0000_0001_0000_0000);
    let ntp = Ntp::server()
        .reference_timestamp(reference)
        .origin_timestamp(origin)
        .receive_timestamp(receive)
        .transmit_timestamp(transmit);

    let compiled = Packet::from_layer(ntp.clone()).compile()?;
    let decoded = Ntp::decode(compiled.as_bytes())?;

    assert_eq!(decoded.reference_timestamp_value(), reference);
    assert_eq!(decoded.origin_timestamp_value(), origin);
    assert_eq!(decoded.receive_timestamp_value(), receive);
    assert_eq!(decoded.transmit_timestamp_value(), transmit);
    assert_eq!(
        Packet::from_layer(decoded).compile()?.as_bytes(),
        compiled.as_bytes()
    );
    Ok(())
}

#[test]
fn ntp_fixed_point_short_format_accessors_preserve_raw_values() {
    let value = NtpShortFormat::from_parts(1, 0x8000);
    assert_eq!(value.raw(), 0x0001_8000);
    assert_eq!(value.integer(), 1);
    assert_eq!(value.fraction(), 0x8000);
    assert_eq!(value.as_seconds(), 1.5);

    let negative_shaped_delay = NtpShortFormat::from_raw(0xffff_0001);
    assert_eq!(negative_shaped_delay.raw(), 0xffff_0001);
    assert_eq!(negative_shaped_delay.integer(), 0xffff);
    assert_eq!(negative_shaped_delay.fraction(), 0x0001);
}

#[test]
fn ntp_fixed_point_root_delay_dispersion_roundtrip_and_show() -> crafter::Result<()> {
    let root_delay = NtpShortFormat::from_raw(0xffff_0001);
    let root_dispersion = NtpShortFormat::from_parts(2, 0x4000);
    let ntp = Ntp::server()
        .root_delay(root_delay)
        .root_dispersion(root_dispersion);

    let compiled = Packet::from_layer(ntp).compile()?;
    let decoded = Ntp::decode(compiled.as_bytes())?;

    assert_eq!(decoded.root_delay_value().raw(), 0xffff_0001);
    assert_eq!(decoded.root_dispersion_value().raw(), 0x0002_4000);
    assert_eq!(decoded.root_delay_value().integer(), 0xffff);
    assert_eq!(decoded.root_dispersion_value().as_seconds(), 2.25);

    let show = Packet::from_layer(decoded).show();
    assert!(show.contains("root_delay: 0xffff0001"), "{show}");
    assert!(show.contains("root_dispersion: 0x00024000"), "{show}");
    Ok(())
}
