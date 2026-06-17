//! Internet checksum helpers used by IP, ICMP, TCP, and UDP.

use core::net::{Ipv4Addr, Ipv6Addr};

/// Add bytes as big-endian 16-bit words to a one's-complement sum.
///
/// Odd trailing bytes are treated as the high byte of the final word, matching
/// RFC 1071 checksum behavior.
pub fn ones_complement_sum(data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    let mut sum = chunks.by_ref().fold(0u32, |sum, chunk| {
        sum + u16::from_be_bytes([chunk[0], chunk[1]]) as u32
    });

    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }

    sum
}

/// Fold a one's-complement sum down to 16 bits.
pub fn fold_sum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Finalize a one's-complement checksum from a partial sum.
pub fn finalize_checksum(sum: u32) -> u16 {
    !fold_sum(sum)
}

/// Compute the Internet checksum for a byte slice.
pub fn internet_checksum(data: &[u8]) -> u16 {
    finalize_checksum(ones_complement_sum(data))
}

/// Compute a checksum from multiple byte slices without copying them.
pub fn internet_checksum_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> u16 {
    let mut sum = 0u32;
    let mut high_byte = None;

    for chunk in chunks {
        for &byte in chunk {
            if let Some(high) = high_byte.take() {
                sum += u16::from_be_bytes([high, byte]) as u32;
            } else {
                high_byte = Some(byte);
            }
        }
    }

    if let Some(high) = high_byte {
        sum += (high as u32) << 8;
    }

    finalize_checksum(sum)
}

/// Return true when `data` has a valid Internet checksum over itself.
pub fn verify_internet_checksum(data: &[u8]) -> bool {
    internet_checksum(data) == 0
}

/// Compute an IPv4 header checksum.
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

/// Compute the checksum for an IPv4 pseudo-header plus transport payload.
pub fn ipv4_pseudo_header_checksum(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    transport: &[u8],
) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let length = transport.len() as u16;
    let mut sum = 0u32;

    sum += u16::from_be_bytes([source[0], source[1]]) as u32;
    sum += u16::from_be_bytes([source[2], source[3]]) as u32;
    sum += u16::from_be_bytes([destination[0], destination[1]]) as u32;
    sum += u16::from_be_bytes([destination[2], destination[3]]) as u32;
    sum += protocol as u32;
    sum += length as u32;
    sum += ones_complement_sum(transport);

    finalize_checksum(sum)
}

/// Compute the checksum for an IPv6 pseudo-header plus transport payload.
pub fn ipv6_pseudo_header_checksum(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    transport: &[u8],
) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let length = transport.len() as u32;
    let mut sum = 0u32;

    sum += u16::from_be_bytes([source[0], source[1]]) as u32;
    sum += u16::from_be_bytes([source[2], source[3]]) as u32;
    sum += u16::from_be_bytes([source[4], source[5]]) as u32;
    sum += u16::from_be_bytes([source[6], source[7]]) as u32;
    sum += u16::from_be_bytes([source[8], source[9]]) as u32;
    sum += u16::from_be_bytes([source[10], source[11]]) as u32;
    sum += u16::from_be_bytes([source[12], source[13]]) as u32;
    sum += u16::from_be_bytes([source[14], source[15]]) as u32;
    sum += u16::from_be_bytes([destination[0], destination[1]]) as u32;
    sum += u16::from_be_bytes([destination[2], destination[3]]) as u32;
    sum += u16::from_be_bytes([destination[4], destination[5]]) as u32;
    sum += u16::from_be_bytes([destination[6], destination[7]]) as u32;
    sum += u16::from_be_bytes([destination[8], destination[9]]) as u32;
    sum += u16::from_be_bytes([destination[10], destination[11]]) as u32;
    sum += u16::from_be_bytes([destination[12], destination[13]]) as u32;
    sum += u16::from_be_bytes([destination[14], destination[15]]) as u32;
    sum += (length >> 16) + (length & 0xffff);
    sum += next_header as u32;
    sum += ones_complement_sum(transport);

    finalize_checksum(sum)
}

/// Compute the two Fletcher-16 check octets for an OSPF link-state advertisement.
///
/// Implements the Fletcher checksum placement algorithm from RFC 905 Annex B
/// (also described in RFC 1008 and used by OSPF in RFC 2328 §12.1.7 / §D). The
/// caller passes the bytes to be protected in `data` with the two-octet checksum
/// field already zeroed, plus `checksum_offset`, the index of that field within
/// `data`. The returned pair is stored at `checksum_offset` so that
/// [`fletcher16_valid`] over the resulting buffer reduces to zero.
///
/// `c0` and `c1` are two running 8-bit sums kept modulo 255. The check octets
/// are derived from `c0`, `c1`, and the distance of the checksum field from the
/// end of `data`, following the RFC 905 Annex B placement formula.
pub fn fletcher16_checkbytes(data: &[u8], checksum_offset: usize) -> [u8; 2] {
    let mut c0: i32 = 0;
    let mut c1: i32 = 0;

    for &byte in data {
        c0 = (c0 + byte as i32) % 255;
        c1 = (c1 + c0) % 255;
    }

    // RFC 905 Annex B expresses the placement in terms of the checksum field's
    // position measured from the start of the protected region, counted so the
    // inserted octets cancel the running sums during verification. `offset` here
    // is the one-based position of the first checksum octet (RFC notation), which
    // is `checksum_offset + 1` for the zero-based `checksum_offset` argument.
    let length = data.len() as i32;
    let offset = checksum_offset as i32 + 1;

    let mut x = ((length - offset) * c0 - c1) % 255;
    if x <= 0 {
        x += 255;
    }

    let mut y = 510 - c0 - x;
    if y > 255 {
        y -= 255;
    }

    [x as u8, y as u8]
}

/// Return true when the Fletcher-16 sums over `data` reduce to zero.
///
/// Used for decode-time validation: `data` must include the stored two-octet
/// checksum in place. Per RFC 905 Annex B a correctly checksummed buffer yields
/// `c0 == 0` and `c1 == 0` when both running 8-bit sums are taken modulo 255
/// over the whole buffer.
pub fn fletcher16_valid(data: &[u8]) -> bool {
    let mut c0: i32 = 0;
    let mut c1: i32 = 0;

    for &byte in data {
        c0 = (c0 + byte as i32) % 255;
        c1 = (c1 + c0) % 255;
    }

    c0 == 0 && c1 == 0
}

/// Compute CRC-32C/Castagnoli over `data`.
pub(crate) fn crc32c(data: &[u8]) -> u32 {
    const POLY_REFLECTED: u32 = 0x82f6_3b78;

    let mut crc = !0u32;

    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLY_REFLECTED & mask);
        }
    }

    !crc
}

#[cfg(test)]
mod tests {
    use super::{
        crc32c, finalize_checksum, fletcher16_checkbytes, fletcher16_valid, fold_sum,
        internet_checksum, internet_checksum_chunks, ipv4_header_checksum,
        ipv4_pseudo_header_checksum, ipv6_pseudo_header_checksum, ones_complement_sum,
        verify_internet_checksum,
    };
    use core::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn checksum_handles_even_length_input() {
        assert_eq!(internet_checksum(&[0x00, 0x01, 0xf2, 0x03]), 0x0dfb);
    }

    #[test]
    fn checksum_handles_odd_length_input() {
        assert_eq!(internet_checksum(&[0x00, 0x01, 0xf2]), 0x0dfe);
    }

    #[test]
    fn checksum_folds_carries() {
        assert_eq!(fold_sum(0x0001_0001), 0x0002);
        assert_eq!(finalize_checksum(0xffff), 0x0000);
    }

    #[test]
    fn checksum_chunks_match_contiguous_bytes() {
        let contiguous = [0x45, 0x00, 0x00, 0x54, 0xab, 0xcd, 0x00, 0x00];
        let chunked = internet_checksum_chunks([&contiguous[..4], &contiguous[4..]]);

        assert_eq!(chunked, internet_checksum(&contiguous));
    }

    #[test]
    fn checksum_chunks_allow_odd_boundaries() {
        let contiguous = [0x01, 0x02, 0x03, 0x04, 0x05];
        let chunked =
            internet_checksum_chunks([&contiguous[..1], &contiguous[1..3], &contiguous[3..]]);

        assert_eq!(chunked, internet_checksum(&contiguous));
    }

    #[test]
    fn checksum_verifies_ipv4_header_fixture() {
        let header = [
            0x45, 0x00, 0x00, 0x54, 0xa6, 0xf2, 0x40, 0x00, 0x40, 0x01, 0x0e, 0xc2, 0xc0, 0xa8,
            0x01, 0x65, 0xac, 0xd9, 0x16, 0x0e,
        ];

        assert!(verify_internet_checksum(&header));

        let mut zeroed = header;
        zeroed[10] = 0;
        zeroed[11] = 0;
        assert_eq!(ipv4_header_checksum(&zeroed), 0x0ec2);
    }

    #[test]
    fn checksum_sums_words_without_complementing() {
        assert_eq!(ones_complement_sum(&[0x12, 0x34, 0x56]), 0x1234 + 0x5600);
    }

    #[test]
    fn checksum_builds_ipv4_pseudo_header() {
        let udp = [0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];

        let checksum = ipv4_pseudo_header_checksum(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 2),
            17,
            &udp,
        );

        assert_eq!(checksum, 0x013e);
    }

    #[test]
    fn checksum_builds_ipv6_pseudo_header() {
        let udp = [0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];

        let checksum = ipv6_pseudo_header_checksum(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            17,
            &udp,
        );

        assert_eq!(checksum, 0x9200);
    }

    #[test]
    fn fletcher16_round_trips_a_zeroed_field() {
        // A small LSA-shaped buffer with a two-octet checksum field at offset 16
        // (mirroring the LSA checksum field that follows LS age + options +
        // type + id + advertising router + sequence). The field is zeroed before
        // computing the check octets, then the octets are stored back in place.
        let mut buffer = [
            0x00, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x00, 0x00, 0x10, 0x11,
        ];
        let offset = 16;

        let check = fletcher16_checkbytes(&buffer, offset);
        buffer[offset] = check[0];
        buffer[offset + 1] = check[1];

        assert!(fletcher16_valid(&buffer));
    }

    #[test]
    fn fletcher16_detects_a_corrupted_octet() {
        let mut buffer = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x55, 0x66,
        ];
        let offset = 8;

        let check = fletcher16_checkbytes(&buffer, offset);
        buffer[offset] = check[0];
        buffer[offset + 1] = check[1];
        assert!(fletcher16_valid(&buffer));

        buffer[2] ^= 0x01;
        assert!(!fletcher16_valid(&buffer));
    }

    #[test]
    fn fletcher16_pins_a_deterministic_pair() {
        // A fixed input with a known check-octet pair so the algorithm stays
        // pinned. The pair was computed once with this implementation and then
        // confirmed to verify.
        let mut buffer = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x09, 0x0a,
        ];
        let offset = 8;

        let check = fletcher16_checkbytes(&buffer, offset);
        assert_eq!(check, [0x80, 0x48]);

        buffer[offset] = check[0];
        buffer[offset + 1] = check[1];
        assert!(fletcher16_valid(&buffer));
    }

    #[test]
    fn crc32c_matches_standard_vectors() {
        assert_eq!(crc32c(b""), 0x0000_0000);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(b"abc"), 0x364b_3fb7);
        assert_eq!(crc32c(b"hello world"), 0xc994_65aa);
    }
}
