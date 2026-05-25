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
    let length = (transport.len() as u16).to_be_bytes();
    let protocol = [0, protocol];
    let pseudo = [
        source.as_slice(),
        destination.as_slice(),
        protocol.as_slice(),
        length.as_slice(),
    ];

    internet_checksum_chunks(pseudo.into_iter().chain([transport]))
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
    let length = (transport.len() as u32).to_be_bytes();
    let next = [0, 0, 0, next_header];
    let pseudo = [
        source.as_slice(),
        destination.as_slice(),
        length.as_slice(),
        next.as_slice(),
    ];

    internet_checksum_chunks(pseudo.into_iter().chain([transport]))
}

#[cfg(test)]
mod tests {
    use super::{
        finalize_checksum, fold_sum, internet_checksum, internet_checksum_chunks,
        ipv4_header_checksum, ipv4_pseudo_header_checksum, ipv6_pseudo_header_checksum,
        ones_complement_sum, verify_internet_checksum,
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
}
