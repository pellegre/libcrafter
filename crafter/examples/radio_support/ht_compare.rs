//! Example-local HT reference interpretation, not a new packet or PHY API.
//! https://www.radiotap.org/fields/MCS.html
//! https://www.radiotap.org/fields/A-MPDU%20status.html
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HtPhy {
    pub mcs: u8,
    pub short_gi: bool,
    pub ldpc: Option<bool>,
    pub stbc: Option<u8>,
    pub greenfield: Option<bool>,
    pub extension_spatial_streams: Option<u8>,
    pub aggregation: Option<bool>,
    pub ampdu_reference: Option<u32>,
    pub delimiter_offset: Option<usize>,
}
impl HtPhy {
    pub fn rate_bps(&self) -> u32 {
        let ndbps = [26u64, 52, 78, 104, 156, 208, 234, 260][self.mcs as usize];
        (ndbps * 20_000_000 / if self.short_gi { 72 } else { 80 }) as u32
    }
    pub fn unknown_configuration(&self) -> bool {
        self.stbc.is_none() || self.greenfield.is_none() || self.extension_spatial_streams.is_none()
    }
    pub fn compatible(&self, other: &Self) -> bool {
        fn agrees<T: PartialEq>(a: Option<T>, b: Option<T>) -> bool {
            match (a, b) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
        }
        self.mcs == other.mcs
            && self.short_gi == other.short_gi
            && agrees(self.ldpc, other.ldpc)
            && agrees(self.stbc, other.stbc)
            && agrees(self.greenfield, other.greenfield)
            && agrees(
                self.extension_spatial_streams,
                other.extension_spatial_streams,
            )
            && agrees(self.aggregation, other.aggregation)
    }
    pub fn reference(mcs: [u8; 3], ampdu: Option<[u8; 8]>) -> Result<Self, &'static str> {
        let [known, flags, index] = mcs;
        if known & 7 != 7 {
            return Err("unknown_ht_rate_or_bandwidth");
        }
        if flags & 3 != 0 || index > 7 {
            return Err("unsupported_ht_bandwidth_or_streams");
        }
        let stbc = (known & 0x20 != 0).then_some((flags >> 5) & 3);
        let greenfield = (known & 8 != 0).then_some(flags & 8 != 0);
        let extension = (known & 0x40 != 0).then_some(((known >> 6) & 2) | (flags >> 7));
        if stbc.is_some_and(|v| v != 0)
            || greenfield == Some(true)
            || extension.is_some_and(|v| v != 0)
        {
            return Err("unsupported_ht_configuration");
        }
        if let Some(a) = ampdu {
            let flags = u16::from_le_bytes([a[4], a[5]]);
            if flags & 0x10 != 0 {
                return Err("corrupt_ampdu_delimiter");
            }
            if flags & 3 == 3 {
                return Err("empty_ampdu_subframe");
            }
        }
        Ok(Self {
            mcs: index,
            short_gi: flags & 4 != 0,
            ldpc: (known & 0x10 != 0).then_some(flags & 0x10 != 0),
            stbc,
            greenfield,
            extension_spatial_streams: extension,
            aggregation: ampdu.map(|_| true),
            ampdu_reference: ampdu.map(|a| u32::from_le_bytes([a[0], a[1], a[2], a[3]])),
            delimiter_offset: None,
        })
    }
    pub fn recovered(value: &Value, raw_len: usize) -> Result<Self, &'static str> {
        let h = &value["ht"];
        let index = h["mcs"]
            .as_u64()
            .filter(|n| *n < 8)
            .ok_or("unsupported_ht_mcs")? as u8;
        if h["bandwidth_mhz"] != 20 || h["stbc"] != 0 || h["extension_spatial_streams"] != 0 {
            return Err("unsupported_ht_configuration");
        }
        let short_gi = match h["guard_interval_ns"].as_u64() {
            Some(400) => true,
            Some(800) => false,
            _ => return Err("unknown_ht_guard_interval"),
        };
        let ldpc = match h["coding"].as_str() {
            Some("ldpc") => true,
            Some("bcc") => false,
            _ => return Err("unknown_ht_coding"),
        };
        let aggregation = h["aggregation"].as_bool().ok_or("unknown_ht_aggregation")?;
        let length = h["psdu_bytes"]
            .as_u64()
            .filter(|n| (4..=65535).contains(n))
            .ok_or("invalid_ht_length")?;
        let delimiter_offset = if aggregation {
            let offset = value["ampdu"]["delimiter_offset"]
                .as_u64()
                .ok_or("missing_ampdu_offset")?;
            if offset % 4 != 0
                || offset
                    .checked_add(4)
                    .and_then(|n| n.checked_add(raw_len as u64))
                    .is_none_or(|n| n > length)
            {
                return Err("invalid_ampdu_offset");
            }
            Some(offset as usize)
        } else {
            if length != raw_len as u64 || !value["ampdu"].is_null() {
                return Err("invalid_ht_length");
            }
            None
        };
        let greenfield = match h.get("format") {
            None | Some(Value::Null) => None,
            Some(v) if v == "mixed" => Some(false),
            _ => return Err("unsupported_ht_configuration"),
        };
        Ok(Self {
            mcs: index,
            short_gi,
            ldpc: Some(ldpc),
            stbc: Some(0),
            greenfield,
            extension_spatial_streams: Some(0),
            aggregation: Some(aggregation),
            ampdu_reference: None,
            delimiter_offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_ht_reference_known_flags_are_conditional() {
        let unknown = HtPhy::reference([7, 0xf8, 3], None).unwrap();
        assert_eq!(
            (
                unknown.ldpc,
                unknown.stbc,
                unknown.greenfield,
                unknown.extension_spatial_streams
            ),
            (None, None, None, None)
        );
        assert!(unknown.unknown_configuration());
        assert_eq!(unknown.rate_bps(), 26_000_000);
        let known = HtPhy::reference([0x7f, 0x14, 3], None).unwrap();
        assert_eq!(known.ldpc, Some(true));
        assert!(known.short_gi);
        assert!(!known.unknown_configuration());
        assert_eq!(known.rate_bps(), 28_888_888);
        for bits in [1, 2, 4] {
            assert!(HtPhy::reference([7 ^ bits, 0, 0], None).is_err());
        }
        for flags in [1, 2, 3, 8, 0x20, 0x40, 0x60, 0x80] {
            assert!(
                HtPhy::reference([0x7f, flags, 0], None).is_err(),
                "flags={flags}"
            );
        }
        assert!(HtPhy::reference([0xff, 0, 0], None).is_err());
        assert!(HtPhy::reference([7, 0, 8], None).is_err());
        assert!(unknown.compatible(&HtPhy::reference([0x17, 0x10, 3], None).unwrap()));
        assert!(!HtPhy::reference([0x17, 0, 3], None)
            .unwrap()
            .compatible(&HtPhy::reference([0x17, 0x10, 3], None).unwrap()));
    }
    #[test]
    fn radio_ht_reference_aggregate_status() {
        let mut status = [0u8; 8];
        status[..4].copy_from_slice(&123u32.to_le_bytes());
        let ht = HtPhy::reference([7, 0, 0], Some(status)).unwrap();
        assert_eq!(ht.ampdu_reference, Some(123));
        assert_eq!(ht.aggregation, Some(true));
        status[4] = 0x10;
        assert_eq!(
            HtPhy::reference([7, 0, 0], Some(status)).unwrap_err(),
            "corrupt_ampdu_delimiter"
        );
        status[4] = 3;
        assert_eq!(
            HtPhy::reference([7, 0, 0], Some(status)).unwrap_err(),
            "empty_ampdu_subframe"
        );
        status[4] = 2; // This bit is not meaningful without the reporting flag.
        assert!(HtPhy::reference([7, 0, 0], Some(status)).is_ok());
    }
}
