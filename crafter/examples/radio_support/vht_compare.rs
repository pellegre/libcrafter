//! Example-local interpretation of observed VHT radiotap fields.
//! https://www.radiotap.org/fields/VHT.html
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VhtPhy {
    pub mcs: u8,
    pub short_gi: bool,
    pub ldpc: bool,
    pub stbc: Option<bool>,
    pub group_id: Option<u8>,
}
impl VhtPhy {
    pub fn rate_bps(&self) -> u32 {
        let ndbps = [26u64, 52, 78, 104, 156, 208, 234, 260, 312][self.mcs as usize];
        (ndbps * 20_000_000 / if self.short_gi { 72 } else { 80 }) as u32
    }
    pub fn compatible(&self, other: &Self) -> bool {
        self.mcs == other.mcs
            && self.short_gi == other.short_gi
            && self.ldpc == other.ldpc
            && match (self.stbc, other.stbc) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
            && match (self.group_id, other.group_id) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
    pub fn reference(v: [u8; 12]) -> Result<Self, &'static str> {
        let known = u16::from_le_bytes([v[0], v[1]]);
        if known & 0x44 != 0x44 {
            return Err("unknown_vht_bandwidth_or_guard");
        }
        if v[3] != 0 || v[4] & 15 != 1 || v[4] >> 4 > 8 || v[5..8].iter().any(|b| *b != 0) {
            return Err("unsupported_vht_bandwidth_or_streams");
        }
        let stbc = (known & 1 != 0).then_some(v[2] & 1 != 0);
        let group_id = (known & 0x80 != 0).then_some(v[9]);
        if stbc == Some(true) || group_id.is_some_and(|g| g != 0 && g != 63) {
            return Err("unsupported_vht_configuration");
        }
        Ok(Self {
            mcs: v[4] >> 4,
            short_gi: v[2] & 4 != 0,
            ldpc: v[8] & 1 != 0,
            stbc,
            group_id,
        })
    }
    pub fn recovered(value: &Value) -> Result<Self, &'static str> {
        let h = &value["vht"];
        if h["bandwidth_mhz"] != 20
            || h["space_time_streams"] != 1
            || h["stbc"] != false
            || h["format"] != "su"
        {
            return Err("unsupported_vht_configuration");
        }
        let mcs = h["mcs"]
            .as_u64()
            .filter(|m| *m <= 8)
            .ok_or("unsupported_vht_mcs")? as u8;
        let short_gi = match h["guard_interval_ns"].as_u64() {
            Some(400) => true,
            Some(800) => false,
            _ => return Err("unknown_vht_guard"),
        };
        let ldpc = match h["coding"].as_str() {
            Some("ldpc") => true,
            Some("bcc") => false,
            _ => return Err("unknown_vht_coding"),
        };
        let group_id = h["group_id"]
            .as_u64()
            .filter(|g| *g == 0 || *g == 63)
            .ok_or("unsupported_vht_group")? as u8;
        Ok(Self {
            mcs,
            short_gi,
            ldpc,
            stbc: Some(false),
            group_id: Some(group_id),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observed_rate_requires_known_bandwidth_and_guard() {
        let mut v = [0; 12];
        v[..2].copy_from_slice(&0xc5u16.to_le_bytes());
        v[4] = 0x81;
        v[8] = 1;
        v[9] = 63;
        let p = VhtPhy::reference(v).unwrap();
        assert_eq!(p.rate_bps(), 78_000_000);
        assert!(p.ldpc);
        v[2] = 4;
        assert_eq!(VhtPhy::reference(v).unwrap().rate_bps(), 86_666_666);
        v[0] &= !4;
        assert!(VhtPhy::reference(v).is_err());
        v[0] |= 4;
        v[4] = 0x91;
        assert!(VhtPhy::reference(v).is_err());
        v[4] = 0x82;
        assert!(VhtPhy::reference(v).is_err());
        v[4] = 0x81;
        v[3] = 4;
        assert!(VhtPhy::reference(v).is_err());
    }
}
