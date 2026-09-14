//! Example-local VHT metadata interpretation, not another packet/PHY API.
//! Source: radiotap.org/fields/VHT.html and fields/A-MPDU%20status.html.
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VhtPhy {
    pub bandwidth_mhz: u16,
    pub spatial_streams: u8,
    pub ldpc: bool,
    pub mcs: u8,
    pub short_gi: bool,
    pub stbc: Option<bool>,
    pub group_id: Option<u8>,
    pub partial_aid: Option<u16>,
    pub beamformed: Option<bool>,
    pub short_gi_disambiguation: Option<bool>,
    pub txop_ps_not_allowed: Option<bool>,
    pub ldpc_extra_symbol: Option<bool>,
    pub eof: Option<bool>,
    pub ampdu_reference: Option<u32>,
    pub delimiter_offset: Option<usize>,
}

impl VhtPhy {
    pub fn rate_bps(&self) -> u32 {
        let ndbps = [26u64, 52, 78, 104, 156, 208, 234, 260, 312][self.mcs as usize];
        (ndbps * 20_000_000 / if self.short_gi { 72 } else { 80 }) as u32
    }
    pub fn unknown_configuration(&self) -> bool {
        self.stbc.is_none() || self.group_id.is_none()
    }
    pub fn compatible(&self, other: &Self) -> bool {
        fn agrees<T: PartialEq>(a: Option<T>, b: Option<T>) -> bool {
            match (a, b) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
        }
        self.bandwidth_mhz == other.bandwidth_mhz
            && self.spatial_streams == other.spatial_streams
            && self.ldpc == other.ldpc
            && self.mcs == other.mcs
            && self.short_gi == other.short_gi
            && agrees(self.stbc, other.stbc)
            && agrees(self.group_id, other.group_id)
            && agrees(self.partial_aid, other.partial_aid)
            && agrees(self.beamformed, other.beamformed)
            && agrees(self.short_gi_disambiguation, other.short_gi_disambiguation)
            && agrees(self.txop_ps_not_allowed, other.txop_ps_not_allowed)
            && agrees(self.ldpc_extra_symbol, other.ldpc_extra_symbol)
            && agrees(self.eof, other.eof)
    }
    pub fn reference(v: [u8; 12], ampdu: Option<[u8; 8]>) -> Result<Self, &'static str> {
        let known = u16::from_le_bytes([v[0], v[1]]);
        if known & 0x44 != 0x44 {
            return Err("unknown_vht_rate_or_bandwidth");
        }
        if v[3] & 31 != 0 {
            return Err("unsupported_vht_bandwidth");
        }
        if v[4] & 15 != 1 || v[5..8].iter().any(|b| b & 15 != 0) {
            return Err("unsupported_vht_streams_or_users");
        }
        let mcs = v[4] >> 4;
        if mcs == 15 {
            return Err("unknown_vht_mcs");
        }
        if mcs > 8 {
            return Err("unsupported_vht_mcs");
        }
        // For a present user, coding is valid without a separate known bit.
        let ldpc = v[8] & 1 != 0;
        let stbc = (known & 1 != 0).then_some(v[2] & 1 != 0);
        let group_id = (known & 0x80 != 0).then_some(v[9]);
        if group_id.is_some_and(|g| g != 0 && g != 63) {
            return Err("unsupported_vht_group");
        }
        let partial_aid = (known & 0x100 != 0).then_some(u16::from_le_bytes([v[10], v[11]]));
        if partial_aid.is_some_and(|aid| aid > 511) {
            return Err("invalid_vht_partial_aid");
        }
        let short_gi = v[2] & 4 != 0;
        let disambiguation = (known & 8 != 0).then_some(v[2] & 8 != 0);
        if (!short_gi && disambiguation == Some(true))
            || (stbc == Some(true) && disambiguation == Some(true))
            || (!ldpc && known & 16 != 0 && v[2] & 16 != 0)
        {
            return Err("inconsistent_vht_flags");
        }
        let mut eof = None;
        if let Some(a) = ampdu {
            let flags = u16::from_le_bytes([a[4], a[5]]);
            if flags & 0x10 != 0 {
                return Err("corrupt_ampdu_delimiter");
            }
            if flags & 3 == 3 {
                return Err("empty_ampdu_subframe");
            }
            eof = (flags & 0x80 != 0).then_some(flags & 0x40 != 0);
        }
        Ok(Self {
            bandwidth_mhz: 20,
            spatial_streams: 1,
            ldpc,
            mcs,
            short_gi,
            stbc,
            group_id,
            partial_aid,
            beamformed: (known & 0x20 != 0).then_some(v[2] & 0x20 != 0),
            short_gi_disambiguation: disambiguation,
            eof,
            txop_ps_not_allowed: (known & 2 != 0).then_some(v[2] & 2 != 0),
            ldpc_extra_symbol: (known & 16 != 0).then_some(v[2] & 16 != 0),
            ampdu_reference: ampdu.map(|a| u32::from_le_bytes([a[0], a[1], a[2], a[3]])),
            delimiter_offset: None,
        })
    }
    pub fn recovered(value: &Value, raw_len: usize) -> Result<Self, &'static str> {
        let h = &value["vht"];
        let mcs = h["mcs"]
            .as_u64()
            .filter(|n| *n <= 8)
            .ok_or("unsupported_vht_mcs")? as u8;
        let stbc = h["stbc"].as_bool().ok_or("unknown_vht_stbc")?;
        if h["bandwidth_code"] != 0
            || h["space_time_streams"] != if stbc { 2 } else { 1 }
            || (h["coding"] != "bcc" && h["coding"] != "ldpc")
        {
            return Err("unsupported_vht_configuration");
        }
        let short_gi = match h["guard_interval_ns"].as_u64() {
            Some(400) => true,
            Some(800) => false,
            _ => return Err("unknown_vht_guard_interval"),
        };
        let disambiguation = h["short_gi_disambiguation"]
            .as_bool()
            .ok_or("unknown_vht_disambiguation")?;
        if (!short_gi || stbc) && disambiguation {
            return Err("inconsistent_vht_flags");
        }
        let group_id = h["group_id"]
            .as_u64()
            .filter(|g| *g == 0 || *g == 63)
            .ok_or("unsupported_vht_group")? as u8;
        let partial_aid = h["partial_aid"]
            .as_u64()
            .filter(|aid| *aid <= 511)
            .ok_or("invalid_vht_partial_aid")? as u16;
        let beamformed = h["beamformed"].as_bool().ok_or("unknown_vht_beamforming")?;
        let optional_bool = |key| match h.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            _ => Err("invalid_vht_flags"),
        };
        let txop_ps_not_allowed = optional_bool("txop_ps_not_allowed")?;
        let ldpc_extra_symbol = optional_bool("ldpc_extra_symbol")?;
        let ldpc = h["coding"] == "ldpc";
        if !ldpc && ldpc_extra_symbol == Some(true) {
            return Err("inconsistent_vht_flags");
        }
        let bounds = h["apep_length_bounds"]
            .as_array()
            .filter(|a| a.len() == 2)
            .ok_or("invalid_vht_length")?;
        let lo = bounds[0].as_u64().ok_or("invalid_vht_length")?;
        let hi = bounds[1]
            .as_u64()
            .filter(|v| *v <= 524284)
            .ok_or("invalid_vht_length")?;
        if h["service_crc_verified"] != true || hi < 4 || hi % 4 != 0 || lo != hi - 3 {
            return Err("invalid_vht_length");
        }
        let offset = value["ampdu"]["delimiter_offset"]
            .as_u64()
            .ok_or("missing_ampdu_offset")?;
        let control = value["ampdu"]["control_bits"]
            .as_u64()
            .filter(|n| *n <= 3)
            .ok_or("invalid_vht_delimiter_flags")?;
        if offset % 4 != 0
            || offset
                .checked_add(4)
                .and_then(|n| n.checked_add(raw_len as u64))
                .is_none_or(|n| n > hi)
        {
            return Err("invalid_ampdu_offset");
        }
        Ok(Self {
            bandwidth_mhz: 20,
            spatial_streams: 1,
            ldpc,
            mcs,
            short_gi,
            stbc: Some(stbc),
            group_id: Some(group_id),
            partial_aid: Some(partial_aid),
            beamformed: Some(beamformed),
            short_gi_disambiguation: Some(disambiguation),
            txop_ps_not_allowed,
            ldpc_extra_symbol,
            eof: Some(control & 1 != 0),
            ampdu_reference: None,
            delimiter_offset: Some(offset as usize),
        })
    }
}

#[cfg(test)]
#[path = "vht_compare_tests.rs"]
mod tests;
