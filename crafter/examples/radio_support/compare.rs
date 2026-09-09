//! Offline workflow: exact original-byte comparisons, never packet recompilation.
use super::artifact::*;
use crafter::{LinkType, Packet, Radiotap};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::BufReader,
};
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EpochAnchor {
    pub epoch: u64,
    #[serde(flatten)]
    pub anchor: Anchor,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub overlap_ns: [u64; 2],
    pub hackrf_capture_ns: [u64; 2],
    pub reference_capture_ns: [u64; 2],
    pub center_frequency_hz: u64,
    pub reference_uncertainty_ns: u64,
    pub match_window_ns: u64,
    pub anchors: Vec<EpochAnchor>,
    pub max_observations: usize,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "crafter.radio.comparison-policy/v1"
            || self.overlap_ns[0] >= self.overlap_ns[1]
            || self.center_frequency_hz == 0
            || self.max_observations == 0
            || self.max_observations > 10_000
        {
            return Err("invalid comparison policy/bounds".into());
        }
        for i in [self.hackrf_capture_ns, self.reference_capture_ns] {
            if i[0] >= i[1] || i[0] > self.overlap_ns[0] || i[1] < self.overlap_ns[1] {
                return Err("overlap outside declared capture interval".into());
            }
        }
        let mut epochs = BTreeSet::new();
        for a in &self.anchors {
            if !epochs.insert(a.epoch) {
                return Err("duplicate epoch anchor".into());
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct Observation {
    pub id: u64,
    pub bytes: Vec<u8>,
    pub time: [u64; 2],
    pub absent_fcs: bool,
    pub rate_bps: u32,
}
#[derive(Debug, Default, Serialize)]
pub struct Counts {
    pub total: u64,
    pub eligible: u64,
    pub absent_fcs: u64,
    pub max_timing_uncertainty_ns: u64,
    pub excluded: BTreeMap<String, u64>,
}
impl Counts {
    fn exclude(&mut self, s: &str) {
        *self.excluded.entry(s.into()).or_default() += 1;
    }
}
fn within(t: [u64; 2], p: &Policy) -> bool {
    t[0] >= p.overlap_ns[0] && t[1] < p.overlap_ns[1]
}
fn supported(rate: u32) -> bool {
    phy_family(rate) != "unknown"
}
fn bracket(time: u64, uncertainty: u64) -> Option<[u64; 2]> {
    Some([
        time.checked_sub(uncertainty)?,
        time.checked_add(uncertainty)?,
    ])
}
fn frame_time(p: &Position, rate: u32, policy: &Policy) -> Option<[u64; 2]> {
    let a = p.anchor.as_ref().or_else(|| {
        policy
            .anchors
            .iter()
            .find(|a| a.epoch == p.epoch)
            .map(|a| &a.anchor)
    })?;
    let delta = (p.sample_index as i128 - a.sample_index as i128) * 1_000_000_000 / rate as i128;
    let time = u64::try_from(a.unix_ns as i128 + delta).ok()?;
    bracket(time, a.uncertainty_ns)
}
fn normalize_fcs(
    mut bytes: Vec<u8>,
    state: &str,
    required: bool,
) -> std::result::Result<(Vec<u8>, bool), &'static str> {
    match state {
        "present_valid" | "present" => {
            if !valid_fcs(&bytes) {
                return Err("corrupt_fcs");
            };
            bytes.truncate(bytes.len() - 4);
            Ok((bytes, false))
        }
        "absent" if !required => Ok((bytes, true)),
        "absent" => Err("absent_fcs"),
        "present_invalid" => Err("corrupt_fcs"),
        _ => Err("unknown_fcs"),
    }
}
pub fn recovered_frame(
    v: &Value,
    policy: &Policy,
) -> Result<std::result::Result<Observation, &'static str>> {
    let config: Config = serde_json::from_value(v["config"].clone())?;
    config.rx()?;
    let position: Position = serde_json::from_value(v["position"].clone())?;
    position.iq()?;
    if config.center_frequency_hz != policy.center_frequency_hz {
        return Ok(Err("channel_mismatch"));
    }
    if config.sample_rate_hz != 20_000_000 {
        return Ok(Err("unsupported_phy"));
    }
    let Some(rate) = v["rate_bps"].as_u64().and_then(|n| u32::try_from(n).ok()) else {
        return Ok(Err("unknown_rate"));
    };
    if !supported(rate) || v["phy"] != phy_family(rate) {
        return Ok(Err("unsupported_phy"));
    }
    if phy_family(rate) != "legacy_ofdm"
        && !(v["preamble"] == "long" || (v["preamble"] == "short" && rate != 1_000_000))
    {
        return Err("invalid DSSS/CCK preamble".into());
    }
    let Some(time) = frame_time(&position, config.sample_rate_hz, policy) else {
        return Ok(Err("unknown_timing"));
    };
    if !within(time, policy) {
        return Ok(Err("outside_or_uncertain_interval"));
    }
    let end = v["end_sample_index"].as_u64().ok_or("missing frame end")?;
    if end <= position.sample_index {
        return Err("invalid frame sample interval".into());
    }
    let mut finish = position.clone();
    finish.sample_index = end;
    if !frame_time(&finish, config.sample_rate_hz, policy).is_some_and(|t| within(t, policy)) {
        return Ok(Err("outside_or_uncertain_interval"));
    }
    let raw = unhex(
        v["original_mac_hex"]
            .as_str()
            .ok_or("missing frame bytes")?,
    )?;
    if raw.len() > config.max_frame_bytes {
        return Ok(Err("truncated_or_oversize"));
    }
    let (bytes, absent_fcs) = match normalize_fcs(raw, v["fcs"].as_str().unwrap_or("unknown"), true)
    {
        Ok(x) => x,
        Err(e) => return Ok(Err(e)),
    };
    Ok(Ok(Observation {
        id: v["ordinal"].as_u64().ok_or("missing ordinal")?,
        bytes,
        time,
        absent_fcs,
        rate_bps: rate,
    }))
}
// Only established legacy MAC layouts are padding-normalized. Unknown layouts,
// extension frames and Order/HT control are excluded instead of guessing offsets.
fn mac_header(bytes: &[u8]) -> Option<usize> {
    let b = *bytes.first()?;
    let flags = *bytes.get(1)?;
    if b & 3 != 0 || flags & 0x80 != 0 {
        return None;
    }
    match (b >> 2) & 3 {
        0 => Some(24),
        1 => match b >> 4 {
            12 | 13 => Some(10),
            8..=11 | 14 | 15 => Some(16),
            _ => None,
        },
        2 => Some(24 + if flags & 3 == 3 { 6 } else { 0 } + if b & 0x80 != 0 { 2 } else { 0 }),
        _ => None,
    }
}
pub fn reference_frame(
    data: &[u8],
    original_len: u32,
    time: [u64; 2],
    id: u64,
    policy: &Policy,
) -> std::result::Result<Observation, &'static str> {
    if data.len() != original_len as usize {
        return Err("truncated");
    }
    if !within(time, policy) {
        return Err("outside_or_uncertain_interval");
    }
    if data.len() < 8 || data[0] != 0 {
        return Err("unsupported_framing");
    }
    let n = u16::from_le_bytes([data[2], data[3]]) as usize;
    if n < 8 || n > data.len() {
        return Err("truncated");
    }
    // Decode just the capture header, so limitations parsing MAC bodies do not
    // discard an otherwise eligible original frame.
    let packet = Packet::decode_from_link(LinkType::Radiotap, &data[..n])
        .map_err(|_| "unsupported_framing")?;
    let rt = packet.layer::<Radiotap>().ok_or("unsupported_framing")?;
    let present = rt.present().map_err(|_| "unsupported_framing")?;
    if present
        .field_bits()
        .any(|b| matches!(b, 19..=21 | 23 | 24 | 34))
    {
        return Err("unsupported_phy");
    }
    // Namespace reset (bit 29) has no payload and resets the next bitmap
    // to standard field zero: https://www.radiotap.org/fields/Radiotap%20Namespace.html
    // Linux monitor captures repeat per-antenna signal/index fields this way.
    // Keep accepting only those unambiguous one-byte repeated observations;
    // vendor namespaces and repeated framing/PHY declarations remain excluded.
    let words = present.words();
    let reset = 1u32 << 29;
    let extension = 1u32 << 31;
    let antenna = (1u32 << 5) | (1u32 << 11);
    if words[0] & (1 << 30) != 0 {
        return Err("unsupported_framing");
    }
    if words.len() > 1 {
        let mut tail_len = 0;
        for i in 1..words.len() {
            if words[i - 1] & reset == 0 || words[i] & !(antenna | reset | extension) != 0 {
                return Err("unsupported_framing");
            }
            tail_len += (words[i] & antenna).count_ones() as usize;
        }
        if rt.raw_fields().len() != tail_len {
            return Err("unsupported_framing");
        }
    }

    let flags = rt.flags_value().ok_or("unknown_fcs")?;
    if flags.failed_fcs() {
        return Err("corrupt_fcs");
    }
    if flags.bits() & 0x80 != 0 {
        return Err("unsupported_phy");
    }
    if rt.rx_flags_value().is_some_and(|f| f.bits() & 2 != 0) {
        return Err("corrupt_phy");
    }
    let rate = rt.rate_value().ok_or("unknown_rate")? as u32 * 500_000;
    if !supported(rate) {
        return Err("unsupported_phy");
    }
    let ch = rt.channel_value().ok_or("unknown_channel")?;
    if ch.frequency() as u64 * 1_000_000 != policy.center_frequency_hz {
        return Err("channel_mismatch");
    }
    // Radiotap Channel: CCK=0x20, OFDM=0x40, 2GHz=0x80,
    // 5GHz=0x100, dynamic CCK/OFDM=0x400; half/quarter=0xc000.
    // Rate is the observed 500-kbit/s value, never advertised capabilities.
    let modulation = ch.flags() & 0x460;
    let expected = if phy_family(rate) == "legacy_ofdm" {
        0x40
    } else {
        0x20
    };
    let band = ch.flags() & 0x180;
    if ch.flags() & !0x07e0 != 0
        || !matches!(band, 0x80 | 0x100)
        || (expected == 0x20 && band != 0x80)
        || !(modulation == expected || (modulation == 0x400 && band == 0x80))
        || (rate == 1_000_000 && flags.bits() & 2 != 0)
    {
        return Err("unsupported_phy");
    }
    let mut bytes = data[n..].to_vec();
    if flags.bits() & 0x20 != 0 {
        let h = mac_header(&bytes).ok_or("unsupported_padding")?;
        let padding = (4 - h % 4) % 4;
        if h + padding > bytes.len() {
            return Err("truncated");
        }
        bytes.drain(h..h + padding);
    }
    let (bytes, absent_fcs) = normalize_fcs(
        bytes,
        if flags.fcs_present() {
            "present"
        } else {
            "absent"
        },
        false,
    )?;
    if bytes.len() < 10 || bytes.len() > 4091 {
        return Err("truncated_or_oversize");
    }
    Ok(Observation {
        id,
        bytes,
        time,
        absent_fcs,
        rate_bps: rate,
    })
}
fn keep(
    result: std::result::Result<Observation, &str>,
    counts: &mut Counts,
    out: &mut Vec<Observation>,
) {
    counts.total += 1;
    match result {
        Ok(o) => {
            counts.eligible += 1;
            counts.absent_fcs += u64::from(o.absent_fcs);
            counts.max_timing_uncertainty_ns = counts
                .max_timing_uncertainty_ns
                .max((o.time[1] - o.time[0]) / 2);
            out.push(o)
        }
        Err(s) => counts.exclude(s),
    }
}
pub fn load_recovered(path: &str, p: &Policy) -> Result<(Vec<Observation>, Counts, Value)> {
    let mut reader = BufReader::new(File::open(path)?);
    let h = read_json(&mut reader)?.ok_or("missing receive header")?;
    if h["kind"] != "header" || !supported_schema(&h["schema"]) {
        return Err("unsupported receive schema".into());
    }
    let config: Config = serde_json::from_value(h["config"].clone())?;
    let config = config.rx()?;
    let mut segment: Option<(u64, u64, u64, u64)> = None;
    let mut samples = 0u64;
    let mut out = Vec::new();
    let mut counts = Counts::default();
    let mut summary = None;
    let mut terminal = false;
    let mut terminal_reason = String::new();
    let mut parser_errors = 0u64;
    let mut gaps = 0u64;
    let mut acquisition = Value::Null;
    let mut ids = BTreeSet::new();
    while let Some(v) = read_json(&mut reader)? {
        match v["kind"].as_str() {
            Some("frame") => {
                if terminal || counts.total >= p.max_observations as u64 {
                    return Err("frame after terminal or observation bound exceeded".into());
                }
                if h["schema"] == "crafter.radio.receive/v1" && v["phy"] != "legacy_ofdm" {
                    return Err("v1 receive artifacts require OFDM".into());
                }
                let id = v["ordinal"].as_u64().ok_or("missing ordinal")?;
                if !ids.insert(id) {
                    return Err("duplicate artifact ordinal".into());
                }
                let pos: Position = serde_json::from_value(v["position"].clone())?;
                let end = v["end_sample_index"].as_u64().ok_or("missing frame end")?;
                let fc: Config = serde_json::from_value(v["config"].clone())?;
                if fc.rx()? != config {
                    return Err("frame configuration mismatch".into());
                }
                if !segment.is_some_and(|(epoch, start, stop, _)| {
                    pos.epoch == epoch && pos.sample_index >= start && end <= stop
                }) {
                    keep(Err("unqualified_continuity"), &mut counts, &mut out);
                } else {
                    keep(recovered_frame(&v, p)?, &mut counts, &mut out);
                }
            }
            Some("chunk") => {
                if terminal {
                    return Err("chunk after terminal".into());
                }
                if v["verified_prefix"] != true {
                    return Err("unverified chunk".into());
                }
                let pos: Position = serde_json::from_value(v["position"].clone())?;
                pos.iq()?;
                let c: Config = serde_json::from_value(v["config"].clone())?;
                if c.rx()? != config {
                    return Err("chunk configuration mismatch".into());
                }
                let n = v["samples"].as_u64().ok_or("missing chunk samples")?;
                if n == 0 || n > config.max_chunk_samples as u64 {
                    return Err("invalid chunk bound".into());
                }
                samples = samples.checked_add(n).ok_or("sample overflow")?;
                if samples > config.max_capture_samples {
                    return Err("capture sample bound exceeded".into());
                }
                let stop = pos
                    .sample_index
                    .checked_add(n)
                    .ok_or("sample end overflow")?;
                let contiguous = pos.gap_reason.is_none()
                    && segment.is_some_and(|(epoch, _, end, seq)| {
                        epoch == pos.epoch
                            && end == pos.sample_index
                            && seq.checked_add(1) == Some(pos.sequence)
                    });
                let start = if contiguous {
                    segment.unwrap().1
                } else {
                    if segment.is_some() || pos.gap_reason.is_some() {
                        gaps += 1;
                    }
                    pos.sample_index
                };
                segment = Some((pos.epoch, start, stop, pos.sequence));
            }
            Some("terminal") => {
                if terminal {
                    return Err("duplicate terminal".into());
                }
                terminal_reason = v["reason"]
                    .as_str()
                    .ok_or("missing terminal reason")?
                    .to_owned();
                if !matches!(
                    terminal_reason.as_str(),
                    "Eof" | "LimitReached" | "Cancelled"
                ) {
                    return Err("invalid terminal reason".into());
                }
                terminal = true;
            }
            Some("summary") => {
                if summary.is_some() || !terminal {
                    return Err("duplicate summary".into());
                }
                summary = Some(v)
            }
            Some("acquisition") => {
                if !acquisition.is_null() {
                    return Err("duplicate acquisition".into());
                }
                acquisition = v
            }
            Some("parser_error") => {
                parser_errors += 1;
            }
            _ => return Err("unexpected receive record".into()),
        }
    }
    let summary = summary.ok_or("missing receive summary")?;
    if !terminal || summary["complete"] != true {
        return Err("incomplete receive artifact".into());
    }
    let valid = summary["decoder"]["valid_frames"]
        .as_u64()
        .ok_or("missing valid frame count")?;
    let dropped = summary["decoder"]["dropped_frames"]
        .as_u64()
        .ok_or("missing dropped count")?;
    let parsed = summary["parsed_packets"]
        .as_u64()
        .ok_or("missing parsed count")?;
    if valid.checked_sub(dropped) != Some(counts.total)
        || parsed.checked_add(parser_errors) != Some(counts.total)
        || summary["parser_failures"].as_u64() != Some(parser_errors)
        || summary["terminal"] != terminal_reason
    {
        return Err("inconsistent receive summary".into());
    }
    Ok((
        out,
        counts,
        json!({"gaps":gaps,"acquisition":acquisition,"receive_summary":summary}),
    ))
}
pub fn load_reference(path: &str, p: &Policy) -> Result<(Vec<Observation>, Counts)> {
    let mut cap = pcap::Capture::from_file_with_precision(path, pcap::Precision::Nano)?;
    if cap.get_datalink() != pcap::Linktype(127) {
        return Err("reference requires radiotap pcap".into());
    }
    let mut out = Vec::new();
    let mut counts = Counts::default();
    loop {
        match cap.next_packet() {
            Ok(pkt) => {
                if counts.total >= p.max_observations as u64 {
                    return Err("reference observation bound exceeded".into());
                }
                let secs = u64::try_from(pkt.header.ts.tv_sec)?;
                let nanos = u64::try_from(pkt.header.ts.tv_usec)?;
                if nanos >= 1_000_000_000 {
                    return Err("invalid pcap timestamp".into());
                }
                let stamp = secs
                    .checked_mul(1_000_000_000)
                    .and_then(|n| n.checked_add(nanos))
                    .ok_or("pcap timestamp overflow")?;
                let o = if let Some(time) = bracket(stamp, p.reference_uncertainty_ns) {
                    reference_frame(pkt.data, pkt.header.len, time, counts.total + 1, p)
                } else {
                    Err("unknown_timing")
                };
                keep(o, &mut counts, &mut out);
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok((out, counts))
}
#[derive(Debug, Serialize)]
pub struct Match {
    pub hackrf_ordinal: u64,
    pub reference_ordinal: u64,
    pub reference_fcs_absent: bool,
    pub rate_bps: u32,
    pub phy: String,
    pub original_mac_without_fcs_hex: String,
}
fn compatible(a: &Observation, b: &Observation, w: u64) -> bool {
    a.rate_bps == b.rate_bps
        && a.time[0] <= b.time[1].saturating_add(w)
        && b.time[0] <= a.time[1].saturating_add(w)
}
pub fn match_frames(a: &[Observation], b: &[Observation], window: u64) -> Vec<Match> {
    let mut groups: BTreeMap<(&[u8], u32), (Vec<&Observation>, Vec<&Observation>)> =
        BTreeMap::new();
    for x in a {
        groups.entry((&x.bytes, x.rate_bps)).or_default().0.push(x)
    }
    for x in b {
        groups.entry((&x.bytes, x.rate_bps)).or_default().1.push(x)
    }
    let mut matches = Vec::new();
    // Earliest finishing interval first; pair it with the earliest finishing
    // compatible interval on the other side. Removing one occurrence from each
    // side preserves multiplicity. Full bytes form the group key (no hash claims).
    for ((bytes, _rate), (mut left, mut right)) in groups {
        left.sort_by_key(|x| (x.time[1], x.id));
        right.sort_by_key(|x| (x.time[1], x.id));
        while !left.is_empty() && !right.is_empty() {
            let pair = if left[0].time[1] <= right[0].time[1] {
                let a = left.remove(0);
                right
                    .iter()
                    .position(|b| compatible(a, b, window))
                    .map(|i| (a, right.remove(i)))
            } else {
                let b = right.remove(0);
                left.iter()
                    .position(|a| compatible(a, b, window))
                    .map(|i| (left.remove(i), b))
            };
            if let Some((a, b)) = pair {
                matches.push(Match {
                    hackrf_ordinal: a.id,
                    reference_ordinal: b.id,
                    reference_fcs_absent: b.absent_fcs,
                    rate_bps: a.rate_bps,
                    phy: phy_family(a.rate_bps).into(),
                    original_mac_without_fcs_hex: hex(bytes),
                });
            }
        }
    }
    matches
}
fn breakdown(a: &[Observation], b: &[Observation], window: u64) -> Value {
    let n = match_frames(a, b, window).len();
    json!({"status":if a.is_empty() || b.is_empty() {"inconclusive"} else {"measured"},
        "hackrf_valid_count":a.len(), "eligible_dongle_count":b.len(), "exact_matches":n,
        "hackrf_fraction":if a.is_empty() {None} else {Some(n as f64/a.len() as f64)},
        "dongle_fraction":if b.is_empty() {None} else {Some(n as f64/b.len() as f64)}})
}
pub fn report(
    a: Vec<Observation>,
    ac: Counts,
    b: Vec<Observation>,
    bc: Counts,
    p: Policy,
    evidence: Value,
) -> Value {
    let pairs = match_frames(&a, &b, p.match_window_ns);
    let n = pairs.len();
    let mut families = BTreeMap::new();
    let mut rates = BTreeMap::new();
    for family in ["dsss", "cck", "legacy_ofdm"] {
        let left: Vec<_> = a
            .iter()
            .filter(|o| phy_family(o.rate_bps) == family)
            .cloned()
            .collect();
        let right: Vec<_> = b
            .iter()
            .filter(|o| phy_family(o.rate_bps) == family)
            .cloned()
            .collect();
        families.insert(family, breakdown(&left, &right, p.match_window_ns));
    }
    for rate in [
        1_000_000, 2_000_000, 5_500_000, 11_000_000, 6_000_000, 9_000_000, 12_000_000, 18_000_000,
        24_000_000, 36_000_000, 48_000_000, 54_000_000,
    ] {
        let left: Vec<_> = a.iter().filter(|o| o.rate_bps == rate).cloned().collect();
        let right: Vec<_> = b.iter().filter(|o| o.rate_bps == rate).cloned().collect();
        rates.insert(
            rate.to_string(),
            breakdown(&left, &right, p.match_window_ns),
        );
    }
    let au: BTreeSet<_> = a.iter().map(|o| &o.bytes).collect();
    let bu: BTreeSet<_> = b.iter().map(|o| &o.bytes).collect();
    json!({"schema":"crafter.radio.comparison/v2","families":families,"rates":rates,"status":if ac.eligible==0 || bc.eligible==0 {"inconclusive"}else{"measured"},"policy":p,"hackrf_valid_count":ac.eligible,"eligible_dongle_count":bc.eligible,"exact_matches":n,"hackrf_fraction":if ac.eligible==0 {None}else{Some(n as f64/ac.eligible as f64)},"dongle_fraction":if bc.eligible==0 {None}else{Some(n as f64/bc.eligible as f64)},"unique_byte_overlap":au.intersection(&bu).count(),"hackrf":ac,"reference":bc,"evidence":evidence,"matches":pairs,"target_assessed":false})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            schema: "crafter.radio.comparison-policy/v1".into(),
            overlap_ns: [100, 10000],
            hackrf_capture_ns: [0, 11000],
            reference_capture_ns: [0, 11000],
            center_frequency_hz: 2_412_000_000,
            reference_uncertainty_ns: 1,
            match_window_ns: 10,
            anchors: vec![],
            max_observations: 100,
        }
    }
    fn mac() -> Vec<u8> {
        vec![0xd4, 0, 0, 0, 2, 0, 0, 0, 0, 1]
    }
    fn fcs(mut m: Vec<u8>) -> Vec<u8> {
        m.extend_from_slice(&crc32(&m).to_le_bytes());
        m
    }
    fn radiotap(m: &[u8], flags: u8, rate: u8) -> Vec<u8> {
        let mut bytes = vec![0, 0, 14, 0, 14, 0, 0, 0, flags, rate, 0x6c, 0x09, 0xc0, 0];
        bytes.extend_from_slice(m);
        bytes
    }
    fn obs(id: u64, t: [u64; 2]) -> Observation {
        Observation {
            id,
            bytes: mac(),
            time: t,
            absent_fcs: false,
            rate_bps: 6_000_000,
        }
    }
    #[test]
    fn radio_comparison_families_rates_and_unknown_modulation() {
        let p = policy();
        for rate in [2, 4, 11, 22] {
            let mut bytes = radiotap(&fcs(mac()), 0x10, rate);
            bytes[12] = 0xa0;
            let o = reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p).unwrap();
            assert_eq!(o.rate_bps, rate as u32 * 500_000);
            bytes[12] = 0x80;
            assert!(reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p).is_err());
            bytes[12] = 0x80;
            bytes[13] = 4;
            assert!(reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p).is_ok());
            bytes[13] = 8;
            assert!(reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p).is_err());
        }
        let a = obs(1, [1000, 1002]);
        let mut b = a.clone();
        b.rate_bps = 1_000_000;
        assert!(match_frames(&[a.clone()], &[b.clone()], 10).is_empty());
        let mut c = a.clone();
        c.id = 3;
        c.rate_bps = 11_000_000;
        let r = report(
            vec![a.clone(), b.clone()],
            Counts {
                eligible: 2,
                ..Counts::default()
            },
            vec![a, b, c],
            Counts {
                eligible: 3,
                ..Counts::default()
            },
            p,
            json!({}),
        );
        assert_eq!(r["exact_matches"], 2);
        assert_eq!(r["families"]["cck"]["status"], "inconclusive");
        assert!(r["families"]["cck"]["hackrf_fraction"].is_null());
        assert_eq!(r["families"]["cck"]["dongle_fraction"], 0.0);
        assert_eq!(r["families"]["dsss"]["exact_matches"], 1);
    }
    #[test]
    fn radio_comparison_duplicate_multiplicity_and_changed_bytes() {
        let a = vec![
            obs(1, [1000, 1002]),
            obs(2, [1000, 1002]),
            obs(3, [1000, 1002]),
        ];
        let mut b = vec![
            obs(8, [1001, 1003]),
            obs(9, [1001, 1003]),
            obs(10, [1001, 1003]),
        ];
        b[2].bytes[2] = 1;
        let matches = match_frames(&a, &b, 1);
        assert_eq!(matches.len(), 2);
        assert_ne!(matches[0].reference_ordinal, matches[1].reference_ordinal);
        b[0].time = [5000, 5001];
        assert_eq!(match_frames(&a, &b, 1).len(), 1);
    }
    #[test]
    fn radio_comparison_fcs_absence_corruption_and_padding() {
        let p = policy();
        let bytes = radiotap(&mac(), 0, 12);
        let o = reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p).unwrap();
        assert!(o.absent_fcs);
        assert_eq!(o.bytes, mac());
        let mut bytes = radiotap(&fcs(mac()), 0x10, 12);
        assert!(
            !reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p)
                .unwrap()
                .absent_fcs
        );
        *bytes.last_mut().unwrap() ^= 1;
        assert_eq!(
            reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p).unwrap_err(),
            "corrupt_fcs"
        );
        // QoS data: 26-byte MAC header, then two capture padding bytes, body, FCS.
        let mut m = vec![0; 29];
        m[0] = 0x88;
        m[26..].copy_from_slice(&[1, 2, 3]);
        let original = fcs(m);
        let mut padded = original.clone();
        padded.splice(26..26, [0, 0]);
        let bytes = radiotap(&padded, 0x30, 12);
        assert_eq!(
            reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p)
                .unwrap()
                .bytes,
            original[..original.len() - 4]
        );
        let bytes = radiotap(&padded, 0x10, 12);
        assert_eq!(
            reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p).unwrap_err(),
            "corrupt_fcs"
        );
    }
    #[test]
    fn radio_comparison_repeated_antenna_namespaces() {
        let p = policy();
        // Synthetic standard fields followed by two antenna namespaces.
        let mut bytes = vec![0, 0, 30, 0];
        for word in [0xa000402eu32, 0xa0000820, 0x00000820] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 12, 0x6c, 0x09, 0xc0, 0, 200, 0, 0, 0, 201, 0, 202, 1]);
        bytes.extend_from_slice(&mac());
        assert_eq!(
            reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p)
                .unwrap()
                .bytes,
            mac()
        );
        // Missing reset, vendor namespace, and repeated Rate are not accepted.
        for (index, mask) in [(7, 0x20), (11, 0x40), (8, 0x04)] {
            let mut bad = bytes.clone();
            bad[index] ^= mask;
            assert!(reference_frame(&bad, bad.len() as u32, [1000, 1002], 1, &p).is_err());
        }
        let mut bad = bytes.clone();
        bad[2] = 29;
        assert!(reference_frame(&bad, bad.len() as u32, [1000, 1002], 1, &p).is_err());
    }
    #[test]
    fn radio_comparison_exclusions_and_inconclusive() {
        let p = policy();
        let bytes = radiotap(&mac(), 0, 2);
        assert_eq!(
            reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p).unwrap_err(),
            "unsupported_phy"
        );
        let mut bytes = radiotap(&mac(), 0, 12);
        bytes[4] = 10;
        bytes.remove(9);
        bytes.insert(9, 0); // absent Rate bit, channel still aligned
        assert_eq!(
            reference_frame(&bytes, bytes.len() as u32, [1000, 1002], 1, &p).unwrap_err(),
            "unknown_rate"
        );
        let bytes = radiotap(&mac(), 0, 12);
        assert_eq!(
            reference_frame(&bytes, (bytes.len() + 1) as u32, [1000, 1002], 1, &p).unwrap_err(),
            "truncated"
        );
        assert_eq!(
            reference_frame(&bytes, bytes.len() as u32, [99, 101], 1, &p).unwrap_err(),
            "outside_or_uncertain_interval"
        );
        let r = report(
            vec![],
            Counts::default(),
            vec![],
            Counts::default(),
            p,
            json!({}),
        );
        assert_eq!(r["status"], "inconclusive");
        assert!(r["dongle_fraction"].is_null());
        assert_eq!(r["target_assessed"], false);
    }
    #[test]
    fn radio_comparison_recovered_requires_integrity_and_timing() {
        let p = policy();
        let mut v = json!({"ordinal":1,"config":{"sample_rate_hz":20000000,"center_frequency_hz":2412000000u64,"max_chunk_samples":100,"max_buffer_samples":1000,"max_frame_bytes":4095,"max_pending_frames":4,"max_capture_samples":10000,"max_duration_ns":1000000000},"position":{"epoch":0,"sequence":0,"sample_index":0,"anchor":{"sample_index":0,"unix_ns":1000,"uncertainty_ns":2},"gap_reason":null,"lost_samples":null},"end_sample_index":100,"phy":"legacy_ofdm","rate_bps":6000000,"fcs":"present_valid","original_mac_hex":hex(&fcs(mac()))});
        assert_eq!(recovered_frame(&v, &p).unwrap().unwrap().bytes, mac());
        let mut dsss = v.clone();
        dsss["phy"] = json!("dsss");
        dsss["rate_bps"] = json!(1_000_000);
        assert!(recovered_frame(&dsss, &p).is_err());
        dsss["preamble"] = json!("short");
        assert!(recovered_frame(&dsss, &p).is_err());
        dsss["preamble"] = json!("long");
        assert!(recovered_frame(&dsss, &p).unwrap().is_ok());
        dsss["rate_bps"] = json!(11_000_000);
        assert_eq!(
            recovered_frame(&dsss, &p).unwrap().unwrap_err(),
            "unsupported_phy"
        );
        v["original_mac_hex"] = json!(hex(&mac()));
        assert_eq!(recovered_frame(&v, &p).unwrap().unwrap_err(), "corrupt_fcs");
        v["fcs"] = json!("absent");
        assert_eq!(recovered_frame(&v, &p).unwrap().unwrap_err(), "absent_fcs");
        v["position"]["anchor"] = Value::Null;
        assert_eq!(
            recovered_frame(&v, &p).unwrap().unwrap_err(),
            "unknown_timing"
        );
    }
    #[test]
    fn radio_comparison_interval_matching_maximum_small_cases() {
        fn brute(a: &[Observation], b: &[Observation], used: u32) -> usize {
            if a.is_empty() {
                return 0;
            }
            let mut best = brute(&a[1..], b, used);
            for (i, o) in b.iter().enumerate() {
                if used & (1 << i) == 0 && compatible(&a[0], o, 0) {
                    best = best.max(1 + brute(&a[1..], b, used | (1 << i)));
                }
            }
            best
        }
        let mut seed = 13u64;
        for _ in 0..1000 {
            let mut make = || {
                let mut out = vec![];
                for i in 0..4 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let lo = (seed >> 32) % 12;
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    out.push(obs(i, [lo, lo + (seed >> 32) % 6]));
                }
                out
            };
            let a = make();
            let b = make();
            assert_eq!(match_frames(&a, &b, 0).len(), brute(&a, &b, 0));
        }
    }
    #[test]
    fn radio_comparison_policy_and_json_bounds() {
        let mut p = policy();
        p.anchors.push(EpochAnchor {
            epoch: 0,
            anchor: Anchor {
                sample_index: 0,
                unix_ns: 1000,
                uncertainty_ns: 1,
            },
        });
        p.validate().unwrap();
        let roundtrip: Policy = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
        roundtrip.validate().unwrap();
        p.overlap_ns = [0, 12000];
        assert!(p.validate().is_err());
        assert!(read_json(&mut std::io::Cursor::new(b"{\"kind\":\"frame\"}")).is_err());
        assert!(unhex("é").is_err());
        assert!(unhex("0").is_err());
    }
    #[test]
    fn radio_comparison_pcap_loader_and_receive_terminal_evidence() {
        let root =
            std::env::temp_dir().join(format!("crafter-radio-compare-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let result = std::panic::catch_unwind(|| {
            let mut p = policy();
            p.overlap_ns = [1_000_000_000, 2_000_000_000];
            p.hackrf_capture_ns = p.overlap_ns;
            p.reference_capture_ns = p.overlap_ns;
            let rt = radiotap(&fcs(mac()), 0x10, 12);
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&0xa1b23c4du32.to_le_bytes());
            bytes.extend_from_slice(&2u16.to_le_bytes());
            bytes.extend_from_slice(&4u16.to_le_bytes());
            for n in [0u32, 0, 65535, 127] {
                bytes.extend_from_slice(&n.to_le_bytes());
            }
            for _ in 0..2 {
                for n in [1u32, 1000, rt.len() as u32, rt.len() as u32] {
                    bytes.extend_from_slice(&n.to_le_bytes());
                }
                bytes.extend_from_slice(&rt);
            }
            let path = root.join("paired.pcap");
            std::fs::write(&path, bytes).unwrap();
            let (observations, counts) = load_reference(path.to_str().unwrap(), &p).unwrap();
            assert_eq!(observations.len(), 2);
            assert_eq!(counts.eligible, 2);
            let config = json!({"sample_rate_hz":20000000,"center_frequency_hz":2412000000u64,"max_chunk_samples":100,"max_buffer_samples":1000,"max_frame_bytes":4095,"max_pending_frames":4,"max_capture_samples":10000,"max_duration_ns":1000000000});
            let path = root.join("receive.jsonl");
            let mut out = Vec::new();
            write_json(
                &mut out,
                &json!({"kind":"header","schema":SCHEMA,"config":config}),
            )
            .unwrap();
            std::fs::write(&path, &out).unwrap();
            assert!(load_recovered(path.to_str().unwrap(), &p).is_err());
            write_json(&mut out, &json!({"kind":"terminal","reason":"Eof"})).unwrap();
            write_json(&mut out,&json!({"kind":"summary","complete":true,"terminal":"Eof","decoder":{"valid_frames":0,"dropped_frames":0},"parsed_packets":0,"parser_failures":0})).unwrap();
            std::fs::write(&path, &out).unwrap();
            let (_, counts, _) = load_recovered(path.to_str().unwrap(), &p).unwrap();
            assert_eq!(counts.eligible, 0);
            let old = String::from_utf8(out.clone())
                .unwrap()
                .replace(SCHEMA, "crafter.radio.receive/v1");
            std::fs::write(&path, old).unwrap();
            assert!(load_recovered(path.to_str().unwrap(), &p).is_ok());
            write_json(&mut out, &json!({"kind":"terminal","reason":"Eof"})).unwrap();
            std::fs::write(&path, &out).unwrap();
            assert!(load_recovered(path.to_str().unwrap(), &p).is_err());
        });
        std::fs::remove_dir_all(&root).unwrap();
        result.unwrap();
    }
}
