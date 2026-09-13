//! HE20 SIG-B common and user fields; IEEE 802.11ax-2021 Tables 27-24..30.
//! Caller establishes bandwidth, compression and allocation context.
//! Bit-level header validation only; no IQ/DATA admission.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeRu20Assignment {
    pub tones: u16,
    /// First column covered in Table 27-26, numbered 1..9 from low to high
    /// frequency. This is not an FFT bin or the ordinal among equal-size RUs.
    pub first_slot: u8,
    /// Zero preserves an explicitly empty RU; otherwise the number of users.
    pub users: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeSigBCommon20Fields {
    allocation_code: u8,
    rus: Vec<HeRu20Assignment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeSigBError {
    BitCount {
        context: &'static str,
        required: usize,
        available: usize,
    },
    NonBinary {
        index: usize,
        value: u8,
    },
    Crc {
        expected: u8,
        received: u8,
    },
    Tail {
        index: usize,
    },
    ReservedAllocation(u8),
    WiderAllocation(u8),
    UserCount {
        available: usize,
    },
    UserContext {
        users: u8,
        position: u8,
    },
    ReservedUserMcs(u8),
    ReservedUserBit {
        index: usize,
    },
    ReservedSpatialConfiguration {
        users: u8,
        code: u8,
    },
}
impl std::fmt::Display for HeSigBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HE SIG-B: {self:?}")
    }
}
impl std::error::Error for HeSigBError {}

/// Allocation context established from SIG-A/SIG-B Common, not inferred from
/// the user bits. MU positions are zero-based within the RU, not the block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeSigBUserContext {
    NonMu,
    MuMimo { users: u8, position: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeSigBUserEncoding {
    /// STA-ID 2046 makes all remaining ten bits arbitrary (Tables 27-28/29).
    Unused { raw_parameters: u16 },
    NonMu {
        space_time_streams: u8,
        beamformed: bool,
        mcs: u8,
        dcm: bool,
        ldpc: bool,
    },
    MuMimo {
        spatial_configuration: u8,
        streams: u8,
        start_stream: u8,
        total_streams: u8,
        mcs: u8,
        ldpc: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeSigBUserFields {
    pub sta_id: u16,
    pub encoding: HeSigBUserEncoding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeSigBUserBlock {
    users: Vec<Result<HeSigBUserFields, HeSigBError>>,
}

impl HeSigBUserBlock {
    /// Decode one or two 21-bit users followed by their shared CRC and tail
    /// (Table 27-27). Integrity failure rejects the entire block; semantic
    /// errors are per-user and preserve the other result. This is header
    /// validation, not cross-field DATA admission or MAC integrity validation.
    pub fn decode(bits: &[u8], contexts: &[HeSigBUserContext]) -> Result<Self, HeSigBError> {
        if !(1..=2).contains(&contexts.len()) {
            return Err(HeSigBError::UserCount {
                available: contexts.len(),
            });
        }
        validate_block(bits, 21 * contexts.len(), "HE SIG-B user block")?;
        Ok(Self {
            users: contexts
                .iter()
                .enumerate()
                .map(|(i, &context)| decode_user(&bits[21 * i..21 * (i + 1)], context))
                .collect(),
        })
    }

    /// Results in transmitted User field order, including unused users/errors.
    pub fn users(&self) -> &[Result<HeSigBUserFields, HeSigBError>] {
        &self.users
    }
}

fn decode_user(bits: &[u8], context: HeSigBUserContext) -> Result<HeSigBUserFields, HeSigBError> {
    if let HeSigBUserContext::MuMimo { users, position } = context {
        if !(2..=8).contains(&users) || position >= users {
            return Err(HeSigBError::UserContext { users, position });
        }
    }
    let field = |start: usize, len: usize| -> u16 {
        bits[start..start + len]
            .iter()
            .enumerate()
            .fold(0, |v, (i, b)| v | ((*b as u16) << i))
    };
    let sta_id = field(0, 11);
    if sta_id == 2046 {
        return Ok(HeSigBUserFields {
            sta_id,
            encoding: HeSigBUserEncoding::Unused {
                raw_parameters: field(11, 10),
            },
        });
    }
    let mcs = field(15, 4) as u8;
    if mcs > 11 {
        return Err(HeSigBError::ReservedUserMcs(mcs));
    }
    let ldpc = bits[20] != 0;
    let encoding = match context {
        HeSigBUserContext::NonMu => HeSigBUserEncoding::NonMu {
            space_time_streams: field(11, 3) as u8 + 1,
            beamformed: bits[14] != 0,
            mcs,
            dcm: bits[19] != 0,
            ldpc,
        },
        HeSigBUserContext::MuMimo { users, position } => {
            if bits[19] != 0 {
                return Err(HeSigBError::ReservedUserBit { index: 19 });
            }
            let code = field(11, 4) as u8;
            let row = spatial_configuration(users, code)?;
            HeSigBUserEncoding::MuMimo {
                spatial_configuration: code,
                streams: row[position as usize],
                start_stream: row[..position as usize].iter().sum(),
                total_streams: row.iter().sum(),
                mcs,
                ldpc,
            }
        }
    };
    Ok(HeSigBUserFields { sta_id, encoding })
}

fn spatial_configuration(users: u8, code: u8) -> Result<&'static [u8], HeSigBError> {
    // IEEE 802.11ax-2021 Table 27-30, in increasing B3..B0 order.
    const TABLE: &[&[&[u8]]] = &[
        &[
            &[1, 1],
            &[2, 1],
            &[3, 1],
            &[4, 1],
            &[2, 2],
            &[3, 2],
            &[4, 2],
            &[3, 3],
            &[4, 3],
            &[4, 4],
        ],
        &[
            &[1, 1, 1],
            &[2, 1, 1],
            &[3, 1, 1],
            &[4, 1, 1],
            &[2, 2, 1],
            &[3, 2, 1],
            &[4, 2, 1],
            &[3, 3, 1],
            &[4, 3, 1],
            &[2, 2, 2],
            &[3, 2, 2],
            &[4, 2, 2],
            &[3, 3, 2],
        ],
        &[
            &[1, 1, 1, 1],
            &[2, 1, 1, 1],
            &[3, 1, 1, 1],
            &[4, 1, 1, 1],
            &[2, 2, 1, 1],
            &[3, 2, 1, 1],
            &[4, 2, 1, 1],
            &[3, 3, 1, 1],
            &[2, 2, 2, 1],
            &[3, 2, 2, 1],
            &[2, 2, 2, 2],
        ],
        &[
            &[1, 1, 1, 1, 1],
            &[2, 1, 1, 1, 1],
            &[3, 1, 1, 1, 1],
            &[4, 1, 1, 1, 1],
            &[2, 2, 1, 1, 1],
            &[3, 2, 1, 1, 1],
            &[2, 2, 2, 1, 1],
        ],
        &[
            &[1, 1, 1, 1, 1, 1],
            &[2, 1, 1, 1, 1, 1],
            &[3, 1, 1, 1, 1, 1],
            &[2, 2, 1, 1, 1, 1],
        ],
        &[&[1, 1, 1, 1, 1, 1, 1], &[2, 1, 1, 1, 1, 1, 1]],
        &[&[1, 1, 1, 1, 1, 1, 1, 1]],
    ];
    TABLE
        .get(usize::from(users).wrapping_sub(2))
        .and_then(|rows| rows.get(code as usize))
        .copied()
        .ok_or(HeSigBError::ReservedSpatialConfiguration { users, code })
}

impl HeSigBCommon20Fields {
    /// Check the 18-bit common field, including CRC and tail, then map its RUs.
    /// This field is absent when SIG-A indicates SIG-B compression.
    pub fn decode(bits: &[u8]) -> Result<Self, HeSigBError> {
        validate_block(bits, 8, "HE20 SIG-B common")?;
        let code = bits[..8]
            .iter()
            .enumerate()
            .fold(0u8, |v, (i, b)| v | (b << i));
        Ok(Self {
            allocation_code: code,
            rus: allocation(code)?,
        })
    }
    pub fn allocation_code(&self) -> u8 {
        self.allocation_code
    }
    pub fn rus(&self) -> &[HeRu20Assignment] {
        &self.rus
    }
    /// Number of subsequent 21-bit User fields, not User Block fields.
    pub fn user_count(&self) -> u8 {
        self.rus.iter().map(|r| r.users).sum()
    }
}

fn validate_block(bits: &[u8], payload: usize, context: &'static str) -> Result<(), HeSigBError> {
    if bits.len() != payload + 10 {
        return Err(HeSigBError::BitCount {
            context,
            required: payload + 10,
            available: bits.len(),
        });
    }
    if let Some((index, &value)) = bits.iter().enumerate().find(|(_, b)| **b > 1) {
        return Err(HeSigBError::NonBinary { index, value });
    }
    let expected = super::ht::crc(&bits[..payload]) >> 4;
    let received = bits[payload..payload + 4]
        .iter()
        .fold(0, |v, b| (v << 1) | b);
    if expected != received {
        return Err(HeSigBError::Crc { expected, received });
    }
    if let Some(index) = (payload + 4..bits.len()).find(|i| bits[*i] != 0) {
        return Err(HeSigBError::Tail { index });
    }
    Ok(())
}

fn assignment(tones: u16, first_slot: u8, users: u8) -> HeRu20Assignment {
    HeRu20Assignment {
        tones,
        first_slot,
        users,
    }
}

fn pair(rus: &mut Vec<HeRu20Assignment>, start: u8, merged: bool) {
    rus.push(assignment(if merged { 52 } else { 26 }, start, 1));
    if !merged {
        rus.push(assignment(26, start + 1, 1));
    }
}

fn half(rus: &mut Vec<HeRu20Assignment>, start: u8, mask: u8) {
    pair(rus, start, mask & 2 != 0);
    pair(rus, start + 2, mask & 1 != 0);
}

fn allocation(code: u8) -> Result<Vec<HeRu20Assignment>, HeSigBError> {
    let mut rus = Vec::with_capacity(9);
    match code {
        0..=15 => {
            half(&mut rus, 1, code >> 2);
            rus.push(assignment(26, 5, 1));
            half(&mut rus, 6, code & 3);
        }
        16..=23 => {
            half(&mut rus, 1, 3);
            rus.push(assignment(26, 5, 0));
            rus.push(assignment(106, 6, (code & 7) + 1));
        }
        24..=31 => {
            rus.push(assignment(106, 1, (code & 7) + 1));
            rus.push(assignment(26, 5, 0));
            half(&mut rus, 6, 3);
        }
        32..=63 => {
            half(&mut rus, 1, (code - 32) / 8);
            rus.push(assignment(26, 5, 1));
            rus.push(assignment(106, 6, (code & 7) + 1));
        }
        64..=95 => {
            // The printed decimal "72-29" row is a typo: 01001yyy = 72..79.
            rus.push(assignment(106, 1, (code & 7) + 1));
            rus.push(assignment(26, 5, 1));
            half(&mut rus, 6, (code - 64) / 8);
        }
        96..=111 => {
            rus.push(assignment(106, 1, ((code >> 2) & 3) + 1));
            rus.push(assignment(26, 5, 0));
            rus.push(assignment(106, 6, (code & 3) + 1));
        }
        112 => {
            half(&mut rus, 1, 3);
            rus.push(assignment(26, 5, 0));
            half(&mut rus, 6, 3);
        }
        113 => rus.push(assignment(242, 1, 0)),
        128..=191 => {
            rus.push(assignment(106, 1, ((code >> 3) & 7) + 1));
            rus.push(assignment(26, 5, 1));
            rus.push(assignment(106, 6, (code & 7) + 1));
        }
        192..=199 => rus.push(assignment(242, 1, (code & 7) + 1)),
        114 | 115 | 200..=215 => return Err(HeSigBError::WiderAllocation(code)),
        _ => return Err(HeSigBError::ReservedAllocation(code)),
    }
    Ok(rus)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn radio_he_sig_b_users_independent() {
        let rows = include_str!("../../tests/fixtures/iq/he-sig-b-users.tsv");
        assert_eq!(rows.lines().skip(1).count(), 3175);
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let bits: Vec<_> = c[0].bytes().map(|b| b - b'0').collect();
            let contexts: Vec<_> = c[1]
                .split(';')
                .map(|s| {
                    if s == "nonmu" {
                        HeSigBUserContext::NonMu
                    } else {
                        let (n, p) = s.split_once(':').unwrap();
                        HeSigBUserContext::MuMimo {
                            users: n.parse().unwrap(),
                            position: p.parse().unwrap(),
                        }
                    }
                })
                .collect();
            let block = HeSigBUserBlock::decode(&bits, &contexts).unwrap();
            let actual: Vec<_> = block.users().iter().map(|user| match user {
                Ok(HeSigBUserFields { sta_id, encoding }) => match encoding {
                    HeSigBUserEncoding::Unused { raw_parameters } => format!("unused:{sta_id}:{raw_parameters}"),
                    HeSigBUserEncoding::NonMu { space_time_streams, beamformed, mcs, dcm, ldpc } => format!("nonmu:{sta_id}:{space_time_streams}:{}:{mcs}:{}:{}", u8::from(*beamformed),u8::from(*dcm),u8::from(*ldpc)),
                    HeSigBUserEncoding::MuMimo { spatial_configuration, streams, start_stream, total_streams, mcs, ldpc } => format!("mu:{sta_id}:{spatial_configuration}:{streams}:{start_stream}:{total_streams}:{mcs}:{}",u8::from(*ldpc)),
                },
                Err(HeSigBError::ReservedSpatialConfiguration { users, code }) => format!("spatial:{users}:{code}"),
                Err(HeSigBError::ReservedUserMcs(mcs)) => format!("mcs:{mcs}"),
                Err(HeSigBError::ReservedUserBit { index }) => format!("reserved:{index}"),
                Err(HeSigBError::UserContext { users, position }) => format!("context:{users}:{position}"),
                other => panic!("unexpected {other:?}"),
            }).collect();
            assert_eq!(actual.join(";"), c[2], "{row}");
            let payload = 21 * contexts.len();
            for index in payload..bits.len() {
                let mut bad = bits.clone();
                bad[index] ^= 1;
                let error = HeSigBUserBlock::decode(&bad, &contexts).unwrap_err();
                if index < payload + 4 {
                    assert!(matches!(error, HeSigBError::Crc { .. }));
                } else {
                    assert_eq!(error, HeSigBError::Tail { index });
                }
            }
        }
    }

    #[test]
    fn radio_he_sig_b_users_bounds() {
        for count in [0, 3, 100] {
            assert_eq!(
                HeSigBUserBlock::decode(&[], &vec![HeSigBUserContext::NonMu; count]),
                Err(HeSigBError::UserCount { available: count })
            );
        }
        for count in 1..=2 {
            let contexts = vec![HeSigBUserContext::NonMu; count];
            let required = 21 * count + 10;
            for available in [0, required - 1, required + 1] {
                assert!(matches!(
                    HeSigBUserBlock::decode(&vec![0; available], &contexts),
                    Err(HeSigBError::BitCount { .. })
                ));
            }
            for index in 0..required {
                let mut bits = vec![0; required];
                bits[index] = 255;
                assert_eq!(
                    HeSigBUserBlock::decode(&bits, &contexts),
                    Err(HeSigBError::NonBinary { index, value: 255 })
                );
            }
        }
    }

    #[test]
    fn radio_he_sig_b_common_independent() {
        let rows = include_str!("../../tests/fixtures/iq/he-sig-b-common.tsv");
        assert_eq!(rows.lines().skip(1).count(), 256);
        let mut totals = [0; 3];
        for row in rows.lines().skip(1) {
            let c: Vec<_> = row.split('\t').collect();
            let code: u8 = c[0].parse().unwrap();
            let bits: Vec<_> = c[1].bytes().map(|b| b - b'0').collect();
            let result = HeSigBCommon20Fields::decode(&bits);
            match c[2] {
                "reserved" => {
                    assert_eq!(result, Err(HeSigBError::ReservedAllocation(code)));
                    totals[1] += 1;
                }
                "wider" => {
                    assert_eq!(result, Err(HeSigBError::WiderAllocation(code)));
                    totals[2] += 1;
                }
                "ok" => {
                    totals[0] += 1;
                    let fields = result.unwrap();
                    assert_eq!(fields.allocation_code(), code);
                    let expected: Vec<_> = c[3]
                        .split(',')
                        .map(|ru| {
                            let n: Vec<u16> = ru.split(':').map(|v| v.parse().unwrap()).collect();
                            assignment(n[0], n[1] as u8, n[2] as u8)
                        })
                        .collect();
                    assert_eq!(fields.rus(), expected, "code {code}");
                    assert_eq!(fields.user_count(), c[4].parse::<u8>().unwrap());
                    assert!(fields.rus().len() <= 9);
                    assert!(fields.user_count() <= 17);
                    assert!(fields
                        .rus()
                        .windows(2)
                        .all(|r| r[0].first_slot < r[1].first_slot));
                }
                _ => panic!("unknown fixture classification"),
            }
            for index in 8..18 {
                let mut bad = bits.clone();
                bad[index] ^= 1;
                let error = HeSigBCommon20Fields::decode(&bad).unwrap_err();
                if index < 12 {
                    assert!(matches!(error, HeSigBError::Crc { .. }));
                } else {
                    assert_eq!(error, HeSigBError::Tail { index });
                }
            }
        }
        assert_eq!(totals, [186, 52, 18]);
    }
    #[test]
    fn radio_he_sig_b_common_bounds() {
        for length in [0, 8, 12, 17, 19, 31, 52] {
            assert!(
                matches!(HeSigBCommon20Fields::decode(&vec![0;length]), Err(HeSigBError::BitCount { required: 18, available, .. }) if available==length)
            );
        }
        for index in 0..18 {
            let mut bits = [0; 18];
            bits[index] = 2;
            assert_eq!(
                HeSigBCommon20Fields::decode(&bits),
                Err(HeSigBError::NonBinary { index, value: 2 })
            );
        }
    }
}
