//! Deterministic byte range tracking for IP defragmentation.
#![allow(dead_code)]

use std::collections::BTreeMap;

use super::metadata::IpDefragOverlapStatus;

/// A byte range in the fragmentable payload, using an exclusive end offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RangeMapRange {
    start: u32,
    end: u32,
}

impl RangeMapRange {
    /// Create a byte range with an exclusive end offset.
    pub(crate) const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Start offset in bytes.
    pub(crate) const fn start(self) -> u32 {
        self.start
    }

    /// Exclusive end offset in bytes.
    pub(crate) const fn end(self) -> u32 {
        self.end
    }

    /// Length in bytes, saturating to zero for malformed ranges.
    pub(crate) const fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// Whether this range contains no bytes.
    pub(crate) const fn is_empty(self) -> bool {
        self.len() == 0
    }

    const fn union(self, other: Self) -> Self {
        Self {
            start: if self.start < other.start {
                self.start
            } else {
                other.start
            },
            end: if self.end > other.end {
                self.end
            } else {
                other.end
            },
        }
    }
}

/// Why a byte range could not be inserted deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RangeMapConflictReason {
    /// An overlapping stored byte and incoming byte differ.
    ByteMismatch,
    /// A fragment byte range extends beyond the known complete payload length.
    BeyondCompleteLength,
    /// A second final length disagrees with the previously recorded one.
    CompleteLengthConflict,
    /// The incoming start plus payload length overflowed the range coordinate.
    RangeEndOverflow,
}

/// Details for a conflicting range observation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RangeMapConflict {
    incoming: RangeMapRange,
    existing: Option<RangeMapRange>,
    offset: u32,
    existing_byte: Option<u8>,
    incoming_byte: Option<u8>,
    reason: RangeMapConflictReason,
}

impl RangeMapConflict {
    fn new(
        reason: RangeMapConflictReason,
        incoming: RangeMapRange,
        existing: Option<RangeMapRange>,
        offset: u32,
        existing_byte: Option<u8>,
        incoming_byte: Option<u8>,
    ) -> Self {
        Self {
            incoming,
            existing,
            offset,
            existing_byte,
            incoming_byte,
            reason,
        }
    }

    /// The incoming range that triggered the conflict.
    pub(crate) const fn incoming(&self) -> RangeMapRange {
        self.incoming
    }

    /// The stored range involved in the conflict, when one exists.
    pub(crate) const fn existing(&self) -> Option<RangeMapRange> {
        self.existing
    }

    /// First byte offset where the conflict is visible.
    pub(crate) const fn offset(&self) -> u32 {
        self.offset
    }

    /// Stored byte at the conflict offset, when applicable.
    pub(crate) const fn existing_byte(&self) -> Option<u8> {
        self.existing_byte
    }

    /// Incoming byte at the conflict offset, when applicable.
    pub(crate) const fn incoming_byte(&self) -> Option<u8> {
        self.incoming_byte
    }

    /// Stable conflict reason.
    pub(crate) const fn reason(&self) -> RangeMapConflictReason {
        self.reason
    }
}

/// Result of inserting one fragment payload into a [`RangeMap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RangeMapInsert {
    /// New bytes were accepted into the map.
    Inserted {
        /// Incoming byte range.
        range: RangeMapRange,
        /// Whether accepted bytes overlapped existing bytes without conflict.
        overlapped: bool,
    },
    /// The incoming range and bytes were already present.
    Duplicate {
        /// Incoming duplicate byte range.
        range: RangeMapRange,
    },
    /// The incoming range conflicted with already recorded state.
    Conflict(RangeMapConflict),
    /// The incoming fragment carried no bytes and did not change state.
    Empty {
        /// Incoming empty byte range.
        range: RangeMapRange,
    },
}

/// Deterministic byte range map used by IP defragmentation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RangeMap {
    ranges: BTreeMap<u32, RangeEntry>,
    complete_len: Option<u32>,
    duplicate_count: usize,
    overlap_status: IpDefragOverlapStatus,
    conflict: Option<RangeMapConflict>,
}

impl RangeMap {
    /// Create an empty byte range map.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Insert fragment payload bytes at `start`.
    pub(crate) fn insert(&mut self, start: u32, payload: &[u8]) -> RangeMapInsert {
        let Some(end) = checked_range_end(start, payload.len()) else {
            let conflict = RangeMapConflict::new(
                RangeMapConflictReason::RangeEndOverflow,
                RangeMapRange::new(start, u32::MAX),
                None,
                start,
                None,
                None,
            );
            return self.conflict_insert(conflict);
        };

        let incoming = RangeMapRange::new(start, end);
        if incoming.is_empty() {
            return RangeMapInsert::Empty { range: incoming };
        }

        if let Some(complete_len) = self.complete_len {
            if end > complete_len {
                let conflict_offset = if start < complete_len {
                    complete_len
                } else {
                    start
                };
                let conflict = RangeMapConflict::new(
                    RangeMapConflictReason::BeyondCompleteLength,
                    incoming,
                    None,
                    conflict_offset,
                    None,
                    payload.get((conflict_offset - start) as usize).copied(),
                );
                return self.conflict_insert(conflict);
            }
        }

        let overlaps = self.overlapping_entries(incoming);
        for entry in &overlaps {
            if let Some(conflict) = byte_conflict(incoming, payload, entry) {
                return self.conflict_insert(conflict);
            }
        }

        if range_is_fully_covered(incoming, &overlaps) {
            self.duplicate_count += 1;
            return RangeMapInsert::Duplicate { range: incoming };
        }

        let overlapped = !overlaps.is_empty();
        if overlapped && !self.overlap_status.has_conflict() {
            self.overlap_status = IpDefragOverlapStatus::NonConflicting;
        }

        self.insert_merged(incoming, payload, &overlaps);
        RangeMapInsert::Inserted {
            range: incoming,
            overlapped,
        }
    }

    /// Record the complete payload length observed from a final fragment.
    pub(crate) fn set_total_len(&mut self, total_len: u32) -> Result<(), RangeMapConflict> {
        if let Some(existing_len) = self.complete_len {
            if existing_len == total_len {
                return Ok(());
            }
            let conflict = RangeMapConflict::new(
                RangeMapConflictReason::CompleteLengthConflict,
                RangeMapRange::new(total_len, total_len),
                Some(RangeMapRange::new(existing_len, existing_len)),
                total_len,
                None,
                None,
            );
            return Err(self.record_conflict(conflict));
        }

        if let Some(entry) = self.first_entry_beyond(total_len) {
            let conflict_offset = if entry.range.start() < total_len {
                total_len
            } else {
                entry.range.start()
            };
            let existing_byte = byte_at(&entry, conflict_offset);
            let conflict = RangeMapConflict::new(
                RangeMapConflictReason::BeyondCompleteLength,
                RangeMapRange::new(total_len, total_len),
                Some(entry.range),
                conflict_offset,
                existing_byte,
                None,
            );
            return Err(self.record_conflict(conflict));
        }

        self.complete_len = Some(total_len);
        Ok(())
    }

    /// Known final payload length, if a final fragment has been observed.
    pub(crate) const fn total_len(&self) -> Option<u32> {
        self.complete_len
    }

    /// Number of accepted, unique stored byte ranges.
    pub(crate) fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Number of accepted, unique payload bytes stored by the map.
    pub(crate) fn byte_len(&self) -> usize {
        self.ranges.values().map(|entry| entry.bytes.len()).sum()
    }

    /// Number of exact duplicate observations.
    pub(crate) const fn duplicate_count(&self) -> usize {
        self.duplicate_count
    }

    /// Overlap status observed by the map.
    pub(crate) const fn overlap_status(&self) -> IpDefragOverlapStatus {
        self.overlap_status
    }

    /// Whether any conflict has been observed.
    pub(crate) const fn has_conflict(&self) -> bool {
        self.conflict.is_some()
    }

    /// First recorded conflict, when one has been observed.
    pub(crate) const fn conflict(&self) -> Option<&RangeMapConflict> {
        self.conflict.as_ref()
    }

    /// Accepted byte ranges in deterministic offset order.
    pub(crate) fn ranges(&self) -> Vec<RangeMapRange> {
        self.ranges
            .iter()
            .map(|(&start, entry)| RangeMapRange::new(start, entry.end))
            .collect()
    }

    /// Known holes from offset zero to the final length, or the highest
    /// observed byte when the final length is not known yet.
    pub(crate) fn holes(&self) -> Vec<RangeMapRange> {
        let Some(limit) = self.known_hole_limit() else {
            return Vec::new();
        };

        let mut holes = Vec::new();
        let mut cursor = 0;
        for (&start, entry) in &self.ranges {
            if start >= limit {
                break;
            }
            if start > cursor {
                holes.push(RangeMapRange::new(cursor, start.min(limit)));
            }
            if entry.end > cursor {
                cursor = entry.end.min(limit);
            }
        }
        if cursor < limit {
            holes.push(RangeMapRange::new(cursor, limit));
        }
        holes
    }

    /// Whether the map has a known final length, no holes, and no conflict.
    pub(crate) fn is_complete(&self) -> bool {
        self.complete_len.is_some() && !self.has_conflict() && self.holes().is_empty()
    }

    /// Return the contiguous payload only after the map is complete.
    pub(crate) fn contiguous_payload(&self) -> Option<Vec<u8>> {
        let total_len = self.complete_len?;
        if self.has_conflict() || !self.holes().is_empty() {
            return None;
        }

        let mut payload = Vec::with_capacity(total_len as usize);
        let mut cursor = 0;
        for (&start, entry) in &self.ranges {
            if start >= total_len {
                break;
            }
            if start != cursor {
                return None;
            }

            let take_end = entry.end.min(total_len);
            let take_len = (take_end - start) as usize;
            payload.extend_from_slice(&entry.bytes[..take_len]);
            cursor = take_end;
        }

        if cursor == total_len {
            Some(payload)
        } else {
            None
        }
    }

    fn conflict_insert(&mut self, conflict: RangeMapConflict) -> RangeMapInsert {
        RangeMapInsert::Conflict(self.record_conflict(conflict))
    }

    fn record_conflict(&mut self, conflict: RangeMapConflict) -> RangeMapConflict {
        if self.conflict.is_none() {
            self.conflict = Some(conflict.clone());
        }
        self.overlap_status = IpDefragOverlapStatus::Conflicting;
        conflict
    }

    fn overlapping_entries(&self, range: RangeMapRange) -> Vec<EntrySnapshot> {
        self.ranges
            .range(..range.end())
            .filter_map(|(&start, entry)| {
                let existing = RangeMapRange::new(start, entry.end);
                (existing.end() > range.start()).then(|| EntrySnapshot {
                    range: existing,
                    bytes: entry.bytes.clone(),
                })
            })
            .collect()
    }

    fn first_entry_beyond(&self, complete_len: u32) -> Option<EntrySnapshot> {
        self.ranges.iter().find_map(|(&start, entry)| {
            let range = RangeMapRange::new(start, entry.end);
            (entry.end > complete_len).then(|| EntrySnapshot {
                range,
                bytes: entry.bytes.clone(),
            })
        })
    }

    fn insert_merged(
        &mut self,
        incoming: RangeMapRange,
        payload: &[u8],
        overlaps: &[EntrySnapshot],
    ) {
        let mut merged_range = incoming;
        for entry in overlaps {
            merged_range = merged_range.union(entry.range);
        }

        let mut merged = vec![0; merged_range.len() as usize];
        for entry in overlaps {
            copy_into(
                &mut merged,
                merged_range.start(),
                entry.range.start(),
                &entry.bytes,
            );
        }
        copy_into(&mut merged, merged_range.start(), incoming.start(), payload);

        for entry in overlaps {
            self.ranges.remove(&entry.range.start());
        }
        self.ranges.insert(
            merged_range.start(),
            RangeEntry {
                end: merged_range.end(),
                bytes: merged,
            },
        );
    }

    fn known_hole_limit(&self) -> Option<u32> {
        if let Some(total_len) = self.complete_len {
            return Some(total_len);
        }
        self.ranges.values().map(|entry| entry.end).max()
    }
}

impl Default for RangeMap {
    fn default() -> Self {
        Self {
            ranges: BTreeMap::new(),
            complete_len: None,
            duplicate_count: 0,
            overlap_status: IpDefragOverlapStatus::None,
            conflict: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RangeEntry {
    end: u32,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntrySnapshot {
    range: RangeMapRange,
    bytes: Vec<u8>,
}

fn checked_range_end(start: u32, payload_len: usize) -> Option<u32> {
    let len = u32::try_from(payload_len).ok()?;
    start.checked_add(len)
}

fn byte_conflict(
    incoming: RangeMapRange,
    payload: &[u8],
    entry: &EntrySnapshot,
) -> Option<RangeMapConflict> {
    let overlap_start = incoming.start().max(entry.range.start());
    let overlap_end = incoming.end().min(entry.range.end());
    let incoming_offset = (overlap_start - incoming.start()) as usize;
    let existing_offset = (overlap_start - entry.range.start()) as usize;
    let overlap_len = (overlap_end - overlap_start) as usize;

    for relative in 0..overlap_len {
        let incoming_byte = payload[incoming_offset + relative];
        let existing_byte = entry.bytes[existing_offset + relative];
        if incoming_byte != existing_byte {
            return Some(RangeMapConflict::new(
                RangeMapConflictReason::ByteMismatch,
                incoming,
                Some(entry.range),
                overlap_start + relative as u32,
                Some(existing_byte),
                Some(incoming_byte),
            ));
        }
    }
    None
}

fn range_is_fully_covered(incoming: RangeMapRange, overlaps: &[EntrySnapshot]) -> bool {
    if overlaps.is_empty() {
        return false;
    }

    let mut cursor = incoming.start();
    for entry in overlaps {
        if entry.range.start() > cursor {
            return false;
        }
        if entry.range.end() > cursor {
            cursor = entry.range.end().min(incoming.end());
        }
        if cursor == incoming.end() {
            return true;
        }
    }
    false
}

fn copy_into(buffer: &mut [u8], base: u32, start: u32, bytes: &[u8]) {
    let offset = (start - base) as usize;
    buffer[offset..offset + bytes.len()].copy_from_slice(bytes);
}

fn byte_at(entry: &EntrySnapshot, offset: u32) -> Option<u8> {
    if offset < entry.range.start() || offset >= entry.range.end() {
        return None;
    }
    entry
        .bytes
        .get((offset - entry.range.start()) as usize)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u32, end: u32) -> RangeMapRange {
        RangeMapRange::new(start, end)
    }

    #[test]
    fn range_map_returns_contiguous_payload_after_out_of_order_fragments() {
        let mut map = RangeMap::new();

        assert_eq!(
            map.insert(8, b"ijkl"),
            RangeMapInsert::Inserted {
                range: range(8, 12),
                overlapped: false,
            }
        );
        assert_eq!(map.holes(), vec![range(0, 8)]);
        assert_eq!(
            map.insert(0, b"abcd"),
            RangeMapInsert::Inserted {
                range: range(0, 4),
                overlapped: false,
            }
        );
        assert_eq!(
            map.insert(4, b"efgh"),
            RangeMapInsert::Inserted {
                range: range(4, 8),
                overlapped: false,
            }
        );

        assert_eq!(map.holes(), Vec::<RangeMapRange>::new());
        assert_eq!(map.contiguous_payload(), None);

        map.set_total_len(12).unwrap();

        assert!(map.is_complete());
        assert_eq!(map.ranges(), vec![range(0, 4), range(4, 8), range(8, 12)]);
        assert_eq!(map.byte_len(), 12);
        assert_eq!(
            map.contiguous_payload().as_deref(),
            Some(&b"abcdefghijkl"[..])
        );
    }

    #[test]
    fn range_map_tracks_holes_until_all_bytes_arrive() {
        let mut map = RangeMap::new();

        map.insert(0, b"abcd");
        map.insert(8, b"ijkl");
        map.set_total_len(16).unwrap();

        assert_eq!(map.holes(), vec![range(4, 8), range(12, 16)]);
        assert!(!map.is_complete());
        assert_eq!(map.contiguous_payload(), None);

        map.insert(4, b"efgh");
        map.insert(12, b"mnop");

        assert_eq!(map.holes(), Vec::<RangeMapRange>::new());
        assert_eq!(
            map.contiguous_payload().as_deref(),
            Some(&b"abcdefghijklmnop"[..])
        );
    }

    #[test]
    fn range_map_detects_exact_duplicate_ranges() {
        let mut map = RangeMap::new();

        map.insert(0, b"abcdef");

        assert_eq!(
            map.insert(0, b"abcdef"),
            RangeMapInsert::Duplicate { range: range(0, 6) }
        );
        assert_eq!(map.duplicate_count(), 1);
        assert_eq!(map.range_count(), 1);
        assert_eq!(map.byte_len(), 6);
        assert_eq!(map.overlap_status(), IpDefragOverlapStatus::None);
    }

    #[test]
    fn range_map_accepts_non_conflicting_overlaps() {
        let mut map = RangeMap::new();

        map.insert(0, b"abcdef");

        assert_eq!(
            map.insert(3, b"defghi"),
            RangeMapInsert::Inserted {
                range: range(3, 9),
                overlapped: true,
            }
        );
        map.set_total_len(9).unwrap();

        assert_eq!(map.overlap_status(), IpDefragOverlapStatus::NonConflicting);
        assert_eq!(map.ranges(), vec![range(0, 9)]);
        assert_eq!(map.holes(), Vec::<RangeMapRange>::new());
        assert_eq!(map.contiguous_payload().as_deref(), Some(&b"abcdefghi"[..]));
    }

    #[test]
    fn range_map_detects_conflicting_overlaps() {
        let mut map = RangeMap::new();

        map.insert(0, b"abcdef");
        let conflict = match map.insert(3, b"XYZ") {
            RangeMapInsert::Conflict(conflict) => conflict,
            result => panic!("expected conflict, got {result:?}"),
        };

        assert!(map.has_conflict());
        assert_eq!(map.overlap_status(), IpDefragOverlapStatus::Conflicting);
        assert_eq!(conflict.reason(), RangeMapConflictReason::ByteMismatch);
        assert_eq!(conflict.incoming(), range(3, 6));
        assert_eq!(conflict.existing(), Some(range(0, 6)));
        assert_eq!(conflict.offset(), 3);
        assert_eq!(conflict.existing_byte(), Some(b'd'));
        assert_eq!(conflict.incoming_byte(), Some(b'X'));
        assert_eq!(map.conflict(), Some(&conflict));

        map.set_total_len(6).unwrap();

        assert_eq!(map.contiguous_payload(), None);
    }

    #[test]
    fn range_map_conflicts_when_bytes_exceed_known_total_length() {
        let mut map = RangeMap::new();

        map.insert(0, b"abcd");
        map.set_total_len(4).unwrap();

        let conflict = match map.insert(4, b"e") {
            RangeMapInsert::Conflict(conflict) => conflict,
            result => panic!("expected conflict, got {result:?}"),
        };

        assert_eq!(
            conflict.reason(),
            RangeMapConflictReason::BeyondCompleteLength
        );
        assert!(map.has_conflict());
        assert_eq!(map.contiguous_payload(), None);
    }
}
