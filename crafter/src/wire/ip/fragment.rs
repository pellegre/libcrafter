//! Internal transmit-side IP fragmentation planners.

pub(super) mod ipv4_planner {
    #![allow(dead_code)]

    use super::super::ipv4::Ipv4FragmentView;
    use super::super::metadata::IpFragmentRange;
    use crate::{CrafterError, Result};

    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPV4_MAX_HEADER_LEN: usize = 60;
    const IPV4_MAX_TOTAL_LEN: usize = 65_535;
    const IPV4_MAX_FRAGMENT_OFFSET: u32 = 0x1fff;
    const IPV4_FRAGMENT_ALIGNMENT: usize = 8;

    /// IPv4 header fields that influence fragment range planning.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(in crate::wire::ip) struct Ipv4FragmentHeaderContext {
        header_len: usize,
        fragment_offset: u16,
        more_fragments: bool,
    }

    impl Ipv4FragmentHeaderContext {
        /// Create IPv4 planning context from explicit header values.
        pub(in crate::wire::ip) const fn new(
            header_len: usize,
            fragment_offset: u16,
            more_fragments: bool,
        ) -> Self {
            Self {
                header_len,
                fragment_offset,
                more_fragments,
            }
        }

        /// Create IPv4 planning context from an extracted packet view.
        pub(in crate::wire::ip) const fn from_view(view: &Ipv4FragmentView) -> Self {
            Self::new(
                view.header_len(),
                view.fragment_offset(),
                view.more_fragments(),
            )
        }

        /// IPv4 header length in bytes.
        pub(in crate::wire::ip) const fn header_len(self) -> usize {
            self.header_len
        }

        /// Base fragment offset from the input header, in 8-byte units.
        pub(in crate::wire::ip) const fn fragment_offset(self) -> u16 {
            self.fragment_offset
        }

        /// Base fragment offset from the input header, in bytes.
        pub(in crate::wire::ip) const fn fragment_offset_bytes(self) -> u32 {
            (self.fragment_offset as u32) * IPV4_FRAGMENT_ALIGNMENT as u32
        }

        /// Whether the input header already had More Fragments set.
        pub(in crate::wire::ip) const fn more_fragments(self) -> bool {
            self.more_fragments
        }
    }

    /// Deterministic IPv4 fragmentation plan for one source payload.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::wire::ip) struct Ipv4FragmentPlan {
        header: Ipv4FragmentHeaderContext,
        payload_len: usize,
        mtu: usize,
        max_fragment_payload_len: usize,
        aligned_fragment_payload_len: usize,
        fragments: Vec<Ipv4PlannedFragment>,
    }

    impl Ipv4FragmentPlan {
        /// Plan IPv4 fragments for a header context, payload length, and MTU.
        pub(in crate::wire::ip) fn new(
            header: Ipv4FragmentHeaderContext,
            payload_len: usize,
            mtu: usize,
        ) -> Result<Self> {
            validate_ipv4_fragment_inputs(header, payload_len, mtu)?;

            let payload_capacity = mtu - header.header_len();
            let max_ipv4_payload_len = IPV4_MAX_TOTAL_LEN - header.header_len();
            let max_fragment_payload_len = payload_capacity.min(max_ipv4_payload_len);
            let aligned_fragment_payload_len =
                align_down(max_fragment_payload_len, IPV4_FRAGMENT_ALIGNMENT);
            let fragments = plan_fragments(
                header,
                payload_len,
                max_fragment_payload_len,
                aligned_fragment_payload_len,
            )?;

            Ok(Self {
                header,
                payload_len,
                mtu,
                max_fragment_payload_len,
                aligned_fragment_payload_len,
                fragments,
            })
        }

        /// Plan IPv4 fragments directly from an extracted packet view.
        pub(in crate::wire::ip) fn from_view(view: &Ipv4FragmentView, mtu: usize) -> Result<Self> {
            Self::new(
                Ipv4FragmentHeaderContext::from_view(view),
                view.payload().len(),
                mtu,
            )
        }

        /// Header context used to produce this plan.
        pub(in crate::wire::ip) const fn header(&self) -> Ipv4FragmentHeaderContext {
            self.header
        }

        /// Source payload length in bytes.
        pub(in crate::wire::ip) const fn payload_len(&self) -> usize {
            self.payload_len
        }

        /// MTU used to produce this plan.
        pub(in crate::wire::ip) const fn mtu(&self) -> usize {
            self.mtu
        }

        /// Maximum payload bytes allowed in any fragment by MTU and IPv4 length.
        pub(in crate::wire::ip) const fn max_fragment_payload_len(&self) -> usize {
            self.max_fragment_payload_len
        }

        /// 8-byte-aligned payload bytes used for non-final fragments.
        pub(in crate::wire::ip) const fn aligned_fragment_payload_len(&self) -> usize {
            self.aligned_fragment_payload_len
        }

        /// Planned fragments in emission order.
        pub(in crate::wire::ip) fn fragments(&self) -> &[Ipv4PlannedFragment] {
            &self.fragments
        }

        /// Number of planned emitted records.
        pub(in crate::wire::ip) fn fragment_count(&self) -> usize {
            self.fragments.len()
        }
    }

    /// One planned IPv4 fragment range and header offset.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(in crate::wire::ip) struct Ipv4PlannedFragment {
        payload_range: IpFragmentRange,
        datagram_range: IpFragmentRange,
        fragment_offset: u16,
        more_fragments: bool,
    }

    impl Ipv4PlannedFragment {
        fn new(
            header: Ipv4FragmentHeaderContext,
            payload_start: usize,
            payload_end: usize,
            more_fragments: bool,
        ) -> Result<Self> {
            let payload_start = u32::try_from(payload_start).map_err(|_| {
                CrafterError::invalid_field_value(
                    "ipv4.payload_length",
                    "payload length exceeds IPv4 total length limit",
                )
            })?;
            let payload_end = u32::try_from(payload_end).map_err(|_| {
                CrafterError::invalid_field_value(
                    "ipv4.payload_length",
                    "payload length exceeds IPv4 total length limit",
                )
            })?;
            let datagram_start = header
                .fragment_offset_bytes()
                .checked_add(payload_start)
                .ok_or_else(fragment_offset_overflow)?;
            let datagram_end = header
                .fragment_offset_bytes()
                .checked_add(payload_end)
                .ok_or_else(fragment_offset_overflow)?;

            if datagram_start % IPV4_FRAGMENT_ALIGNMENT as u32 != 0 {
                return Err(CrafterError::invalid_field_value(
                    "ipv4.fragment_offset",
                    "planned fragment offset must be 8-byte aligned",
                ));
            }

            let offset_units = datagram_start / IPV4_FRAGMENT_ALIGNMENT as u32;
            if offset_units > IPV4_MAX_FRAGMENT_OFFSET {
                return Err(fragment_offset_overflow());
            }

            Ok(Self {
                payload_range: IpFragmentRange::new(payload_start, payload_end),
                datagram_range: IpFragmentRange::new(datagram_start, datagram_end),
                fragment_offset: offset_units as u16,
                more_fragments,
            })
        }

        /// Byte range in the input packet payload, suitable for slicing.
        pub(in crate::wire::ip) const fn payload_range(self) -> IpFragmentRange {
            self.payload_range
        }

        /// Byte range in the original datagram payload.
        pub(in crate::wire::ip) const fn datagram_range(self) -> IpFragmentRange {
            self.datagram_range
        }

        /// IPv4 Fragment Offset field value in 8-byte units.
        pub(in crate::wire::ip) const fn fragment_offset(self) -> u16 {
            self.fragment_offset
        }

        /// Whether this planned fragment should carry More Fragments.
        pub(in crate::wire::ip) const fn more_fragments(self) -> bool {
            self.more_fragments
        }
    }

    fn validate_ipv4_fragment_inputs(
        header: Ipv4FragmentHeaderContext,
        payload_len: usize,
        mtu: usize,
    ) -> Result<()> {
        if header.header_len() < IPV4_MIN_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ipv4.header_length",
                "must be at least 20 bytes",
            ));
        }
        if header.header_len() > IPV4_MAX_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "ipv4.header_length",
                "must fit the IPv4 IHL field",
            ));
        }
        if header.header_len() % 4 != 0 {
            return Err(CrafterError::invalid_field_value(
                "ipv4.header_length",
                "must be a multiple of 4 bytes",
            ));
        }
        if header.fragment_offset() as u32 > IPV4_MAX_FRAGMENT_OFFSET {
            return Err(fragment_offset_overflow());
        }

        let payload_capacity = mtu.checked_sub(header.header_len()).ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ip.fragment.mtu",
                "must fit the IPv4 header and one aligned 8-byte payload unit",
            )
        })?;
        if payload_capacity < IPV4_FRAGMENT_ALIGNMENT {
            return Err(CrafterError::invalid_field_value(
                "ip.fragment.mtu",
                "must fit the IPv4 header and one aligned 8-byte payload unit",
            ));
        }

        let max_ipv4_payload_len = IPV4_MAX_TOTAL_LEN - header.header_len();
        if payload_len > max_ipv4_payload_len {
            return Err(CrafterError::invalid_field_value(
                "ipv4.payload_length",
                "payload length exceeds IPv4 total length limit",
            ));
        }

        Ok(())
    }

    fn plan_fragments(
        header: Ipv4FragmentHeaderContext,
        payload_len: usize,
        max_fragment_payload_len: usize,
        aligned_fragment_payload_len: usize,
    ) -> Result<Vec<Ipv4PlannedFragment>> {
        if payload_len == 0 {
            return Ok(vec![Ipv4PlannedFragment::new(
                header,
                0,
                0,
                header.more_fragments(),
            )?]);
        }

        let mut fragments = Vec::new();
        let mut payload_start = 0usize;
        while payload_start < payload_len {
            let remaining = payload_len - payload_start;
            let fragment_payload_len = if remaining <= max_fragment_payload_len {
                remaining
            } else {
                aligned_fragment_payload_len
            };
            let payload_end = payload_start + fragment_payload_len;
            let has_later_planned_fragment = payload_end < payload_len;
            fragments.push(Ipv4PlannedFragment::new(
                header,
                payload_start,
                payload_end,
                has_later_planned_fragment || header.more_fragments(),
            )?);
            payload_start = payload_end;
        }

        Ok(fragments)
    }

    const fn align_down(value: usize, alignment: usize) -> usize {
        value - (value % alignment)
    }

    fn fragment_offset_overflow() -> CrafterError {
        CrafterError::invalid_field_value(
            "ipv4.fragment_offset",
            "planned fragment offset must fit in 13 bits",
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn context(header_len: usize) -> Ipv4FragmentHeaderContext {
            Ipv4FragmentHeaderContext::new(header_len, 0, false)
        }

        fn range(start: u32, end: u32) -> IpFragmentRange {
            IpFragmentRange::new(start, end)
        }

        fn assert_invalid_field(error: CrafterError, expected_field: &'static str) {
            match error {
                CrafterError::InvalidFieldValue { field, .. } => assert_eq!(field, expected_field),
                other => panic!("expected InvalidFieldValue, got {other:?}"),
            }
        }

        #[test]
        fn plans_single_fragment_when_payload_fits_mtu() {
            let plan = Ipv4FragmentPlan::new(context(20), 12, 32).unwrap();

            assert_eq!(plan.header(), context(20));
            assert_eq!(plan.payload_len(), 12);
            assert_eq!(plan.mtu(), 32);
            assert_eq!(plan.max_fragment_payload_len(), 12);
            assert_eq!(plan.aligned_fragment_payload_len(), 8);
            assert_eq!(plan.fragment_count(), 1);
            let fragment = plan.fragments()[0];
            assert_eq!(fragment.payload_range(), range(0, 12));
            assert_eq!(fragment.datagram_range(), range(0, 12));
            assert_eq!(fragment.fragment_offset(), 0);
            assert!(!fragment.more_fragments());
        }

        #[test]
        fn plans_8_byte_aligned_non_final_fragments() {
            let plan = Ipv4FragmentPlan::new(context(20), 27, 34).unwrap();

            assert_eq!(plan.max_fragment_payload_len(), 14);
            assert_eq!(plan.aligned_fragment_payload_len(), 8);
            assert_eq!(plan.fragment_count(), 3);

            let fragments = plan.fragments();
            assert_eq!(fragments[0].payload_range(), range(0, 8));
            assert_eq!(fragments[0].datagram_range(), range(0, 8));
            assert_eq!(fragments[0].fragment_offset(), 0);
            assert!(fragments[0].more_fragments());

            assert_eq!(fragments[1].payload_range(), range(8, 16));
            assert_eq!(fragments[1].datagram_range(), range(8, 16));
            assert_eq!(fragments[1].fragment_offset(), 1);
            assert!(fragments[1].more_fragments());

            assert_eq!(fragments[2].payload_range(), range(16, 27));
            assert_eq!(fragments[2].datagram_range(), range(16, 27));
            assert_eq!(fragments[2].fragment_offset(), 2);
            assert!(!fragments[2].more_fragments());
        }

        #[test]
        fn allows_minimum_mtu_for_actual_header_length() {
            let plan = Ipv4FragmentPlan::new(context(24), 9, 32).unwrap();

            assert_eq!(plan.max_fragment_payload_len(), 8);
            assert_eq!(plan.aligned_fragment_payload_len(), 8);
            assert_eq!(plan.fragment_count(), 2);
            assert_eq!(plan.fragments()[0].payload_range(), range(0, 8));
            assert_eq!(plan.fragments()[1].payload_range(), range(8, 9));
        }

        #[test]
        fn rejects_mtu_without_one_aligned_payload_unit_after_header() {
            let error = Ipv4FragmentPlan::new(context(24), 1, 31).unwrap_err();

            assert_invalid_field(error, "ip.fragment.mtu");
        }

        #[test]
        fn carries_base_fragment_offset_and_inherited_more_fragments() {
            let header = Ipv4FragmentHeaderContext::new(20, 3, true);
            let plan = Ipv4FragmentPlan::new(header, 17, 34).unwrap();

            let fragments = plan.fragments();
            assert_eq!(fragments.len(), 2);
            assert_eq!(fragments[0].payload_range(), range(0, 8));
            assert_eq!(fragments[0].datagram_range(), range(24, 32));
            assert_eq!(fragments[0].fragment_offset(), 3);
            assert!(fragments[0].more_fragments());
            assert_eq!(fragments[1].payload_range(), range(8, 17));
            assert_eq!(fragments[1].datagram_range(), range(32, 41));
            assert_eq!(fragments[1].fragment_offset(), 4);
            assert!(fragments[1].more_fragments());
        }

        #[test]
        fn zero_payload_still_gets_one_deterministic_record() {
            let header = Ipv4FragmentHeaderContext::new(20, 5, false);
            let plan = Ipv4FragmentPlan::new(header, 0, 28).unwrap();

            assert_eq!(plan.fragment_count(), 1);
            let fragment = plan.fragments()[0];
            assert_eq!(fragment.payload_range(), range(0, 0));
            assert_eq!(fragment.datagram_range(), range(40, 40));
            assert_eq!(fragment.fragment_offset(), 5);
            assert!(!fragment.more_fragments());
        }

        #[test]
        fn rejects_invalid_header_context() {
            let short = Ipv4FragmentPlan::new(context(19), 0, 28).unwrap_err();
            assert_invalid_field(short, "ipv4.header_length");

            let too_long = Ipv4FragmentPlan::new(context(64), 0, 72).unwrap_err();
            assert_invalid_field(too_long, "ipv4.header_length");

            let unaligned = Ipv4FragmentPlan::new(context(22), 0, 30).unwrap_err();
            assert_invalid_field(unaligned, "ipv4.header_length");
        }

        #[test]
        fn rejects_payloads_that_exceed_ipv4_total_length() {
            let error = Ipv4FragmentPlan::new(context(20), 65_516, 1500).unwrap_err();

            assert_invalid_field(error, "ipv4.payload_length");
        }

        #[test]
        fn rejects_planned_offsets_that_cannot_fit_ipv4_header_field() {
            let header = Ipv4FragmentHeaderContext::new(20, 0x1fff, true);
            let error = Ipv4FragmentPlan::new(header, 16, 28).unwrap_err();

            assert_invalid_field(error, "ipv4.fragment_offset");
        }
    }
}
