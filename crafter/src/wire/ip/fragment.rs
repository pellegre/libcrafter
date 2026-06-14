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

pub(super) mod ipv6_planner {
    #![allow(dead_code)]

    use super::super::ipv6::{Ipv6FragmentExtensionContext, Ipv6FragmentView};
    use super::super::metadata::IpFragmentRange;
    use crate::{CrafterError, Result};

    const IPV6_HEADER_LEN: usize = 40;
    const IPV6_FRAGMENT_HEADER_LEN: usize = 8;
    const IPV6_MAX_PAYLOAD_LEN: usize = 65_535;
    const IPV6_MAX_FRAGMENT_OFFSET: u32 = 0x1fff;
    const IPV6_FRAGMENT_ALIGNMENT: usize = 8;

    /// IPv6 source-side header lengths that influence Fragment Header planning.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(in crate::wire::ip) struct Ipv6FragmentHeaderContext {
        unfragmentable_len: usize,
    }

    impl Ipv6FragmentHeaderContext {
        /// Create IPv6 planning context from the bytes before the Fragment Header.
        pub(in crate::wire::ip) const fn new(unfragmentable_len: usize) -> Self {
            Self { unfragmentable_len }
        }

        /// Create planning context from an already extracted supported scope.
        pub(in crate::wire::ip) fn from_extension_context(
            extension_chain: &Ipv6FragmentExtensionContext,
        ) -> Self {
            Self::new(extension_chain.unfragmentable().len())
        }

        /// Create planning context from an already extracted IPv6 Fragment Header view.
        pub(in crate::wire::ip) fn from_fragment_view(view: &Ipv6FragmentView) -> Self {
            Self::from_extension_context(view.extension_chain())
        }

        /// Extension bytes that remain before the inserted Fragment Header.
        pub(in crate::wire::ip) const fn unfragmentable_len(self) -> usize {
            self.unfragmentable_len
        }

        /// IPv6 fixed header plus supported unfragmentable extension headers.
        pub(in crate::wire::ip) const fn per_fragment_header_len(self) -> usize {
            IPV6_HEADER_LEN + self.unfragmentable_len
        }

        /// Per-fragment headers after the Fragment Header is inserted.
        pub(in crate::wire::ip) const fn per_fragment_header_len_with_fragment_header(
            self,
        ) -> usize {
            IPV6_HEADER_LEN + self.unfragmentable_len + IPV6_FRAGMENT_HEADER_LEN
        }
    }

    /// Deterministic IPv6 source-side fragmentation plan for one fragmentable part.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::wire::ip) struct Ipv6FragmentPlan {
        header: Ipv6FragmentHeaderContext,
        fragmentable_payload_len: usize,
        mtu: usize,
        max_fragmentable_payload_len: usize,
        aligned_fragmentable_payload_len: usize,
        fragments: Vec<Ipv6PlannedFragment>,
    }

    impl Ipv6FragmentPlan {
        /// Plan IPv6 fragments for supported unfragmentable headers, payload, and MTU.
        pub(in crate::wire::ip) fn new(
            header: Ipv6FragmentHeaderContext,
            fragmentable_payload_len: usize,
            mtu: usize,
        ) -> Result<Self> {
            validate_ipv6_fragment_inputs(header, fragmentable_payload_len, mtu)?;

            let payload_capacity = mtu - header.per_fragment_header_len_with_fragment_header();
            let max_ipv6_fragment_payload_len =
                IPV6_MAX_PAYLOAD_LEN - header.unfragmentable_len() - IPV6_FRAGMENT_HEADER_LEN;
            let max_fragmentable_payload_len = payload_capacity.min(max_ipv6_fragment_payload_len);
            let aligned_fragmentable_payload_len =
                align_down(max_fragmentable_payload_len, IPV6_FRAGMENT_ALIGNMENT);
            if fragmentable_payload_len > max_fragmentable_payload_len
                && aligned_fragmentable_payload_len == 0
            {
                return Err(unfragmentable_alignment_room());
            }
            let fragments = plan_fragments(
                fragmentable_payload_len,
                max_fragmentable_payload_len,
                aligned_fragmentable_payload_len,
            )?;

            Ok(Self {
                header,
                fragmentable_payload_len,
                mtu,
                max_fragmentable_payload_len,
                aligned_fragmentable_payload_len,
                fragments,
            })
        }

        /// Header context used to produce this plan.
        pub(in crate::wire::ip) const fn header(&self) -> Ipv6FragmentHeaderContext {
            self.header
        }

        /// Source fragmentable payload length in bytes.
        pub(in crate::wire::ip) const fn fragmentable_payload_len(&self) -> usize {
            self.fragmentable_payload_len
        }

        /// MTU used to produce this plan.
        pub(in crate::wire::ip) const fn mtu(&self) -> usize {
            self.mtu
        }

        /// Maximum fragmentable bytes allowed in any emitted IPv6 fragment.
        pub(in crate::wire::ip) const fn max_fragmentable_payload_len(&self) -> usize {
            self.max_fragmentable_payload_len
        }

        /// 8-byte-aligned fragmentable bytes used for non-final fragments.
        pub(in crate::wire::ip) const fn aligned_fragmentable_payload_len(&self) -> usize {
            self.aligned_fragmentable_payload_len
        }

        /// Planned fragments in emission order.
        pub(in crate::wire::ip) fn fragments(&self) -> &[Ipv6PlannedFragment] {
            &self.fragments
        }

        /// Number of planned emitted records.
        pub(in crate::wire::ip) fn fragment_count(&self) -> usize {
            self.fragments.len()
        }
    }

    /// One planned IPv6 fragmentable range and Fragment Header offset.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(in crate::wire::ip) struct Ipv6PlannedFragment {
        fragmentable_range: IpFragmentRange,
        fragment_offset: u16,
        more_fragments: bool,
    }

    impl Ipv6PlannedFragment {
        fn new(
            fragmentable_start: usize,
            fragmentable_end: usize,
            more_fragments: bool,
        ) -> Result<Self> {
            if fragmentable_start > fragmentable_end {
                return Err(CrafterError::invalid_field_value(
                    "ipv6.fragmentable_range",
                    "fragmentable range start must not exceed end",
                ));
            }
            if fragmentable_start % IPV6_FRAGMENT_ALIGNMENT != 0 {
                return Err(CrafterError::invalid_field_value(
                    "ipv6.fragment_offset",
                    "planned fragment offset must be 8-byte aligned",
                ));
            }

            let fragmentable_len = fragmentable_end - fragmentable_start;
            if more_fragments && fragmentable_len % IPV6_FRAGMENT_ALIGNMENT != 0 {
                return Err(CrafterError::invalid_field_value(
                    "ipv6.fragmentable_length",
                    "non-final fragmentable payload length must be 8-byte aligned",
                ));
            }

            let fragmentable_start = u32::try_from(fragmentable_start).map_err(|_| {
                CrafterError::invalid_field_value(
                    "ipv6.fragmentable_length",
                    "fragmentable payload length exceeds IPv6 payload length limit",
                )
            })?;
            let fragmentable_end = u32::try_from(fragmentable_end).map_err(|_| {
                CrafterError::invalid_field_value(
                    "ipv6.fragmentable_length",
                    "fragmentable payload length exceeds IPv6 payload length limit",
                )
            })?;
            let offset_units = fragmentable_start / IPV6_FRAGMENT_ALIGNMENT as u32;
            if offset_units > IPV6_MAX_FRAGMENT_OFFSET {
                return Err(fragment_offset_overflow());
            }

            Ok(Self {
                fragmentable_range: IpFragmentRange::new(fragmentable_start, fragmentable_end),
                fragment_offset: offset_units as u16,
                more_fragments,
            })
        }

        /// Byte range in the input packet's fragmentable part.
        pub(in crate::wire::ip) const fn fragmentable_range(self) -> IpFragmentRange {
            self.fragmentable_range
        }

        /// IPv6 Fragment Header Fragment Offset field value in 8-byte units.
        pub(in crate::wire::ip) const fn fragment_offset(self) -> u16 {
            self.fragment_offset
        }

        /// Whether this planned fragment should carry More Fragments.
        pub(in crate::wire::ip) const fn more_fragments(self) -> bool {
            self.more_fragments
        }
    }

    fn validate_ipv6_fragment_inputs(
        header: Ipv6FragmentHeaderContext,
        fragmentable_payload_len: usize,
        mtu: usize,
    ) -> Result<()> {
        if header.unfragmentable_len() % IPV6_FRAGMENT_ALIGNMENT != 0 {
            return Err(CrafterError::invalid_field_value(
                "ipv6.unfragmentable_length",
                "must be a multiple of 8 bytes for the supported extension-header scope",
            ));
        }

        let original_payload_len = header
            .unfragmentable_len()
            .checked_add(fragmentable_payload_len)
            .ok_or_else(fragmentable_payload_overflow)?;
        if original_payload_len > IPV6_MAX_PAYLOAD_LEN {
            return Err(fragmentable_payload_overflow());
        }

        let fragment_header_payload_len = header
            .unfragmentable_len()
            .checked_add(IPV6_FRAGMENT_HEADER_LEN)
            .ok_or_else(unfragmentable_length_overflow)?;
        if fragment_header_payload_len > IPV6_MAX_PAYLOAD_LEN {
            return Err(unfragmentable_length_overflow());
        }

        let payload_capacity = mtu
            .checked_sub(header.per_fragment_header_len_with_fragment_header())
            .ok_or_else(mtu_too_small)?;
        if payload_capacity < IPV6_FRAGMENT_ALIGNMENT {
            return Err(mtu_too_small());
        }

        Ok(())
    }

    fn plan_fragments(
        fragmentable_payload_len: usize,
        max_fragmentable_payload_len: usize,
        aligned_fragmentable_payload_len: usize,
    ) -> Result<Vec<Ipv6PlannedFragment>> {
        if fragmentable_payload_len == 0 {
            return Ok(vec![Ipv6PlannedFragment::new(0, 0, false)?]);
        }

        let mut fragments = Vec::new();
        let mut fragmentable_start = 0usize;
        while fragmentable_start < fragmentable_payload_len {
            let remaining = fragmentable_payload_len - fragmentable_start;
            let fragmentable_len = if remaining <= max_fragmentable_payload_len {
                remaining
            } else {
                aligned_fragmentable_payload_len
            };
            let fragmentable_end = fragmentable_start + fragmentable_len;
            let more_fragments = fragmentable_end < fragmentable_payload_len;
            fragments.push(Ipv6PlannedFragment::new(
                fragmentable_start,
                fragmentable_end,
                more_fragments,
            )?);
            fragmentable_start = fragmentable_end;
        }

        Ok(fragments)
    }

    const fn align_down(value: usize, alignment: usize) -> usize {
        value - (value % alignment)
    }

    fn mtu_too_small() -> CrafterError {
        CrafterError::invalid_field_value(
            "ip.fragment.mtu",
            "must fit the IPv6 fixed header, unfragmentable headers, Fragment Header, and one aligned 8-byte fragment unit",
        )
    }

    fn fragmentable_payload_overflow() -> CrafterError {
        CrafterError::invalid_field_value(
            "ipv6.fragmentable_length",
            "fragmentable payload length exceeds IPv6 payload length limit",
        )
    }

    fn unfragmentable_length_overflow() -> CrafterError {
        CrafterError::invalid_field_value(
            "ipv6.unfragmentable_length",
            "unfragmentable headers plus Fragment Header exceed IPv6 payload length limit",
        )
    }

    fn unfragmentable_alignment_room() -> CrafterError {
        CrafterError::invalid_field_value(
            "ipv6.unfragmentable_length",
            "unfragmentable headers plus Fragment Header leave no aligned non-final fragmentable payload room",
        )
    }

    fn fragment_offset_overflow() -> CrafterError {
        CrafterError::invalid_field_value(
            "ipv6.fragment_offset",
            "planned fragment offset must fit in 13 bits",
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn context(unfragmentable_len: usize) -> Ipv6FragmentHeaderContext {
            Ipv6FragmentHeaderContext::new(unfragmentable_len)
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
        fn plans_single_fragment_when_fragmentable_payload_fits_mtu() {
            let header = context(0);
            let plan = Ipv6FragmentPlan::new(header, 120, 168).unwrap();

            assert_eq!(plan.header(), header);
            assert_eq!(plan.fragmentable_payload_len(), 120);
            assert_eq!(plan.mtu(), 168);
            assert_eq!(plan.max_fragmentable_payload_len(), 120);
            assert_eq!(plan.aligned_fragmentable_payload_len(), 120);
            assert_eq!(plan.fragment_count(), 1);
            let fragment = plan.fragments()[0];
            assert_eq!(fragment.fragmentable_range(), range(0, 120));
            assert_eq!(fragment.fragment_offset(), 0);
            assert!(!fragment.more_fragments());
        }

        #[test]
        fn plans_8_byte_aligned_non_final_fragments() {
            let plan = Ipv6FragmentPlan::new(context(0), 73, 72).unwrap();

            assert_eq!(plan.max_fragmentable_payload_len(), 24);
            assert_eq!(plan.aligned_fragmentable_payload_len(), 24);
            assert_eq!(plan.fragment_count(), 4);

            let fragments = plan.fragments();
            assert_eq!(fragments[0].fragmentable_range(), range(0, 24));
            assert_eq!(fragments[0].fragment_offset(), 0);
            assert!(fragments[0].more_fragments());

            assert_eq!(fragments[1].fragmentable_range(), range(24, 48));
            assert_eq!(fragments[1].fragment_offset(), 3);
            assert!(fragments[1].more_fragments());

            assert_eq!(fragments[2].fragmentable_range(), range(48, 72));
            assert_eq!(fragments[2].fragment_offset(), 6);
            assert!(fragments[2].more_fragments());

            assert_eq!(fragments[3].fragmentable_range(), range(72, 73));
            assert_eq!(fragments[3].fragment_offset(), 9);
            assert!(!fragments[3].more_fragments());
        }

        #[test]
        fn accounts_for_unfragmentable_extension_headers_before_fragment_header() {
            let header = context(24);
            let plan = Ipv6FragmentPlan::new(header, 49, 96).unwrap();

            assert_eq!(header.unfragmentable_len(), 24);
            assert_eq!(header.per_fragment_header_len(), 64);
            assert_eq!(header.per_fragment_header_len_with_fragment_header(), 72);
            assert_eq!(plan.max_fragmentable_payload_len(), 24);
            assert_eq!(plan.fragment_count(), 3);
            assert_eq!(plan.fragments()[0].fragmentable_range(), range(0, 24));
            assert_eq!(plan.fragments()[1].fragmentable_range(), range(24, 48));
            assert_eq!(plan.fragments()[2].fragmentable_range(), range(48, 49));
        }

        #[test]
        fn builds_context_from_existing_supported_fragment_header_scope() {
            use super::super::super::ipv6::{extract_ipv6_fragment, Ipv6FragmentExtract};
            use crate::wire::record::PacketRecord;
            use crate::{
                Ipv6, Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Ipv6HopByHopOptionsHeader,
                Ipv6RoutingHeader, Raw, IPPROTO_UDP,
            };

            let packet = Ipv6::new()
                .src("2001:db8:30::1".parse().unwrap())
                .dst("2001:db8:30::2".parse().unwrap())
                / Ipv6HopByHopOptionsHeader::new()
                / Ipv6DestinationOptionsHeader::new()
                / Ipv6RoutingHeader::new()
                / Ipv6FragmentHeader::new()
                    .next_header(IPPROTO_UDP)
                    .identification(0x3030_3030)
                    .more_fragments(true)
                / Raw::from_bytes(b"abcdefgh");
            let record = PacketRecord::new(packet);
            let view = match extract_ipv6_fragment(&record).unwrap() {
                Ipv6FragmentExtract::View(view) => view,
                Ipv6FragmentExtract::PassThrough(pass_through) => {
                    panic!("expected supported Fragment Header scope, got {pass_through:?}")
                }
            };

            let header = Ipv6FragmentHeaderContext::from_fragment_view(&view);
            let plan =
                Ipv6FragmentPlan::new(header, view.fragmentable_payload().len(), 88).unwrap();

            assert_eq!(header.unfragmentable_len(), 24);
            assert_eq!(plan.fragment_count(), 1);
            assert_eq!(plan.fragments()[0].fragmentable_range(), range(0, 8));
        }

        #[test]
        fn zero_fragmentable_payload_still_gets_one_deterministic_record() {
            let plan = Ipv6FragmentPlan::new(context(0), 0, 56).unwrap();

            assert_eq!(plan.fragment_count(), 1);
            let fragment = plan.fragments()[0];
            assert_eq!(fragment.fragmentable_range(), range(0, 0));
            assert_eq!(fragment.fragment_offset(), 0);
            assert!(!fragment.more_fragments());
        }

        #[test]
        fn rejects_mtu_without_required_headers_and_aligned_fragment_unit() {
            let error = Ipv6FragmentPlan::new(context(16), 1, 71).unwrap_err();

            assert_invalid_field(error, "ip.fragment.mtu");
        }

        #[test]
        fn rejects_unaligned_unfragmentable_header_length() {
            let error = Ipv6FragmentPlan::new(context(10), 1, 80).unwrap_err();

            assert_invalid_field(error, "ipv6.unfragmentable_length");
        }

        #[test]
        fn rejects_fragmentable_payloads_that_exceed_ipv6_payload_length() {
            let error = Ipv6FragmentPlan::new(context(8), 65_528, 1280).unwrap_err();

            assert_invalid_field(error, "ipv6.fragmentable_length");
        }

        #[test]
        fn rejects_unfragmentable_headers_that_leave_no_fragment_header_room() {
            let error = Ipv6FragmentPlan::new(context(65_528), 0, 65_584).unwrap_err();

            assert_invalid_field(error, "ipv6.unfragmentable_length");
        }

        #[test]
        fn rejects_unfragmentable_headers_that_leave_no_aligned_non_final_room() {
            let error = Ipv6FragmentPlan::new(context(65_520), 8, 65_576).unwrap_err();

            assert_invalid_field(error, "ipv6.unfragmentable_length");
        }

        #[test]
        fn planned_fragment_validation_rejects_unaligned_non_final_ranges() {
            let unaligned_offset = Ipv6PlannedFragment::new(1, 9, true).unwrap_err();
            assert_invalid_field(unaligned_offset, "ipv6.fragment_offset");

            let unaligned_len = Ipv6PlannedFragment::new(0, 9, true).unwrap_err();
            assert_invalid_field(unaligned_len, "ipv6.fragmentable_length");
        }
    }
}

pub(super) mod ipv6_identification {
    #![allow(dead_code)]

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const IPV6_IDENTIFICATION_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
    static IPV6_IDENTIFICATION_AUTO_SEED: AtomicU64 = AtomicU64::new(0x243f_6a88_85a3_08d3);

    /// Stateful IPv6 Fragment Header Identification generator.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::wire::ip) struct Ipv6IdentificationGenerator {
        state: Option<u64>,
        previous: Option<u32>,
    }

    impl Ipv6IdentificationGenerator {
        pub(in crate::wire::ip) const fn new() -> Self {
            Self {
                state: None,
                previous: None,
            }
        }

        pub(in crate::wire::ip) fn next(&mut self, configured_seed: Option<u64>) -> u32 {
            loop {
                let value = {
                    let state = self
                        .state
                        .get_or_insert_with(|| initial_ipv6_identification_seed(configured_seed));
                    next_splitmix64(state)
                };
                let identification = (value >> 32) as u32;
                if self.previous == Some(identification) {
                    continue;
                }
                self.previous = Some(identification);
                return identification;
            }
        }
    }

    fn initial_ipv6_identification_seed(configured_seed: Option<u64>) -> u64 {
        configured_seed.unwrap_or_else(automatic_ipv6_identification_seed)
    }

    fn automatic_ipv6_identification_seed() -> u64 {
        let counter =
            IPV6_IDENTIFICATION_AUTO_SEED.fetch_add(IPV6_IDENTIFICATION_GAMMA, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| {
                let nanos = duration.as_nanos();
                (nanos as u64) ^ ((nanos >> 64) as u64)
            })
            .unwrap_or(0);
        let pid = u64::from(std::process::id());
        let stack = (&counter as *const u64 as usize) as u64;

        let mut seed = counter ^ now ^ pid.rotate_left(17) ^ stack.rotate_left(32);
        next_splitmix64(&mut seed)
    }

    fn next_splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(IPV6_IDENTIFICATION_GAMMA);
        let mut value = *state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    #[cfg(test)]
    mod tests {
        use super::super::super::{IpFragment, IpFragmentConfig, Ipv6FragmentIdentificationPolicy};
        use crate::{Ipv6, Ipv6FragmentHeader, Raw, IPPROTO_IPV6_FRAGMENT, IPPROTO_UDP};
        use std::net::Ipv6Addr;

        fn source() -> Ipv6Addr {
            "2001:db8:31::1".parse().unwrap()
        }

        fn destination() -> Ipv6Addr {
            "2001:db8:31::2".parse().unwrap()
        }

        #[test]
        fn fixed_policy_uses_explicit_fragment_identification() {
            let config = IpFragmentConfig::new(1280)
                .ipv6_identification(0x0102_0304)
                .ipv6_identification_seed(0x31);
            let mut transform = IpFragment::with_config(config);

            assert_eq!(transform.next_ipv6_fragment_identification(), 0x0102_0304);
            assert_eq!(transform.next_ipv6_fragment_identification(), 0x0102_0304);
        }

        #[test]
        fn seeded_generation_is_deterministic_and_stateful() {
            let config =
                IpFragmentConfig::new(1280).ipv6_identification_seed(0x0123_4567_89ab_cdef);
            let mut first = IpFragment::with_config(config);
            let mut second = IpFragment::with_config(config);

            assert_eq!(
                config.configured_ipv6_identification_policy(),
                Ipv6FragmentIdentificationPolicy::Generate
            );
            assert_eq!(
                config.configured_ipv6_identification_seed(),
                Some(0x0123_4567_89ab_cdef)
            );
            assert_eq!(first.next_ipv6_fragment_identification(), 0x157a_3807);
            assert_eq!(first.next_ipv6_fragment_identification(), 0xd573_529b);
            assert_eq!(second.next_ipv6_fragment_identification(), 0x157a_3807);
            assert_eq!(second.next_ipv6_fragment_identification(), 0xd573_529b);
        }

        #[test]
        fn automatic_generation_uses_unseeded_generate_policy() {
            let config = IpFragmentConfig::new(1280);
            let mut transform = IpFragment::with_config(config);

            assert_eq!(
                config.configured_ipv6_identification_policy(),
                Ipv6FragmentIdentificationPolicy::Generate
            );
            assert_eq!(config.configured_ipv6_identification_seed(), None);
            assert_ne!(
                transform.next_ipv6_fragment_identification(),
                transform.next_ipv6_fragment_identification()
            );
        }

        #[test]
        fn seeded_identification_produces_exact_fragment_header_bytes() {
            let config = IpFragmentConfig::new(1280).ipv6_identification_seed(0x31);
            let mut transform = IpFragment::with_config(config);
            let identification = transform.next_ipv6_fragment_identification();

            let wire = (Ipv6::new()
                .src(source())
                .dst(destination())
                .next_header(IPPROTO_IPV6_FRAGMENT)
                / Ipv6FragmentHeader::new()
                    .next_header(IPPROTO_UDP)
                    .identification(identification)
                    .more_fragments(true)
                / Raw::from_bytes(b"abcdefgh"))
            .compile()
            .unwrap();

            assert_eq!(identification, 0x1c4a_97a6);
            assert_eq!(
                &wire.as_bytes()[40..48],
                &[IPPROTO_UDP, 0x00, 0x00, 0x01, 0x1c, 0x4a, 0x97, 0xa6]
            );
        }
    }
}

#[cfg(test)]
mod ipv4_df {
    use super::super::{
        IpFragment, IpFragmentConfig, IpFragmentFamily, IpFragmentRange, IpFragmentReason,
        Ipv4DontFragmentPolicy,
    };
    use crate::wire::record::PacketRecord;
    use crate::wire::WireError;
    use crate::{Ipv4, Raw, IPPROTO_UDP};
    use std::net::Ipv4Addr;

    const SMALL_MTU: usize = 36;

    fn source() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 26)
    }

    fn destination() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 26)
    }

    fn df_record(payload: &'static [u8]) -> PacketRecord {
        PacketRecord::new(
            Ipv4::with_addresses(source(), destination())
                .protocol(IPPROTO_UDP)
                .identification(0x2626)
                .dont_fragment(true)
                / Raw::from_bytes(payload),
        )
    }

    #[test]
    fn default_policy_errors_when_df_packet_would_need_fragmentation() {
        let mut transform = IpFragment::new(SMALL_MTU);

        let error = transform
            .fragment_record(df_record(b"abcdefghijklmnopqrstuvwxyz"))
            .unwrap_err();

        match error {
            WireError::Transform { transform, reason } => {
                assert_eq!(transform, "ip-fragment");
                assert_eq!(
                    reason,
                    "IPv4 Don't Fragment is set and packet exceeds configured MTU"
                );
            }
            other => panic!("expected transform error, got {other:?}"),
        }
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn default_policy_allows_df_packet_that_already_fits_mtu() {
        let mut transform = IpFragment::new(1500);

        let output = transform.fragment_record(df_record(b"fits")).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let metadata = &output.records()[0].metadata().ip_fragment_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
        assert_eq!(metadata.byte_range(), IpFragmentRange::new(0, 4));
        assert_eq!(metadata.reason(), Some(&IpFragmentReason::AlreadyFits));
        assert!(output.records()[0].metadata().transforms().is_empty());
    }

    #[test]
    fn pass_through_policy_emits_df_packet_with_explicit_metadata_and_trace() {
        let mut transform = IpFragment::with_config(
            IpFragmentConfig::new(SMALL_MTU)
                .dont_fragment_policy(Ipv4DontFragmentPolicy::PassThrough),
        );

        let output = transform
            .fragment_record(df_record(b"abcdefghijklmnopqrstuvwxyz"))
            .unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let metadata = &output.records()[0].metadata().ip_fragment_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
        assert_eq!(metadata.mtu(), SMALL_MTU);
        assert_eq!(metadata.identification(), 0x2626);
        assert_eq!(metadata.fragment_count(), 1);
        assert_eq!(metadata.fragment_index(), 0);
        assert_eq!(metadata.byte_range(), IpFragmentRange::new(0, 26));
        assert_eq!(metadata.original_len(), Some(26));
        assert_eq!(metadata.reason(), Some(&IpFragmentReason::DontFragment));

        let traces = output.records()[0].metadata().transforms();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].name(), "ip-fragment");
        assert_eq!(traces[0].note(), Some("ipv4 don't-fragment pass-through"));
    }

    #[test]
    fn fragment_anyway_policy_is_an_explicit_df_override() {
        let mut transform = IpFragment::with_config(
            IpFragmentConfig::new(SMALL_MTU)
                .dont_fragment_policy(Ipv4DontFragmentPolicy::FragmentAnyway),
        );

        let output = transform
            .fragment_record(df_record(b"abcdefghijklmnopqrstuvwxyz"))
            .unwrap();

        assert_eq!(output.len(), 2);
        assert_eq!(transform.emitted_count(), 2);
        for (index, record) in output.records().iter().enumerate() {
            let metadata = &record.metadata().ip_fragment_metadata()[0];
            assert_eq!(metadata.reason(), Some(&IpFragmentReason::Fragmented));
            assert_eq!(metadata.fragment_count(), 2);
            assert_eq!(metadata.fragment_index(), index);

            let traces = record.metadata().transforms();
            assert_eq!(traces.len(), 1);
            assert_eq!(traces[0].name(), "ip-fragment");
            assert_eq!(traces[0].note(), Some("ipv4 don't-fragment override"));
        }
    }
}

#[cfg(test)]
mod ipv4_emit {
    use super::super::{IpFragment, IpFragmentFamily, IpFragmentRange, IpFragmentReason};
    use crate::checksum::verify_internet_checksum;
    use crate::wire::record::{PacketOrigin, PacketRecord};
    use crate::wire::{MemoryPacketWriter, Transmitter, WireError};
    use crate::{
        CrafterError, Ipv4, Ipv4ChecksumStatus, NetworkLayer, Packet, Raw, IPV4_OPTION_NOP,
    };
    use std::net::Ipv4Addr;

    const MTU: usize = 40;
    const PROTOCOL: u8 = 253;

    fn source() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 27)
    }

    fn destination() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 27)
    }

    fn plain_record(payload: &[u8]) -> PacketRecord {
        PacketRecord::new(
            Ipv4::with_addresses(source(), destination())
                .protocol(PROTOCOL)
                .identification(0x2727)
                .ttl(37)
                .ds_field(0xb9)
                / Raw::from_bytes(payload),
        )
    }

    fn oversized_record(payload: &[u8]) -> PacketRecord {
        PacketRecord::new(
            Ipv4::with_addresses(source(), destination())
                .protocol(PROTOCOL)
                .identification(0x2727)
                .ttl(37)
                .ds_field(0xb9)
                .option([IPV4_OPTION_NOP])
                / Raw::from_bytes(payload),
        )
    }

    #[derive(Debug, Clone, Copy)]
    struct ExpectedFragment {
        start: usize,
        end: usize,
        offset: u16,
        more_fragments: bool,
        total_len: u16,
    }

    impl ExpectedFragment {
        const fn new(
            start: usize,
            end: usize,
            offset: u16,
            more_fragments: bool,
            total_len: u16,
        ) -> Self {
            Self {
                start,
                end,
                offset,
                more_fragments,
                total_len,
            }
        }
    }

    fn assert_decodable_ipv4_fragment(
        record: &PacketRecord,
        payload: &[u8],
        mtu: usize,
        index: usize,
        fragment_count: usize,
        expected: ExpectedFragment,
        reason: IpFragmentReason,
    ) -> Vec<u8> {
        let packet = record.packet();
        let ipv4 = packet.layer::<Ipv4>().unwrap();
        let raw = packet.layer::<Raw>().unwrap();

        assert_eq!(ipv4.source(), source());
        assert_eq!(ipv4.destination(), destination());
        assert_eq!(ipv4.protocol_value(), PROTOCOL);
        assert_eq!(ipv4.identification_value(), 0x2727);
        assert_eq!(ipv4.ttl_value(), 37);
        assert_eq!(ipv4.ds_field_value(), 0xb9);
        assert_eq!(ipv4.fragment_offset_value(), expected.offset);
        assert_eq!(ipv4.has_more_fragments(), expected.more_fragments);
        if let Some(total_length) = ipv4.total_length_value() {
            assert_eq!(total_length, expected.total_len);
        }
        assert_eq!(raw.as_bytes(), &payload[expected.start..expected.end]);

        let wire = packet.compile().unwrap();
        assert!(wire.as_bytes().len() <= mtu);
        assert_eq!(&wire.as_bytes()[2..4], &expected.total_len.to_be_bytes());
        assert!(verify_internet_checksum(
            &wire.as_bytes()[..ipv4.header_len()]
        ));

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, wire.as_bytes()).unwrap();
        let decoded_ipv4 = decoded.layer::<Ipv4>().unwrap();
        let decoded_raw = decoded.layer::<Raw>().unwrap();
        assert_eq!(decoded_ipv4.checksum_status(), Ipv4ChecksumStatus::Valid);
        assert_eq!(decoded_ipv4.fragment_offset_value(), expected.offset);
        assert_eq!(decoded_ipv4.has_more_fragments(), expected.more_fragments);
        assert_eq!(decoded_ipv4.total_length_value(), Some(expected.total_len));
        assert_eq!(
            decoded_raw.as_bytes(),
            &payload[expected.start..expected.end]
        );

        let metadata = &record.metadata().ip_fragment_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
        assert_eq!(metadata.mtu(), mtu);
        assert_eq!(metadata.identification(), 0x2727);
        assert_eq!(metadata.fragment_offset(), expected.offset);
        assert_eq!(metadata.more_fragments(), expected.more_fragments);
        assert_eq!(metadata.fragment_count(), fragment_count);
        assert_eq!(metadata.fragment_index(), index);
        assert_eq!(
            metadata.byte_range(),
            IpFragmentRange::new(expected.start as u32, expected.end as u32)
        );
        assert_eq!(metadata.original_len(), Some(payload.len() as u32));
        assert_eq!(metadata.reason(), Some(&reason));

        decoded_raw.as_bytes().to_vec()
    }

    fn assert_fragment_sequence_reconstructs_payload(
        records: &[PacketRecord],
        payload: &[u8],
        mtu: usize,
        expected: &[ExpectedFragment],
    ) {
        assert_eq!(records.len(), expected.len());
        let mut reconstructed = Vec::new();

        for (index, (record, fragment)) in records.iter().zip(expected).enumerate() {
            assert_eq!(fragment.start, reconstructed.len());
            assert_eq!(fragment.offset, (fragment.start / 8) as u16);
            if index + 1 < expected.len() {
                assert_eq!((fragment.end - fragment.start) % 8, 0);
                assert!(fragment.more_fragments);
            } else {
                assert!(!fragment.more_fragments);
            }

            reconstructed.extend(assert_decodable_ipv4_fragment(
                record,
                payload,
                mtu,
                index,
                expected.len(),
                *fragment,
                IpFragmentReason::Fragmented,
            ));
        }

        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn exact_mtu_ipv4_packet_passes_through_as_one_decodable_record() {
        let payload = (0u8..20).collect::<Vec<_>>();
        let mut transform = IpFragment::new(MTU);

        let output = transform.fragment_record(plain_record(&payload)).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let fragment = ExpectedFragment::new(0, 20, 0, false, MTU as u16);
        let decoded_payload = assert_decodable_ipv4_fragment(
            &output.records()[0],
            &payload,
            MTU,
            0,
            1,
            fragment,
            IpFragmentReason::AlreadyFits,
        );
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn one_byte_over_mtu_ipv4_packet_emits_two_ordered_fragments() {
        let payload = (0u8..21).collect::<Vec<_>>();
        let mut transform = IpFragment::new(MTU);

        let output = transform.fragment_record(plain_record(&payload)).unwrap();

        assert_eq!(transform.emitted_count(), 2);
        assert_fragment_sequence_reconstructs_payload(
            output.records(),
            &payload,
            MTU,
            &[
                ExpectedFragment::new(0, 16, 0, true, 36),
                ExpectedFragment::new(16, 21, 2, false, 25),
            ],
        );
    }

    #[test]
    fn many_fragments_reconstruct_original_ipv4_payload() {
        let payload = (0u8..73).collect::<Vec<_>>();
        let mtu = 36;
        let mut transform = IpFragment::new(mtu);

        let output = transform.fragment_record(plain_record(&payload)).unwrap();

        assert_eq!(transform.emitted_count(), 5);
        assert_fragment_sequence_reconstructs_payload(
            output.records(),
            &payload,
            mtu,
            &[
                ExpectedFragment::new(0, 16, 0, true, 36),
                ExpectedFragment::new(16, 32, 2, true, 36),
                ExpectedFragment::new(32, 48, 4, true, 36),
                ExpectedFragment::new(48, 64, 6, true, 36),
                ExpectedFragment::new(64, 73, 8, false, 29),
            ],
        );
    }

    #[test]
    fn small_mtu_rejects_ipv4_options_header_without_aligned_payload_room() {
        let payload = (0u8..8).collect::<Vec<_>>();
        let mut transform = IpFragment::new(31);

        let error = transform
            .fragment_record(oversized_record(&payload))
            .unwrap_err();

        match error {
            WireError::Packet(CrafterError::InvalidFieldValue { field, .. }) => {
                assert_eq!(field, "ip.fragment.mtu");
            }
            other => panic!("expected InvalidFieldValue, got {other:?}"),
        }
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn oversized_ipv4_packet_emits_valid_aligned_fragments() {
        let payload = (0u8..38).collect::<Vec<_>>();
        let mut transform = IpFragment::new(MTU);

        let output = transform
            .fragment_record(oversized_record(&payload))
            .unwrap();

        assert_eq!(output.len(), 3);
        assert_eq!(transform.emitted_count(), 3);

        let expected = [
            (0usize, 16usize, 0u16, true, 40u16),
            (16, 32, 2, true, 40),
            (32, 38, 4, false, 30),
        ];
        for (index, (record, (start, end, offset, more_fragments, total_len))) in
            output.records().iter().zip(expected).enumerate()
        {
            let packet = record.packet();
            let ipv4 = packet.layer::<Ipv4>().unwrap();
            let raw = packet.layer::<Raw>().unwrap();

            assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
            assert!(record.metadata().captured_bytes().is_none());
            assert_eq!(ipv4.source(), source());
            assert_eq!(ipv4.destination(), destination());
            assert_eq!(ipv4.protocol_value(), PROTOCOL);
            assert_eq!(ipv4.identification_value(), 0x2727);
            assert_eq!(ipv4.ttl_value(), 37);
            assert_eq!(ipv4.ds_field_value(), 0xb9);
            assert_eq!(ipv4.option_bytes(), &[IPV4_OPTION_NOP, 0, 0, 0]);
            assert_eq!(ipv4.fragment_offset_value(), offset);
            assert_eq!(ipv4.has_more_fragments(), more_fragments);
            assert_eq!(ipv4.total_length_value(), Some(total_len));
            assert_eq!(raw.as_bytes(), &payload[start..end]);

            let wire = packet.compile().unwrap();
            assert_eq!(&wire.as_bytes()[2..4], &total_len.to_be_bytes());
            assert!(verify_internet_checksum(&wire.as_bytes()[..24]));

            let metadata = &record.metadata().ip_fragment_metadata()[0];
            assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
            assert_eq!(metadata.mtu(), MTU);
            assert_eq!(metadata.identification(), 0x2727);
            assert_eq!(metadata.fragment_offset(), offset);
            assert_eq!(metadata.more_fragments(), more_fragments);
            assert_eq!(metadata.fragment_count(), 3);
            assert_eq!(metadata.fragment_index(), index);
            assert_eq!(
                metadata.byte_range(),
                IpFragmentRange::new(start as u32, end as u32)
            );
            assert_eq!(metadata.original_len(), Some(payload.len() as u32));
            assert_eq!(metadata.reason(), Some(&IpFragmentReason::Fragmented));
        }
    }

    #[test]
    fn options_with_odd_final_fragment_length_reconstruct_payload() {
        let payload = (0u8..35).collect::<Vec<_>>();
        let mut transform = IpFragment::new(MTU);

        let output = transform
            .fragment_record(oversized_record(&payload))
            .unwrap();

        assert_eq!(transform.emitted_count(), 3);
        for record in output.records() {
            let ipv4 = record.packet().layer::<Ipv4>().unwrap();
            assert_eq!(ipv4.option_bytes(), &[IPV4_OPTION_NOP, 0, 0, 0]);
        }
        assert_fragment_sequence_reconstructs_payload(
            output.records(),
            &payload,
            MTU,
            &[
                ExpectedFragment::new(0, 16, 0, true, 40),
                ExpectedFragment::new(16, 32, 2, true, 40),
                ExpectedFragment::new(32, 35, 4, false, 27),
            ],
        );
    }

    #[test]
    fn transmitter_path_writes_multiple_fragments_through_memory_writer() {
        let payload = (0u8..21).collect::<Vec<_>>();
        let mut transmitter =
            Transmitter::new(MemoryPacketWriter::new()).with(IpFragment::new(MTU));

        let reports = transmitter.write_record(plain_record(&payload)).unwrap();

        assert_eq!(reports.len(), 2);
        assert_eq!(
            reports
                .iter()
                .map(|report| report.bytes_requested())
                .collect::<Vec<_>>(),
            [36, 25]
        );
        assert!(reports
            .iter()
            .all(|report| report.bytes_written() == report.bytes_requested()));
    }
}

#[cfg(test)]
mod ipv4_link_wrapper {
    use super::super::{IpFragment, IpFragmentFamily, IpFragmentRange, IpFragmentReason};
    use crate::wire::record::{PacketOrigin, PacketRecord};
    use crate::{Ethernet, Ipv4, MacAddr, Packet, Raw, ETHERTYPE_IPV4};
    use std::net::Ipv4Addr;

    const MTU: usize = 36;
    const PROTOCOL: u8 = 253;

    fn source() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 28)
    }

    fn destination() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 28)
    }

    fn source_mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x28])
    }

    fn destination_mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x29])
    }

    fn oversized_ipv4_packet(payload: &[u8]) -> Packet {
        Ipv4::with_addresses(source(), destination())
            .protocol(PROTOCOL)
            .identification(0x2828)
            / Raw::from_bytes(payload)
    }

    fn raw_ipv4_record(payload: &[u8]) -> PacketRecord {
        PacketRecord::new(oversized_ipv4_packet(payload))
    }

    fn ethernet_wrapped_ipv4_record(payload: &[u8]) -> PacketRecord {
        PacketRecord::new(
            Ethernet::new()
                .src(source_mac())
                .dst(destination_mac())
                .ethertype(ETHERTYPE_IPV4)
                / oversized_ipv4_packet(payload),
        )
    }

    fn expected_fragments() -> [(usize, usize, u16, bool, u16); 3] {
        [
            (0, 16, 0, true, 36),
            (16, 32, 2, true, 36),
            (32, 34, 4, false, 22),
        ]
    }

    fn assert_ipv4_fragment(
        record: &PacketRecord,
        payload: &[u8],
        index: usize,
        expected: (usize, usize, u16, bool, u16),
    ) {
        let (start, end, offset, more_fragments, total_len) = expected;
        let packet = record.packet();
        let ipv4 = packet.layer::<Ipv4>().unwrap();
        let raw = packet.layer::<Raw>().unwrap();

        assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
        assert!(record.metadata().captured_bytes().is_none());
        assert_eq!(ipv4.source(), source());
        assert_eq!(ipv4.destination(), destination());
        assert_eq!(ipv4.protocol_value(), PROTOCOL);
        assert_eq!(ipv4.identification_value(), 0x2828);
        assert_eq!(ipv4.fragment_offset_value(), offset);
        assert_eq!(ipv4.has_more_fragments(), more_fragments);
        assert_eq!(ipv4.total_length_value(), Some(total_len));
        assert_eq!(raw.as_bytes(), &payload[start..end]);

        let metadata = &record.metadata().ip_fragment_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv4);
        assert_eq!(metadata.mtu(), MTU);
        assert_eq!(metadata.identification(), 0x2828);
        assert_eq!(metadata.fragment_offset(), offset);
        assert_eq!(metadata.more_fragments(), more_fragments);
        assert_eq!(metadata.fragment_count(), 3);
        assert_eq!(metadata.fragment_index(), index);
        assert_eq!(
            metadata.byte_range(),
            IpFragmentRange::new(start as u32, end as u32)
        );
        assert_eq!(metadata.original_len(), Some(payload.len() as u32));
        assert_eq!(metadata.reason(), Some(&IpFragmentReason::Fragmented));
    }

    #[test]
    fn raw_ipv4_fragmentation_emits_l3_records() {
        let payload = (0u8..34).collect::<Vec<_>>();
        let mut transform = IpFragment::new(MTU);

        let output = transform
            .fragment_record(raw_ipv4_record(&payload))
            .unwrap();

        assert_eq!(output.len(), 3);
        assert_eq!(transform.emitted_count(), 3);

        for (index, (record, expected)) in output
            .records()
            .iter()
            .zip(expected_fragments())
            .enumerate()
        {
            assert!(record.packet().layer::<Ethernet>().is_none());
            assert_ipv4_fragment(record, &payload, index, expected);

            let wire = record.packet().compile().unwrap();
            assert_eq!(wire.as_bytes()[0] >> 4, 4);
            assert_eq!(record.metadata().original_len(), Some(54));
            assert_eq!(record.metadata().captured_len(), Some(54));
            assert_eq!(record.metadata().emitted_len(), Some(u32::from(expected.4)));
        }
    }

    #[test]
    fn ethernet_wrapped_ipv4_fragmentation_preserves_link_wrapper_on_all_fragments() {
        let payload = (0u8..34).collect::<Vec<_>>();
        let mut transform = IpFragment::new(MTU);

        let output = transform
            .fragment_record(ethernet_wrapped_ipv4_record(&payload))
            .unwrap();

        assert_eq!(output.len(), 3);
        assert_eq!(transform.emitted_count(), 3);

        for (index, (record, expected)) in output
            .records()
            .iter()
            .zip(expected_fragments())
            .enumerate()
        {
            let ethernet = record.packet().layer::<Ethernet>().unwrap();
            assert_eq!(ethernet.source(), Some(source_mac()));
            assert_eq!(ethernet.destination(), Some(destination_mac()));
            assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_IPV4));
            assert_ipv4_fragment(record, &payload, index, expected);

            let wire = record.packet().compile().unwrap();
            assert_eq!(&wire.as_bytes()[0..6], &destination_mac().octets());
            assert_eq!(&wire.as_bytes()[6..12], &source_mac().octets());
            assert_eq!(&wire.as_bytes()[12..14], &ETHERTYPE_IPV4.to_be_bytes());
            assert_eq!(wire.as_bytes()[14] >> 4, 4);
            assert_eq!(record.metadata().original_len(), Some(68));
            assert_eq!(record.metadata().captured_len(), Some(68));
            assert_eq!(
                record.metadata().emitted_len(),
                Some(u32::from(expected.4) + 14)
            );
        }
    }
}

#[cfg(test)]
mod ipv6_emit {
    use super::super::{
        IpFragment, IpFragmentConfig, IpFragmentFamily, IpFragmentRange, IpFragmentReason,
    };
    use crate::wire::record::{PacketOrigin, PacketRecord};
    use crate::{
        Ethernet, Ipv6, Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, MacAddr, Packet, Raw,
        ETHERTYPE_IPV6, IPPROTO_IPV6_DSTOPTS, IPPROTO_IPV6_FRAGMENT, IPPROTO_UDP,
    };
    use std::net::Ipv6Addr;

    const MTU: usize = 72;
    const IDENTIFICATION: u32 = 0x3232_3232;

    fn source() -> Ipv6Addr {
        "2001:db8:32::1".parse().unwrap()
    }

    fn destination() -> Ipv6Addr {
        "2001:db8:32::2".parse().unwrap()
    }

    fn source_mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x32, 0x01])
    }

    fn destination_mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x32, 0x02])
    }

    fn plain_packet(payload: &[u8]) -> Packet {
        Ipv6::new()
            .src(source())
            .dst(destination())
            .traffic_class(0xab)
            .flow_label(0x0cdef)
            .hop_limit(37)
            .next_header(IPPROTO_UDP)
            / Raw::from_bytes(payload)
    }

    fn extension_packet(payload: &[u8]) -> Packet {
        Ipv6::new()
            .src(source())
            .dst(destination())
            .next_header(IPPROTO_IPV6_DSTOPTS)
            / Ipv6DestinationOptionsHeader::new().next_header(IPPROTO_UDP)
            / Raw::from_bytes(payload)
    }

    fn ethernet_record(payload: &[u8]) -> PacketRecord {
        PacketRecord::new(
            Ethernet::new()
                .src(source_mac())
                .dst(destination_mac())
                .ethertype(ETHERTYPE_IPV6)
                / plain_packet(payload),
        )
    }

    #[derive(Debug, Clone, Copy)]
    struct ExpectedFragment {
        start: usize,
        end: usize,
        offset: u16,
        more_fragments: bool,
        payload_length: u16,
    }

    impl ExpectedFragment {
        const fn new(
            start: usize,
            end: usize,
            offset: u16,
            more_fragments: bool,
            payload_length: u16,
        ) -> Self {
            Self {
                start,
                end,
                offset,
                more_fragments,
                payload_length,
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_plain_ipv6_fragment(
        record: &PacketRecord,
        payload: &[u8],
        index: usize,
        fragment_count: usize,
        expected: ExpectedFragment,
        input_len: u32,
        emitted_len: u32,
        l3_offset: usize,
    ) -> Vec<u8> {
        let packet = record.packet();
        let ipv6 = packet.layer::<Ipv6>().unwrap();
        let fragment = packet.layer::<Ipv6FragmentHeader>().unwrap();
        let raw = packet.layer::<Raw>().unwrap();

        assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
        assert!(record.metadata().captured_bytes().is_none());
        assert_eq!(record.metadata().original_len(), Some(input_len));
        assert_eq!(record.metadata().captured_len(), Some(input_len));
        assert_eq!(record.metadata().emitted_len(), Some(emitted_len));

        assert_eq!(ipv6.source(), source());
        assert_eq!(ipv6.destination(), destination());
        assert_eq!(ipv6.traffic_class_value(), 0xab);
        assert_eq!(ipv6.flow_label_value(), 0x0cdef);
        assert_eq!(ipv6.hop_limit_value(), 37);
        assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_FRAGMENT);
        assert_eq!(ipv6.payload_length_value(), Some(expected.payload_length));

        assert_eq!(fragment.next_header_value(), IPPROTO_UDP);
        assert_eq!(fragment.identification_value(), IDENTIFICATION);
        assert_eq!(fragment.fragment_offset_value(), expected.offset);
        assert_eq!(fragment.more_fragments_value(), expected.more_fragments);
        assert!(fragment.reserved_fields_are_zero());
        assert_eq!(raw.as_bytes(), &payload[expected.start..expected.end]);

        let wire = packet.compile().unwrap();
        assert_eq!(
            &wire.as_bytes()[l3_offset + 4..l3_offset + 6],
            &expected.payload_length.to_be_bytes()
        );
        assert_eq!(wire.as_bytes()[l3_offset + 6], IPPROTO_IPV6_FRAGMENT);
        assert_eq!(wire.as_bytes()[l3_offset + 40], IPPROTO_UDP);
        assert_eq!(
            u16::from_be_bytes([
                wire.as_bytes()[l3_offset + 42],
                wire.as_bytes()[l3_offset + 43]
            ]) >> 3,
            expected.offset
        );
        assert_eq!(
            wire.as_bytes()[l3_offset + 43] & 0x01 != 0,
            expected.more_fragments
        );

        let metadata = &record.metadata().ip_fragment_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
        assert_eq!(metadata.mtu(), MTU);
        assert_eq!(metadata.identification(), IDENTIFICATION);
        assert_eq!(metadata.fragment_offset(), expected.offset);
        assert_eq!(metadata.more_fragments(), expected.more_fragments);
        assert_eq!(metadata.fragment_count(), fragment_count);
        assert_eq!(metadata.fragment_index(), index);
        assert_eq!(
            metadata.byte_range(),
            IpFragmentRange::new(expected.start as u32, expected.end as u32)
        );
        assert_eq!(metadata.original_len(), Some(payload.len() as u32));
        assert_eq!(metadata.reason(), Some(&IpFragmentReason::Fragmented));

        raw.as_bytes().to_vec()
    }

    #[test]
    fn oversized_plain_ipv6_packet_emits_valid_fragment_headers() {
        let payload = (0u8..73).collect::<Vec<_>>();
        let config = IpFragmentConfig::new(MTU).ipv6_identification(IDENTIFICATION);
        let mut transform = IpFragment::with_config(config);

        let output = transform
            .fragment_record(PacketRecord::new(plain_packet(&payload)))
            .unwrap();

        assert_eq!(output.len(), 4);
        assert_eq!(transform.emitted_count(), 4);

        let expected_fragments = [
            ExpectedFragment::new(0, 24, 0, true, 32),
            ExpectedFragment::new(24, 48, 3, true, 32),
            ExpectedFragment::new(48, 72, 6, true, 32),
            ExpectedFragment::new(72, 73, 9, false, 9),
        ];
        let mut reconstructed = Vec::new();
        for (index, (record, expected)) in
            output.records().iter().zip(expected_fragments).enumerate()
        {
            reconstructed.extend(assert_plain_ipv6_fragment(
                record,
                &payload,
                index,
                expected_fragments.len(),
                expected,
                40 + payload.len() as u32,
                40 + u32::from(expected.payload_length),
                0,
            ));
        }

        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn supported_extension_chain_is_preserved_before_fragment_header() {
        let payload = (0u8..49).collect::<Vec<_>>();
        let config = IpFragmentConfig::new(80).ipv6_identification(IDENTIFICATION);
        let mut transform = IpFragment::with_config(config);

        let output = transform
            .fragment_record(PacketRecord::new(extension_packet(&payload)))
            .unwrap();

        assert_eq!(output.len(), 3);
        for (index, record) in output.records().iter().enumerate() {
            let ipv6 = record.packet().layer::<Ipv6>().unwrap();
            let destination_options = record
                .packet()
                .layer::<Ipv6DestinationOptionsHeader>()
                .unwrap();
            let fragment = record.packet().layer::<Ipv6FragmentHeader>().unwrap();
            let raw = record.packet().layer::<Raw>().unwrap();

            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_DSTOPTS);
            assert_eq!(
                destination_options.next_header_value(),
                IPPROTO_IPV6_FRAGMENT
            );
            assert_eq!(fragment.next_header_value(), IPPROTO_UDP);
            assert_eq!(fragment.identification_value(), IDENTIFICATION);
            assert_eq!(fragment.fragment_offset_value(), (index * 3) as u16);
            assert_eq!(fragment.more_fragments_value(), index < 2);

            let wire = record.packet().compile().unwrap();
            assert!(wire.as_bytes().len() <= 80);
            assert_eq!(wire.as_bytes()[6], IPPROTO_IPV6_DSTOPTS);
            assert_eq!(wire.as_bytes()[40], IPPROTO_IPV6_FRAGMENT);
            assert_eq!(wire.as_bytes()[48], IPPROTO_UDP);

            let metadata = &record.metadata().ip_fragment_metadata()[0];
            assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
            assert_eq!(metadata.fragment_count(), 3);
            assert_eq!(metadata.fragment_index(), index);
            assert_eq!(metadata.original_len(), Some(payload.len() as u32));

            let start = index * 24;
            let end = if index < 2 { start + 24 } else { payload.len() };
            assert_eq!(raw.as_bytes(), &payload[start..end]);
        }
    }

    #[test]
    fn ethernet_wrapped_ipv6_fragmentation_preserves_link_wrapper() {
        let payload = (0u8..49).collect::<Vec<_>>();
        let config = IpFragmentConfig::new(MTU).ipv6_identification(IDENTIFICATION);
        let mut transform = IpFragment::with_config(config);

        let output = transform
            .fragment_record(ethernet_record(&payload))
            .unwrap();

        assert_eq!(output.len(), 3);
        let expected_fragments = [
            ExpectedFragment::new(0, 24, 0, true, 32),
            ExpectedFragment::new(24, 48, 3, true, 32),
            ExpectedFragment::new(48, 49, 6, false, 9),
        ];
        for (index, (record, expected)) in
            output.records().iter().zip(expected_fragments).enumerate()
        {
            let ethernet = record.packet().layer::<Ethernet>().unwrap();
            assert_eq!(ethernet.source(), Some(source_mac()));
            assert_eq!(ethernet.destination(), Some(destination_mac()));
            assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_IPV6));

            assert_plain_ipv6_fragment(
                record,
                &payload,
                index,
                expected_fragments.len(),
                expected,
                14 + 40 + payload.len() as u32,
                14 + 40 + u32::from(expected.payload_length),
                14,
            );
        }
    }
}

#[cfg(test)]
mod ipv6_link_wrapper {
    use super::super::{IpFragment, IpFragmentConfig};
    use crate::wire::record::PacketRecord;
    use crate::{
        Ethernet, Ipv6, Ipv6FragmentHeader, MacAddr, Packet, Raw, ETHERTYPE_IPV6,
        IPPROTO_IPV6_FRAGMENT, IPPROTO_UDP,
    };
    use std::net::Ipv6Addr;

    const MTU: usize = 72;
    const IDENTIFICATION: u32 = 0x3333_3333;

    fn source() -> Ipv6Addr {
        "2001:db8:33::1".parse().unwrap()
    }

    fn destination() -> Ipv6Addr {
        "2001:db8:33::2".parse().unwrap()
    }

    fn source_mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x33, 0x01])
    }

    fn destination_mac() -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x33, 0x02])
    }

    fn ipv6_packet(payload: &[u8]) -> Packet {
        Ipv6::new()
            .src(source())
            .dst(destination())
            .hop_limit(51)
            .next_header(IPPROTO_UDP)
            / Raw::from_bytes(payload)
    }

    fn raw_ipv6_record(payload: &[u8]) -> PacketRecord {
        PacketRecord::new(ipv6_packet(payload))
    }

    fn ethernet_wrapped_ipv6_record(payload: &[u8]) -> PacketRecord {
        PacketRecord::new(
            Ethernet::new()
                .src(source_mac())
                .dst(destination_mac())
                .ethertype(ETHERTYPE_IPV6)
                / ipv6_packet(payload),
        )
    }

    #[test]
    fn raw_ipv6_fragmentation_emits_l3_packet_records() {
        let payload = (0u8..49).collect::<Vec<_>>();
        let config = IpFragmentConfig::new(MTU).ipv6_identification(IDENTIFICATION);
        let mut transform = IpFragment::with_config(config);

        let output = transform
            .fragment_record(raw_ipv6_record(&payload))
            .unwrap();

        assert_eq!(output.len(), 3);
        for record in output.records() {
            assert!(record.packet().layer::<Ethernet>().is_none());

            let ipv6 = record.packet().layer::<Ipv6>().unwrap();
            let fragment = record.packet().layer::<Ipv6FragmentHeader>().unwrap();
            assert_eq!(ipv6.source(), source());
            assert_eq!(ipv6.destination(), destination());
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_FRAGMENT);
            assert_eq!(fragment.next_header_value(), IPPROTO_UDP);
            assert_eq!(fragment.identification_value(), IDENTIFICATION);

            let wire = record.packet().compile().unwrap();
            assert_eq!(wire.as_bytes()[0] >> 4, 6);
        }
    }

    #[test]
    fn ethernet_wrapped_ipv6_fragmentation_preserves_link_wrapper_on_all_fragments() {
        let payload = (0u8..49).collect::<Vec<_>>();
        let config = IpFragmentConfig::new(MTU).ipv6_identification(IDENTIFICATION);
        let mut transform = IpFragment::with_config(config);

        let output = transform
            .fragment_record(ethernet_wrapped_ipv6_record(&payload))
            .unwrap();

        assert_eq!(output.len(), 3);
        for record in output.records() {
            let ethernet = record.packet().layer::<Ethernet>().unwrap();
            assert_eq!(ethernet.source(), Some(source_mac()));
            assert_eq!(ethernet.destination(), Some(destination_mac()));
            assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_IPV6));

            let ipv6 = record.packet().layer::<Ipv6>().unwrap();
            let fragment = record.packet().layer::<Ipv6FragmentHeader>().unwrap();
            assert_eq!(ipv6.source(), source());
            assert_eq!(ipv6.destination(), destination());
            assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_FRAGMENT);
            assert_eq!(fragment.identification_value(), IDENTIFICATION);

            let wire = record.packet().compile().unwrap();
            assert_eq!(&wire.as_bytes()[0..6], &destination_mac().octets());
            assert_eq!(&wire.as_bytes()[6..12], &source_mac().octets());
            assert_eq!(&wire.as_bytes()[12..14], &ETHERTYPE_IPV6.to_be_bytes());
            assert_eq!(wire.as_bytes()[14] >> 4, 6);
        }
    }
}

#[cfg(test)]
mod ipv6 {
    use super::super::ipv6::IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE;
    use super::super::{
        IpFragment, IpFragmentConfig, IpFragmentFamily, IpFragmentRange, IpFragmentReason,
    };
    use crate::wire::record::{BackendKind, PacketOrigin, PacketRecord};
    use crate::wire::{MemoryPacketWriter, Transmitter, WireError};
    use crate::{
        CrafterError, Ipv6, Ipv6FragmentHeader, Packet, Raw, IPPROTO_IPV6_AH,
        IPPROTO_IPV6_FRAGMENT, IPPROTO_UDP,
    };
    use std::net::Ipv6Addr;

    const MTU: usize = 72;
    const IDENTIFICATION: u32 = 0x3434_3434;

    fn source() -> Ipv6Addr {
        "2001:db8:34::1".parse().unwrap()
    }

    fn destination() -> Ipv6Addr {
        "2001:db8:34::2".parse().unwrap()
    }

    fn plain_packet(payload: &[u8]) -> Packet {
        Ipv6::new()
            .src(source())
            .dst(destination())
            .traffic_class(0x34)
            .flow_label(0x03434)
            .hop_limit(44)
            .next_header(IPPROTO_UDP)
            / Raw::from_bytes(payload)
    }

    fn unsupported_extension_packet(payload: &[u8]) -> Packet {
        Ipv6::new()
            .src(source())
            .dst(destination())
            .next_header(IPPROTO_IPV6_AH)
            / Raw::from_bytes(payload)
    }

    #[derive(Debug, Clone, Copy)]
    struct ExpectedFragment {
        start: usize,
        end: usize,
        offset: u16,
        more_fragments: bool,
        payload_length: u16,
    }

    impl ExpectedFragment {
        const fn new(
            start: usize,
            end: usize,
            offset: u16,
            more_fragments: bool,
            payload_length: u16,
        ) -> Self {
            Self {
                start,
                end,
                offset,
                more_fragments,
                payload_length,
            }
        }
    }

    fn fixed_identification_transform(mtu: usize) -> IpFragment {
        IpFragment::with_config(IpFragmentConfig::new(mtu).ipv6_identification(IDENTIFICATION))
    }

    fn assert_ipv6_fragment(
        record: &PacketRecord,
        payload: &[u8],
        index: usize,
        fragment_count: usize,
        expected: ExpectedFragment,
    ) -> Vec<u8> {
        let packet = record.packet();
        let ipv6 = packet.layer::<Ipv6>().unwrap();
        let fragment = packet.layer::<Ipv6FragmentHeader>().unwrap();
        let raw = packet.layer::<Raw>().unwrap();

        assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
        assert!(record.metadata().captured_bytes().is_none());
        assert_eq!(ipv6.source(), source());
        assert_eq!(ipv6.destination(), destination());
        assert_eq!(ipv6.traffic_class_value(), 0x34);
        assert_eq!(ipv6.flow_label_value(), 0x03434);
        assert_eq!(ipv6.hop_limit_value(), 44);
        assert_eq!(ipv6.next_header_value(), IPPROTO_IPV6_FRAGMENT);
        assert_eq!(ipv6.payload_length_value(), Some(expected.payload_length));

        assert_eq!(fragment.next_header_value(), IPPROTO_UDP);
        assert_eq!(fragment.identification_value(), IDENTIFICATION);
        assert_eq!(fragment.fragment_offset_value(), expected.offset);
        assert_eq!(fragment.more_fragments_value(), expected.more_fragments);
        assert_eq!(raw.as_bytes(), &payload[expected.start..expected.end]);

        let metadata = &record.metadata().ip_fragment_metadata()[0];
        assert_eq!(metadata.family(), IpFragmentFamily::Ipv6);
        assert_eq!(metadata.mtu(), MTU);
        assert_eq!(metadata.identification(), IDENTIFICATION);
        assert_eq!(metadata.fragment_offset(), expected.offset);
        assert_eq!(metadata.more_fragments(), expected.more_fragments);
        assert_eq!(metadata.fragment_count(), fragment_count);
        assert_eq!(metadata.fragment_index(), index);
        assert_eq!(
            metadata.byte_range(),
            IpFragmentRange::new(expected.start as u32, expected.end as u32)
        );
        assert_eq!(metadata.original_len(), Some(payload.len() as u32));
        assert_eq!(metadata.reason(), Some(&IpFragmentReason::Fragmented));

        let wire = packet.compile().unwrap();
        assert!(wire.as_bytes().len() <= MTU);
        assert_eq!(
            &wire.as_bytes()[4..6],
            &expected.payload_length.to_be_bytes()
        );
        assert_eq!(wire.as_bytes()[6], IPPROTO_IPV6_FRAGMENT);
        assert_eq!(wire.as_bytes()[40], IPPROTO_UDP);

        raw.as_bytes().to_vec()
    }

    fn assert_fragment_sequence(payload: &[u8], expected: &[ExpectedFragment]) {
        let mut transform = fixed_identification_transform(MTU);

        let output = transform
            .fragment_record(PacketRecord::new(plain_packet(payload)))
            .unwrap();

        assert_eq!(output.len(), expected.len());
        assert_eq!(transform.emitted_count(), expected.len());
        let fragment_count = expected.len();
        let mut reconstructed = Vec::new();
        for (index, (record, expected)) in output.records().iter().zip(expected).enumerate() {
            reconstructed.extend(assert_ipv6_fragment(
                record,
                payload,
                index,
                fragment_count,
                *expected,
            ));
        }
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn exact_mtu_ipv6_packet_passes_through_without_fragment_header() {
        let payload = (0u8..32).collect::<Vec<_>>();
        let input = PacketRecord::new(plain_packet(&payload));
        let expected_summary = input.packet().summary();
        let expected_metadata = input.metadata().clone();
        let mut transform = fixed_identification_transform(MTU);

        let output = transform.fragment_record(input).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let record = &output.records()[0];
        assert_eq!(record.packet().summary(), expected_summary);
        assert!(record.packet().layer::<Ipv6FragmentHeader>().is_none());
        assert_eq!(record.metadata(), &expected_metadata);
    }

    #[test]
    fn one_byte_over_mtu_emits_two_ipv6_fragments() {
        let payload = (0u8..33).collect::<Vec<_>>();

        assert_fragment_sequence(
            &payload,
            &[
                ExpectedFragment::new(0, 24, 0, true, 32),
                ExpectedFragment::new(24, 33, 3, false, 17),
            ],
        );
    }

    #[test]
    fn many_fragments_keep_offsets_lengths_and_payload_order() {
        let payload = (0u8..97).collect::<Vec<_>>();

        assert_fragment_sequence(
            &payload,
            &[
                ExpectedFragment::new(0, 24, 0, true, 32),
                ExpectedFragment::new(24, 48, 3, true, 32),
                ExpectedFragment::new(48, 72, 6, true, 32),
                ExpectedFragment::new(72, 96, 9, true, 32),
                ExpectedFragment::new(96, 97, 12, false, 9),
            ],
        );
    }

    #[test]
    fn too_small_mtu_for_ipv6_fragment_unit_returns_structured_error() {
        let payload = (0u8..24).collect::<Vec<_>>();
        let mut transform = fixed_identification_transform(55);

        let error = transform
            .fragment_record(PacketRecord::new(plain_packet(&payload)))
            .unwrap_err();

        match error {
            WireError::Packet(CrafterError::InvalidFieldValue { field, .. }) => {
                assert_eq!(field, "ip.fragment.mtu");
            }
            other => panic!("expected IPv6 too_small_mtu InvalidFieldValue, got {other:?}"),
        }
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn atomic_sized_no_fragment_pass_through_at_ipv6_minimum_mtu() {
        let payload = vec![0x34; 1240];
        let input = PacketRecord::new(plain_packet(&payload));
        let expected_summary = input.packet().summary();
        let expected_metadata = input.metadata().clone();
        let mut transform = fixed_identification_transform(1280);

        let output = transform.fragment_record(input).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let record = &output.records()[0];
        assert_eq!(record.packet().summary(), expected_summary);
        assert!(record.packet().layer::<Ipv6FragmentHeader>().is_none());
        assert_eq!(record.metadata(), &expected_metadata);
        assert_eq!(record.packet().compile().unwrap().as_bytes().len(), 1280);
    }

    #[test]
    fn unsupported_extension_chain_passes_through_with_trace_when_oversized() {
        let payload = vec![0u8; 96];
        let input = PacketRecord::new(unsupported_extension_packet(&payload));
        let expected_summary = input.packet().summary();
        let mut transform = fixed_identification_transform(MTU);

        let output = transform.fragment_record(input).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let record = &output.records()[0];
        assert_eq!(record.packet().summary(), expected_summary);
        assert!(record.metadata().ip_fragment_metadata().is_empty());
        let traces = record.metadata().transforms();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].name(), "ip-fragment");
        assert_eq!(
            traces[0].note(),
            Some(IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE)
        );
    }

    #[test]
    fn transmitter_path_writes_ipv6_fragments_through_memorypacketwriter() {
        let payload = (0u8..49).collect::<Vec<_>>();
        let mut transmitter =
            Transmitter::new(MemoryPacketWriter::new()).with(fixed_identification_transform(MTU));

        let reports = transmitter
            .write_record(PacketRecord::new(plain_packet(&payload)))
            .unwrap();

        assert_eq!(reports.len(), 3);
        assert_eq!(
            reports
                .iter()
                .map(|report| report.bytes_requested())
                .collect::<Vec<_>>(),
            [72, 72, 49]
        );
        assert_eq!(
            reports
                .iter()
                .map(|report| report.bytes_written())
                .collect::<Vec<_>>(),
            [72, 72, 49]
        );
        assert!(reports
            .iter()
            .all(|report| report.backend() == &BackendKind::Memory));
    }
}
