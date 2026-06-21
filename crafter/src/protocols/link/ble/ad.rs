//! GAP Advertising Data structures.

/// One GAP Advertising Data length/type/value structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdStructure {
    pub ad_type: u8,
    pub data: Vec<u8>,
    pub length_override: Option<u8>,
}

impl AdStructure {
    pub fn new(ad_type: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            ad_type,
            data: data.into(),
            length_override: None,
        }
    }

    pub fn raw(ad_type: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::new(ad_type, data)
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let length = self.length_override.unwrap_or_else(|| {
            self.data
                .len()
                .saturating_add(1)
                .min(u8::MAX as usize) as u8
        });

        out.push(length);
        out.push(self.ad_type);
        out.extend_from_slice(&self.data);
    }

    pub(crate) fn encoded_len(&self) -> usize {
        1 + 1 + self.data.len()
    }
}

/// A concatenated GAP Advertising Data payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdList(pub Vec<AdStructure>);

impl AdList {
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        for structure in &self.0 {
            structure.encode(out);
        }
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.0.iter().map(AdStructure::encoded_len).sum()
    }

    pub fn push(&mut self, structure: AdStructure) {
        self.0.push(structure);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ble_ad_encode_derives_length() {
        let structure = AdStructure::new(0x01, vec![0x06]);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(encoded, [0x02, 0x01, 0x06]);
        assert_eq!(structure.encoded_len(), 3);
    }

    #[test]
    fn ble_ad_encode_honors_length_override() {
        let mut structure = AdStructure::new(0x01, vec![0x06]);
        structure.length_override = Some(0x7f);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(encoded, [0x7f, 0x01, 0x06]);
    }
}
