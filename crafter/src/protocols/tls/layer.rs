//! TLS packet layer.
//!
//! A [`Tls`] layer is an ordered sequence of complete TLS records. Record
//! fragments remain opaque here; later source-backed steps can add typed body
//! parsing without changing the packet-layer container.

use super::{TlsAlert, TlsContentType, TlsRecord, TLS_RECORD_HEADER_LEN};
use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::Result;

/// TLS record layer that composes inside [`crate::packet::Packet`] stacks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tls {
    records: Vec<TlsRecord>,
}

impl Tls {
    /// Construct a TLS layer containing one complete record.
    pub fn new(record: impl Into<TlsRecord>) -> Self {
        Self::from_record(record)
    }

    /// Construct an empty TLS layer.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct a TLS layer containing one complete record.
    pub fn from_record(record: impl Into<TlsRecord>) -> Self {
        Self {
            records: vec![record.into()],
        }
    }

    /// Construct a TLS layer from complete caller-built records.
    pub fn from_records<I, R>(records: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<TlsRecord>,
    {
        Self {
            records: records.into_iter().map(Into::into).collect(),
        }
    }

    /// Construct a TLS layer containing one raw-preserving record.
    pub fn raw_record(
        content_type: impl Into<TlsContentType>,
        fragment: impl Into<Vec<u8>>,
    ) -> Self {
        Self::from_record(TlsRecord::from_fragment(content_type, fragment))
    }

    /// Construct a TLS layer from raw-preserving `(content_type, fragment)` records.
    pub fn raw_records<I, C, F>(records: I) -> Self
    where
        I: IntoIterator<Item = (C, F)>,
        C: Into<TlsContentType>,
        F: Into<Vec<u8>>,
    {
        Self::from_records(
            records
                .into_iter()
                .map(|(content_type, fragment)| TlsRecord::from_fragment(content_type, fragment)),
        )
    }

    /// Construct a TLS `alert` record with an opaque fragment.
    pub fn alert(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_record(TlsRecord::alert(fragment))
    }

    /// Construct a TLS `alert` record from the typed alert helper.
    pub fn alert_message(alert: TlsAlert) -> Self {
        Self::alert(alert.encode_to_vec())
    }

    /// Construct a TLS `handshake` record with an opaque fragment.
    pub fn handshake(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_record(TlsRecord::handshake(fragment))
    }

    /// Construct a TLS `application_data` record with an opaque fragment.
    pub fn application_data(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_record(TlsRecord::application_data(fragment))
    }

    /// Construct a TLS `change_cipher_spec` record with an opaque fragment.
    pub fn change_cipher_spec(fragment: impl Into<Vec<u8>>) -> Self {
        Self::from_record(TlsRecord::change_cipher_spec(fragment))
    }

    /// Append a complete record and return the updated TLS layer.
    pub fn with_record(mut self, record: impl Into<TlsRecord>) -> Self {
        self.records.push(record.into());
        self
    }

    /// Append complete records and return the updated TLS layer.
    pub fn with_records<I, R>(mut self, records: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<TlsRecord>,
    {
        self.records.extend(records.into_iter().map(Into::into));
        self
    }

    /// Borrow the ordered records carried by this TLS layer.
    pub fn records(&self) -> &[TlsRecord] {
        &self.records
    }

    /// Consume this layer and return its ordered records.
    pub fn into_records(self) -> Vec<TlsRecord> {
        self.records
    }

    /// Number of TLS records in this layer.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// True when this layer carries no records and encodes to no bytes.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn checked_encoded_len(&self) -> Option<usize> {
        self.records.iter().try_fold(0usize, |total, record| {
            TLS_RECORD_HEADER_LEN
                .checked_add(record.fragment_len())
                .and_then(|record_len| total.checked_add(record_len))
        })
    }

    fn content_type_summary(&self) -> String {
        let labels = self
            .records
            .iter()
            .map(|record| record.content_type().label())
            .collect::<Vec<_>>()
            .join(", ");
        format!("[{labels}]")
    }
}

impl From<TlsRecord> for Tls {
    fn from(record: TlsRecord) -> Self {
        Self::from_record(record)
    }
}

impl From<Vec<TlsRecord>> for Tls {
    fn from(records: Vec<TlsRecord>) -> Self {
        Self::from_records(records)
    }
}

impl Layer for Tls {
    fn name(&self) -> &'static str {
        "TLS"
    }

    fn summary(&self) -> String {
        let bytes = self
            .checked_encoded_len()
            .map(|len| len.to_string())
            .unwrap_or_else(|| "overflow".to_string());
        format!(
            "TLS records={} bytes={} types={}",
            self.records.len(),
            bytes,
            self.content_type_summary()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("records", self.records.len().to_string()),
            (
                "record_bytes",
                self.checked_encoded_len()
                    .map(|len| len.to_string())
                    .unwrap_or_else(|| "overflow".to_string()),
            ),
            ("content_types", self.content_type_summary()),
        ];

        for record in &self.records {
            fields.push(("record", record.summary()));
        }

        fields
    }

    fn encoded_len(&self) -> usize {
        self.checked_encoded_len().unwrap_or(usize::MAX)
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        for record in &self.records {
            record.encode(out)?;
        }
        Ok(())
    }

    impl_layer_object!(Tls);
}

impl_layer_div!(Tls);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Packet, Raw};
    use crate::protocols::transport::Tcp;

    #[test]
    fn tls_layer_single_record_compiles_and_composes_after_tcp() -> Result<()> {
        let tls = Tls::handshake([0x01, 0x00, 0x00, 0x00]);
        let packet = Tcp::new().sport(49_152).dport(443).ack_segment() / tls.clone();

        let compiled = packet.compile()?;
        let tls_payload = &compiled.as_bytes()[20..];

        assert_eq!(
            tls_payload,
            &[0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(tls.encoded_len(), 9);
        assert_eq!(tls.summary(), "TLS records=1 bytes=9 types=[handshake]");
        assert_eq!(packet.layer::<Tls>().unwrap().record_count(), 1);
        Ok(())
    }

    #[test]
    fn tls_layer_multiple_and_raw_record_constructors_preserve_order() -> Result<()> {
        let tls = Tls::from_records([TlsRecord::handshake([0xaa]), TlsRecord::alert([0x01, 0x00])])
            .with_record(TlsRecord::application_data([0xde, 0xad]));

        assert_eq!(tls.record_count(), 3);
        assert_eq!(
            Packet::from_layer(tls).compile()?.as_bytes(),
            &[
                0x16, 0x03, 0x03, 0x00, 0x01, 0xaa, 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00, 0x17,
                0x03, 0x03, 0x00, 0x02, 0xde, 0xad,
            ]
        );

        let raw = Tls::raw_records([(0xfe, [0xbe, 0xef]), (0x30, [0xca, 0xfe])]);
        assert_eq!(
            Packet::from_layer(raw).compile()?.as_bytes(),
            &[0xfe, 0x03, 0x03, 0x00, 0x02, 0xbe, 0xef, 0x30, 0x03, 0x03, 0x00, 0x02, 0xca, 0xfe,]
        );
        Ok(())
    }

    #[test]
    fn tls_layer_convenience_constructors_keep_fragments_opaque() -> Result<()> {
        assert_eq!(
            Packet::from_layer(Tls::alert_message(TlsAlert::close_notify()))
                .compile()?
                .as_bytes(),
            &[0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]
        );
        assert_eq!(
            Packet::from_layer(Tls::change_cipher_spec([0x01]))
                .compile()?
                .as_bytes(),
            &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]
        );
        assert_eq!(
            Packet::from_layer(Tls::application_data(b"GET /".as_slice()))
                .compile()?
                .as_bytes(),
            &[0x17, 0x03, 0x03, 0x00, 0x05, b'G', b'E', b'T', b' ', b'/']
        );
        Ok(())
    }

    #[test]
    fn tls_layer_preserves_explicit_record_length_override() -> Result<()> {
        let record = TlsRecord::handshake([0xaa, 0xbb, 0xcc]).with_length(1);
        let compiled = Packet::from_layer(Tls::new(record)).compile()?;

        assert_eq!(
            compiled.as_bytes(),
            &[0x16, 0x03, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc]
        );
        Ok(())
    }

    #[test]
    fn tls_layer_inspection_clone_downcast_and_div_composition_work() {
        let tls = Tls::raw_record(0xff, [0x01, 0x02]) / Raw::from("tail");
        let layer = tls.layer::<Tls>().expect("TLS layer");

        let fields = layer.inspection_fields();
        assert!(fields.contains(&("records", "1".to_string())));
        assert!(fields.contains(&("record_bytes", "7".to_string())));
        assert!(fields.contains(&(
            "content_types",
            "[unassigned content type 0xff]".to_string()
        )));
        assert!(fields.iter().any(|(name, value)| {
            *name == "record" && value.contains("content_type=unassigned content type 0xff")
        }));

        let cloned = layer.clone_layer();
        let downcast = cloned
            .as_any()
            .downcast_ref::<Tls>()
            .expect("cloned TLS layer");
        assert_eq!(downcast.records()[0].fragment(), &[0x01, 0x02]);
    }
}
