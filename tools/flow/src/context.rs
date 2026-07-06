//! Per-run packet state threaded across flow transitions.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crafter::MacAddr;

const TRANSACTION_ID: &str = "transaction_id";
const CLIENT_MAC: &str = "client_mac";
const OFFERED_IPV4: &str = "offered_ipv4";
const ASSIGNED_IPV4: &str = "assigned_ipv4";
const SERVER_IDENTIFIER: &str = "server_identifier";
const DNS_TRANSACTION_ID: &str = "dns_transaction_id";
const DNS_QUESTION_NAME: &str = "dns_question_name";

/// Typed in-memory values carried through one flow run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PacketContext {
    values: BTreeMap<String, ContextValue>,
}

impl PacketContext {
    /// Create an empty packet context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert raw bytes for a key without a typed accessor.
    pub fn insert(&mut self, key: &str, value: Vec<u8>) {
        self.values
            .insert(key.to_string(), ContextValue::Bytes(value));
    }

    /// Return raw bytes for a key inserted with [`PacketContext::insert`].
    pub fn get_bytes(&self, key: &str) -> Option<&[u8]> {
        match self.values.get(key) {
            Some(ContextValue::Bytes(value)) => Some(value.as_slice()),
            _ => None,
        }
    }

    /// Store a DHCPv4 transaction id.
    pub fn set_transaction_id(&mut self, value: u32) {
        self.values
            .insert(TRANSACTION_ID.to_string(), ContextValue::U32(value));
    }

    /// Return the stored DHCPv4 transaction id.
    pub fn get_transaction_id(&self) -> Option<u32> {
        match self.values.get(TRANSACTION_ID) {
            Some(ContextValue::U32(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store the client MAC address for the current conversation.
    pub fn set_client_mac(&mut self, value: MacAddr) {
        self.values
            .insert(CLIENT_MAC.to_string(), ContextValue::Mac(value));
    }

    /// Return the stored client MAC address.
    pub fn get_client_mac(&self) -> Option<MacAddr> {
        match self.values.get(CLIENT_MAC) {
            Some(ContextValue::Mac(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store an offered IPv4 address.
    pub fn set_offered_ipv4(&mut self, value: Ipv4Addr) {
        self.values
            .insert(OFFERED_IPV4.to_string(), ContextValue::Ipv4(value));
    }

    /// Return the stored offered IPv4 address.
    pub fn get_offered_ipv4(&self) -> Option<Ipv4Addr> {
        match self.values.get(OFFERED_IPV4) {
            Some(ContextValue::Ipv4(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store an assigned IPv4 address.
    pub fn set_assigned_ipv4(&mut self, value: Ipv4Addr) {
        self.values
            .insert(ASSIGNED_IPV4.to_string(), ContextValue::Ipv4(value));
    }

    /// Return the stored assigned IPv4 address.
    pub fn get_assigned_ipv4(&self) -> Option<Ipv4Addr> {
        match self.values.get(ASSIGNED_IPV4) {
            Some(ContextValue::Ipv4(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store a DHCPv4 server identifier.
    pub fn set_server_identifier(&mut self, value: Ipv4Addr) {
        self.values
            .insert(SERVER_IDENTIFIER.to_string(), ContextValue::Ipv4(value));
    }

    /// Return the stored DHCPv4 server identifier.
    pub fn get_server_identifier(&self) -> Option<Ipv4Addr> {
        match self.values.get(SERVER_IDENTIFIER) {
            Some(ContextValue::Ipv4(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store a DNS transaction id.
    pub fn set_dns_transaction_id(&mut self, value: u16) {
        self.values
            .insert(DNS_TRANSACTION_ID.to_string(), ContextValue::U16(value));
    }

    /// Return the stored DNS transaction id.
    pub fn get_dns_transaction_id(&self) -> Option<u16> {
        match self.values.get(DNS_TRANSACTION_ID) {
            Some(ContextValue::U16(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store a DNS question name.
    pub fn set_dns_question_name(&mut self, value: impl Into<String>) {
        self.values.insert(
            DNS_QUESTION_NAME.to_string(),
            ContextValue::String(value.into()),
        );
    }

    /// Return the stored DNS question name.
    pub fn get_dns_question_name(&self) -> Option<String> {
        match self.values.get(DNS_QUESTION_NAME) {
            Some(ContextValue::String(value)) => Some(value.clone()),
            _ => None,
        }
    }

    /// Return a compact inspectable list of currently set keys.
    pub fn summary(&self) -> String {
        let keys = self.values.keys().cloned().collect::<Vec<_>>().join(", ");
        format!("PacketContext keys=[{keys}]")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContextValue {
    U32(u32),
    U16(u16),
    Mac(MacAddr),
    Ipv4(Ipv4Addr),
    String(String),
    Bytes(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::PacketContext;
    use std::net::Ipv4Addr;

    #[test]
    fn context_round_trips_transaction_id() {
        let mut context = PacketContext::new();

        context.set_transaction_id(0x1234_5678);

        assert_eq!(context.get_transaction_id(), Some(0x1234_5678));
    }

    #[test]
    fn context_round_trips_offered_ipv4() {
        let mut context = PacketContext::new();
        let offered = Ipv4Addr::new(192, 0, 2, 42);

        context.set_offered_ipv4(offered);

        assert_eq!(context.get_offered_ipv4(), Some(offered));
    }

    #[test]
    fn context_unset_value_returns_none() {
        let context = PacketContext::new();

        assert_eq!(context.get_transaction_id(), None);
        assert_eq!(context.get_offered_ipv4(), None);
    }

    #[test]
    fn context_summary_lists_set_keys() {
        let mut context = PacketContext::new();

        context.set_transaction_id(0x1122_3344);
        context.set_offered_ipv4(Ipv4Addr::new(192, 0, 2, 10));

        let summary = context.summary();
        assert!(summary.contains("transaction_id"));
        assert!(summary.contains("offered_ipv4"));
    }
}
