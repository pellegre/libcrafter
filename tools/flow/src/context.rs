//! Per-run packet state threaded across flow transitions.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crafter::MacAddr;

use crate::{FlowError, Result};

const NAMESPACE_SEPARATOR: &str = "::";

const TRANSACTION_ID: &str = "transaction_id";
const CLIENT_MAC: &str = "client_mac";
const OFFERED_IPV4: &str = "offered_ipv4";
const ASSIGNED_IPV4: &str = "assigned_ipv4";
const SERVER_IDENTIFIER: &str = "server_identifier";
const DNS_TRANSACTION_ID: &str = "dns_transaction_id";
const DNS_QUESTION_NAME: &str = "dns_question_name";
const TCP_SND_NXT: &str = "tcp_snd_nxt";
const TCP_RCV_NXT: &str = "tcp_rcv_nxt";
const TCP_ISS: &str = "tcp_iss";
const TCP_LOCAL_PORT: &str = "tcp_local_port";
const TCP_REMOTE_PORT: &str = "tcp_remote_port";
const TCP_REMOTE_IPV4: &str = "tcp_remote_ipv4";
const TCP_PEER_MSS: &str = "tcp_peer_mss";
const TCP_PEER_WINDOW: &str = "tcp_peer_window";
const TCP_RECEIVED_PAYLOAD: &str = "tcp_received_payload";

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

    /// Insert an unsigned 64-bit value under a caller-supplied key.
    pub fn insert_u64(&mut self, key: &str, value: u64) {
        self.values
            .insert(key.to_string(), ContextValue::U64(value));
    }

    /// Return an unsigned 64-bit value stored under a caller-supplied key.
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        match self.values.get(key) {
            Some(ContextValue::U64(value)) => Some(*value),
            _ => None,
        }
    }

    /// Insert a boolean value under a caller-supplied key.
    pub fn insert_bool(&mut self, key: &str, value: bool) {
        self.values
            .insert(key.to_string(), ContextValue::Bool(value));
    }

    /// Return a boolean value stored under a caller-supplied key.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.values.get(key) {
            Some(ContextValue::Bool(value)) => Some(*value),
            _ => None,
        }
    }

    /// Insert an unsigned 64-bit value under `namespace::key`.
    pub fn insert_namespaced_u64(&mut self, namespace: &str, key: &str, value: u64) -> Result<()> {
        let key = namespaced_key(namespace, key)?;
        self.values.insert(key, ContextValue::U64(value));
        Ok(())
    }

    /// Return an unsigned 64-bit value stored under `namespace::key`.
    pub fn get_namespaced_u64(&self, namespace: &str, key: &str) -> Result<Option<u64>> {
        let key = namespaced_key(namespace, key)?;
        Ok(match self.values.get(&key) {
            Some(ContextValue::U64(value)) => Some(*value),
            _ => None,
        })
    }

    /// Insert a boolean value under `namespace::key`.
    pub fn insert_namespaced_bool(
        &mut self,
        namespace: &str,
        key: &str,
        value: bool,
    ) -> Result<()> {
        let key = namespaced_key(namespace, key)?;
        self.values.insert(key, ContextValue::Bool(value));
        Ok(())
    }

    /// Return a boolean value stored under `namespace::key`.
    pub fn get_namespaced_bool(&self, namespace: &str, key: &str) -> Result<Option<bool>> {
        let key = namespaced_key(namespace, key)?;
        Ok(match self.values.get(&key) {
            Some(ContextValue::Bool(value)) => Some(*value),
            _ => None,
        })
    }

    /// Insert bytes under `namespace::key`.
    pub fn insert_namespaced_bytes(
        &mut self,
        namespace: &str,
        key: &str,
        value: Vec<u8>,
    ) -> Result<()> {
        let key = namespaced_key(namespace, key)?;
        self.values.insert(key, ContextValue::Bytes(value));
        Ok(())
    }

    /// Return bytes stored under `namespace::key`.
    pub fn get_namespaced_bytes(&self, namespace: &str, key: &str) -> Result<Option<&[u8]>> {
        let key = namespaced_key(namespace, key)?;
        Ok(match self.values.get(&key) {
            Some(ContextValue::Bytes(value)) => Some(value.as_slice()),
            _ => None,
        })
    }

    /// Insert a string under `namespace::key`.
    pub fn insert_namespaced_string(
        &mut self,
        namespace: &str,
        key: &str,
        value: impl Into<String>,
    ) -> Result<()> {
        let key = namespaced_key(namespace, key)?;
        self.values.insert(key, ContextValue::String(value.into()));
        Ok(())
    }

    /// Return a string stored under `namespace::key`.
    pub fn get_namespaced_string(&self, namespace: &str, key: &str) -> Result<Option<&str>> {
        let key = namespaced_key(namespace, key)?;
        Ok(match self.values.get(&key) {
            Some(ContextValue::String(value)) => Some(value.as_str()),
            _ => None,
        })
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

    /// Store the next TCP sequence number to send.
    pub fn set_tcp_snd_nxt(&mut self, value: u32) {
        self.values
            .insert(TCP_SND_NXT.to_string(), ContextValue::U32(value));
    }

    /// Return the next TCP sequence number to send.
    pub fn get_tcp_snd_nxt(&self) -> Option<u32> {
        match self.values.get(TCP_SND_NXT) {
            Some(ContextValue::U32(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store the next expected peer TCP sequence number.
    pub fn set_tcp_rcv_nxt(&mut self, value: u32) {
        self.values
            .insert(TCP_RCV_NXT.to_string(), ContextValue::U32(value));
    }

    /// Return the next expected peer TCP sequence number.
    pub fn get_tcp_rcv_nxt(&self) -> Option<u32> {
        match self.values.get(TCP_RCV_NXT) {
            Some(ContextValue::U32(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store our initial TCP send sequence number.
    pub fn set_tcp_iss(&mut self, value: u32) {
        self.values
            .insert(TCP_ISS.to_string(), ContextValue::U32(value));
    }

    /// Return our initial TCP send sequence number.
    pub fn get_tcp_iss(&self) -> Option<u32> {
        match self.values.get(TCP_ISS) {
            Some(ContextValue::U32(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store the local TCP port for the current connection.
    pub fn set_tcp_local_port(&mut self, value: u16) {
        self.values
            .insert(TCP_LOCAL_PORT.to_string(), ContextValue::U16(value));
    }

    /// Return the local TCP port for the current connection.
    pub fn get_tcp_local_port(&self) -> Option<u16> {
        match self.values.get(TCP_LOCAL_PORT) {
            Some(ContextValue::U16(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store the remote TCP port for the current connection.
    pub fn set_tcp_remote_port(&mut self, value: u16) {
        self.values
            .insert(TCP_REMOTE_PORT.to_string(), ContextValue::U16(value));
    }

    /// Return the remote TCP port for the current connection.
    pub fn get_tcp_remote_port(&self) -> Option<u16> {
        match self.values.get(TCP_REMOTE_PORT) {
            Some(ContextValue::U16(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store the remote IPv4 address for the current TCP connection.
    pub fn set_tcp_remote_ipv4(&mut self, value: Ipv4Addr) {
        self.values
            .insert(TCP_REMOTE_IPV4.to_string(), ContextValue::Ipv4(value));
    }

    /// Return the remote IPv4 address for the current TCP connection.
    pub fn get_tcp_remote_ipv4(&self) -> Option<Ipv4Addr> {
        match self.values.get(TCP_REMOTE_IPV4) {
            Some(ContextValue::Ipv4(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store the peer's advertised TCP MSS.
    pub fn set_tcp_peer_mss(&mut self, value: u16) {
        self.values
            .insert(TCP_PEER_MSS.to_string(), ContextValue::U16(value));
    }

    /// Return the peer's advertised TCP MSS.
    pub fn get_tcp_peer_mss(&self) -> Option<u16> {
        match self.values.get(TCP_PEER_MSS) {
            Some(ContextValue::U16(value)) => Some(*value),
            _ => None,
        }
    }

    /// Store the peer's advertised TCP window.
    pub fn set_tcp_peer_window(&mut self, value: u16) {
        self.values
            .insert(TCP_PEER_WINDOW.to_string(), ContextValue::U16(value));
    }

    /// Return the peer's advertised TCP window.
    pub fn get_tcp_peer_window(&self) -> Option<u16> {
        match self.values.get(TCP_PEER_WINDOW) {
            Some(ContextValue::U16(value)) => Some(*value),
            _ => None,
        }
    }

    /// Append received TCP payload bytes for the current connection.
    pub fn append_tcp_payload(&mut self, bytes: &[u8]) {
        match self.values.get_mut(TCP_RECEIVED_PAYLOAD) {
            Some(ContextValue::Bytes(value)) => value.extend_from_slice(bytes),
            Some(_) | None => {
                self.values.insert(
                    TCP_RECEIVED_PAYLOAD.to_string(),
                    ContextValue::Bytes(bytes.to_vec()),
                );
            }
        }
    }

    /// Return received TCP payload bytes accumulated for the current connection.
    pub fn tcp_received_payload(&self) -> &[u8] {
        match self.values.get(TCP_RECEIVED_PAYLOAD) {
            Some(ContextValue::Bytes(value)) => value.as_slice(),
            _ => &[],
        }
    }

    /// Return a compact inspectable list of currently set keys.
    pub fn summary(&self) -> String {
        let keys = self.values.keys().cloned().collect::<Vec<_>>().join(", ");
        format!("PacketContext keys=[{keys}]")
    }
}

fn namespaced_key(namespace: &str, key: &str) -> Result<String> {
    validate_key_component("namespace", namespace)?;
    validate_key_component("local key", key)?;
    Ok(format!("{namespace}{NAMESPACE_SEPARATOR}{key}"))
}

fn validate_key_component(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(FlowError::Build(format!(
            "context {label} must not be empty"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(FlowError::Build(format!(
            "context {label} contains an invalid character"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContextValue {
    U64(u64),
    U32(u32),
    U16(u16),
    Bool(bool),
    Mac(MacAddr),
    Ipv4(Ipv4Addr),
    String(String),
    Bytes(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::PacketContext;
    use crate::FlowError;
    use std::net::Ipv4Addr;

    #[test]
    fn context_round_trips_transaction_id() {
        let mut context = PacketContext::new();

        context.set_transaction_id(0x1234_5678);

        assert_eq!(context.get_transaction_id(), Some(0x1234_5678));
    }

    #[test]
    fn context_round_trips_generic_u64_and_bool() {
        let mut context = PacketContext::new();

        context.insert_u64("quic.packet_number", u64::MAX - 1);
        context.insert_bool("quic.handshake_complete", true);

        assert_eq!(context.get_u64("quic.packet_number"), Some(u64::MAX - 1));
        assert_eq!(context.get_bool("quic.handshake_complete"), Some(true));
        assert_eq!(
            context.summary(),
            "PacketContext keys=[quic.handshake_complete, quic.packet_number]"
        );
    }

    #[test]
    fn context_generic_scalar_unset_values_return_none() {
        let context = PacketContext::new();

        assert_eq!(context.get_u64("missing"), None);
        assert_eq!(context.get_bool("missing"), None);
    }

    #[test]
    fn context_generic_scalar_type_mismatches_return_none() {
        let mut context = PacketContext::new();

        context.insert_u64("shared", 42);
        assert_eq!(context.get_bool("shared"), None);

        context.insert_bool("shared", false);
        assert_eq!(context.get_u64("shared"), None);
    }

    #[test]
    fn context_namespaces_isolate_protocol_values() {
        let mut context = PacketContext::new();

        context
            .insert_namespaced_u64("tcp", "packet_number", 7)
            .unwrap();
        context
            .insert_namespaced_u64("quic", "packet_number", 11)
            .unwrap();
        context
            .insert_namespaced_bool("quic", "established", true)
            .unwrap();
        context
            .insert_namespaced_bytes("quic", "connection_id", vec![0xde, 0xad])
            .unwrap();
        context
            .insert_namespaced_string("quic", "lifecycle", "handshaking")
            .unwrap();

        assert_eq!(
            context.get_namespaced_u64("tcp", "packet_number"),
            Ok(Some(7))
        );
        assert_eq!(
            context.get_namespaced_u64("quic", "packet_number"),
            Ok(Some(11))
        );
        assert_eq!(
            context.get_namespaced_bool("quic", "established"),
            Ok(Some(true))
        );
        assert_eq!(
            context.get_namespaced_bytes("quic", "connection_id"),
            Ok(Some(&[0xde, 0xad][..]))
        );
        assert_eq!(
            context.get_namespaced_string("quic", "lifecycle"),
            Ok(Some("handshaking"))
        );
        assert_eq!(
            context.summary(),
            "PacketContext keys=[quic::connection_id, quic::established, quic::lifecycle, quic::packet_number, tcp::packet_number]"
        );
        assert!(!context.summary().contains("dead"));
    }

    #[test]
    fn context_namespaces_reject_ambiguous_keys() {
        let mut context = PacketContext::new();

        for result in [
            context.insert_namespaced_u64("", "packet_number", 1),
            context.insert_namespaced_u64("quic", "", 1),
            context.insert_namespaced_u64("quic::peer", "packet_number", 1),
            context.insert_namespaced_u64("quic", "peer::packet_number", 1),
            context.insert_namespaced_u64(" quic", "packet_number", 1),
        ] {
            assert!(matches!(result, Err(FlowError::Build(_))));
        }

        assert!(matches!(
            context.get_namespaced_bool("quic", "bad:key"),
            Err(FlowError::Build(_))
        ));
        assert_eq!(context.summary(), "PacketContext keys=[]");
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
        assert_eq!(context.get_tcp_snd_nxt(), None);
        assert_eq!(context.get_tcp_rcv_nxt(), None);
        assert_eq!(context.get_tcp_iss(), None);
        assert_eq!(context.get_tcp_local_port(), None);
        assert_eq!(context.get_tcp_remote_port(), None);
        assert_eq!(context.get_tcp_remote_ipv4(), None);
        assert_eq!(context.get_tcp_peer_mss(), None);
        assert_eq!(context.get_tcp_peer_window(), None);
        assert_eq!(context.tcp_received_payload(), b"");
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

    #[test]
    fn context_round_trips_tcp_fields() {
        let mut context = PacketContext::new();
        let remote = Ipv4Addr::new(198, 51, 100, 20);

        context.set_tcp_snd_nxt(0x0102_0304);
        context.set_tcp_rcv_nxt(0x1112_1314);
        context.set_tcp_iss(0x2122_2324);
        context.set_tcp_local_port(49_152);
        context.set_tcp_remote_port(443);
        context.set_tcp_remote_ipv4(remote);
        context.set_tcp_peer_mss(1_460);
        context.set_tcp_peer_window(65_535);

        assert_eq!(context.get_tcp_snd_nxt(), Some(0x0102_0304));
        assert_eq!(context.get_tcp_rcv_nxt(), Some(0x1112_1314));
        assert_eq!(context.get_tcp_iss(), Some(0x2122_2324));
        assert_eq!(context.get_tcp_local_port(), Some(49_152));
        assert_eq!(context.get_tcp_remote_port(), Some(443));
        assert_eq!(context.get_tcp_remote_ipv4(), Some(remote));
        assert_eq!(context.get_tcp_peer_mss(), Some(1_460));
        assert_eq!(context.get_tcp_peer_window(), Some(65_535));
    }

    #[test]
    fn context_appends_tcp_payload_chunks() {
        let mut context = PacketContext::new();

        context.append_tcp_payload(b"hello ");
        context.append_tcp_payload(b"peer");

        assert_eq!(context.tcp_received_payload(), b"hello peer");
    }

    #[test]
    fn context_summary_lists_set_tcp_keys() {
        let mut context = PacketContext::new();

        context.set_tcp_snd_nxt(1);
        context.set_tcp_rcv_nxt(2);
        context.set_tcp_iss(3);
        context.set_tcp_local_port(4);
        context.set_tcp_remote_port(5);
        context.set_tcp_remote_ipv4(Ipv4Addr::new(203, 0, 113, 9));
        context.set_tcp_peer_mss(6);
        context.set_tcp_peer_window(7);
        context.append_tcp_payload(b"abc");

        let summary = context.summary();
        assert!(summary.contains("tcp_snd_nxt"));
        assert!(summary.contains("tcp_rcv_nxt"));
        assert!(summary.contains("tcp_iss"));
        assert!(summary.contains("tcp_local_port"));
        assert!(summary.contains("tcp_remote_port"));
        assert!(summary.contains("tcp_remote_ipv4"));
        assert!(summary.contains("tcp_peer_mss"));
        assert!(summary.contains("tcp_peer_window"));
        assert!(summary.contains("tcp_received_payload"));
    }
}
