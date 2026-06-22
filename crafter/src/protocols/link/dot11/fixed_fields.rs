//! IEEE 802.11 management frame fixed fields.

use crate::mac::MacAddr;

use super::*;
use super::{read_mac_at, read_u16_le_at};

/// Source-backed typed management fixed fields, or the raw fallback bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dot11ManagementFixedFields<'a> {
    /// Beacon fixed fields.
    Beacon(Dot11BeaconFixedFields),
    /// Probe Response fixed fields.
    ProbeResponse(Dot11BeaconFixedFields),
    /// Association Request fixed fields.
    AssociationRequest(Dot11AssociationRequestFixedFields),
    /// Association Response fixed fields.
    AssociationResponse(Dot11AssociationResponseFixedFields),
    /// Reassociation Request fixed fields.
    ReassociationRequest(Dot11ReassociationRequestFixedFields),
    /// Reassociation Response fixed fields.
    ReassociationResponse(Dot11AssociationResponseFixedFields),
    /// Authentication fixed fields.
    Authentication(Dot11AuthenticationFixedFields),
    /// Deauthentication fixed fields.
    Deauthentication(Dot11ReasonCodeFixedFields),
    /// Disassociation fixed fields.
    Disassociation(Dot11ReasonCodeFixedFields),
    /// Action or Action No Ack fixed fields.
    Action(Dot11ActionFixedFields),
    /// Unsupported subtype or malformed fixed-field override bytes.
    Raw(&'a [u8]),
}

/// Timestamp, beacon interval, and capability information fixed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dot11BeaconFixedFields {
    timestamp: u64,
    beacon_interval: u16,
    capability_information: u16,
}

impl Dot11BeaconFixedFields {
    /// Create beacon/probe-response fixed fields.
    pub const fn new(timestamp: u64, beacon_interval: u16, capability_information: u16) -> Self {
        Self {
            timestamp,
            beacon_interval,
            capability_information,
        }
    }

    /// Timestamp field.
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Beacon Interval field.
    pub const fn beacon_interval(&self) -> u16 {
        self.beacon_interval
    }

    /// Capability Information field.
    pub const fn capability_information(&self) -> u16 {
        self.capability_information
    }

    /// Compile to little-endian wire bytes.
    pub fn to_bytes(self) -> [u8; DOT11_MGMT_BEACON_FIXED_LEN] {
        let mut bytes = [0; DOT11_MGMT_BEACON_FIXED_LEN];
        bytes[0..8].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.beacon_interval.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.capability_information.to_le_bytes());
        bytes
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DOT11_MGMT_BEACON_FIXED_LEN {
            return None;
        }

        Some(Self::new(
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            read_u16_le_at(bytes, 8),
            read_u16_le_at(bytes, 10),
        ))
    }
}

/// Capability information and listen interval fixed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dot11AssociationRequestFixedFields {
    capability_information: u16,
    listen_interval: u16,
}

impl Dot11AssociationRequestFixedFields {
    /// Create Association Request fixed fields.
    pub const fn new(capability_information: u16, listen_interval: u16) -> Self {
        Self {
            capability_information,
            listen_interval,
        }
    }

    /// Capability Information field.
    pub const fn capability_information(&self) -> u16 {
        self.capability_information
    }

    /// Listen Interval field.
    pub const fn listen_interval(&self) -> u16 {
        self.listen_interval
    }

    /// Compile to little-endian wire bytes.
    pub fn to_bytes(self) -> [u8; DOT11_MGMT_ASSOCIATION_REQUEST_FIXED_LEN] {
        let mut bytes = [0; DOT11_MGMT_ASSOCIATION_REQUEST_FIXED_LEN];
        bytes[0..2].copy_from_slice(&self.capability_information.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.listen_interval.to_le_bytes());
        bytes
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DOT11_MGMT_ASSOCIATION_REQUEST_FIXED_LEN {
            return None;
        }

        Some(Self::new(
            read_u16_le_at(bytes, 0),
            read_u16_le_at(bytes, 2),
        ))
    }
}

/// Capability information, status code, and association ID fixed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dot11AssociationResponseFixedFields {
    capability_information: u16,
    status_code: u16,
    association_id: u16,
}

impl Dot11AssociationResponseFixedFields {
    /// Create Association/Reassociation Response fixed fields.
    pub const fn new(capability_information: u16, status_code: u16, association_id: u16) -> Self {
        Self {
            capability_information,
            status_code,
            association_id,
        }
    }

    /// Capability Information field.
    pub const fn capability_information(&self) -> u16 {
        self.capability_information
    }

    /// Status Code field.
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Association ID field.
    pub const fn association_id(&self) -> u16 {
        self.association_id
    }

    /// Compile to little-endian wire bytes.
    pub fn to_bytes(self) -> [u8; DOT11_MGMT_ASSOCIATION_RESPONSE_FIXED_LEN] {
        let mut bytes = [0; DOT11_MGMT_ASSOCIATION_RESPONSE_FIXED_LEN];
        bytes[0..2].copy_from_slice(&self.capability_information.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.status_code.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.association_id.to_le_bytes());
        bytes
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DOT11_MGMT_ASSOCIATION_RESPONSE_FIXED_LEN {
            return None;
        }

        Some(Self::new(
            read_u16_le_at(bytes, 0),
            read_u16_le_at(bytes, 2),
            read_u16_le_at(bytes, 4),
        ))
    }
}

/// Capability information, listen interval, and current AP address fixed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dot11ReassociationRequestFixedFields {
    capability_information: u16,
    listen_interval: u16,
    current_ap_address: MacAddr,
}

impl Dot11ReassociationRequestFixedFields {
    /// Create Reassociation Request fixed fields.
    pub const fn new(
        capability_information: u16,
        listen_interval: u16,
        current_ap_address: MacAddr,
    ) -> Self {
        Self {
            capability_information,
            listen_interval,
            current_ap_address,
        }
    }

    /// Capability Information field.
    pub const fn capability_information(&self) -> u16 {
        self.capability_information
    }

    /// Listen Interval field.
    pub const fn listen_interval(&self) -> u16 {
        self.listen_interval
    }

    /// Current AP Address field.
    pub const fn current_ap_address(&self) -> MacAddr {
        self.current_ap_address
    }

    /// Compile to little-endian wire bytes.
    pub fn to_bytes(self) -> [u8; DOT11_MGMT_REASSOCIATION_REQUEST_FIXED_LEN] {
        let mut bytes = [0; DOT11_MGMT_REASSOCIATION_REQUEST_FIXED_LEN];
        bytes[0..2].copy_from_slice(&self.capability_information.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.listen_interval.to_le_bytes());
        bytes[4..10].copy_from_slice(&self.current_ap_address.octets());
        bytes
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DOT11_MGMT_REASSOCIATION_REQUEST_FIXED_LEN {
            return None;
        }

        Some(Self::new(
            read_u16_le_at(bytes, 0),
            read_u16_le_at(bytes, 2),
            read_mac_at(bytes, 4),
        ))
    }
}

/// Authentication algorithm, transaction sequence, and status code fixed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dot11AuthenticationFixedFields {
    algorithm_number: u16,
    transaction_sequence_number: u16,
    status_code: u16,
}

impl Dot11AuthenticationFixedFields {
    /// Create Authentication fixed fields.
    pub const fn new(
        algorithm_number: u16,
        transaction_sequence_number: u16,
        status_code: u16,
    ) -> Self {
        Self {
            algorithm_number,
            transaction_sequence_number,
            status_code,
        }
    }

    /// Authentication Algorithm Number field.
    pub const fn algorithm_number(&self) -> u16 {
        self.algorithm_number
    }

    /// Authentication Transaction Sequence Number field.
    pub const fn transaction_sequence_number(&self) -> u16 {
        self.transaction_sequence_number
    }

    /// Status Code field.
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Compile to little-endian wire bytes.
    pub fn to_bytes(self) -> [u8; DOT11_MGMT_AUTHENTICATION_FIXED_LEN] {
        let mut bytes = [0; DOT11_MGMT_AUTHENTICATION_FIXED_LEN];
        bytes[0..2].copy_from_slice(&self.algorithm_number.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.transaction_sequence_number.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.status_code.to_le_bytes());
        bytes
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DOT11_MGMT_AUTHENTICATION_FIXED_LEN {
            return None;
        }

        Some(Self::new(
            read_u16_le_at(bytes, 0),
            read_u16_le_at(bytes, 2),
            read_u16_le_at(bytes, 4),
        ))
    }
}

/// Reason Code fixed field used by deauthentication and disassociation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dot11ReasonCodeFixedFields {
    reason_code: u16,
}

impl Dot11ReasonCodeFixedFields {
    /// Create a Reason Code fixed field.
    pub const fn new(reason_code: u16) -> Self {
        Self { reason_code }
    }

    /// Reason Code field.
    pub const fn reason_code(&self) -> u16 {
        self.reason_code
    }

    /// Compile to little-endian wire bytes.
    pub fn to_bytes(self) -> [u8; DOT11_MGMT_DEAUTHENTICATION_FIXED_LEN] {
        self.reason_code.to_le_bytes()
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DOT11_MGMT_DEAUTHENTICATION_FIXED_LEN {
            return None;
        }

        Some(Self::new(read_u16_le_at(bytes, 0)))
    }
}

/// Action category fixed field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dot11ActionFixedFields {
    category: u8,
}

impl Dot11ActionFixedFields {
    /// Create an Action fixed field with a category code.
    pub const fn new(category: u8) -> Self {
        Self { category }
    }

    /// Category field.
    pub const fn category(&self) -> u8 {
        self.category
    }

    /// Compile to wire bytes.
    pub const fn to_bytes(self) -> [u8; DOT11_MGMT_ACTION_FIXED_LEN] {
        [self.category]
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DOT11_MGMT_ACTION_FIXED_LEN {
            return None;
        }

        Some(Self::new(bytes[0]))
    }
}
