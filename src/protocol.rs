//! Wire protocol types for named-pipe communication between 4lock-agent and this service.
//!
//! Frame format: 4-byte little-endian u32 length prefix + UTF-8 JSON payload.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceRequest {
    pub action: String,
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub via: Option<String>,
    #[serde(default)]
    pub dns: Option<String>,
    #[serde(default)]
    pub host_adapter: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ServiceResponse {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: Some(message.into()),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: Some(message.into()),
        }
    }
}

/// Convert a CIDR notation string (e.g. "10.35.0.0/16") to (network, subnet mask).
/// Returns ("10.35.0.0", "255.255.0.0") for "/16".
pub fn cidr_to_network_mask(cidr: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR: {}", cidr));
    }
    let network = parts[0];
    // Validate network looks like an IP
    let octets: Vec<&str> = network.split('.').collect();
    if octets.len() != 4 || octets.iter().any(|o| o.parse::<u8>().is_err()) {
        return Err(format!("Invalid network address: {}", network));
    }
    let prefix_len: u32 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid prefix length: {}", parts[1]))?;
    if prefix_len > 32 {
        return Err(format!("Prefix length out of range: {}", prefix_len));
    }
    let mask_bits: u32 = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    let mask = format!(
        "{}.{}.{}.{}",
        (mask_bits >> 24) & 0xFF,
        (mask_bits >> 16) & 0xFF,
        (mask_bits >> 8) & 0xFF,
        mask_bits & 0xFF,
    );
    Ok((network.to_string(), mask))
}
