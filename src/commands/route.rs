//! Route table management via `route.exe`.

use crate::protocol::{cidr_to_network_mask, ServiceResponse};
use std::process::Command;

/// Add a route: `route ADD <network> MASK <mask> <gateway>`
pub fn add_route(cidr: &str, via: &str) -> ServiceResponse {
    let (network, mask) = match cidr_to_network_mask(cidr) {
        Ok(v) => v,
        Err(e) => return ServiceResponse::err(e),
    };

    match Command::new("route")
        .args(["ADD", &network, "MASK", &mask, via])
        .output()
    {
        Ok(output) if output.status.success() => {
            ServiceResponse::ok(format!("Route {} via {} added", cidr, via))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            ServiceResponse::err(format!(
                "route ADD failed: {} {}",
                stderr.trim(),
                stdout.trim()
            ))
        }
        Err(e) => ServiceResponse::err(format!("Failed to execute route.exe: {}", e)),
    }
}

/// Remove a route: `route DELETE <network>`
pub fn remove_route(cidr: &str) -> ServiceResponse {
    let (network, _mask) = match cidr_to_network_mask(cidr) {
        Ok(v) => v,
        Err(e) => return ServiceResponse::err(e),
    };

    match Command::new("route").args(["DELETE", &network]).output() {
        Ok(output) if output.status.success() => {
            ServiceResponse::ok(format!("Route {} removed", cidr))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            ServiceResponse::err(format!(
                "route DELETE failed: {} {}",
                stderr.trim(),
                stdout.trim()
            ))
        }
        Err(e) => ServiceResponse::err(format!("Failed to execute route.exe: {}", e)),
    }
}

/// Update a route: delete then add.
pub fn update_route(cidr: &str, via: &str) -> ServiceResponse {
    let _ = remove_route(cidr); // Best-effort remove
    add_route(cidr, via)
}
