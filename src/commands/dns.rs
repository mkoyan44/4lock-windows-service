//! DNS override via `netsh`.

use crate::protocol::ServiceResponse;
use std::process::Command;

/// Default adapter name when none is specified.
const DEFAULT_ADAPTER: &str = "Wi-Fi";

/// Set DNS on an adapter: `netsh interface ip set dns name=<adapter> static <server>`
pub fn set_dns(adapter: Option<&str>, dns_server: &str) -> ServiceResponse {
    let adapter_name = adapter.unwrap_or(DEFAULT_ADAPTER);

    match Command::new("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "dns",
            &format!("name={}", adapter_name),
            "static",
            dns_server,
        ])
        .output()
    {
        Ok(output) if output.status.success() => ServiceResponse::ok(format!(
            "DNS set to {} on {}",
            dns_server, adapter_name
        )),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            ServiceResponse::err(format!(
                "netsh set dns failed: {} {}",
                stderr.trim(),
                stdout.trim()
            ))
        }
        Err(e) => ServiceResponse::err(format!("Failed to execute netsh: {}", e)),
    }
}

/// Clear DNS (revert to DHCP): `netsh interface ip set dns name=<adapter> dhcp`
pub fn clear_dns(adapter: Option<&str>) -> ServiceResponse {
    let adapter_name = adapter.unwrap_or(DEFAULT_ADAPTER);

    match Command::new("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "dns",
            &format!("name={}", adapter_name),
            "dhcp",
        ])
        .output()
    {
        Ok(output) if output.status.success() => {
            ServiceResponse::ok(format!("DNS cleared on {} (DHCP)", adapter_name))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            ServiceResponse::err(format!(
                "netsh clear dns failed: {} {}",
                stderr.trim(),
                stdout.trim()
            ))
        }
        Err(e) => ServiceResponse::err(format!("Failed to execute netsh: {}", e)),
    }
}
