//! Integration tests for DNS override. Require admin privileges.
//! Run with: cargo test --test dns_test -- --ignored

use fourlock_windows_service::commands::dns;

#[test]
#[ignore] // Requires admin
fn set_and_clear_dns_on_loopback() {
    // Use "Loopback Pseudo-Interface 1" which always exists on Windows
    let adapter = "Loopback Pseudo-Interface 1";

    let resp = dns::set_dns(Some(adapter), "8.8.8.8");
    assert!(resp.success, "set_dns failed: {:?}", resp.message);

    // Verify via netsh
    let output = std::process::Command::new("netsh")
        .args(["interface", "ip", "show", "dns", &format!("name={}", adapter)])
        .output()
        .expect("netsh show dns failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("8.8.8.8"),
        "DNS server not found in netsh output: {}",
        stdout
    );

    // Clear
    let resp = dns::clear_dns(Some(adapter));
    assert!(resp.success, "clear_dns failed: {:?}", resp.message);
}

#[test]
#[ignore] // Requires admin
fn set_dns_nonexistent_adapter_returns_error() {
    let resp = dns::set_dns(Some("NonExistentAdapter99"), "8.8.8.8");
    assert!(!resp.success, "Expected failure for non-existent adapter");
}
