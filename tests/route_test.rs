//! Integration tests for route management. Require admin privileges.
//! Run with: cargo test --test route_test -- --ignored

use fourlock_windows_service::commands::route;

/// RFC 5737 TEST-NET-3 — safe, non-routable subnet for testing.
const TEST_CIDR: &str = "198.51.100.0/24";
const TEST_GATEWAY: &str = "127.0.0.1";
const TEST_GATEWAY_2: &str = "127.0.0.2";

fn route_exists(network: &str) -> bool {
    let output = std::process::Command::new("route")
        .args(["print"])
        .output()
        .expect("route print failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.contains(network)
}

#[test]
#[ignore] // Requires admin
fn add_and_remove_route() {
    // Cleanup in case a previous test left it
    let _ = route::remove_route(TEST_CIDR);

    // Add
    let resp = route::add_route(TEST_CIDR, TEST_GATEWAY);
    assert!(resp.success, "add_route failed: {:?}", resp.message);
    assert!(route_exists("198.51.100.0"), "Route not found in route print");

    // Remove
    let resp = route::remove_route(TEST_CIDR);
    assert!(resp.success, "remove_route failed: {:?}", resp.message);
    assert!(
        !route_exists("198.51.100.0"),
        "Route still present after removal"
    );
}

#[test]
#[ignore] // Requires admin
fn update_route_changes_gateway() {
    let _ = route::remove_route(TEST_CIDR);

    // Add initial
    let resp = route::add_route(TEST_CIDR, TEST_GATEWAY);
    assert!(resp.success, "initial add failed: {:?}", resp.message);

    // Update to new gateway
    let resp = route::update_route(TEST_CIDR, TEST_GATEWAY_2);
    assert!(resp.success, "update_route failed: {:?}", resp.message);
    assert!(route_exists("198.51.100.0"), "Route missing after update");

    // Cleanup
    let _ = route::remove_route(TEST_CIDR);
}

#[test]
#[ignore] // Requires admin
fn remove_nonexistent_route_returns_error() {
    // Ensure it doesn't exist
    let _ = route::remove_route("203.0.113.0/24");

    let resp = route::remove_route("203.0.113.0/24");
    // Should fail gracefully, not panic
    assert!(!resp.success);
}

#[test]
fn invalid_cidr_returns_error() {
    let resp = route::add_route("not-a-cidr", TEST_GATEWAY);
    assert!(!resp.success);
    assert!(resp.message.as_ref().unwrap().contains("Invalid"));
}
