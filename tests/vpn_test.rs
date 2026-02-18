//! Integration tests for VPN composite operations via pipe.
//! Require admin privileges. Run with: cargo test --test vpn_test -- --ignored

use fourlock_windows_service::pipe_server::{run_pipe_server_on, send_request};
use fourlock_windows_service::protocol::ServiceRequest;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// RFC 5737 TEST-NET-3
const TEST_CIDR: &str = "198.51.100.0/24";
const TEST_GATEWAY: &str = "127.0.0.1";

fn test_pipe_name() -> String {
    format!(r"\\.\pipe\4lock-vpn-test-{}", uuid::Uuid::new_v4())
}

fn spawn_server(pipe_name: &str) -> Arc<AtomicBool> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);
    let name = pipe_name.to_string();
    thread::spawn(move || run_pipe_server_on(&name, shutdown_clone));
    thread::sleep(Duration::from_millis(200));
    shutdown
}

fn stop_server(pipe_name: &str, shutdown: &Arc<AtomicBool>) {
    shutdown.store(true, Ordering::Relaxed);
    let _ = send_request(
        pipe_name,
        &ServiceRequest {
            action: "status".into(),
            cidr: None,
            via: None,
            dns: None,
            host_adapter: None,
        },
    );
}

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
fn enable_vpn_adds_route_via_pipe() {
    let pipe = test_pipe_name();
    let shutdown = spawn_server(&pipe);

    // Cleanup
    let _ = send_request(
        &pipe,
        &ServiceRequest {
            action: "remove_route".into(),
            cidr: Some(TEST_CIDR.into()),
            via: None,
            dns: None,
            host_adapter: None,
        },
    );

    // Enable VPN
    let resp = send_request(
        &pipe,
        &ServiceRequest {
            action: "enable_vpn".into(),
            cidr: Some(TEST_CIDR.into()),
            via: Some(TEST_GATEWAY.into()),
            dns: None,
            host_adapter: None,
        },
    )
    .expect("enable_vpn request failed");

    assert!(resp.success, "enable_vpn failed: {:?}", resp.message);
    assert!(
        route_exists("198.51.100.0"),
        "Route not found after enable_vpn"
    );

    // Disable VPN
    let resp = send_request(
        &pipe,
        &ServiceRequest {
            action: "disable_vpn".into(),
            cidr: Some(TEST_CIDR.into()),
            via: Some(TEST_GATEWAY.into()),
            dns: None,
            host_adapter: None,
        },
    )
    .expect("disable_vpn request failed");

    assert!(resp.success, "disable_vpn failed: {:?}", resp.message);
    assert!(
        !route_exists("198.51.100.0"),
        "Route still present after disable_vpn"
    );

    stop_server(&pipe, &shutdown);
}

#[test]
#[ignore] // Requires admin
fn enable_vpn_missing_cidr_returns_error() {
    let pipe = test_pipe_name();
    let shutdown = spawn_server(&pipe);

    let resp = send_request(
        &pipe,
        &ServiceRequest {
            action: "enable_vpn".into(),
            cidr: None,
            via: Some(TEST_GATEWAY.into()),
            dns: None,
            host_adapter: None,
        },
    )
    .expect("request failed");

    assert!(!resp.success);
    assert!(resp.message.as_ref().unwrap().contains("cidr"));

    stop_server(&pipe, &shutdown);
}

#[test]
fn status_via_pipe_works() {
    let pipe = test_pipe_name();
    let shutdown = spawn_server(&pipe);

    let resp = send_request(
        &pipe,
        &ServiceRequest {
            action: "status".into(),
            cidr: None,
            via: None,
            dns: None,
            host_adapter: None,
        },
    )
    .expect("status request failed");

    assert!(resp.success);

    stop_server(&pipe, &shutdown);
}
