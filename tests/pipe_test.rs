use fourlock_windows_service::pipe_server::{run_pipe_server_on, send_request};
use fourlock_windows_service::protocol::ServiceRequest;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Generate a unique pipe name per test to avoid collisions.
fn test_pipe_name() -> String {
    format!(r"\\.\pipe\4lock-test-{}", uuid::Uuid::new_v4())
}

/// Spawn a pipe server on a background thread, returning the shutdown handle.
fn spawn_server(pipe_name: &str) -> Arc<AtomicBool> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);
    let name = pipe_name.to_string();
    thread::spawn(move || run_pipe_server_on(&name, shutdown_clone));
    // Give the server a moment to create the pipe
    thread::sleep(Duration::from_millis(200));
    shutdown
}

#[test]
fn status_request_succeeds() {
    let pipe = test_pipe_name();
    let shutdown = spawn_server(&pipe);

    let req = ServiceRequest {
        action: "status".to_string(),
        cidr: None,
        via: None,
        dns: None,
        host_adapter: None,
    };

    let resp = send_request(&pipe, &req).expect("send_request failed");
    assert!(resp.success);
    assert!(resp.message.is_some());

    shutdown.store(true, Ordering::Relaxed);
    // Connect once more to unblock the server's ConnectNamedPipe wait
    let _ = send_request(&pipe, &req);
}

#[test]
fn unknown_action_returns_error() {
    let pipe = test_pipe_name();
    let shutdown = spawn_server(&pipe);

    let req = ServiceRequest {
        action: "nonexistent_action".to_string(),
        cidr: None,
        via: None,
        dns: None,
        host_adapter: None,
    };

    let resp = send_request(&pipe, &req).expect("send_request failed");
    assert!(!resp.success);
    assert!(resp
        .message
        .as_ref()
        .unwrap()
        .contains("Unknown action"));

    shutdown.store(true, Ordering::Relaxed);
    let _ = send_request(
        &pipe,
        &ServiceRequest {
            action: "status".into(),
            cidr: None,
            via: None,
            dns: None,
            host_adapter: None,
        },
    );
}

#[test]
fn missing_required_fields_returns_error() {
    let pipe = test_pipe_name();
    let shutdown = spawn_server(&pipe);

    // add_route without cidr
    let req = ServiceRequest {
        action: "add_route".to_string(),
        cidr: None,
        via: Some("10.0.0.1".into()),
        dns: None,
        host_adapter: None,
    };

    let resp = send_request(&pipe, &req).expect("send_request failed");
    assert!(!resp.success);
    assert!(resp.message.as_ref().unwrap().contains("cidr"));

    shutdown.store(true, Ordering::Relaxed);
    let _ = send_request(
        &pipe,
        &ServiceRequest {
            action: "status".into(),
            cidr: None,
            via: None,
            dns: None,
            host_adapter: None,
        },
    );
}

#[test]
fn multiple_sequential_requests() {
    let pipe = test_pipe_name();
    let shutdown = spawn_server(&pipe);

    for i in 0..3 {
        let req = ServiceRequest {
            action: "status".to_string(),
            cidr: None,
            via: None,
            dns: None,
            host_adapter: None,
        };
        let resp = send_request(&pipe, &req).unwrap_or_else(|e| panic!("request {} failed: {}", i, e));
        assert!(resp.success, "request {} was not successful", i);
    }

    shutdown.store(true, Ordering::Relaxed);
    let _ = send_request(
        &pipe,
        &ServiceRequest {
            action: "status".into(),
            cidr: None,
            via: None,
            dns: None,
            host_adapter: None,
        },
    );
}

#[test]
fn server_shutdown_is_clean() {
    let pipe = test_pipe_name();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);
    let name = pipe.clone();

    let handle = thread::spawn(move || run_pipe_server_on(&name, shutdown_clone));

    thread::sleep(Duration::from_millis(200));

    // Signal shutdown
    shutdown.store(true, Ordering::Relaxed);

    // Unblock the server by connecting
    let _ = send_request(
        &pipe,
        &ServiceRequest {
            action: "status".into(),
            cidr: None,
            via: None,
            dns: None,
            host_adapter: None,
        },
    );

    // Server thread should finish within a few seconds
    handle
        .join()
        .expect("Server thread panicked or did not stop cleanly");
}
