//! Service work logic. Runs in both CLI (test) and Windows service mode.

use fourlock_windows_service::{pipe_server, watchdog};
use log::info;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub const PIPE_NAME: &str = pipe_server::DEFAULT_PIPE_NAME;

/// Runs the pipe server and watchdog until `shutdown` is set to true.
pub fn run_service_work(shutdown: Arc<AtomicBool>) {
    info!("Service work loop started — launching pipe server and watchdog");

    // Spawn watchdog in background thread
    let watchdog_shutdown = Arc::clone(&shutdown);
    let watchdog_handle = std::thread::spawn(move || {
        watchdog::run_watchdog(watchdog_shutdown);
    });

    // Pipe server runs on the current thread (blocking)
    pipe_server::run_pipe_server(Arc::clone(&shutdown));

    // Wait for watchdog to finish (it checks shutdown flag too)
    if let Err(e) = watchdog_handle.join() {
        log::error!("Watchdog thread panicked: {:?}", e);
    }

    info!("Service work loop stopped");
}
