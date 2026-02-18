//! Service work logic. Runs in both CLI (test) and Windows service mode.

use fourlock_windows_service::pipe_server;
use log::info;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub const PIPE_NAME: &str = pipe_server::DEFAULT_PIPE_NAME;

/// Runs the named pipe server until `shutdown` is set to true.
pub fn run_service_work(shutdown: Arc<AtomicBool>) {
    info!("Service work loop started — launching pipe server");
    pipe_server::run_pipe_server(shutdown);
    info!("Service work loop stopped");
}
