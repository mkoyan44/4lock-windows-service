//! Service work logic. Runs in both CLI (test) and Windows service mode.
//! Later: replace the health-logging loop with Hyper-V event monitoring.

use log::info;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Interval between "Service is Healthy and Working" log messages.
const HEALTH_LOG_INTERVAL_SECS: u64 = 5;

/// Runs the main service work loop until `shutdown` is set to true.
/// In service mode, the Windows service control handler sets shutdown when STOP is received.
/// In CLI mode, shutdown can be set by a timeout or user interrupt.
pub fn run_service_work(shutdown: Arc<AtomicBool>) {
    info!("Service work loop started");

    while !shutdown.load(Ordering::Relaxed) {
        info!("Service is Healthy and Working");
        thread::sleep(Duration::from_secs(HEALTH_LOG_INTERVAL_SECS));
    }

    info!("Service work loop stopped");
}
