//! 4lock Windows service: CLI (test) and Windows service modes.
//! - Run from command line: runs service work loop until Ctrl+C (CLI mode).
//! - Run by Service Control Manager: runs as a Windows service (service mode).

mod service;

use log::info;
use simplelog::{ConfigBuilder, LevelFilter, SimpleLogger, WriteLogger};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const SERVICE_NAME: &str = "4lock-windows-service";
#[cfg(windows)]
const SERVICE_TYPE: windows_service::service::ServiceType =
    windows_service::service::ServiceType::OWN_PROCESS;

/// Initialize logging to stdout (for CLI mode).
fn init_logging_stdout() -> Result<(), log::SetLoggerError> {
    let config = ConfigBuilder::new()
        .set_time_level(LevelFilter::Info)
        .build();
    SimpleLogger::init(LevelFilter::Info, config)
}

/// Initialize logging to a file (for service mode; no console available).
fn init_logging_file() -> Result<(), Box<dyn std::error::Error>> {
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
    let log_dir: PathBuf = [program_data, "4lock-windows-service".into()].iter().collect();
    std::fs::create_dir_all(&log_dir)?;
    let log_path = log_dir.join("service.log");
    let file = File::create(&log_path)?;
    let config = ConfigBuilder::new()
        .set_time_level(LevelFilter::Info)
        .build();
    WriteLogger::init(LevelFilter::Info, config, file)?;
    info!("Logging to {:?}", log_path);
    Ok(())
}

/// CLI mode: run the service work loop until Ctrl+C.
fn run_cli() -> io::Result<()> {
    if let Err(e) = init_logging_stdout() {
        eprintln!("Failed to init logging: {}", e);
        return Err(io::Error::new(io::ErrorKind::Other, e));
    }
    info!("Running in CLI mode (press Ctrl+C to stop)");

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);

    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let worker = thread::spawn(move || service::run_service_work(shutdown));
    worker.join().map_err(|_| io::Error::new(io::ErrorKind::Other, "worker panicked"))?;

    info!("CLI mode finished");
    Ok(())
}

#[cfg(windows)]
fn run_windows_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, my_service_main);

#[cfg(windows)]
fn my_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = init_logging_file() {
        eprintln!("Failed to init service logging: {}", e);
        return;
    }
    info!("Service entry point started");

    if let Err(e) = run_service() {
        log::error!("Service error: {}", e);
    }
}

#[cfg(windows)]
fn run_service() -> windows_service::Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handle = Arc::clone(&shutdown);

    // Share the status handle with the event handler via OnceLock (set after register).
    let status_handle_cell: Arc<OnceLock<service_control_handler::ServiceStatusHandle>> =
        Arc::new(OnceLock::new());
    let status_handle_for_handler = Arc::clone(&status_handle_cell);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                shutdown_handle.store(true, Ordering::Relaxed);
                // Report STOP_PENDING so SCM (and `net stop`) waits for graceful shutdown.
                if let Some(handle) = status_handle_for_handler.get() {
                    let _ = handle.set_service_status(ServiceStatus {
                        service_type: SERVICE_TYPE,
                        current_state: ServiceState::StopPending,
                        controls_accepted: ServiceControlAccept::empty(),
                        exit_code: ServiceExitCode::Win32(0),
                        checkpoint: 0,
                        wait_hint: std::time::Duration::from_secs(30),
                        process_id: None,
                    });
                }
                // Connect to the pipe to unblock the server's ConnectNamedPipe call
                let _ = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(service::PIPE_NAME);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    let _ = status_handle_cell.set(status_handle);

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    let worker = thread::spawn(move || service::run_service_work(shutdown));
    if worker.join().is_err() {
        log::error!("Service work thread panicked");
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

fn main() {
    #[cfg(windows)]
    {
        match run_windows_service() {
            Ok(()) => {}
            Err(_) => {
                if let Err(e) = run_cli() {
                    eprintln!("CLI mode error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        eprintln!("This program is only intended to run on Windows.");
        std::process::exit(1);
    }
}
