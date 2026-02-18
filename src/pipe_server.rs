//! Named pipe server for receiving commands from 4lock-agent.
//!
//! Listens on `\\.\pipe\4lock-service` (or a custom name for testing).
//! Protocol: 4-byte LE u32 length prefix + UTF-8 JSON payload, for both request and response.

use crate::commands;
use crate::protocol::{ServiceRequest, ServiceResponse};
use log::{error, info, warn};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR,
};
// SECURITY_DESCRIPTOR_REVISION is in Win32::System::SystemServices — just use the constant directly
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX,
};
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};

pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\4lock-service";
const BUFFER_SIZE: u32 = 8192;
const MAX_MESSAGE_SIZE: u32 = 65536;

/// Run the pipe server loop. Blocks until `shutdown` is set.
pub fn run_pipe_server(shutdown: Arc<AtomicBool>) {
    run_pipe_server_on(DEFAULT_PIPE_NAME, shutdown);
}

/// Run the pipe server on a specific pipe name (for testing).
pub fn run_pipe_server_on(pipe_name: &str, shutdown: Arc<AtomicBool>) {
    info!("Pipe server starting on {}", pipe_name);

    #[cfg(windows)]
    {
        run_pipe_server_windows(pipe_name, shutdown);
    }

    #[cfg(not(windows))]
    {
        let _ = (pipe_name, shutdown);
        error!("Named pipe server is only supported on Windows");
    }
}

#[cfg(windows)]
fn run_pipe_server_windows(pipe_name: &str, shutdown: Arc<AtomicBool>) {
    let wide_name: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

    // Build a security descriptor with a NULL DACL so non-elevated clients can connect
    // when the service runs as LocalSystem / admin.
    let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    unsafe {
        InitializeSecurityDescriptor(&mut sd as *mut _ as *mut _, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&mut sd as *mut _ as *mut _, 1, std::ptr::null_mut(), 0);
    }
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: &mut sd as *mut _ as *mut _,
        bInheritHandle: 0,
    };

    while !shutdown.load(Ordering::Relaxed) {
        // Create a new pipe instance for each connection
        let pipe = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,           // max instances
                BUFFER_SIZE, // out buffer
                BUFFER_SIZE, // in buffer
                1000,        // default timeout ms (for ConnectNamedPipe)
                &mut sa as *mut _ as *mut _,
            )
        };

        if pipe == INVALID_HANDLE_VALUE {
            error!("CreateNamedPipeW failed: {}", std::io::Error::last_os_error());
            std::thread::sleep(std::time::Duration::from_secs(1));
            continue;
        }

        // Wait for a client to connect
        let connected = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) };
        if connected == 0 {
            let err = std::io::Error::last_os_error();
            // ERROR_PIPE_CONNECTED (535) means client connected before ConnectNamedPipe — that's OK
            if err.raw_os_error() != Some(535) {
                warn!("ConnectNamedPipe failed: {}", err);
                unsafe { CloseHandle(pipe) };
                continue;
            }
        }

        if shutdown.load(Ordering::Relaxed) {
            unsafe {
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
            }
            break;
        }

        // Handle the connection
        handle_connection(pipe);

        unsafe {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    }

    info!("Pipe server stopped");
}

#[cfg(windows)]
fn handle_connection(pipe: HANDLE) {
    // Read length prefix (4 bytes LE)
    let mut len_buf = [0u8; 4];
    if !pipe_read_exact(pipe, &mut len_buf) {
        warn!("Failed to read message length");
        let resp = ServiceResponse::err("Failed to read message length");
        let _ = write_response(pipe, &resp);
        return;
    }
    let msg_len = u32::from_le_bytes(len_buf);

    if msg_len == 0 || msg_len > MAX_MESSAGE_SIZE {
        warn!("Invalid message length: {}", msg_len);
        let resp = ServiceResponse::err(format!("Invalid message length: {}", msg_len));
        let _ = write_response(pipe, &resp);
        return;
    }

    // Read JSON payload
    let mut payload = vec![0u8; msg_len as usize];
    if !pipe_read_exact(pipe, &mut payload) {
        warn!("Failed to read message payload");
        let resp = ServiceResponse::err("Failed to read message payload");
        let _ = write_response(pipe, &resp);
        return;
    }

    // Parse request
    let response = match serde_json::from_slice::<ServiceRequest>(&payload) {
        Ok(request) => {
            info!("Received action: {}", request.action);
            commands::dispatch(&request)
        }
        Err(e) => {
            warn!("Invalid JSON request: {}", e);
            ServiceResponse::err(format!("Invalid JSON: {}", e))
        }
    };

    // Write response
    if let Err(e) = write_response(pipe, &response) {
        warn!("Failed to write response: {}", e);
    }
}

#[cfg(windows)]
fn write_response(pipe: HANDLE, response: &ServiceResponse) -> Result<(), String> {
    let json = serde_json::to_vec(response).map_err(|e| format!("serialize error: {}", e))?;
    let len = json.len() as u32;

    pipe_write_all(pipe, &len.to_le_bytes())?;
    pipe_write_all(pipe, &json)?;
    unsafe {
        FlushFileBuffers(pipe);
    }
    Ok(())
}

#[cfg(windows)]
fn pipe_read_exact(pipe: HANDLE, buf: &mut [u8]) -> bool {
    let mut offset = 0;
    while offset < buf.len() {
        let mut bytes_read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                pipe,
                buf[offset..].as_mut_ptr() as *mut _,
                (buf.len() - offset) as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || bytes_read == 0 {
            return false;
        }
        offset += bytes_read as usize;
    }
    true
}

#[cfg(windows)]
fn pipe_write_all(pipe: HANDLE, data: &[u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < data.len() {
        let mut bytes_written: u32 = 0;
        let ok = unsafe {
            WriteFile(
                pipe,
                data[offset..].as_ptr() as *const _,
                (data.len() - offset) as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("WriteFile failed: {}", std::io::Error::last_os_error()));
        }
        offset += bytes_written as usize;
    }
    Ok(())
}

/// Pipe client helper — used by tests and potentially by agent-side code.
/// Opens a named pipe, sends a request, reads a response.
/// Retries connection up to 5 times with 100ms delay (pipe may be recreating between requests).
pub fn send_request(pipe_name: &str, request: &ServiceRequest) -> Result<ServiceResponse, String> {
    let json = serde_json::to_vec(request).map_err(|e| format!("serialize error: {}", e))?;
    let len = json.len() as u32;

    let mut pipe = {
        let mut last_err = String::new();
        let mut connected = None;
        for _ in 0..5 {
            match std::fs::OpenOptions::new().read(true).write(true).open(pipe_name) {
                Ok(p) => {
                    connected = Some(p);
                    break;
                }
                Err(e) => {
                    last_err = format!("{}", e);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
        connected.ok_or_else(|| {
            format!(
                "Failed to connect to pipe {} after retries: {}",
                pipe_name, last_err
            )
        })?
    };

    // Write length-prefixed request
    pipe.write_all(&len.to_le_bytes())
        .map_err(|e| format!("write length error: {}", e))?;
    pipe.write_all(&json)
        .map_err(|e| format!("write payload error: {}", e))?;
    pipe.flush()
        .map_err(|e| format!("flush error: {}", e))?;

    // Read length-prefixed response
    let mut len_buf = [0u8; 4];
    pipe.read_exact(&mut len_buf)
        .map_err(|e| format!("read response length error: {}", e))?;
    let resp_len = u32::from_le_bytes(len_buf);

    if resp_len > MAX_MESSAGE_SIZE {
        return Err(format!("Response too large: {} bytes", resp_len));
    }

    let mut resp_buf = vec![0u8; resp_len as usize];
    pipe.read_exact(&mut resp_buf)
        .map_err(|e| format!("read response payload error: {}", e))?;

    serde_json::from_slice(&resp_buf).map_err(|e| format!("parse response error: {}", e))
}
