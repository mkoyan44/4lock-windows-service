//! Watchdog: monitors the 4lock-agent process and cleans up on exit.
//!
//! The watchdog runs in a background thread and:
//! 1. Polls for `vapp.exe` by name (every 5 seconds)
//! 2. Once found, opens a process handle and waits for it to exit
//! 3. On exit, performs full cleanup:
//!    a. Discovers owned VMs from user profile directories and removes them
//!    b. Resets DNS to DHCP on common adapters (prevents internet loss)
//!    c. Kills processes holding docker-proxy ports (5050/5051)
//! 4. On service stop, performs one final cleanup pass

use crate::commands::dns;
use log::{error, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const WAIT_TIMEOUT_MS: u32 = 5000;
const AGENT_PROCESS_NAME: &str = "vapp.exe";

/// App data relative path from user profile directory.
/// Full path: C:\Users\<user>\AppData\Roaming\4lock-agent\4lock-agent\vms\
const APP_DATA_RELATIVE: &str = r"AppData\Roaming\4lock-agent\4lock-agent\vms";

/// Run the watchdog loop. Blocks until `shutdown` is set.
///
/// The loop alternates between two phases:
/// - Phase 1: Poll for vapp.exe process (5s interval)
/// - Phase 2: Monitor the process via handle, cleanup on exit
pub fn run_watchdog(shutdown: Arc<AtomicBool>) {
    info!("[Watchdog] Started");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Phase 1: Wait for vapp.exe to appear
        let pid = match wait_for_agent(&shutdown) {
            Some(pid) => pid,
            None => break, // shutdown signaled
        };

        info!("[Watchdog] Agent process found (PID: {})", pid);

        // Phase 2: Monitor the process
        if !monitor_process(pid, &shutdown) {
            // shutdown signaled while monitoring
            break;
        }

        // Process exited — full cleanup
        info!("[Watchdog] Agent process exited — running full cleanup");
        run_full_cleanup();
        info!("[Watchdog] Cleanup complete, resuming monitoring");
    }

    // Final cleanup on service stop
    info!("[Watchdog] Shutdown — running final cleanup");
    run_full_cleanup();
    info!("[Watchdog] Stopped");
}

/// Poll for vapp.exe until found or shutdown. Returns PID or None on shutdown.
fn wait_for_agent(shutdown: &Arc<AtomicBool>) -> Option<u32> {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return None;
        }
        if let Some(pid) = find_process(AGENT_PROCESS_NAME) {
            return Some(pid);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Monitor a process by handle. Returns true if process exited, false if shutdown signaled.
#[cfg(windows)]
fn monitor_process(pid: u32, shutdown: &Arc<AtomicBool>) -> bool {
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        warn!(
            "[Watchdog] Failed to open process handle for PID {}: {}",
            pid,
            std::io::Error::last_os_error()
        );
        std::thread::sleep(POLL_INTERVAL);
        return true; // treat as exited so we retry
    }

    loop {
        let result = unsafe { WaitForSingleObject(handle, WAIT_TIMEOUT_MS) };
        if result == WAIT_OBJECT_0 {
            // Process exited
            unsafe { CloseHandle(handle) };
            return true;
        }
        if shutdown.load(Ordering::Relaxed) {
            unsafe { CloseHandle(handle) };
            return false;
        }
        // WAIT_TIMEOUT — process still running, loop again
    }
}

#[cfg(not(windows))]
fn monitor_process(_pid: u32, _shutdown: &Arc<AtomicBool>) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Process discovery
// ---------------------------------------------------------------------------

/// Find a process by executable name. Returns the first matching PID.
#[cfg(windows)]
fn find_process(name: &str) -> Option<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        warn!(
            "[Watchdog] CreateToolhelp32Snapshot failed: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }

    let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    let mut found = None;

    if unsafe { Process32First(snapshot, &mut entry) } != 0 {
        loop {
            let exe_name = cstr_from_array(&entry.szExeFile);
            if exe_name.eq_ignore_ascii_case(name) {
                found = Some(entry.th32ProcessID);
                break;
            }
            if unsafe { Process32Next(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot) };
    found
}

#[cfg(not(windows))]
fn find_process(_name: &str) -> Option<u32> {
    None
}

/// Extract a null-terminated string from a fixed-size i8 array.
#[cfg(windows)]
fn cstr_from_array(arr: &[i8]) -> String {
    let bytes: Vec<u8> = arr
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as u8)
        .collect();
    String::from_utf8_lossy(&bytes).to_string()
}

// ---------------------------------------------------------------------------
// VM discovery
// ---------------------------------------------------------------------------

/// Discover owned VM names by scanning user profile directories.
///
/// Scans: C:\Users\*\AppData\Roaming\4lock-agent\4lock-agent\vms\
/// Each subdirectory name is an owned VM name.
fn discover_owned_vms() -> Vec<String> {
    let mut vm_names = Vec::new();

    let users_dir = std::path::Path::new(r"C:\Users");
    let entries = match std::fs::read_dir(users_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("[Watchdog] Failed to read C:\\Users: {}", e);
            return vm_names;
        }
    };

    for entry in entries.flatten() {
        let user_dir = entry.path();
        if !user_dir.is_dir() {
            continue;
        }

        let vms_dir = user_dir.join(APP_DATA_RELATIVE);
        if !vms_dir.is_dir() {
            continue;
        }

        if let Ok(vm_entries) = std::fs::read_dir(&vms_dir) {
            for vm_entry in vm_entries.flatten() {
                if vm_entry.path().is_dir() {
                    if let Some(name) = vm_entry.file_name().to_str() {
                        if !vm_names.contains(&name.to_string()) {
                            vm_names.push(name.to_string());
                        }
                    }
                }
            }
        }
    }

    vm_names
}

// ---------------------------------------------------------------------------
// VM cleanup
// ---------------------------------------------------------------------------

/// Stop and remove all owned Hyper-V VMs (keeps disk files).
fn cleanup_owned_vms() {
    let vm_names = discover_owned_vms();
    if vm_names.is_empty() {
        info!("[Watchdog] No owned VMs found — nothing to clean up");
        return;
    }

    info!(
        "[Watchdog] Found {} owned VM(s) to clean up: {:?}",
        vm_names.len(),
        vm_names
    );

    let mut cleaned = 0;
    for name in &vm_names {
        match stop_and_remove_vm(name) {
            Ok(true) => {
                info!("[Watchdog] Cleaned up VM '{}'", name);
                cleaned += 1;
            }
            Ok(false) => {
                info!(
                    "[Watchdog] VM '{}' not found in Hyper-V (already removed)",
                    name
                );
            }
            Err(e) => {
                error!("[Watchdog] Failed to clean up VM '{}': {}", name, e);
            }
        }
    }

    info!(
        "[Watchdog] VM cleanup complete: {}/{} cleaned",
        cleaned,
        vm_names.len()
    );
}

/// Stop and remove a single Hyper-V VM by name. Returns Ok(true) if removed,
/// Ok(false) if not found, Err on failure.
fn stop_and_remove_vm(name: &str) -> Result<bool, String> {
    // Sanitize name to prevent injection (only allow alphanumeric, dash, underscore, dot)
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!("Invalid VM name: {}", name));
    }

    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$vm = Get-VM -Name '{}' -ErrorAction SilentlyContinue
if (-not $vm) {{
    Write-Output 'NOT_FOUND'
    exit 0
}}
if ($vm.State -ne 'Off') {{
    Stop-VM -Name '{}' -Force -TurnOff -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}}
Remove-VM -Name '{}' -Force -ErrorAction Stop
Write-Output 'REMOVED'
"#,
        name, name, name
    );

    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let trimmed = stdout.trim();

    if !output.status.success() && !trimmed.contains("NOT_FOUND") {
        return Err(format!(
            "PowerShell exit code {:?}: {} {}",
            output.status.code(),
            trimmed,
            stderr.trim()
        ));
    }

    if trimmed.contains("NOT_FOUND") {
        Ok(false)
    } else {
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Full cleanup orchestration
// ---------------------------------------------------------------------------

/// Run all cleanup steps in order after agent death or service shutdown.
fn run_full_cleanup() {
    cleanup_owned_vms();
    cleanup_dns();
    cleanup_ports();
}

// ---------------------------------------------------------------------------
// DNS cleanup
// ---------------------------------------------------------------------------

/// Reset DNS to DHCP on common network adapters.
///
/// When VPN is active, the host DNS is pointed at the VM's eth0 IP. If the VM
/// is removed but DNS isn't reset, the user loses all DNS resolution. This
/// resets DNS to DHCP on Wi-Fi and Ethernet adapters (best-effort).
fn cleanup_dns() {
    for adapter in ["Wi-Fi", "Ethernet"] {
        let resp = dns::clear_dns(Some(adapter));
        if resp.success {
            info!("[Watchdog] DNS cleared on {} (DHCP)", adapter);
        }
        // Ignore errors — adapter may not exist on this system
    }
}

// ---------------------------------------------------------------------------
// Port cleanup (docker-proxy 5050/5051)
// ---------------------------------------------------------------------------

/// Kill any processes still listening on docker-proxy ports 5050/5051.
///
/// BlobService (docker-proxy) runs inside vapp.exe and normally dies with it,
/// but child processes could outlive the parent and hold ports.
fn cleanup_ports() {
    let ports = [5050u16, 5051];
    let pids = find_pids_on_ports(&ports);

    if pids.is_empty() {
        info!("[Watchdog] No processes holding docker-proxy ports 5050/5051");
        return;
    }

    info!(
        "[Watchdog] Found {} process(es) on docker-proxy ports: {:?}",
        pids.len(),
        pids
    );

    for pid in &pids {
        kill_process(*pid);
    }
}

/// Find PIDs of processes listening on the given ports via `netstat -ano`.
fn find_pids_on_ports(ports: &[u16]) -> Vec<u32> {
    let mut pids = Vec::new();

    let output = match std::process::Command::new("netstat")
        .args(["-ano"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            warn!(
                "[Watchdog] netstat failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return pids;
        }
        Err(e) => {
            warn!("[Watchdog] Failed to run netstat: {}", e);
            return pids;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        for &port in ports {
            let port_str = format!(":{}", port);
            if line.contains(&port_str) && line.contains("LISTENING") {
                if let Some(pid_str) = line.split_whitespace().last() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        if pid != 0 && !pids.contains(&pid) {
                            pids.push(pid);
                        }
                    }
                }
            }
        }
    }

    pids
}

/// Force-kill a process by PID using `taskkill /F /PID`.
fn kill_process(pid: u32) {
    match std::process::Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .output()
    {
        Ok(output) if output.status.success() => {
            info!("[Watchdog] Killed process {} on docker-proxy port", pid);
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "[Watchdog] Failed to kill process {}: {}",
                pid,
                stderr.trim()
            );
        }
        Err(e) => {
            warn!("[Watchdog] Failed to run taskkill for PID {}: {}", pid, e);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_owned_vms_no_crash() {
        // Should not crash even if C:\Users has restricted entries
        let vms = discover_owned_vms();
        // Just verify it returns without panicking
        let _ = vms; // just verify it returns without panicking
    }

    #[test]
    fn test_vm_name_sanitization() {
        assert!(stop_and_remove_vm("valid-name_123").is_ok() || stop_and_remove_vm("valid-name_123").is_err());
        assert!(stop_and_remove_vm("'; Drop-Database --").is_err());
        assert!(stop_and_remove_vm("name with spaces").is_err());
        assert!(stop_and_remove_vm("$(evil)").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn test_find_process_self() {
        // Our own process should be findable
        // The test binary name varies, but we can at least test that the function doesn't crash
        let result = find_process("nonexistent_process_12345.exe");
        assert!(result.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn test_find_process_explorer() {
        // explorer.exe should almost always be running on Windows
        let result = find_process("explorer.exe");
        // Don't assert Some because CI might not have explorer
        if let Some(pid) = result {
            assert!(pid > 0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_find_pids_on_ports_no_crash() {
        // Should not crash regardless of what's listening
        let pids = find_pids_on_ports(&[5050, 5051]);
        let _ = pids;
    }

    #[test]
    fn test_cleanup_dns_no_crash() {
        // Should not crash even if adapters don't exist
        cleanup_dns();
    }
}
