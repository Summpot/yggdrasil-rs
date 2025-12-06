//! Wintun DLL embedding for Windows.
//!
//! This module embeds the wintun.dll binary and extracts it to the executable
//! directory at runtime, allowing the TUN adapter to work without requiring
//! users to manually copy the DLL.

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Once;

use crate::TunError;

// Embed wintun.dll for the appropriate architecture
#[cfg(target_arch = "x86_64")]
static WINTUN_DLL: &[u8] = include_bytes!("../../../lib/amd64/wintun.dll");

#[cfg(target_arch = "aarch64")]
static WINTUN_DLL: &[u8] = include_bytes!("../../../lib/arm64/wintun.dll");

static INIT: Once = Once::new();

/// Ensure wintun.dll is available in the executable directory.
pub fn ensure_wintun_dll() -> Result<(), TunError> {
    let mut result = Ok(());

    INIT.call_once(|| {
        if let Err(e) = extract_wintun_dll() {
            result = Err(e);
        }
    });

    result
}

/// Extract wintun.dll to the executable directory.
fn extract_wintun_dll() -> Result<(), TunError> {
    let dll_path = get_wintun_dll_path()?;

    // Check if DLL already exists and has the correct size
    if dll_path.exists() {
        if let Ok(metadata) = fs::metadata(&dll_path) {
            if metadata.len() == WINTUN_DLL.len() as u64 {
                tracing::debug!(?dll_path, "wintun.dll already exists with correct size");
                return Ok(());
            }
        }
    }

    // Create the directory if it doesn't exist
    if let Some(parent) = dll_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            TunError::Device(format!("failed to create directory for wintun.dll: {}", e))
        })?;
    }

    // Write the DLL
    let mut file = fs::File::create(&dll_path)
        .map_err(|e| TunError::Device(format!("failed to create wintun.dll: {}", e)))?;

    file.write_all(WINTUN_DLL)
        .map_err(|e| TunError::Device(format!("failed to write wintun.dll: {}", e)))?;

    tracing::info!(?dll_path, "Extracted wintun.dll");
    Ok(())
}

/// Get the path where wintun.dll should be placed.
fn get_wintun_dll_path() -> Result<PathBuf, TunError> {
    // Try to get the executable directory first
    if let Ok(exe_path) = env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            return Ok(exe_dir.join("wintun.dll"));
        }
    }

    // Fall back to current directory
    let current_dir = env::current_dir()
        .map_err(|e| TunError::Device(format!("failed to get current directory: {}", e)))?;

    Ok(current_dir.join("wintun.dll"))
}
