//! Utility functions for yggdrasil command-line tool.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use yggdrasil::NodeConfig;

/// Load configuration from file or stdin
pub fn load_config(path: Option<PathBuf>) -> Result<NodeConfig> {
    if let Some(ref path) = path {
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;
        Ok(NodeConfig::from_hjson(&data)?)
    } else if !atty::is(atty::Stream::Stdin) {
        let mut data = Vec::new();
        std::io::stdin().read_to_end(&mut data)?;
        Ok(NodeConfig::from_hjson(&data)?)
    } else {
        anyhow::bail!("No configuration provided. Use --config or pipe to stdin.")
    }
}

/// Format duration in seconds to human-readable string
pub fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{}h{}m{}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m{}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

/// Format bytes to human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Base64 encode data
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// Get default configuration file path for the platform
pub fn default_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        // Expand %PROGRAMDATA% to avoid literal env var in path
        if let Some(pd) = std::env::var_os("PROGRAMDATA") {
            let mut p = PathBuf::from(pd);
            p.push("Yggdrasil");
            p.push("yggdrasil.conf");
            p
        } else {
            PathBuf::from(r"C:\ProgramData\Yggdrasil\yggdrasil.conf")
        }
    }

    #[cfg(target_os = "freebsd")]
    {
        PathBuf::from("/usr/local/etc/yggdrasil.conf")
    }

    #[cfg(all(unix, not(target_os = "freebsd")))]
    {
        PathBuf::from("/etc/yggdrasil.conf")
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        PathBuf::from("yggdrasil.conf")
    }
}

/// Ensure configuration file exists, optionally generating it
pub fn ensure_config_file(path: &Path, generate: bool) -> Result<()> {
    if path.exists() {
        return Ok(());
    }

    if !generate {
        anyhow::bail!("Config file not found: {:?}. Use --generate-config to create it.", path);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("Failed to create config directory: {:?}", parent))?;
    }

    let config = NodeConfig::generate();
    let content = config.to_hjson_with_comments()?;
    fs::write(path, content).with_context(|| format!("Failed to write generated config to {:?}", path))?;
    Ok(())
}

// Re-implement atty for stdin detection
pub mod atty {
    pub enum Stream {
        Stdin,
    }

    pub fn is(stream: Stream) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = match stream {
                Stream::Stdin => std::io::stdin().as_raw_fd(),
            };
            unsafe { libc::isatty(fd) != 0 }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let handle = match stream {
                Stream::Stdin => std::io::stdin().as_raw_handle(),
            };
            unsafe {
                let mut mode = 0;
                windows_sys::Win32::System::Console::GetConsoleMode(handle as _, &mut mode) != 0
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            true
        }
    }
}
