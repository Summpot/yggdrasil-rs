#![forbid(unsafe_code)]

//! Service management module for installing, starting, stopping, and uninstalling
//! Yggdrasil as a system service on Linux, macOS, and Windows.

use anyhow::{Context, Result};
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use std::env;
use std::path::PathBuf;

const SERVICE_NAME: &str = "yggdrasil";
const SERVICE_DISPLAY_NAME: &str = "Yggdrasil Network";
const SERVICE_DESCRIPTION: &str = "End-to-end encrypted IPv6 mesh network";

/// Get the path to the current executable
fn get_executable_path() -> Result<PathBuf> {
    env::current_exe().context("Failed to get current executable path")
}

/// Get the default configuration file path
fn get_config_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from("C:\\ProgramData\\Yggdrasil\\config.hjson")
    } else {
        PathBuf::from("/etc/yggdrasil/config.hjson")
    }
}

/// Install Yggdrasil as a system service
pub fn install_service(config_path: Option<String>) -> Result<()> {
    let manager =
        <dyn ServiceManager>::native().context("Failed to detect native service manager")?;

    let executable = get_executable_path()?;
    let config = config_path
        .map(PathBuf::from)
        .unwrap_or_else(get_config_path);

    // Ensure configuration file exists
    if !config.exists() {
        anyhow::bail!(
            "Configuration file not found: {}. Please create it first using 'yggdrasil gen-conf > {}'",
            config.display(),
            config.display()
        );
    }

    let label: ServiceLabel = SERVICE_NAME.parse()?;

    let install_ctx = ServiceInstallCtx {
        label: label.clone(),
        program: executable,
        args: vec![
            "run".into(),
            "--config".into(),
            config.to_string_lossy().to_string().into(),
        ],
        contents: None,
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        disable_restart_on_failure: false,
    };

    manager
        .install(install_ctx)
        .context("Failed to install service")?;

    println!("✓ Service '{}' installed successfully", SERVICE_NAME);
    println!("  Display Name: {}", SERVICE_DISPLAY_NAME);
    println!("  Description: {}", SERVICE_DESCRIPTION);
    println!("  Config: {}", config.display());
    println!("\nTo start the service, run:");
    println!("  yggdrasil service start");

    Ok(())
}

/// Start the Yggdrasil service
pub fn start_service() -> Result<()> {
    let manager =
        <dyn ServiceManager>::native().context("Failed to detect native service manager")?;

    let label: ServiceLabel = SERVICE_NAME.parse()?;

    let start_ctx = ServiceStartCtx { label };

    manager
        .start(start_ctx)
        .context("Failed to start service")?;

    println!("✓ Service '{}' started successfully", SERVICE_NAME);

    Ok(())
}

/// Stop the Yggdrasil service
pub fn stop_service() -> Result<()> {
    let manager =
        <dyn ServiceManager>::native().context("Failed to detect native service manager")?;

    let label: ServiceLabel = SERVICE_NAME.parse()?;

    let stop_ctx = ServiceStopCtx { label };

    manager.stop(stop_ctx).context("Failed to stop service")?;

    println!("✓ Service '{}' stopped successfully", SERVICE_NAME);

    Ok(())
}

/// Restart the Yggdrasil service (stop then start)
pub fn restart_service() -> Result<()> {
    println!("Stopping service...");
    stop_service()?;

    println!("Starting service...");
    start_service()?;

    println!("✓ Service '{}' restarted successfully", SERVICE_NAME);

    Ok(())
}

/// Uninstall the Yggdrasil service
pub fn uninstall_service() -> Result<()> {
    let manager =
        <dyn ServiceManager>::native().context("Failed to detect native service manager")?;

    let label: ServiceLabel = SERVICE_NAME.parse()?;

    // Try to stop the service first (ignore errors if not running)
    let _ = stop_service();

    let uninstall_ctx = ServiceUninstallCtx { label };

    manager
        .uninstall(uninstall_ctx)
        .context("Failed to uninstall service")?;

    println!("✓ Service '{}' uninstalled successfully", SERVICE_NAME);

    Ok(())
}

/// Get the status of the Yggdrasil service
pub fn status_service() -> Result<()> {
    let _manager =
        <dyn ServiceManager>::native().context("Failed to detect native service manager")?;

    let _label: ServiceLabel = SERVICE_NAME.parse()?;

    // Note: service-manager doesn't have a direct status API
    // We'll provide basic information instead
    println!("Service Information:");
    println!("  Name: {}", SERVICE_NAME);
    println!("  Display Name: {}", SERVICE_DISPLAY_NAME);
    println!("  Description: {}", SERVICE_DESCRIPTION);
    println!("\nTo check if the service is running:");

    if cfg!(target_os = "linux") {
        println!("  systemctl status {}", SERVICE_NAME);
    } else if cfg!(target_os = "macos") {
        println!("  launchctl list | grep {}", SERVICE_NAME);
    } else if cfg!(target_os = "windows") {
        println!("  sc query {}", SERVICE_NAME);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_executable_path() {
        let path = get_executable_path();
        assert!(path.is_ok());
        let path = path.unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_get_config_path() {
        let path = get_config_path();
        assert!(!path.to_string_lossy().is_empty());
    }

    #[test]
    fn test_service_name() {
        assert_eq!(SERVICE_NAME, "yggdrasil");
    }
}
