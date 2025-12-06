//! Service management commands for yggdrasil daemon.

use std::ffi::OsString;

use anyhow::{Context, Result};
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx, ServiceStatus,
    ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx,
};

use crate::cli::ServiceCommand;
use crate::utils::{default_config_path, ensure_config_file};

/// Helper to create and configure a service manager
fn get_service_manager(label: String, user: bool) -> Result<(Box<dyn ServiceManager>, ServiceLabel)> {
    let label: ServiceLabel = label.parse()?;
    let mut manager = <dyn ServiceManager>::native()
        .context("Failed to detect service management platform")?;
    
    if user {
        manager
            .set_level(ServiceLevel::User)
            .context("Service manager does not support user-level services")?;
    }
    
    Ok((manager, label))
}

pub fn handle_service_command(action: ServiceCommand) -> Result<()> {
    match action {
        ServiceCommand::Install {
            label,
            config,
            log_file,
            log_level,
            autostart,
            user,
            username,
            working_directory,
            generate_config,
            disable_restart_on_failure,
        } => {
            let label: ServiceLabel = label.parse()?;
            let mut manager = <dyn ServiceManager>::native()
                .context("Failed to detect service management platform")?;

            if user {
                manager
                    .set_level(ServiceLevel::User)
                    .context("Service manager does not support user-level services")?;
            }

            // Determine program path (current executable)
            let program = std::env::current_exe().context("Failed to locate current executable")?;

            // Resolve configuration path (default matches yggdrasil-go packaging)
            let config_path = config.unwrap_or_else(default_config_path);
            ensure_config_file(&config_path, generate_config)?;

            // Build arguments to run the daemon with fixed config
            let mut args: Vec<OsString> = vec![OsString::from("run")];
            args.push(OsString::from("--config"));
            args.push(config_path.into_os_string());

            // Apply log level and optional file
            args.push(OsString::from("--log-level"));
            args.push(OsString::from(log_level.to_string()));
            if let Some(log_path) = log_file {
                args.push(OsString::from("--log-file"));
                args.push(log_path.into_os_string());
            }

            let install_ctx = ServiceInstallCtx {
                label,
                program,
                args,
                contents: None,
                username,
                working_directory,
                environment: None,
                autostart,
                disable_restart_on_failure,
            };

            manager.install(install_ctx)?;
            println!("Service installed successfully");
        }
        ServiceCommand::Uninstall { label, user } => {
            let (manager, label) = get_service_manager(label, user)?;
            manager.uninstall(ServiceUninstallCtx { label })?;
            println!("Service uninstalled successfully");
        }
        ServiceCommand::Start { label, user } => {
            let (manager, label) = get_service_manager(label, user)?;
            manager.start(ServiceStartCtx { label })?;
            println!("Service started");
        }
        ServiceCommand::Stop { label, user } => {
            let (manager, label) = get_service_manager(label, user)?;
            manager.stop(ServiceStopCtx { label })?;
            println!("Service stopped");
        }
        ServiceCommand::Status { label, user } => {
            let (manager, label) = get_service_manager(label, user)?;
            match manager.status(ServiceStatusCtx { label })? {
                ServiceStatus::NotInstalled => println!("Service not installed"),
                ServiceStatus::Stopped(reason) => {
                    if let Some(reason) = reason {
                        println!("Service stopped: {reason}");
                    } else {
                        println!("Service stopped");
                    }
                }
                ServiceStatus::Running => println!("Service running"),
            }
        }
    }

    Ok(())
}
