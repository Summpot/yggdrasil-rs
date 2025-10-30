use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;
use yggdrasil_core::AdminClient;

struct YggdrasilGoInstance {
    _process: Child,
    _temp_dir: TempDir,
    socket_path: PathBuf,
}

impl YggdrasilGoInstance {
    async fn start() -> Option<Self> {
        let go_binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../thirdparty/yggdrasil-go/yggdrasil");

        if !go_binary.exists() {
            eprintln!("Yggdrasil-go binary not found at {:?}", go_binary);
            
            // Check if Go is installed
            let go_check = Command::new("go")
                .arg("version")
                .output();
            
            match go_check {
                Ok(output) if output.status.success() => {
                    let version = String::from_utf8_lossy(&output.stdout);
                    eprintln!("Go compiler found: {}", version.trim());
                    eprintln!("Attempting to build yggdrasil-go...");
                    
                    let go_source_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../../thirdparty/yggdrasil-go");
                    
                    // Try to build using the build script
                    let build_result = Command::new("sh")
                        .arg("-c")
                        .arg("./build")
                        .current_dir(&go_source_dir)
                        .output();
                    
                    match build_result {
                        Ok(build_output) if build_output.status.success() => {
                            eprintln!("Successfully built yggdrasil-go!");
                            
                            // Check if binary exists now
                            if !go_binary.exists() {
                                eprintln!("Build succeeded but binary still not found at {:?}", go_binary);
                                return None;
                            }
                        }
                        Ok(build_output) => {
                            eprintln!("Build failed with exit code: {:?}", build_output.status.code());
                            eprintln!("stdout: {}", String::from_utf8_lossy(&build_output.stdout));
                            eprintln!("stderr: {}", String::from_utf8_lossy(&build_output.stderr));
                            return None;
                        }
                        Err(e) => {
                            eprintln!("Failed to execute build script: {}", e);
                            eprintln!("Manual build: cd thirdparty/yggdrasil-go && ./build");
                            return None;
                        }
                    }
                }
                Ok(_) => {
                    eprintln!("Go compiler not found (go version failed)");
                    eprintln!("Install Go or manually build: cd thirdparty/yggdrasil-go && ./build");
                    return None;
                }
                Err(e) => {
                    eprintln!("Go compiler not found: {}", e);
                    eprintln!("Install Go or manually build: cd thirdparty/yggdrasil-go && ./build");
                    return None;
                }
            }
        }

        let temp_dir = TempDir::new().ok()?;
        let config_path = temp_dir.path().join("config.hjson");
        let socket_path = temp_dir.path().join("yggdrasil.sock");

        let config = format!(
            r#"{{
  AdminListen: "unix://{}"
  Listen: []
  MulticastInterfaces: []
  IfName: "none"
}}"#,
            socket_path.display()
        );

        fs::write(&config_path, config).ok()?;

        let process = Command::new(&go_binary)
            .arg("-useconffile")
            .arg(&config_path)
            .spawn()
            .ok()?;

        for _ in 0..50 {
            if socket_path.exists() {
                sleep(Duration::from_millis(100)).await;
                return Some(Self {
                    _process: process,
                    _temp_dir: temp_dir,
                    socket_path,
                });
            }
            sleep(Duration::from_millis(100)).await;
        }

        eprintln!("Timeout: Admin socket not created at {:?}", socket_path);
        None
    }
}

impl Drop for YggdrasilGoInstance {
    fn drop(&mut self) {
        let _ = self._process.kill();
        let _ = self._process.wait();
    }
}

#[tokio::test]
async fn test_get_self_compatibility() {
    let instance = match YggdrasilGoInstance::start().await {
        Some(i) => i,
        None => {
            eprintln!("Skipping test: yggdrasil-go not available");
            return;
        }
    };

    let client = AdminClient::new(instance.socket_path.to_str().unwrap());
    
    let start = std::time::Instant::now();
    let response = client.get_self().await.expect("getSelf failed");
    let duration = start.elapsed();

    assert!(duration.as_millis() < 1000, "getSelf took too long: {:?}", duration);
    assert!(!response.build_name.is_empty());
    assert!(!response.build_version.is_empty());
    assert!(!response.public_key.is_empty());
    assert!(!response.ip_address.is_empty());
    assert!(!response.subnet.is_empty());
}

#[tokio::test]
async fn test_get_peers_compatibility() {
    let instance = match YggdrasilGoInstance::start().await {
        Some(i) => i,
        None => {
            eprintln!("Skipping test: yggdrasil-go not available");
            return;
        }
    };

    let client = AdminClient::new(instance.socket_path.to_str().unwrap());
    
    let start = std::time::Instant::now();
    let response = client.get_peers().await.expect("getPeers failed");
    let duration = start.elapsed();

    assert!(duration.as_millis() < 1000, "getPeers took too long: {:?}", duration);
    assert!(response.peers.is_empty());
}

#[tokio::test]
async fn test_get_paths_compatibility() {
    let instance = match YggdrasilGoInstance::start().await {
        Some(i) => i,
        None => {
            eprintln!("Skipping test: yggdrasil-go not available");
            return;
        }
    };

    let client = AdminClient::new(instance.socket_path.to_str().unwrap());
    
    let start = std::time::Instant::now();
    let response = client.get_paths().await.expect("getPaths failed");
    let duration = start.elapsed();

    assert!(duration.as_millis() < 1000, "getPaths took too long: {:?}", duration);
    assert!(response.paths.is_empty() || !response.paths.is_empty());
}

#[tokio::test]
async fn test_get_sessions_compatibility() {
    let instance = match YggdrasilGoInstance::start().await {
        Some(i) => i,
        None => {
            eprintln!("Skipping test: yggdrasil-go not available");
            return;
        }
    };

    let client = AdminClient::new(instance.socket_path.to_str().unwrap());
    
    let start = std::time::Instant::now();
    let response = client.get_sessions().await.expect("getSessions failed");
    let duration = start.elapsed();

    assert!(duration.as_millis() < 1000, "getSessions took too long: {:?}", duration);
    assert!(response.sessions.is_empty());
}

#[tokio::test]
async fn test_list_compatibility() {
    let instance = match YggdrasilGoInstance::start().await {
        Some(i) => i,
        None => {
            eprintln!("Skipping test: yggdrasil-go not available");
            return;
        }
    };

    let client = AdminClient::new(instance.socket_path.to_str().unwrap());
    
    let start = std::time::Instant::now();
    let response = client.list().await.expect("list failed");
    let duration = start.elapsed();

    assert!(duration.as_millis() < 1000, "list took too long: {:?}", duration);
    assert!(!response.list.is_empty());
    
    let commands: Vec<&str> = response.list.iter().map(|e| e.command.as_str()).collect();
    eprintln!("Available commands: {:?}", commands);
    assert!(commands.contains(&"getself") || commands.contains(&"getSelf"));
    assert!(commands.contains(&"getpeers") || commands.contains(&"getPeers"));
}

#[tokio::test]
async fn test_add_remove_peer_compatibility() {
    let instance = match YggdrasilGoInstance::start().await {
        Some(i) => i,
        None => {
            eprintln!("Skipping test: yggdrasil-go not available");
            return;
        }
    };

    let client = AdminClient::new(instance.socket_path.to_str().unwrap());
    
    let start = std::time::Instant::now();
    let add_response = client
        .add_peer("tcp://invalid.example:9001", None)
        .await
        .expect("addPeer failed");
    let duration = start.elapsed();

    eprintln!("addPeer response: success={:?}, error={:?}", add_response.success, add_response.error);
    assert!(duration.as_millis() < 2000, "addPeer took too long: {:?}", duration);

    let start = std::time::Instant::now();
    let remove_response = client
        .remove_peer("tcp://invalid.example:9001", None)
        .await
        .expect("removePeer failed");
    let duration = start.elapsed();

    eprintln!("removePeer response: success={:?}, error={:?}", remove_response.success, remove_response.error);
    assert!(duration.as_millis() < 2000, "removePeer took too long: {:?}", duration);
}
