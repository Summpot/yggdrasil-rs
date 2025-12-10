use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tracing::warn;
use yggdrasil_types::PublicKey;

#[derive(Clone)]
pub struct PlaintextDebugLogger {
    path: PathBuf,
    writer: Arc<Mutex<BufWriter<std::fs::File>>>,
}

impl PlaintextDebugLogger {
    pub fn from_path(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        Ok(Self {
            path,
            writer: Arc::new(Mutex::new(BufWriter::new(file))),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn log_out(&self, peer: &PublicKey, data: &[u8]) {
        self.log("OUT", peer, data);
    }

    pub fn log_in(&self, peer: &PublicKey, data: &[u8]) {
        self.log("IN", peer, data);
    }

    fn log(&self, direction: &str, peer: &PublicKey, data: &[u8]) {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        let line = format!(
            "[PLAINTEXT {direction}] ts={ts_ms} peer={} len={} data={}",
            hex::encode(peer.as_bytes()),
            data.len(),
            hex::encode(data),
        );

        let mut guard = self.writer.lock();
        if let Err(e) = writeln!(&mut *guard, "{line}") {
            warn!(path = %self.path.display(), error = %e, "Failed to write plaintext debug log");
            return;
        }

        if let Err(e) = guard.flush() {
            warn!(path = %self.path.display(), error = %e, "Failed to flush plaintext debug log");
        }
    }
}
