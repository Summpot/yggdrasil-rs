#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use log::{debug, warn};
use std::fs;
use std::time::Duration;
use tokio::sync::mpsc;

/// Memory statistics from /proc/self/statm
#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    /// Resident Set Size in bytes
    pub rss_bytes: u64,
    /// Virtual memory size in bytes
    pub vsize_bytes: u64,
    /// Timestamp when sample was taken
    pub timestamp: std::time::Instant,
}

impl MemoryStats {
    /// Read current process memory statistics from /proc/self/statm
    pub fn read() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let statm = fs::read_to_string("/proc/self/statm")
                .context("Failed to read /proc/self/statm")?;

            let parts: Vec<&str> = statm.split_whitespace().collect();
            if parts.len() < 2 {
                anyhow::bail!("Invalid /proc/self/statm format");
            }

            let page_size = 4096; // Standard Linux page size
            let vsize_pages: u64 = parts[0].parse().context("Failed to parse vsize")?;
            let rss_pages: u64 = parts[1].parse().context("Failed to parse rss")?;

            Ok(Self {
                rss_bytes: rss_pages * page_size,
                vsize_bytes: vsize_pages * page_size,
                timestamp: std::time::Instant::now(),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!("Memory monitoring only supported on Linux, returning zeros");
            Ok(Self {
                rss_bytes: 0,
                vsize_bytes: 0,
                timestamp: std::time::Instant::now(),
            })
        }
    }

    pub fn rss_mb(&self) -> f64 {
        self.rss_bytes as f64 / 1_048_576.0
    }

    pub fn vsize_mb(&self) -> f64 {
        self.vsize_bytes as f64 / 1_048_576.0
    }
}

/// Memory probe that samples RSS at regular intervals
pub struct MemoryProbe {
    samples: Vec<MemoryStats>,
    rx: mpsc::Receiver<MemoryStats>,
}

impl MemoryProbe {
    /// Create new memory probe that samples at given interval
    pub fn spawn(interval: Duration) -> Self {
        let (tx, rx) = mpsc::channel(1024);

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval_timer.tick().await;

                match MemoryStats::read() {
                    Ok(stats) => {
                        debug!("Memory sample: RSS={:.2} MB", stats.rss_mb());
                        if tx.send(stats).await.is_err() {
                            break; // Receiver dropped
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read memory stats: {}", e);
                    }
                }
            }
        });

        Self {
            samples: Vec::new(),
            rx,
        }
    }

    /// Collect all pending samples
    pub async fn collect(&mut self) {
        while let Ok(stats) = self.rx.try_recv() {
            self.samples.push(stats);
        }
    }

    /// Get peak RSS across all samples
    pub fn peak_rss(&self) -> u64 {
        self.samples.iter().map(|s| s.rss_bytes).max().unwrap_or(0)
    }

    /// Get mean RSS across all samples
    pub fn mean_rss(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.samples.iter().map(|s| s.rss_bytes).sum();
        sum as f64 / self.samples.len() as f64
    }

    /// Get steady-state RSS (mean of last 50% of samples)
    pub fn steady_state_rss(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }

        let skip = self.samples.len() / 2;
        let steady_samples: Vec<_> = self.samples.iter().skip(skip).collect();

        if steady_samples.is_empty() {
            return 0.0;
        }

        let sum: u64 = steady_samples.iter().map(|s| s.rss_bytes).sum();
        sum as f64 / steady_samples.len() as f64
    }

    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_stats_read() {
        let result = MemoryStats::read();
        #[cfg(target_os = "linux")]
        {
            let stats = result.unwrap();
            assert!(stats.rss_bytes > 0);
            assert!(stats.vsize_bytes > 0);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let stats = result.unwrap();
            assert_eq!(stats.rss_bytes, 0);
        }
    }

    #[tokio::test]
    async fn test_memory_probe() {
        let mut probe = MemoryProbe::spawn(Duration::from_millis(10));

        tokio::time::sleep(Duration::from_millis(100)).await;
        probe.collect().await;

        #[cfg(target_os = "linux")]
        {
            assert!(probe.sample_count() > 0);
            assert!(probe.peak_rss() > 0);
            assert!(probe.mean_rss() > 0.0);
        }
    }
}
