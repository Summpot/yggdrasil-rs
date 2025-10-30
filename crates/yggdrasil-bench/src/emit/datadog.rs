#![forbid(unsafe_code)]

use std::net::UdpSocket;
use anyhow::{Context, Result};
use log::{debug, warn};

use super::results::BenchmarkResult;

/// DogStatsD client for sending metrics to Datadog
pub struct DatadogClient {
    socket: Option<UdpSocket>,
    address: String,
}

impl DatadogClient {
    /// Create new Datadog client
    /// 
    /// # Arguments
    /// * `address` - DogStatsD address (e.g., "127.0.0.1:8125")
    pub fn new(address: &str) -> Result<Self> {
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => Some(s),
            Err(e) => {
                warn!("Failed to create UDP socket for DogStatsD: {}", e);
                None
            }
        };

        Ok(Self {
            socket,
            address: address.to_string(),
        })
    }

    /// Send gauge metric
    fn send_gauge(&self, name: &str, value: f64, tags: &[String]) -> Result<()> {
        let metric = self.format_metric(name, value, "g", tags);
        self.send(&metric)
    }

    /// Send counter metric
    fn send_counter(&self, name: &str, value: u64, tags: &[String]) -> Result<()> {
        let metric = self.format_metric(name, value as f64, "c", tags);
        self.send(&metric)
    }

    /// Format metric in DogStatsD format
    fn format_metric(&self, name: &str, value: f64, metric_type: &str, tags: &[String]) -> String {
        if tags.is_empty() {
            format!("{}:{}|{}", name, value, metric_type)
        } else {
            format!("{}:{}|{}|#{}", name, value, metric_type, tags.join(","))
        }
    }

    /// Send raw metric string
    fn send(&self, metric: &str) -> Result<()> {
        if let Some(ref socket) = self.socket {
            socket.send_to(metric.as_bytes(), &self.address)
                .with_context(|| format!("Failed to send metric to {}", self.address))?;
            debug!("Sent metric: {}", metric);
            Ok(())
        } else {
            warn!("DogStatsD socket not available, skipping metric: {}", metric);
            Ok(())
        }
    }

    /// Push benchmark result to Datadog
    pub fn push_result(&self, result: &BenchmarkResult) -> Result<()> {
        let mut tags = vec![
            format!("proto:{}", result.proto),
            format!("overlay:{}", result.overlay),
            format!("scenario:{}", result.scenario_id),
            "env:bench".to_string(),
        ];

        if let Some(ref commit) = result.commit_sha {
            tags.push(format!("commit:{}", commit));
        }
        if let Some(ref branch) = result.branch {
            tags.push(format!("branch:{}", branch));
        }
        if let Some(ref env_hash) = result.env_hash {
            tags.push(format!("env_hash:{}", env_hash));
        }

        // Send latency metrics (microseconds)
        self.send_gauge("ygg.bench.latency.p50", result.latency_p50 as f64, &tags)?;
        self.send_gauge("ygg.bench.latency.p95", result.latency_p95 as f64, &tags)?;
        self.send_gauge("ygg.bench.latency.p99", result.latency_p99 as f64, &tags)?;
        self.send_gauge("ygg.bench.latency.mean", result.latency_mean, &tags)?;

        // Send throughput metrics
        self.send_gauge("ygg.bench.throughput.ops", result.throughput_ops, &tags)?;
        self.send_gauge("ygg.bench.throughput.mbps", result.throughput_mbps, &tags)?;

        // Send memory metrics (convert to MB)
        self.send_gauge("ygg.bench.rss.peak", result.rss_peak as f64 / 1_048_576.0, &tags)?;
        self.send_gauge("ygg.bench.rss.mean", result.rss_mean / 1_048_576.0, &tags)?;
        self.send_gauge("ygg.bench.rss.steady", result.rss_steady / 1_048_576.0, &tags)?;

        // Send operation counters
        self.send_counter("ygg.bench.operations.total", result.total_operations, &tags)?;
        self.send_counter("ygg.bench.bytes.total", result.total_bytes, &tags)?;

        Ok(())
    }

    /// Check if client is connected
    pub fn is_connected(&self) -> bool {
        self.socket.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_metric() {
        let client = DatadogClient::new("127.0.0.1:8125").unwrap();
        
        let metric = client.format_metric("test.metric", 42.5, "g", &[]);
        assert_eq!(metric, "test.metric:42.5|g");

        let tags = vec!["env:test".to_string(), "version:1".to_string()];
        let metric = client.format_metric("test.metric", 100.0, "c", &tags);
        assert_eq!(metric, "test.metric:100|c|#env:test,version:1");
    }

    #[test]
    fn test_client_creation() {
        let client = DatadogClient::new("127.0.0.1:8125").unwrap();
        // Socket creation may fail in test environment, but client should still be created
        assert_eq!(client.address, "127.0.0.1:8125");
    }
}
