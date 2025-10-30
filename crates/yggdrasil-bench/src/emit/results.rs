#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use anyhow::{Context, Result};

/// Benchmark result for a single scenario run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub scenario_name: String,
    pub scenario_id: String,
    pub proto: String,
    pub overlay: String,
    
    // Latency metrics (microseconds)
    pub latency_p50: u64,
    pub latency_p95: u64,
    pub latency_p99: u64,
    pub latency_mean: f64,
    pub latency_min: u64,
    pub latency_max: u64,
    
    // Throughput metrics
    pub throughput_ops: f64,
    pub throughput_mbps: f64,
    pub total_operations: u64,
    pub total_bytes: u64,
    
    // Memory metrics (bytes)
    pub rss_peak: u64,
    pub rss_mean: f64,
    pub rss_steady: f64,
    
    // Metadata
    pub duration_secs: f64,
    pub warmup_count: u64,
    pub sample_count: u64,
    pub concurrency: usize,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_hash: Option<String>,
    
    pub timestamp: String,
}

impl BenchmarkResult {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("Failed to serialize benchmark result to JSON")
    }

    pub fn to_json_compact(&self) -> Result<String> {
        serde_json::to_string(self)
            .context("Failed to serialize benchmark result to JSON")
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = self.to_json()?;
        fs::write(path.as_ref(), json)
            .with_context(|| format!("Failed to write result to {:?}", path.as_ref()))?;
        Ok(())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read result from {:?}", path.as_ref()))?;
        let result: BenchmarkResult = serde_json::from_str(&content)
            .context("Failed to parse benchmark result JSON")?;
        Ok(result)
    }
}

/// Collection of benchmark results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSuite {
    pub results: Vec<BenchmarkResult>,
    pub metadata: HashMap<String, String>,
}

impl BenchmarkSuite {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn add_result(&mut self, result: BenchmarkResult) {
        self.results.push(result);
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize benchmark suite to JSON")?;
        fs::write(path.as_ref(), json)
            .with_context(|| format!("Failed to write suite to {:?}", path.as_ref()))?;
        Ok(())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read suite from {:?}", path.as_ref()))?;
        let suite: BenchmarkSuite = serde_json::from_str(&content)
            .context("Failed to parse benchmark suite JSON")?;
        Ok(suite)
    }

    /// Generate markdown summary table
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# Benchmark Results\n\n");
        
        if !self.metadata.is_empty() {
            md.push_str("## Metadata\n\n");
            for (key, value) in &self.metadata {
                md.push_str(&format!("- **{}**: {}\n", key, value));
            }
            md.push_str("\n");
        }

        md.push_str("## Performance Summary\n\n");
        md.push_str("| Scenario | P50 (µs) | P95 (µs) | P99 (µs) | Throughput (Mbps) | Peak RSS (MB) |\n");
        md.push_str("|----------|----------|----------|----------|-------------------|---------------|\n");

        for result in &self.results {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {:.2} | {:.2} |\n",
                result.scenario_id,
                result.latency_p50,
                result.latency_p95,
                result.latency_p99,
                result.throughput_mbps,
                result.rss_peak as f64 / 1_048_576.0
            ));
        }

        md
    }

    /// Save markdown summary to file
    pub fn save_markdown<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let md = self.to_markdown();
        let mut file = fs::File::create(path.as_ref())
            .with_context(|| format!("Failed to create markdown file: {:?}", path.as_ref()))?;
        file.write_all(md.as_bytes())
            .context("Failed to write markdown content")?;
        Ok(())
    }
}

impl Default for BenchmarkSuite {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_result() -> BenchmarkResult {
        BenchmarkResult {
            scenario_name: "TCP over IPv6".to_string(),
            scenario_id: "tcp_ipv6".to_string(),
            proto: "tcp".to_string(),
            overlay: "ipv6".to_string(),
            latency_p50: 100,
            latency_p95: 200,
            latency_p99: 300,
            latency_mean: 120.5,
            latency_min: 50,
            latency_max: 400,
            throughput_ops: 10000.0,
            throughput_mbps: 82.0,
            total_operations: 100000,
            total_bytes: 102400000,
            rss_peak: 52428800,
            rss_mean: 50000000.0,
            rss_steady: 49000000.0,
            duration_secs: 10.0,
            warmup_count: 1000,
            sample_count: 100000,
            concurrency: 1,
            commit_sha: Some("abc123".to_string()),
            branch: Some("main".to_string()),
            env_hash: Some("env001".to_string()),
            timestamp: "2025-10-30T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_result_json_serialization() {
        let result = create_test_result();
        let json = result.to_json().unwrap();
        assert!(json.contains("tcp_ipv6"));
        assert!(json.contains("latency_p99"));
    }

    #[test]
    fn test_suite_markdown_generation() {
        let mut suite = BenchmarkSuite::new();
        suite.add_result(create_test_result());
        suite.metadata.insert("runner".to_string(), "test".to_string());

        let md = suite.to_markdown();
        assert!(md.contains("# Benchmark Results"));
        assert!(md.contains("tcp_ipv6"));
        assert!(md.contains("| 100 | 200 | 300 |"));
    }

    #[test]
    fn test_suite_add_results() {
        let mut suite = BenchmarkSuite::new();
        assert_eq!(suite.results.len(), 0);

        suite.add_result(create_test_result());
        assert_eq!(suite.results.len(), 1);
    }
}
