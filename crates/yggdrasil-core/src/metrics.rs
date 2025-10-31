use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Metrics registry for Prometheus-compatible metrics
#[derive(Clone)]
pub struct MetricsRegistry {
    counters: Arc<RwLock<HashMap<String, u64>>>,
    gauges: Arc<RwLock<HashMap<String, i64>>>,
    histograms: Arc<RwLock<HashMap<String, Vec<f64>>>>,
}

impl MetricsRegistry {
    /// Create a new metrics registry
    pub fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            histograms: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Increment a counter
    pub async fn inc_counter(&self, name: &str, value: u64) {
        let mut counters = self.counters.write().await;
        *counters.entry(name.to_string()).or_insert(0) += value;
    }

    /// Set a gauge value
    pub async fn set_gauge(&self, name: &str, value: i64) {
        let mut gauges = self.gauges.write().await;
        gauges.insert(name.to_string(), value);
    }

    /// Record a histogram observation
    pub async fn observe_histogram(&self, name: &str, value: f64) {
        let mut histograms = self.histograms.write().await;
        histograms
            .entry(name.to_string())
            .or_insert_with(Vec::new)
            .push(value);
    }

    /// Export metrics in Prometheus text format
    pub async fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Export counters
        let counters = self.counters.read().await;
        for (name, value) in counters.iter() {
            output.push_str(&format!("# TYPE {} counter\n", name));
            output.push_str(&format!("{} {}\n", name, value));
        }

        // Export gauges
        let gauges = self.gauges.read().await;
        for (name, value) in gauges.iter() {
            output.push_str(&format!("# TYPE {} gauge\n", name));
            output.push_str(&format!("{} {}\n", name, value));
        }

        // Export histograms (simplified - just count and sum)
        let histograms = self.histograms.read().await;
        for (name, values) in histograms.iter() {
            let count = values.len();
            let sum: f64 = values.iter().sum();

            output.push_str(&format!("# TYPE {} histogram\n", name));
            output.push_str(&format!("{}_count {}\n", name, count));
            output.push_str(&format!("{}_sum {:.2}\n", name, sum));
        }

        output
    }

    /// Reset all metrics
    pub async fn reset(&self) {
        self.counters.write().await.clear();
        self.gauges.write().await.clear();
        self.histograms.write().await.clear();
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Yggdrasil network metrics
pub struct YggdrasilMetrics {
    registry: MetricsRegistry,
}

impl YggdrasilMetrics {
    /// Create a new Yggdrasil metrics collector
    pub fn new() -> Self {
        Self {
            registry: MetricsRegistry::new(),
        }
    }

    /// Get the underlying registry
    pub fn registry(&self) -> &MetricsRegistry {
        &self.registry
    }

    /// Record packet sent
    pub async fn record_packet_sent(&self, bytes: u64) {
        self.registry
            .inc_counter("yggdrasil_packets_sent_total", 1)
            .await;
        self.registry
            .inc_counter("yggdrasil_bytes_sent_total", bytes)
            .await;
    }

    /// Record packet received
    pub async fn record_packet_received(&self, bytes: u64) {
        self.registry
            .inc_counter("yggdrasil_packets_received_total", 1)
            .await;
        self.registry
            .inc_counter("yggdrasil_bytes_received_total", bytes)
            .await;
    }

    /// Set peer count
    pub async fn set_peer_count(&self, count: i64) {
        self.registry
            .set_gauge("yggdrasil_peers_connected", count)
            .await;
    }

    /// Set route count
    pub async fn set_route_count(&self, count: i64) {
        self.registry
            .set_gauge("yggdrasil_routing_entries", count)
            .await;
    }

    /// Set session count
    pub async fn set_session_count(&self, count: i64) {
        self.registry
            .set_gauge("yggdrasil_sessions_active", count)
            .await;
    }

    /// Record packet latency
    pub async fn record_latency(&self, latency_ms: f64) {
        self.registry
            .observe_histogram("yggdrasil_packet_latency_ms", latency_ms)
            .await;
    }

    /// Record session establishment time
    pub async fn record_session_establishment(&self, duration_ms: f64) {
        self.registry
            .observe_histogram("yggdrasil_session_establishment_ms", duration_ms)
            .await;
    }

    /// Set TUN device MTU
    pub async fn set_tun_mtu(&self, mtu: i64) {
        self.registry
            .set_gauge("yggdrasil_tun_mtu_bytes", mtu)
            .await;
    }

    /// Record dropped packet
    pub async fn record_dropped_packet(&self, reason: &str) {
        let metric_name = format!("yggdrasil_packets_dropped_total_reason_{}", reason);
        self.registry.inc_counter(&metric_name, 1).await;
    }

    /// Set spanning tree root distance
    pub async fn set_tree_root_distance(&self, distance: i64) {
        self.registry
            .set_gauge("yggdrasil_tree_root_distance", distance)
            .await;
    }

    /// Set lookup cache size
    pub async fn set_lookup_cache_size(&self, size: i64) {
        self.registry
            .set_gauge("yggdrasil_lookup_cache_entries", size)
            .await;
    }

    /// Export all metrics in Prometheus format
    pub async fn export(&self) -> String {
        self.registry.export_prometheus().await
    }
}

impl Default for YggdrasilMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP server for Prometheus metrics endpoint
#[cfg(feature = "metrics-server")]
pub async fn serve_metrics(bind_addr: &str, metrics: Arc<YggdrasilMetrics>) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(bind_addr).await?;
    log::info!("Metrics server listening on http://{}/metrics", bind_addr);

    loop {
        let (mut stream, _) = listener.accept().await?;
        let metrics_clone = Arc::clone(&metrics);

        tokio::spawn(async move {
            let mut buffer = vec![0u8; 1024];

            // Read HTTP request (simplified - just check for GET /metrics)
            if let Ok(n) = stream.read(&mut buffer).await {
                let request = String::from_utf8_lossy(&buffer[..n]);

                if request.contains("GET /metrics") {
                    // Export metrics
                    let metrics_text = metrics_clone.export().await;

                    // Send HTTP response
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                        metrics_text.len(),
                        metrics_text
                    );

                    let _ = stream.write_all(response.as_bytes()).await;
                } else {
                    // 404 Not Found
                    let response = "HTTP/1.1 404 Not Found\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_registry() {
        let registry = MetricsRegistry::new();

        registry.inc_counter("test_counter", 5).await;
        registry.set_gauge("test_gauge", 42).await;
        registry.observe_histogram("test_histogram", 1.5).await;
        registry.observe_histogram("test_histogram", 2.5).await;

        let output = registry.export_prometheus().await;

        assert!(output.contains("test_counter 5"));
        assert!(output.contains("test_gauge 42"));
        assert!(output.contains("test_histogram_count 2"));
        assert!(output.contains("test_histogram_sum 4.00"));
    }

    #[tokio::test]
    async fn test_yggdrasil_metrics() {
        let metrics = YggdrasilMetrics::new();

        metrics.record_packet_sent(100).await;
        metrics.record_packet_received(200).await;
        metrics.set_peer_count(5).await;
        metrics.set_route_count(10).await;

        let output = metrics.export().await;

        assert!(output.contains("yggdrasil_packets_sent_total 1"));
        assert!(output.contains("yggdrasil_bytes_sent_total 100"));
        assert!(output.contains("yggdrasil_packets_received_total 1"));
        assert!(output.contains("yggdrasil_bytes_received_total 200"));
        assert!(output.contains("yggdrasil_peers_connected 5"));
        assert!(output.contains("yggdrasil_routing_entries 10"));
    }
}
