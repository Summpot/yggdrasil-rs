#![forbid(unsafe_code)]

use anyhow::Result;
use hdrhistogram::Histogram;
use std::time::{Duration, Instant};

/// High-resolution timer for latency measurements
#[derive(Debug, Clone)]
pub struct Timer {
    start: Instant,
}

impl Timer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn elapsed_micros(&self) -> u64 {
        self.elapsed().as_micros() as u64
    }

    pub fn reset(&mut self) {
        self.start = Instant::now();
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics collector for latency measurements
pub struct LatencyStats {
    histogram: Histogram<u64>,
    count: u64,
    sum_micros: u128,
}

impl LatencyStats {
    pub fn new() -> Result<Self> {
        // HDR Histogram with 3 significant digits, max 1 hour
        let histogram = Histogram::new_with_bounds(1, 3_600_000_000, 3)?;
        Ok(Self {
            histogram,
            count: 0,
            sum_micros: 0,
        })
    }

    pub fn record(&mut self, duration: Duration) -> Result<()> {
        let micros = duration.as_micros() as u64;
        self.histogram.record(micros)?;
        self.count += 1;
        self.sum_micros += duration.as_micros();
        Ok(())
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum_micros as f64 / self.count as f64
        }
    }

    pub fn p50(&self) -> u64 {
        self.histogram.value_at_percentile(50.0)
    }

    pub fn p95(&self) -> u64 {
        self.histogram.value_at_percentile(95.0)
    }

    pub fn p99(&self) -> u64 {
        self.histogram.value_at_percentile(99.0)
    }

    pub fn min(&self) -> u64 {
        self.histogram.min()
    }

    pub fn max(&self) -> u64 {
        self.histogram.max()
    }
}

impl Default for LatencyStats {
    fn default() -> Self {
        Self::new().expect("Failed to create LatencyStats")
    }
}

/// Throughput counter
pub struct ThroughputCounter {
    count: u64,
    bytes: u64,
    start: Instant,
}

impl ThroughputCounter {
    pub fn new() -> Self {
        Self {
            count: 0,
            bytes: 0,
            start: Instant::now(),
        }
    }

    pub fn record(&mut self, bytes: usize) {
        self.count += 1;
        self.bytes += bytes as u64;
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn duration(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn ops_per_sec(&self) -> f64 {
        let duration = self.duration().as_secs_f64();
        if duration == 0.0 {
            0.0
        } else {
            self.count as f64 / duration
        }
    }

    pub fn bytes_per_sec(&self) -> f64 {
        let duration = self.duration().as_secs_f64();
        if duration == 0.0 {
            0.0
        } else {
            self.bytes as f64 / duration
        }
    }

    pub fn megabits_per_sec(&self) -> f64 {
        self.bytes_per_sec() * 8.0 / 1_000_000.0
    }
}

impl Default for ThroughputCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_timer() {
        let timer = Timer::new();
        thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed();
        assert!(elapsed >= Duration::from_millis(10));
    }

    #[test]
    fn test_latency_stats() {
        let mut stats = LatencyStats::new().unwrap();

        for i in 1..=100 {
            stats.record(Duration::from_micros(i * 100)).unwrap();
        }

        assert_eq!(stats.count(), 100);
        assert!(stats.mean() > 0.0);
        assert!(stats.p50() > 0);
        assert!(stats.p95() > stats.p50());
        assert!(stats.p99() > stats.p95());
    }

    #[test]
    fn test_throughput_counter() {
        let mut counter = ThroughputCounter::new();

        for _ in 0..100 {
            counter.record(1024);
        }

        assert_eq!(counter.count(), 100);
        assert_eq!(counter.bytes(), 102400);
        assert!(counter.ops_per_sec() > 0.0);
        assert!(counter.bytes_per_sec() > 0.0);
    }
}
