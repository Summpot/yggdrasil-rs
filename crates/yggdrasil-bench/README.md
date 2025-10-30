# Yggdrasil Performance Benchmark System

A comprehensive performance regression detection system for the Yggdrasil network implementation.

## Overview

This benchmark system provides:
- **Automated performance tracking** across protocol × overlay combinations
- **Regression detection** with configurable thresholds
- **Datadog integration** for monitoring and alerting
- **GitHub Actions integration** for CI/CD pipelines
- **Baseline comparison** to detect performance changes

## Architecture

### Module Structure

```
yggdrasil-bench/
├── core/           # Timing, statistics, and metrics collection
│   └── timing.rs   # Timer, LatencyStats, ThroughputCounter
├── scenario/       # Benchmark scenario definitions
│   └── config.rs   # Protocol × Overlay matrix configuration
├── probe/          # Resource monitoring
│   └── memory.rs   # RSS memory sampling
└── emit/           # Results output
    ├── results.rs  # JSON serialization, markdown reports
    └── datadog.rs  # DogStatsD metric pushing
```

### Key Design Principles

1. **Single Executable**: All scenarios run through one binary with command-line parameters
2. **Isolated Measurements**: Internal timing only, no external instrumentation
3. **Fixed Resources**: CPU cores, memory, and network parameters are fixed per scenario
4. **Statistical Rigor**: HDR Histogram for latency, multiple repetitions for variance

## Usage

### Generate Configuration

```bash
# Generate full scenario matrix (5 protocols × 5 overlays = 25 scenarios)
cargo run -p yggdrasil-bench -- gen-config -o benchmarks.toml

# Generate lightweight matrix (for PR testing)
cargo run -p yggdrasil-bench -- gen-config -o benchmarks-light.toml --lightweight
```

### Run Benchmarks

```bash
# Run all scenarios with default config
cargo run --release -p yggdrasil-bench -- run --output results.json

# Run lightweight scenarios (faster, for PRs)
cargo run --release -p yggdrasil-bench -- run --lightweight --output results.json

# Run specific scenario only
cargo run --release -p yggdrasil-bench -- run --scenario tcp_ipv6 --output results.json

# Run with Datadog metrics push
cargo run --release -p yggdrasil-bench -- run \
  --push-datadog \
  --datadog-address "127.0.0.1:8125" \
  --commit "abc123" \
  --branch "main" \
  --env-hash "x86_64_8c_16g" \
  --output results.json
```

### Compare Results

```bash
# Compare current results against baseline
cargo run --release -p yggdrasil-bench -- compare \
  --current results.json \
  --baseline baseline.json \
  --output comparison.md \
  --warn-threshold 1.05 \
  --fail-threshold 1.10
```

### Generate Datadog Dashboard

```bash
# Generate dashboard JSON file
cargo run --release -p yggdrasil-bench -- gen-dashboard -o datadog-dashboard.json

# The output file can be imported directly to Datadog
# See the Complete Setup Guide section below for detailed instructions
```

## Complete Setup Guide

This section provides comprehensive setup instructions for GitHub repository configuration and Datadog integration.

### Table of Contents

- [GitHub Repository Setup](#github-repository-setup)
- [Datadog Setup](#datadog-setup)
- [Dashboard Import](#dashboard-import)
- [Testing the Integration](#testing-the-integration)
- [Troubleshooting](#troubleshooting)
- [Quick Start Checklist](#quick-start-checklist)

---

## GitHub Repository Setup

### 1. Enable GitHub Actions

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Actions** → **General**
3. Under "Actions permissions", select:
   - ✅ **Allow all actions and reusable workflows**
4. Under "Workflow permissions", select:
   - ✅ **Read and write permissions**
   - ✅ **Allow GitHub Actions to create and approve pull requests**
5. Click **Save**

### 2. Configure Repository Secrets

Secrets are used to store sensitive information like API keys.

#### Required Secrets for Datadog Integration

1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add the following secrets:

| Name | Value | Description |
|------|-------|-------------|
| `DD_API_KEY` | `your_datadog_api_key` | Datadog API key for metrics push |
| `DD_APP_KEY` | `your_datadog_app_key` | Datadog Application key for dashboard API |

**How to get your Datadog API Key:**
1. Log in to [Datadog](https://app.datadoghq.com/)
2. Go to **Organization Settings** → **API Keys**
3. Create a new API key or copy an existing one
4. Paste it as the secret value in GitHub

**How to get your Datadog Application Key:**
1. Go to **Organization Settings** → **Application Keys**
2. Create a new application key with a descriptive name (e.g., `yggdrasil-benchmarks`)
3. Copy the key and save it to GitHub Secrets

**Note:** If you don't add `DD_API_KEY`, benchmarks will still run but won't push metrics to Datadog. If you don't add `DD_APP_KEY`, the workflow won't automatically update the dashboard.

### 3. Enable Workflow

The workflow file is already created at `.github/workflows/benchmark.yml`. No additional action needed.

### 4. Configure Branch Protection (Recommended)

To prevent merging PRs with performance regressions:

1. Go to **Settings** → **Branches**
2. Add branch protection rule for `main` or `master`:
   - Branch name pattern: `main` (or `master`)
   - ✅ **Require status checks to pass before merging**
   - Search and select: **Run Performance Benchmarks**
   - ✅ **Require branches to be up to date before merging**
3. Click **Create** or **Save changes**

### 5. Configure Actions Permissions for Artifacts

1. Go to **Settings** → **Actions** → **General**
2. Scroll to **Artifact and log retention**
3. Set retention days:
   - Artifacts: **90 days** (for benchmark results)
   - Logs: **30 days** (default)
4. Click **Save**

---

## Datadog Setup

### 1. Create Datadog Account

If you don't have a Datadog account:

1. Sign up at [https://www.datadoghq.com/](https://www.datadoghq.com/)
2. Choose your Datadog site (e.g., US1, EU, US3)
3. Complete the setup wizard

### 2. Get API Keys

#### API Key (for metrics push)

1. Log in to [Datadog](https://app.datadoghq.com/)
2. Go to **Organization Settings** → **API Keys**
3. Click **New Key**
4. Name it: `yggdrasil-benchmarks`
5. Copy the key and save it to GitHub Secrets as `DD_API_KEY`

#### Application Key (for dashboard API)

1. Go to **Organization Settings** → **Application Keys**
2. Click **New Key**
3. Name it: `yggdrasil-benchmarks-api`
4. Copy the key and save it to GitHub Secrets as `DD_APP_KEY`

### 3. Generate Dashboard JSON

Run the benchmark tool to generate the dashboard configuration:

```bash
cargo run --release -p yggdrasil-bench -- gen-dashboard -o datadog-dashboard.json
```

This creates a `datadog-dashboard.json` file with a pre-configured dashboard.

### 4. Initial Dashboard Setup

The workflow will automatically create or update the dashboard on the first run. However, you can also manually import it:

#### Manual Import (Optional)

1. Go to [Datadog Dashboards](https://app.datadoghq.com/dashboard/lists)
2. Click **New Dashboard** (top right)
3. Give it a name: `Yggdrasil Performance Benchmarks`
4. Click the **settings icon (⚙️)** in the top right
5. Select **Import dashboard JSON**
6. Copy the content from `datadog-dashboard.json`
7. Paste it into the import dialog
8. Click **Save**
9. Note the dashboard ID from the URL (e.g., `https://app.datadoghq.com/dashboard/abc-def-ghi`)

### 5. Configure Dashboard Template Variables

After importing, the dashboard will have template variables:

- **proto**: Filter by protocol (tcp, tls, quic, ws, wss)
- **overlay**: Filter by overlay type (ipv4, ipv6, udp, tcp, quic)
- **branch**: Filter by git branch (main, master)

These are automatically populated from your benchmark metrics.

### 6. Set Up Alerts (Optional)

Create monitors to get notified of performance regressions:

#### P99 Latency Monitor

1. Go to **Monitors** → **New Monitor**
2. Select **Metric**
3. Choose metric: `ygg.bench.latency.p99`
4. Set alert conditions:
   ```
   Alert threshold: > 10% increase from previous week
   Warning threshold: > 5% increase from previous week
   ```
5. Configure notifications (email, Slack, PagerDuty)
6. Name: `Yggdrasil P99 Latency Regression`
7. Click **Save**

#### Throughput Monitor

1. Go to **Monitors** → **New Monitor**
2. Select **Metric**
3. Choose metric: `ygg.bench.throughput.mbps`
4. Set alert conditions:
   ```
   Alert threshold: < 10% decrease from previous week
   Warning threshold: < 5% decrease from previous week
   ```
5. Configure notifications
6. Name: `Yggdrasil Throughput Degradation`
7. Click **Save**

---

## Dashboard Import

### Dashboard Features

The generated dashboard includes:

**Widgets:**
1. **Overview Note** - Introduction and guide
2. **P99 Latency by Protocol** - Line chart comparing protocols
3. **P99 Latency by Overlay** - Line chart comparing overlays
4. **P95 Latency Trends** - All scenarios over time
5. **Throughput by Protocol** - Mbps comparison
6. **Throughput by Overlay** - Overlay performance
7. **P99 Latency Matrix** - Table view (Protocol × Overlay)
8. **Throughput Matrix** - Table view (Protocol × Overlay)
9. **Peak RSS Memory** - Memory usage trends
10. **Mean Latency** - Average latency comparison
11. **Operations per Second** - Request rate metrics
12. **Regression Note** - Threshold reference

**Template Variables:**
- `$proto` - Filter by protocol
- `$overlay` - Filter by overlay type
- `$branch` - Filter by git branch

### Customizing the Dashboard

Edit the dashboard after import:

1. Click **Edit** (top right)
2. Add/remove widgets as needed
3. Adjust time ranges
4. Change color schemes
5. Add custom queries
6. Click **Save**

### Dashboard URL

After creating, bookmark the dashboard URL:
```
https://app.datadoghq.com/dashboard/<dashboard-id>
```

Share this with your team for easy access.

---

## Testing the Integration

### 1. Test Local Benchmark

Run a single scenario to verify the tool works:

```bash
cargo run --release -p yggdrasil-bench -- run \
  --scenario tcp_ipv6 \
  --output test-results.json
```

Expected output:
```
[INFO] Loading benchmark scenarios...
[INFO] Running scenario: tcp over ipv6
[INFO] Warmup phase: 1000 iterations
[INFO] Sampling phase: 30 seconds
[INFO] Scenario tcp_ipv6 completed: p99=XXXµs, throughput=XX.XX Mbps
[INFO] Benchmark complete!
```

### 2. Test Datadog Connection

Start a local DogStatsD agent:

```bash
docker run -d --name dd-agent \
  -e DD_API_KEY=your_api_key \
  -e DD_SITE=datadoghq.com \
  -e DD_DOGSTATSD_NON_LOCAL_TRAFFIC=true \
  -p 8125:8125/udp \
  gcr.io/datadoghq/agent:latest
```

Run benchmark with Datadog push:

```bash
cargo run --release -p yggdrasil-bench -- run \
  --scenario tcp_ipv6 \
  --push-datadog \
  --datadog-address "127.0.0.1:8125"
```

Check Datadog Metrics Explorer after 1-2 minutes:
1. Go to **Metrics** → **Explorer**
2. Search for: `ygg.bench.latency.p99`
3. You should see data points appearing

### 3. Test GitHub Actions Workflow

#### Trigger Workflow Manually

1. Go to **Actions** tab in your repository
2. Select **Performance Benchmarks** workflow
3. Click **Run workflow** (right side)
4. Select branch and mode (full or lightweight)
5. Click **Run workflow**
6. Wait for completion (~5-10 minutes for lightweight, ~30-60 minutes for full)

#### Trigger via Pull Request

1. Create a test branch: `git checkout -b test-benchmarks`
2. Make a small change: `echo "# Test" >> README.md`
3. Commit and push:
   ```bash
   git add README.md
   git commit -m "Test benchmark workflow"
   git push origin test-benchmarks
   ```
4. Create a Pull Request
5. GitHub Actions will automatically run lightweight benchmarks
6. Check the PR for a comment with comparison results

### 4. Verify Dashboard Data

After running benchmarks with `--push-datadog`:

1. Go to your Datadog dashboard
2. Select template variables (e.g., `proto:tcp`, `overlay:ipv6`)
3. Verify charts show data
4. Check that metrics update over time

---

## Troubleshooting

### GitHub Actions Issues

#### Workflow Not Running

**Problem:** Workflow doesn't trigger on PR or push

**Solution:**
1. Check **Settings** → **Actions** → **General**
2. Ensure "Allow all actions" is selected
3. Verify workflow file exists: `.github/workflows/benchmark.yml`
4. Check branch protection rules aren't blocking

#### Missing Secrets

**Problem:** Workflow fails with "DD_API_KEY not found" or "DD_APP_KEY not found"

**Solution:**
1. Verify secrets are added in **Settings** → **Secrets and variables** → **Actions**
2. Secret names must be exactly: `DD_API_KEY` and `DD_APP_KEY`
3. Re-run workflow after adding secrets

#### Artifact Download Failed

**Problem:** Baseline artifact not found in PR

**Solution:**
1. Run workflow on `main` branch first to create baseline
2. Ensure artifact retention is set to 30+ days
3. Check that `env_hash` matches between runs

#### Dashboard Update Failed

**Problem:** Workflow fails to update Datadog dashboard

**Solution:**
1. Verify both `DD_API_KEY` and `DD_APP_KEY` are set
2. Check application key has sufficient permissions
3. Verify Datadog site URL is correct (datadoghq.com, datadoghq.eu, etc.)
4. Check workflow logs for specific API error messages

### Datadog Issues

#### No Metrics Appearing

**Problem:** Metrics not showing in Datadog after push

**Solution:**
1. Verify DogStatsD agent is running: `docker ps | grep dd-agent`
2. Check agent logs: `docker logs dd-agent`
3. Verify API key is correct
4. Metrics may take 1-2 minutes to appear
5. Check metric names: `ygg.bench.*`

#### Dashboard Empty

**Problem:** Dashboard shows no data

**Solution:**
1. Verify metrics have been pushed
2. Check template variable filters (set to `*` to see all)
3. Adjust time range (top right) to include recent data
4. Verify metric names in dashboard match pushed metrics

#### Wrong Datadog Site

**Problem:** API key works locally but not in GitHub Actions

**Solution:**
1. Check your Datadog site: US1, EU, US3, etc.
2. Update workflow if needed:
   ```yaml
   -e DD_SITE=datadoghq.eu  # For EU site
   -e DD_SITE=us3.datadoghq.com  # For US3 site
   ```

### Benchmark Issues

#### Build Failures

**Problem:** `cargo build` fails

**Solution:**
```bash
cargo clean
cargo build --workspace
```

#### Test Timeouts

**Problem:** Benchmark takes too long

**Solution:**
1. Use `--lightweight` flag for faster runs
2. Reduce `sample_duration_secs` in config
3. Run single scenario: `--scenario tcp_ipv6`

#### Memory Monitoring Returns Zero

**Problem:** RSS metrics are all zero

**Solution:**
- Memory monitoring requires Linux
- On macOS/Windows, metrics will be zero (non-blocking)
- Run benchmarks on Linux for memory data

### Network Issues

#### DogStatsD Connection Refused

**Problem:** Cannot connect to 127.0.0.1:8125

**Solution:**
```bash
# Check if agent is running
docker ps | grep dd-agent

# Check port binding
netstat -tulpn | grep 8125

# Restart agent
docker restart dd-agent
```

---

## Quick Start Checklist

Use this checklist to ensure everything is configured:

### GitHub
- [ ] GitHub Actions enabled
- [ ] Repository secrets added (`DD_API_KEY` and `DD_APP_KEY`)
- [ ] Workflow file exists (`.github/workflows/benchmark.yml`)
- [ ] Branch protection configured (optional)
- [ ] Artifact retention set to 90 days

### Datadog
- [ ] Datadog account created
- [ ] API key generated and saved to GitHub
- [ ] Application key generated and saved to GitHub
- [ ] Dashboard JSON generated (`gen-dashboard` command)
- [ ] Workflow successfully updates dashboard
- [ ] Template variables working
- [ ] Metrics appearing in Explorer

### Testing
- [ ] Local benchmark runs successfully
- [ ] DogStatsD agent running (for local tests)
- [ ] Metrics pushed to Datadog successfully
- [ ] GitHub Actions workflow runs on PR
- [ ] Dashboard shows live data
- [ ] PR comments appear with comparison

### Monitoring (Optional)
- [ ] Latency alert configured
- [ ] Throughput alert configured
- [ ] Team notification channels set up
- [ ] Dashboard bookmarked/shared

---

## Configuration Examples

### Full Setup for New Repository

```bash
# 1. Generate dashboard
cargo run --release -p yggdrasil-bench -- gen-dashboard -o dashboard.json

# 2. Generate lightweight config for PR testing
cargo run --release -p yggdrasil-bench -- gen-config --lightweight -o benchmarks-pr.toml

# 3. Run initial baseline
cargo run --release -p yggdrasil-bench -- run \
  --push-datadog \
  --commit $(git rev-parse HEAD) \
  --branch $(git branch --show-current)

# 4. Add DD_API_KEY and DD_APP_KEY to GitHub secrets

# 5. Push to main - workflow will run automatically and create dashboard
```

### Team Dashboard Access

Share these URLs with your team:

```
Dashboard: https://app.datadoghq.com/dashboard/<dashboard-id>
Metrics Explorer: https://app.datadoghq.com/metric/explorer?q=ygg.bench.*
Workflow Runs: https://github.com/<org>/<repo>/actions/workflows/benchmark.yml
```

## Scenarios

### Protocol Types

- **tcp**: Standard TCP connections
- **tls**: TLS-encrypted TCP connections
- **quic**: QUIC protocol (UDP-based, multiplexed)
- **ws**: WebSocket connections (HTTP upgrade)
- **wss**: WebSocket Secure (TLS-encrypted WebSocket)

### Overlay Types

- **ipv4**: IPv4 encapsulation
- **ipv6**: IPv6 encapsulation (native Yggdrasil)
- **udp**: UDP encapsulation
- **tcp**: TCP encapsulation
- **quic**: QUIC encapsulation

### Scenario Configuration

Each scenario defines:

```toml
[[scenarios]]
name = "TCP over IPv6"
proto = "tcp"
overlay = "ipv6"
packet_size = 1024          # Bytes per packet
warmup_count = 1000         # Iterations before measurement
sample_duration_secs = 30   # Measurement window
concurrency = 1             # Concurrent operations
repeat = 5                  # Repetitions for variance
```

## Metrics

### Latency Metrics

- **P50**: Median latency (microseconds)
- **P95**: 95th percentile latency
- **P99**: 99th percentile latency
- **Mean**: Average latency
- **Min/Max**: Minimum and maximum observed

### Throughput Metrics

- **ops_per_sec**: Operations per second
- **throughput_mbps**: Megabits per second
- **total_operations**: Total operations completed
- **total_bytes**: Total bytes transferred

### Memory Metrics

- **rss_peak**: Peak Resident Set Size (bytes)
- **rss_mean**: Average RSS during sampling
- **rss_steady**: Steady-state RSS (last 50% of samples)

## Datadog Integration

### Metric Names

```
ygg.bench.latency.p50       # 50th percentile latency (µs)
ygg.bench.latency.p95       # 95th percentile latency (µs)
ygg.bench.latency.p99       # 99th percentile latency (µs)
ygg.bench.latency.mean      # Mean latency (µs)
ygg.bench.throughput.ops    # Operations per second
ygg.bench.throughput.mbps   # Megabits per second
ygg.bench.rss.peak          # Peak RSS (MB)
ygg.bench.rss.mean          # Mean RSS (MB)
ygg.bench.rss.steady        # Steady-state RSS (MB)
ygg.bench.operations.total  # Total operations (counter)
ygg.bench.bytes.total       # Total bytes (counter)
```

### Tags

All metrics include these tags:

- `proto:<tcp|tls|quic|ws|wss>`
- `overlay:<ipv4|ipv6|udp|tcp|quic>`
- `scenario:<proto>_<overlay>`
- `commit:<sha>`
- `branch:<branch_name>`
- `env:bench`
- `env_hash:<cpu_mem_signature>`

### DogStatsD Setup

```bash
# Start Datadog Agent with DogStatsD
docker run -d --name dd-agent \
  -e DD_API_KEY=<your_api_key> \
  -e DD_SITE=datadoghq.com \
  -e DD_DOGSTATSD_NON_LOCAL_TRAFFIC=true \
  -p 8125:8125/udp \
  gcr.io/datadoghq/agent:latest
```

## GitHub Actions Workflow

### Trigger Modes

1. **Pull Request**: Lightweight benchmarks, comparison with baseline
2. **Main Branch Push**: Full benchmarks with Datadog metrics
3. **Daily Cron**: Full benchmarks at 2 AM UTC
4. **Manual Dispatch**: Configurable mode selection

### Environment Setup

The workflow automatically:
- Sets CPU governor to performance mode
- Generates environment hash for consistent baseline matching
- Caches Rust dependencies
- Downloads baseline results (PR only)
- Starts Datadog Agent (main/cron only)

### Regression Detection

Thresholds:
- **Warning**: ≥5% performance degradation
- **Failure**: ≥10% performance degradation

For latency (lower is better):
- `current / baseline >= 1.05` → Warning
- `current / baseline >= 1.10` → Failure

For throughput (higher is better):
- `current / baseline <= 0.95` → Warning
- `current / baseline <= 0.90` → Failure

### Artifacts

- **benchmark-results-{sha}**: Current run results (90 day retention)
- **benchmark-baseline-{env_hash}**: Baseline for comparison (30 day retention)

## Implementation Notes

### Current State

The benchmark system includes:
- ✅ Complete infrastructure (timing, scenarios, probes, outputs)
- ✅ Statistical analysis (HDR Histogram with p50/p95/p99)
- ✅ Memory monitoring (RSS sampling via /proc/self/statm)
- ✅ Datadog integration (DogStatsD UDP push)
- ✅ GitHub Actions workflow (PR/main/cron triggers)
- ✅ Regression detection (configurable thresholds)
- ✅ Markdown report generation

### Simulation Mode

**Current**: Benchmarks use `simulate_operation()` placeholder

**TODO**: Replace with actual Yggdrasil network operations:
```rust
// Replace in run_single_scenario()
async fn simulate_operation(packet_size: usize) {
    // TODO: Actual implementation
    // 1. Create Yggdrasil nodes (sender + receiver)
    // 2. Establish connection via specified protocol
    // 3. Send packet through network stack
    // 4. Wait for response/acknowledgment
    // 5. Measure end-to-end latency
}
```

Integration points:
- Use `yggdrasil-core::Core` for node setup
- Use `yggdrasil-core::link::LinkManager` for connections
- Use `yggdrasil-core::session::SessionManager` for encryption
- Leverage existing protocol handlers (TCP/TLS/QUIC/WS/WSS)

## Performance Tuning

### CPU Isolation

```bash
# Set CPU governor to performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Pin to specific cores (optional)
taskset -c 0-3 cargo run --release -p yggdrasil-bench -- run
```

### Memory Tuning

```bash
# Clear system cache before benchmarks
sync
echo 3 | sudo tee /proc/sys/vm/drop_caches
```

### Timing Precision

- Uses `std::time::Instant` for high-resolution timing
- HDR Histogram with 3 significant digits (1µs to 1 hour range)
- Warmup phase discards initial JIT/cache effects
- Multiple repetitions reduce noise

## Troubleshooting

### Build Errors

```bash
# Clean and rebuild
cargo clean
cargo build --release -p yggdrasil-bench
```

### Memory Monitoring Not Working

Memory monitoring requires Linux. On other platforms, it returns zero values with a warning.

### Datadog Connection Failed

Ensure DogStatsD is listening:
```bash
nc -u -v 127.0.0.1 8125
```

Check Datadog Agent logs:
```bash
docker logs dd-agent
```

### No Baseline for Comparison

First run on a branch won't have a baseline. The workflow gracefully handles this case.

## Examples

### Quick Test

```bash
# Run single scenario quickly
cargo run --release -p yggdrasil-bench -- run \
  --scenario tcp_ipv6 \
  --output test-results.json
```

### Full Benchmark Suite

```bash
# Run complete matrix with Datadog
cargo run --release -p yggdrasil-bench -- run \
  --config benchmarks.toml \
  --push-datadog \
  --commit $(git rev-parse HEAD) \
  --branch $(git branch --show-current) \
  --output results-$(date +%Y%m%d).json
```

### Local Comparison

```bash
# Compare two runs
cargo run --release -p yggdrasil-bench -- compare \
  --current results-new.json \
  --baseline results-old.json \
  --output report.md
```

## Future Enhancements

1. **Network Integration**: Connect to actual Yggdrasil nodes
2. **Multi-Node Scenarios**: Test with multiple hops
3. **Packet Loss Simulation**: Test under adverse conditions
4. **Concurrency Testing**: Multiple simultaneous operations
5. **Long-Running Tests**: Stability over 24+ hours
6. **Cross-Platform**: macOS and Windows support for memory monitoring
7. **Grafana Dashboard**: Pre-built Datadog dashboard template

## Contributing

When adding new scenarios or metrics:

1. Update `scenario/config.rs` for new scenario types
2. Add metrics to `emit/datadog.rs` if needed
3. Update this documentation
4. Run tests: `cargo test -p yggdrasil-bench`
5. Verify GitHub Actions workflow runs successfully

## License

Same as parent Yggdrasil project.
