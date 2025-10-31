#![forbid(unsafe_code)]

mod core;
mod emit;
mod probe;
mod scenario;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::{info, warn};
use std::time::Duration;

use crate::core::{LatencyStats, ThroughputCounter, Timer};
use crate::emit::{save_dashboard_json, BenchmarkResult, BenchmarkSuite, DatadogClient};
use crate::probe::MemoryProbe;
use crate::scenario::{Scenario, ScenarioConfig};

#[derive(Parser)]
#[command(name = "yggdrasil-bench")]
#[command(about = "Performance benchmark tool for Yggdrasil network")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run benchmark scenarios
    Run {
        /// Path to scenario configuration file
        #[arg(short, long)]
        config: Option<String>,

        /// Use lightweight scenario matrix (for PR testing)
        #[arg(long)]
        lightweight: bool,

        /// Specific scenario ID to run (e.g., "tcp_ipv6")
        #[arg(short, long)]
        scenario: Option<String>,

        /// Output file for results (JSON)
        #[arg(short, long, default_value = "results.json")]
        output: String,

        /// Push results to Datadog
        #[arg(long)]
        push_datadog: bool,

        /// DogStatsD address
        #[arg(long, default_value = "127.0.0.1:8125")]
        datadog_address: String,

        /// Git commit SHA
        #[arg(long)]
        commit: Option<String>,

        /// Git branch name
        #[arg(long)]
        branch: Option<String>,

        /// Environment hash (for identifying runner/config)
        #[arg(long)]
        env_hash: Option<String>,
    },

    /// Generate default scenario configuration
    GenConfig {
        /// Output file path
        #[arg(short, long, default_value = "benchmarks.toml")]
        output: String,

        /// Generate lightweight config
        #[arg(long)]
        lightweight: bool,
    },

    /// Compare results with baseline
    Compare {
        /// Current results file
        #[arg(short, long)]
        current: String,

        /// Baseline results file
        #[arg(short, long)]
        baseline: String,

        /// Output markdown file
        #[arg(short, long)]
        output: Option<String>,

        /// Warning threshold (e.g., 1.05 for 5% regression)
        #[arg(long, default_value = "1.05")]
        warn_threshold: f64,

        /// Fail threshold (e.g., 1.10 for 10% regression)
        #[arg(long, default_value = "1.10")]
        fail_threshold: f64,
    },

    /// Generate Datadog dashboard JSON
    GenDashboard {
        /// Output file path
        #[arg(short, long, default_value = "datadog-dashboard.json")]
        output: String,
    },

    /// Create or update Datadog dashboard using API
    UpdateDashboard {
        /// Dashboard title
        #[arg(long, default_value = "Yggdrasil Performance Benchmarks")]
        title: String,

        /// Datadog API key (or use DD_API_KEY env var)
        #[arg(long)]
        api_key: Option<String>,

        /// Datadog Application key (or use DD_APP_KEY env var)
        #[arg(long)]
        app_key: Option<String>,

        /// Datadog site (or use DD_SITE env var, default: datadoghq.com)
        #[arg(long)]
        site: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config,
            lightweight,
            scenario,
            output,
            push_datadog,
            datadog_address,
            commit,
            branch,
            env_hash,
        } => {
            run_benchmarks(
                config,
                lightweight,
                scenario,
                output,
                push_datadog,
                datadog_address,
                commit,
                branch,
                env_hash,
            )
            .await?;
        }
        Commands::GenConfig {
            output,
            lightweight,
        } => {
            generate_config(output, lightweight)?;
        }
        Commands::Compare {
            current,
            baseline,
            output,
            warn_threshold,
            fail_threshold,
        } => {
            compare_results(current, baseline, output, warn_threshold, fail_threshold)?;
        }
        Commands::GenDashboard { output } => {
            generate_dashboard(output)?;
        }
        Commands::UpdateDashboard {
            title,
            api_key,
            app_key,
            site,
        } => {
            update_dashboard(title, api_key, app_key, site).await?;
        }
    }

    Ok(())
}

async fn run_benchmarks(
    config_path: Option<String>,
    lightweight: bool,
    scenario_filter: Option<String>,
    output_path: String,
    push_datadog: bool,
    datadog_address: String,
    commit: Option<String>,
    branch: Option<String>,
    env_hash: Option<String>,
) -> Result<()> {
    info!("Loading benchmark scenarios...");

    let config = if let Some(path) = config_path {
        ScenarioConfig::from_file(path)?
    } else if lightweight {
        ScenarioConfig::lightweight_matrix()
    } else {
        ScenarioConfig::default_matrix()
    };

    info!("Loaded {} scenarios", config.scenario_count());

    let scenarios: Vec<_> = if let Some(filter) = scenario_filter {
        config
            .scenarios
            .into_iter()
            .filter(|s| s.id() == filter)
            .collect()
    } else {
        config.scenarios
    };

    if scenarios.is_empty() {
        anyhow::bail!("No scenarios to run");
    }

    info!("Running {} scenarios", scenarios.len());

    let mut suite = BenchmarkSuite::new();
    if let Some(ref c) = commit {
        suite.metadata.insert("commit".to_string(), c.clone());
    }
    if let Some(ref b) = branch {
        suite.metadata.insert("branch".to_string(), b.clone());
    }
    if let Some(ref h) = env_hash {
        suite.metadata.insert("env_hash".to_string(), h.clone());
    }

    let datadog = if push_datadog {
        Some(DatadogClient::new(&datadog_address)?)
    } else {
        None
    };

    for scenario in scenarios {
        info!("Running scenario: {}", scenario.name);

        let result =
            run_single_scenario(&scenario, commit.clone(), branch.clone(), env_hash.clone())
                .await?;

        info!(
            "Scenario {} completed: p99={}µs, throughput={:.2} Mbps",
            scenario.id(),
            result.latency_p99,
            result.throughput_mbps
        );

        if let Some(ref dd) = datadog {
            if let Err(e) = dd.push_result(&result) {
                warn!("Failed to push metrics to Datadog: {}", e);
            } else {
                info!("Pushed metrics to Datadog");
            }
        }

        suite.add_result(result);
    }

    info!("Saving results to {}", output_path);
    suite.save_to_file(&output_path)?;

    info!("Benchmark complete!");
    println!("\n{}", suite.to_markdown());

    Ok(())
}

async fn run_single_scenario(
    scenario: &Scenario,
    commit: Option<String>,
    branch: Option<String>,
    env_hash: Option<String>,
) -> Result<BenchmarkResult> {
    info!("  Warmup phase: {} iterations", scenario.warmup_count);

    // Warmup phase
    for _ in 0..scenario.warmup_count {
        simulate_operation(scenario.packet_size).await;
    }

    info!(
        "  Sampling phase: {} seconds",
        scenario.sample_duration_secs
    );

    // Start memory probe
    let mut memory_probe = MemoryProbe::spawn(Duration::from_millis(100));

    // Sampling phase
    let mut latency_stats = LatencyStats::new()?;
    let mut throughput_counter = ThroughputCounter::new();

    let start = std::time::Instant::now();
    let duration = Duration::from_secs(scenario.sample_duration_secs);

    while start.elapsed() < duration {
        let timer = Timer::new();

        simulate_operation(scenario.packet_size).await;

        let elapsed = timer.elapsed();
        latency_stats.record(elapsed)?;
        throughput_counter.record(scenario.packet_size);
    }

    // Collect memory samples
    memory_probe.collect().await;

    let timestamp = chrono::Utc::now().to_rfc3339();

    Ok(BenchmarkResult {
        scenario_name: scenario.name.clone(),
        scenario_id: scenario.id(),
        proto: scenario.proto.to_string(),
        overlay: scenario.overlay.to_string(),
        latency_p50: latency_stats.p50(),
        latency_p95: latency_stats.p95(),
        latency_p99: latency_stats.p99(),
        latency_mean: latency_stats.mean(),
        latency_min: latency_stats.min(),
        latency_max: latency_stats.max(),
        throughput_ops: throughput_counter.ops_per_sec(),
        throughput_mbps: throughput_counter.megabits_per_sec(),
        total_operations: throughput_counter.count(),
        total_bytes: throughput_counter.bytes(),
        rss_peak: memory_probe.peak_rss(),
        rss_mean: memory_probe.mean_rss(),
        rss_steady: memory_probe.steady_state_rss(),
        duration_secs: throughput_counter.duration().as_secs_f64(),
        warmup_count: scenario.warmup_count,
        sample_count: latency_stats.count(),
        concurrency: scenario.concurrency,
        commit_sha: commit,
        branch,
        env_hash,
        timestamp,
    })
}

/// Simulate a network operation
/// TODO: Replace with actual Yggdrasil network operations
async fn simulate_operation(packet_size: usize) {
    // Simulate network latency
    tokio::time::sleep(Duration::from_micros(100)).await;

    // Simulate packet processing
    let _data = vec![0u8; packet_size];
    tokio::task::yield_now().await;
}

fn generate_config(output: String, lightweight: bool) -> Result<()> {
    info!(
        "Generating {} configuration...",
        if lightweight {
            "lightweight"
        } else {
            "default"
        }
    );

    let config = if lightweight {
        ScenarioConfig::lightweight_matrix()
    } else {
        ScenarioConfig::default_matrix()
    };

    let toml_str =
        toml::to_string_pretty(&config).context("Failed to serialize configuration to TOML")?;

    std::fs::write(&output, toml_str)
        .with_context(|| format!("Failed to write configuration to {}", output))?;

    info!(
        "Generated configuration with {} scenarios: {}",
        config.scenario_count(),
        output
    );
    Ok(())
}

fn compare_results(
    current_path: String,
    baseline_path: String,
    output_path: Option<String>,
    warn_threshold: f64,
    fail_threshold: f64,
) -> Result<()> {
    info!("Loading current results from {}", current_path);
    let current = BenchmarkSuite::from_file(current_path)?;

    info!("Loading baseline results from {}", baseline_path);
    let baseline = BenchmarkSuite::from_file(baseline_path)?;

    info!("Comparing {} results", current.results.len());

    let mut markdown = String::new();
    markdown.push_str("# Benchmark Comparison\n\n");
    markdown.push_str("## Regression Analysis\n\n");
    markdown.push_str("| Scenario | Metric | Current | Baseline | Change | Status |\n");
    markdown.push_str("|----------|--------|---------|----------|--------|--------|\n");

    let mut has_failures = false;
    let mut has_warnings = false;

    for current_result in &current.results {
        if let Some(baseline_result) = baseline
            .results
            .iter()
            .find(|r| r.scenario_id == current_result.scenario_id)
        {
            // Compare P99 latency (lower is better)
            let p99_ratio = current_result.latency_p99 as f64 / baseline_result.latency_p99 as f64;
            let p99_status = if p99_ratio >= fail_threshold {
                has_failures = true;
                "❌ FAIL"
            } else if p99_ratio >= warn_threshold {
                has_warnings = true;
                "⚠️  WARN"
            } else {
                "✅ PASS"
            };
            let p99_change = (p99_ratio - 1.0) * 100.0;

            markdown.push_str(&format!(
                "| {} | P99 Latency | {}µs | {}µs | {:+.1}% | {} |\n",
                current_result.scenario_id,
                current_result.latency_p99,
                baseline_result.latency_p99,
                p99_change,
                p99_status
            ));

            // Compare throughput (higher is better)
            let tp_ratio = current_result.throughput_mbps / baseline_result.throughput_mbps;
            let tp_status = if tp_ratio <= (2.0 - fail_threshold) {
                has_failures = true;
                "❌ FAIL"
            } else if tp_ratio <= (2.0 - warn_threshold) {
                has_warnings = true;
                "⚠️  WARN"
            } else {
                "✅ PASS"
            };
            let tp_change = (tp_ratio - 1.0) * 100.0;

            markdown.push_str(&format!(
                "| {} | Throughput | {:.2} Mbps | {:.2} Mbps | {:+.1}% | {} |\n",
                current_result.scenario_id,
                current_result.throughput_mbps,
                baseline_result.throughput_mbps,
                tp_change,
                tp_status
            ));
        }
    }

    markdown.push_str("\n## Summary\n\n");
    if has_failures {
        markdown
            .push_str("❌ **FAILED**: Performance regressions detected beyond failure threshold\n");
    } else if has_warnings {
        markdown.push_str("⚠️  **WARNING**: Performance regressions detected\n");
    } else {
        markdown.push_str("✅ **PASSED**: No significant performance regressions\n");
    }

    println!("{}", markdown);

    if let Some(output) = output_path {
        std::fs::write(&output, &markdown)
            .with_context(|| format!("Failed to write comparison to {}", output))?;
        info!("Saved comparison to {}", output);
    }

    if has_failures {
        anyhow::bail!("Performance regression tests failed");
    }

    Ok(())
}

fn generate_dashboard(output: String) -> Result<()> {
    info!("Generating Datadog dashboard JSON...");

    save_dashboard_json(&output)
        .with_context(|| format!("Failed to save dashboard JSON to {}", output))?;

    info!("Generated Datadog dashboard JSON: {}", output);
    println!("\n✅ Dashboard JSON saved to: {}", output);
    println!("\n📊 To import to Datadog:");
    println!("   1. Go to Datadog Dashboards: https://app.datadoghq.com/dashboard/lists");
    println!("   2. Click 'New Dashboard'");
    println!("   3. Click the settings icon (⚙️) → 'Import dashboard JSON'");
    println!("   4. Paste the contents of {}", output);
    println!("   5. Click 'Save'\n");

    Ok(())
}

async fn update_dashboard(
    title: String,
    api_key: Option<String>,
    app_key: Option<String>,
    site: Option<String>,
) -> Result<()> {
    use datadog_api_client::datadog;
    use datadog_api_client::datadog::APIKey;
    use datadog_api_client::datadogV1::api_dashboards::{
        DashboardsAPI, ListDashboardsOptionalParams,
    };

    // Get API keys and site from arguments or environment variables
    let api_key_str = api_key
        .or_else(|| std::env::var("DD_API_KEY").ok())
        .context("DD_API_KEY not provided (use --api-key or DD_API_KEY env var)")?;
    let app_key_str = app_key
        .or_else(|| std::env::var("DD_APP_KEY").ok())
        .context("DD_APP_KEY not provided (use --app-key or DD_APP_KEY env var)")?;
    let site_str = site
        .or_else(|| std::env::var("DD_SITE").ok())
        .unwrap_or_else(|| "datadoghq.com".to_string());

    info!("Configuring Datadog API client for site: {}", site_str);

    // Configure Datadog client
    let mut config = datadog::Configuration::new();
    config.set_auth_key(
        "apiKeyAuth",
        APIKey {
            key: api_key_str,
            prefix: String::new(),
        },
    );
    config.set_auth_key(
        "appKeyAuth",
        APIKey {
            key: app_key_str,
            prefix: String::new(),
        },
    );
    // Note: base_path cannot be changed in this version, uses default datadoghq.com

    let api = DashboardsAPI::with_config(config);

    info!("🔍 Searching for existing dashboard: '{}'", title);

    // List all dashboards to find existing one
    let dashboards_response = api
        .list_dashboards(ListDashboardsOptionalParams::default())
        .await
        .context("Failed to list dashboards")?;

    let existing_dashboard = dashboards_response
        .dashboards
        .as_ref()
        .and_then(|dashboards| dashboards.iter().find(|d| d.title.as_ref() == Some(&title)));

    // Load dashboard JSON from file or generate it
    info!("Loading dashboard configuration...");
    let dashboard_json_str = crate::emit::generate_dashboard_json()?;
    let mut dashboard_value: serde_json::Value =
        serde_json::from_str(&dashboard_json_str).context("Failed to parse dashboard JSON")?;

    // Ensure title matches
    dashboard_value["title"] = serde_json::json!(title);

    if let Some(existing) = existing_dashboard {
        let dashboard_id = existing.id.as_ref().context("Dashboard missing ID")?;

        info!("📊 Dashboard found with ID: {}", dashboard_id);
        info!("🔄 Updating existing dashboard...");

        // Parse JSON into Dashboard struct for update
        let dashboard: datadog_api_client::datadogV1::model::Dashboard =
            serde_json::from_value(dashboard_value).context("Failed to deserialize dashboard")?;

        let result = api
            .update_dashboard(dashboard_id.clone(), dashboard)
            .await
            .context("Failed to update dashboard")?;

        let url = result
            .url
            .unwrap_or_else(|| format!("https://app.{}/dashboard/{}", site_str, dashboard_id));

        println!("\n✅ Dashboard updated successfully!");
        println!("   Dashboard ID: {}", dashboard_id);
        println!("   Dashboard URL: {}", url);
        info!("Dashboard updated: {}", url);
    } else {
        info!("📊 Dashboard not found. Creating new dashboard...");

        // Parse JSON into Dashboard struct for creation
        let dashboard: datadog_api_client::datadogV1::model::Dashboard =
            serde_json::from_value(dashboard_value).context("Failed to deserialize dashboard")?;

        let result = api
            .create_dashboard(dashboard)
            .await
            .context("Failed to create dashboard")?;

        let dashboard_id = result.id.context("Created dashboard missing ID")?;
        let url = result
            .url
            .unwrap_or_else(|| format!("https://app.{}/dashboard/{}", site_str, dashboard_id));

        println!("\n✅ Dashboard created successfully!");
        println!("   Dashboard ID: {}", dashboard_id);
        println!("   Dashboard URL: {}", url);
        info!("Dashboard created: {}", url);
    }

    Ok(())
}
