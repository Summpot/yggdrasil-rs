#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

/// Datadog Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub title: String,
    pub description: String,
    pub layout_type: String,
    pub widgets: Vec<Widget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Widget {
    pub definition: WidgetDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WidgetDefinition {
    #[serde(rename = "timeseries")]
    Timeseries {
        title: String,
        requests: Vec<TimeseriesRequest>,
    },
    #[serde(rename = "query_table")]
    QueryTable {
        title: String,
        requests: Vec<TableRequest>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeseriesRequest {
    pub q: String,
    pub display_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRequest {
    pub q: String,
}

/// Generate a complete Datadog dashboard for Yggdrasil benchmarks
pub fn generate_dashboard_json() -> Result<String> {
    let dashboard = json!({
        "title": "Yggdrasil Performance Benchmarks",
        "description": "Automated performance metrics for Yggdrasil network implementation",
        "layout_type": "ordered",
        "template_variables": [
            {
                "name": "proto",
                "prefix": "proto",
                "available_values": ["tcp", "tls", "quic", "ws", "wss"],
                "default": "*"
            },
            {
                "name": "overlay",
                "prefix": "overlay",
                "available_values": ["ipv4", "ipv6", "udp", "tcp", "quic"],
                "default": "*"
            },
            {
                "name": "branch",
                "prefix": "branch",
                "available_values": ["main", "master"],
                "default": "main"
            }
        ],
        "widgets": [
            {
                "definition": {
                    "type": "note",
                    "content": "# Yggdrasil Performance Overview\n\nThis dashboard tracks automated performance benchmarks across different protocol and overlay combinations.\n\n**Metrics:**\n- Latency (p50, p95, p99)\n- Throughput (Mbps)\n- Memory usage (RSS)\n\n**Use template variables to filter by protocol, overlay, or branch.**",
                    "background_color": "white",
                    "font_size": "14",
                    "text_align": "left",
                    "vertical_align": "top",
                    "show_tick": false,
                    "tick_pos": "50%",
                    "tick_edge": "left"
                }
            },
            {
                "definition": {
                    "type": "timeseries",
                    "title": "P99 Latency by Protocol",
                    "show_legend": true,
                    "legend_layout": "auto",
                    "legend_columns": ["avg", "min", "max", "value"],
                    "requests": [
                        {
                            "q": "avg:ygg.bench.latency.p99{proto:$proto,overlay:$overlay,branch:$branch} by {proto}",
                            "display_type": "line",
                            "style": {
                                "palette": "dog_classic",
                                "line_type": "solid",
                                "line_width": "normal"
                            }
                        }
                    ],
                    "yaxis": {
                        "label": "Latency (µs)",
                        "scale": "linear",
                        "include_zero": true
                    }
                }
            },
            {
                "definition": {
                    "type": "timeseries",
                    "title": "P99 Latency by Overlay",
                    "show_legend": true,
                    "legend_layout": "auto",
                    "legend_columns": ["avg", "min", "max", "value"],
                    "requests": [
                        {
                            "q": "avg:ygg.bench.latency.p99{proto:$proto,overlay:$overlay,branch:$branch} by {overlay}",
                            "display_type": "line",
                            "style": {
                                "palette": "cool",
                                "line_type": "solid",
                                "line_width": "normal"
                            }
                        }
                    ],
                    "yaxis": {
                        "label": "Latency (µs)",
                        "scale": "linear",
                        "include_zero": true
                    }
                }
            },
            {
                "definition": {
                    "type": "timeseries",
                    "title": "P95 Latency Trends",
                    "show_legend": true,
                    "legend_layout": "auto",
                    "requests": [
                        {
                            "q": "avg:ygg.bench.latency.p95{proto:$proto,overlay:$overlay,branch:$branch} by {scenario}",
                            "display_type": "line"
                        }
                    ],
                    "yaxis": {
                        "label": "Latency (µs)",
                        "scale": "linear"
                    }
                }
            },
            {
                "definition": {
                    "type": "timeseries",
                    "title": "Throughput by Protocol (Mbps)",
                    "show_legend": true,
                    "legend_layout": "auto",
                    "legend_columns": ["avg", "min", "max", "value"],
                    "requests": [
                        {
                            "q": "avg:ygg.bench.throughput.mbps{proto:$proto,overlay:$overlay,branch:$branch} by {proto}",
                            "display_type": "line",
                            "style": {
                                "palette": "green",
                                "line_type": "solid",
                                "line_width": "normal"
                            }
                        }
                    ],
                    "yaxis": {
                        "label": "Throughput (Mbps)",
                        "scale": "linear",
                        "include_zero": true
                    }
                }
            },
            {
                "definition": {
                    "type": "timeseries",
                    "title": "Throughput by Overlay (Mbps)",
                    "show_legend": true,
                    "legend_layout": "auto",
                    "legend_columns": ["avg", "min", "max", "value"],
                    "requests": [
                        {
                            "q": "avg:ygg.bench.throughput.mbps{proto:$proto,overlay:$overlay,branch:$branch} by {overlay}",
                            "display_type": "line",
                            "style": {
                                "palette": "purple",
                                "line_type": "solid",
                                "line_width": "normal"
                            }
                        }
                    ],
                    "yaxis": {
                        "label": "Throughput (Mbps)",
                        "scale": "linear",
                        "include_zero": true
                    }
                }
            },
            {
                "definition": {
                    "type": "query_table",
                    "title": "Latest P99 Latency Matrix (Protocol × Overlay)",
                    "requests": [
                        {
                            "q": "avg:ygg.bench.latency.p99{proto:$proto,overlay:$overlay,branch:$branch} by {proto,overlay}",
                            "aggregator": "last",
                            "alias": "P99 Latency (µs)"
                        }
                    ]
                }
            },
            {
                "definition": {
                    "type": "query_table",
                    "title": "Latest Throughput Matrix (Protocol × Overlay)",
                    "requests": [
                        {
                            "q": "avg:ygg.bench.throughput.mbps{proto:$proto,overlay:$overlay,branch:$branch} by {proto,overlay}",
                            "aggregator": "last",
                            "alias": "Throughput (Mbps)"
                        }
                    ]
                }
            },
            {
                "definition": {
                    "type": "timeseries",
                    "title": "Peak RSS Memory Usage (MB)",
                    "show_legend": true,
                    "legend_layout": "auto",
                    "requests": [
                        {
                            "q": "avg:ygg.bench.rss.peak{proto:$proto,overlay:$overlay,branch:$branch} by {scenario}",
                            "display_type": "line",
                            "style": {
                                "palette": "orange",
                                "line_type": "solid",
                                "line_width": "normal"
                            }
                        }
                    ],
                    "yaxis": {
                        "label": "Memory (MB)",
                        "scale": "linear",
                        "include_zero": true
                    }
                }
            },
            {
                "definition": {
                    "type": "timeseries",
                    "title": "Mean Latency Comparison",
                    "show_legend": true,
                    "legend_layout": "auto",
                    "requests": [
                        {
                            "q": "avg:ygg.bench.latency.mean{proto:$proto,overlay:$overlay,branch:$branch} by {proto}",
                            "display_type": "line"
                        }
                    ],
                    "yaxis": {
                        "label": "Latency (µs)",
                        "scale": "linear"
                    }
                }
            },
            {
                "definition": {
                    "type": "timeseries",
                    "title": "Operations per Second",
                    "show_legend": true,
                    "legend_layout": "auto",
                    "requests": [
                        {
                            "q": "avg:ygg.bench.throughput.ops{proto:$proto,overlay:$overlay,branch:$branch} by {scenario}",
                            "display_type": "line"
                        }
                    ],
                    "yaxis": {
                        "label": "Operations/sec",
                        "scale": "linear"
                    }
                }
            },
            {
                "definition": {
                    "type": "note",
                    "content": "## Regression Thresholds\n\n**Latency** (lower is better):\n- ⚠️  Warning: ≥5% increase\n- ❌ Failure: ≥10% increase\n\n**Throughput** (higher is better):\n- ⚠️  Warning: ≥5% decrease\n- ❌ Failure: ≥10% decrease\n\n**Memory**: Monitor for leaks and unexpected growth.",
                    "background_color": "yellow",
                    "font_size": "14",
                    "text_align": "left"
                }
            }
        ]
    });

    serde_json::to_string_pretty(&dashboard)
        .context("Failed to serialize dashboard JSON")
}

/// Save dashboard JSON to file
pub fn save_dashboard_json<P: AsRef<Path>>(path: P) -> Result<()> {
    let json = generate_dashboard_json()?;
    fs::write(path.as_ref(), json)
        .with_context(|| format!("Failed to write dashboard JSON to {:?}", path.as_ref()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dashboard_json() {
        let json = generate_dashboard_json().unwrap();
        assert!(json.contains("Yggdrasil Performance Benchmarks"));
        assert!(json.contains("ygg.bench.latency.p99"));
        assert!(json.contains("template_variables"));
    }

    #[test]
    fn test_dashboard_json_valid() {
        let json = generate_dashboard_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["title"], "Yggdrasil Performance Benchmarks");
        assert!(parsed["widgets"].is_array());
    }
}
