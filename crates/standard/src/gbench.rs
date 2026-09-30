//! Reading Google Benchmark's JSON report.

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};
use bench_core::stats::{self, SummaryMs, P95};
use serde::Serialize;
use serde_json::{Map, Value};

/// One `benchmarks[]` entry, kept as a map because Google Benchmark writes the
/// user counters (`prove_ns`, `verify_ns`) as extra top-level keys.
pub struct Row(Map<String, Value>);

impl Row {
    /// `name`, falling back to `run_name`.
    pub fn name(&self) -> &str {
        self.0
            .get("name")
            .or_else(|| self.0.get("run_name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// Aggregate rows (`mean`, `stddev`, …) are summaries, not samples.
    pub fn is_aggregate(&self) -> bool {
        self.0.contains_key("aggregate_name")
    }

    pub fn number(&self, key: &str) -> Option<f64> {
        self.0.get(key).and_then(Value::as_f64)
    }

    pub fn time_unit(&self) -> &str {
        self.0
            .get("time_unit")
            .and_then(Value::as_str)
            .unwrap_or("ns")
    }
}

/// Reads a `--benchmark_out` JSON file.
///
/// The binary may print before the JSON object, so the outermost braces are
/// located first, as the JS did.
pub fn read_report(path: &Path) -> Result<Vec<Row>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read Google Benchmark JSON output {}", path.display()))?;

    let (start, end) = (text.find('{'), text.rfind('}'));
    let (Some(start), Some(end)) = (start, end) else {
        bail!(
            "no JSON object found in {} (check the binary's exit status and filter)",
            path.display()
        );
    };
    if end <= start {
        bail!("malformed JSON object in {}", path.display());
    }

    let report: Value =
        serde_json::from_str(&text[start..=end]).context("parse Google Benchmark JSON")?;
    Ok(report
        .get("benchmarks")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.as_object().cloned().map(Row))
                .collect()
        })
        .unwrap_or_default())
}

/// Converts a Google Benchmark duration into milliseconds.
pub fn to_ms(value: f64, unit: &str) -> Option<f64> {
    match unit {
        "ns" => Some(value / 1e6),
        "us" => Some(value / 1e3),
        "ms" => Some(value),
        "s" => Some(value * 1e3),
        _ => None,
    }
}

/// Strips the repetition suffix Google Benchmark appends to a run name.
pub fn base_name(run_name: &str) -> &str {
    run_name
        .rsplit_once("/repetition:")
        .or_else(|| run_name.rsplit_once("_repetition_"))
        .filter(|(_, tail)| !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()))
        .map_or(run_name, |(head, _)| head)
}

/// `--benchmark_min_time` accepts `0.05`, `0.05s`, `50ms` or `500us`.
pub fn parse_min_time_seconds(raw: &str) -> Result<f64> {
    let t = raw.trim();
    let (digits, scale) = if let Some(head) = t.strip_suffix("ms") {
        (head, 1e-3)
    } else if let Some(head) = t.strip_suffix("us") {
        (head, 1e-6)
    } else if let Some(head) = t.strip_suffix('s') {
        (head, 1.0)
    } else {
        (t, 1.0)
    };

    digits
        .parse::<f64>()
        .map(|v| v * scale)
        .map_err(|_| anyhow::anyhow!("invalid BENCH_MIN_TIME / --min_time: {raw}"))
}

/// The canonical `<seconds>s` form recorded in the summary metadata.
pub fn format_min_time_for_meta(raw: &str) -> Result<String> {
    Ok(format!("{}s", parse_min_time_seconds(raw)?))
}

/// Older Google Benchmark builds reject the `s` suffix on `--benchmark_min_time`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MinTimeFormat {
    Plain,
    Suffix,
}

fn detect_min_time_format(bin: &Path) -> MinTimeFormat {
    static FORMAT: OnceLock<MinTimeFormat> = OnceLock::new();
    *FORMAT.get_or_init(|| {
        match std::env::var("BENCH_MIN_TIME_FORMAT")
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Ok("plain") => return MinTimeFormat::Plain,
            Ok("suffix") => return MinTimeFormat::Suffix,
            _ => {}
        }

        let probe = Command::new(bin)
            .args(["--benchmark_min_time=0.001s", "--benchmark_list_tests"])
            .output();
        let Ok(out) = probe else {
            return MinTimeFormat::Plain;
        };
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if combined
            .to_ascii_lowercase()
            .contains("expected to be a double")
        {
            MinTimeFormat::Plain
        } else {
            MinTimeFormat::Suffix
        }
    })
}

/// The `--benchmark_min_time` value this binary accepts.
pub fn format_min_time_for_gbench(raw: &str, bin: &Path) -> Result<String> {
    let seconds = parse_min_time_seconds(raw)?;
    Ok(match detect_min_time_format(bin) {
        MinTimeFormat::Suffix => format!("{seconds}s"),
        MinTimeFormat::Plain => seconds.to_string(),
    })
}

/// Per-repetition `prove_ns` / `verify_ns` from the `Combined` rows.
///
/// Longfellow has no witness/prove split, so `prove_ns` is the whole prover.
pub struct Combined {
    pub prove_ms: Vec<f64>,
    pub verify_ms: Vec<f64>,
}

impl Combined {
    pub fn full_cycle_ms(&self) -> Vec<f64> {
        self.prove_ms
            .iter()
            .zip(&self.verify_ms)
            .map(|(p, v)| p + v)
            .collect()
    }
}

pub fn rollup_combined(rows: &[Row]) -> Option<Combined> {
    let mut prove_ms = Vec::new();
    let mut verify_ms = Vec::new();

    for row in rows {
        if row.is_aggregate() || !row.name().contains("Combined") {
            continue;
        }
        let (Some(prove_ns), Some(verify_ns)) = (row.number("prove_ns"), row.number("verify_ns"))
        else {
            continue;
        };
        if !prove_ns.is_finite() || !verify_ns.is_finite() {
            continue;
        }
        prove_ms.push(prove_ns / 1e6);
        verify_ms.push(verify_ns / 1e6);
    }

    (!prove_ms.is_empty()).then_some(Combined {
        prove_ms,
        verify_ms,
    })
}

#[derive(Serialize)]
pub struct Meta {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub variant: &'static str,
    #[serde(rename = "N")]
    pub n: usize,
    #[serde(rename = "credentialMode")]
    pub credential_mode: &'static str,
    #[serde(rename = "timestampIso")]
    pub timestamp_iso: String,
}

#[derive(Serialize)]
pub struct Results {
    #[serde(rename = "successfulIters")]
    pub successful_iters: usize,
}

#[derive(Serialize)]
pub struct AvgMs {
    #[serde(rename = "proverTotal")]
    pub prover_total: Option<f64>,
    pub verify: Option<f64>,
}

#[derive(Serialize)]
pub struct StatsMs {
    #[serde(rename = "proverTotal")]
    pub prover_total: Option<SummaryMs>,
    pub verify: Option<SummaryMs>,
    #[serde(rename = "fullCycle")]
    pub full_cycle: Option<SummaryMs>,
}

/// The zk-friendly-shaped timing summary, minus the witness/prove split.
#[derive(Serialize)]
pub struct TimingSummary {
    pub meta: Meta,
    pub results: Results,
    #[serde(rename = "avgMs")]
    pub avg_ms: AvgMs,
    #[serde(rename = "statsMs")]
    pub stats_ms: StatsMs,
}

pub fn build_timing_summary(rows: &[Row], meta: Meta) -> Option<TimingSummary> {
    let combined = rollup_combined(rows)?;
    let prover_total = stats::summary_ms(&combined.prove_ms, P95::FloorNMinus1);
    let verify = stats::summary_ms(&combined.verify_ms, P95::FloorNMinus1);

    Some(TimingSummary {
        results: Results {
            successful_iters: combined.prove_ms.len(),
        },
        avg_ms: AvgMs {
            prover_total: prover_total.map(|s| s.avg_ms),
            verify: verify.map(|s| s.avg_ms),
        },
        stats_ms: StatsMs {
            prover_total,
            verify,
            full_cycle: stats::summary_ms(&combined.full_cycle_ms(), P95::FloorNMinus1),
        },
        meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_time_accepts_every_suffix() {
        assert_eq!(parse_min_time_seconds("0.05").unwrap(), 0.05);
        assert_eq!(parse_min_time_seconds("0.2s").unwrap(), 0.2);
        assert_eq!(parse_min_time_seconds("50ms").unwrap(), 0.05);
        assert_eq!(parse_min_time_seconds("500us").unwrap(), 0.0005);
        assert!(parse_min_time_seconds("fast").is_err());
        assert_eq!(format_min_time_for_meta("50ms").unwrap(), "0.05s");
    }

    #[test]
    fn base_name_strips_only_a_repetition_suffix() {
        assert_eq!(base_name("BM_X/repetition:3"), "BM_X");
        assert_eq!(base_name("BM_X_repetition_12"), "BM_X");
        assert_eq!(base_name("BM_X/12"), "BM_X/12");
        assert_eq!(base_name("BM_X"), "BM_X");
    }

    #[test]
    fn units_convert_to_milliseconds() {
        assert_eq!(to_ms(1e6, "ns"), Some(1.0));
        assert_eq!(to_ms(1e3, "us"), Some(1.0));
        assert_eq!(to_ms(1.0, "ms"), Some(1.0));
        assert_eq!(to_ms(1.0, "s"), Some(1000.0));
        assert_eq!(to_ms(1.0, "fortnight"), None);
    }

    fn rows_from(json: &str) -> Vec<Row> {
        serde_json::from_str::<Value>(json)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| Row(v.as_object().unwrap().clone()))
            .collect()
    }

    #[test]
    fn rollup_keeps_combined_samples_only() {
        let rows = rows_from(
            r#"[
              {"name":"BM_Combined_P256/repetition:0","prove_ns":2.0e6,"verify_ns":1.0e6},
              {"name":"BM_Combined_P256/repetition:1","prove_ns":4.0e6,"verify_ns":3.0e6},
              {"name":"BM_Combined_P256_mean","aggregate_name":"mean","prove_ns":3.0e6,"verify_ns":2.0e6},
              {"name":"BM_ProverOnly_P256","real_time":1.0}
            ]"#,
        );

        let combined = rollup_combined(&rows).unwrap();
        assert_eq!(combined.prove_ms, [2.0, 4.0]);
        assert_eq!(combined.verify_ms, [1.0, 3.0]);
        assert_eq!(combined.full_cycle_ms(), [3.0, 7.0]);
    }

    #[test]
    fn rollup_is_none_without_combined_rows() {
        let rows = rows_from(r#"[{"name":"BM_Other","real_time":1.0}]"#);
        assert!(rollup_combined(&rows).is_none());
    }

    #[test]
    fn summary_uses_the_js_percentile_index() {
        // floor((4 - 1) * 0.95) == 2
        let s = stats::summary_ms(&[4.0, 1.0, 3.0, 2.0], P95::FloorNMinus1).unwrap();
        assert_eq!(s.p95_ms, 3.0);
        assert_eq!(s.median_ms, 2.5);
        assert_eq!(s.min_ms, 1.0);
        assert_eq!(s.max_ms, 4.0);
    }
}
