//! The summary JSON both prove/verify benchmarks write; see
//! [`bench_core::report::write`].

use bench_core::stats::SummaryMs;
use serde::Serialize;

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
    pub witness: Option<f64>,
    pub prove: Option<f64>,
    pub verify: Option<f64>,
}

#[derive(Serialize)]
pub struct StatsMs {
    pub witness: Option<SummaryMs>,
    pub prove: Option<SummaryMs>,
    pub verify: Option<SummaryMs>,
    #[serde(rename = "proverTotal")]
    pub prover_total: Option<SummaryMs>,
    #[serde(rename = "fullCycle")]
    pub full_cycle: Option<SummaryMs>,
}

#[derive(Serialize)]
pub struct TimingSummary {
    pub meta: Meta,
    pub results: Results,
    #[serde(rename = "avgMs")]
    pub avg_ms: AvgMs,
    #[serde(rename = "statsMs")]
    pub stats_ms: StatsMs,
}
