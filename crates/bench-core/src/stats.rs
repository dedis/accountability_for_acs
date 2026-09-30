//! Timing summaries written into the benchmark JSON.

use serde::Serialize;

/// `min`, `max` and `avg` — what the revocation sweep reports per scale.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Summary {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
}

/// Which sample is reported as p95. Each stack keeps its own rule so its numbers
/// stay comparable with its recorded results.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum P95 {
    /// `sorted[floor(n * 0.95)]` (zk-friendly).
    FloorN,
    /// `sorted[floor((n - 1) * 0.95)]` (standard).
    FloorNMinus1,
}

/// The five-number summary the prove/verify benches report, with the JSON
/// field names the plot scripts expect.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryMs {
    pub min_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub median_ms: f64,
    pub p95_ms: f64,
}

pub fn mean(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

fn sorted(values: &[f64]) -> Vec<f64> {
    let mut out = values.to_vec();
    out.sort_by(f64::total_cmp);
    out
}

pub fn summary(values: &[f64]) -> Option<Summary> {
    let sorted = sorted(values);
    Some(Summary {
        min: *sorted.first()?,
        max: *sorted.last()?,
        avg: mean(values)?,
    })
}

pub fn summary_ms(values: &[f64], p95: P95) -> Option<SummaryMs> {
    let sorted = sorted(values);
    let n = sorted.len();
    if n == 0 {
        return None;
    }
    let median = if n.is_multiple_of(2) {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    };
    Some(SummaryMs {
        min_ms: sorted[0],
        max_ms: sorted[n - 1],
        avg_ms: mean(values)?,
        median_ms: median,
        p95_ms: sorted[(match p95 {
            P95::FloorN => (n as f64 * 0.95) as usize,
            P95::FloorNMinus1 => ((n - 1) as f64 * 0.95) as usize,
        })
        .min(n - 1)],
    })
}

/// Element-wise sum of two equal-length series, for the derived
/// `proverTotal` and `fullCycle` rows.
pub fn add_series(a: &[f64], b: &[f64]) -> Vec<f64> {
    a.iter().zip(b).map(|(x, y)| x + y).collect()
}

/// `label  min=… avg=… median=… p95=… max=…`.
pub fn print_stats(label: &str, values: &[f64], p95: P95) {
    let Some(s) = summary_ms(values, p95) else {
        return;
    };
    println!(
        "{label:<18} min={:>9.2}ms  avg={:>9.2}ms  median={:>9.2}ms  p95={:>9.2}ms  max={:>9.2}ms",
        s.min_ms, s.avg_ms, s.median_ms, s.p95_ms, s.max_ms
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_series_have_no_summary() {
        assert!(summary(&[]).is_none());
        assert!(summary_ms(&[], P95::FloorN).is_none());
        assert!(mean(&[]).is_none());
    }

    #[test]
    fn median_averages_the_middle_pair_for_even_counts() {
        let s = summary_ms(&[4.0, 1.0, 3.0, 2.0], P95::FloorN).unwrap();
        assert_eq!(s.min_ms, 1.0);
        assert_eq!(s.max_ms, 4.0);
        assert_eq!(s.median_ms, 2.5);
        assert_eq!(s.avg_ms, 2.5);
        // floor(4 * 0.95) == 3
        assert_eq!(s.p95_ms, 4.0);
        // floor((4 - 1) * 0.95) == 2
        let s = summary_ms(&[4.0, 1.0, 3.0, 2.0], P95::FloorNMinus1).unwrap();
        assert_eq!(s.p95_ms, 3.0);
    }

    #[test]
    fn median_takes_the_middle_for_odd_counts() {
        let s = summary_ms(&[5.0, 1.0, 3.0], P95::FloorN).unwrap();
        assert_eq!(s.median_ms, 3.0);
    }

    #[test]
    fn series_add_element_wise() {
        assert_eq!(add_series(&[1.0, 2.0], &[10.0, 20.0]), [11.0, 22.0]);
    }
}
