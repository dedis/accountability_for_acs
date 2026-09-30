//! Summary statistics and the linear cost models the experiments report.

/// Population mean and standard deviation, matching the JS `meanStd`.
#[derive(Clone, Copy, Debug, Default)]
pub struct MeanStd {
    pub mean: f64,
    pub std: f64,
}

pub fn mean_std(values: &[f64]) -> MeanStd {
    if values.is_empty() {
        return MeanStd::default();
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    MeanStd {
        mean,
        std: variance.sqrt(),
    }
}

/// One `(set_size, set_size_after_filter, total_ms)` observation.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub x: f64,
    pub z: f64,
    pub y: f64,
}

/// Ordinary least squares for `y ≈ t1·x + t2·z`.
///
/// When `x == z` for every sample the two regressors are identical and the
/// model collapses to `y ≈ t1·x`.
#[derive(Clone, Copy, Debug)]
pub struct TimeModel {
    pub t1: Option<f64>,
    pub t2: Option<f64>,
    pub collapsed: bool,
}

pub fn fit_time_model(samples: &[Sample]) -> TimeModel {
    if samples.iter().all(|s| s.x == s.z) {
        let sxx: f64 = samples.iter().map(|s| s.x * s.x).sum();
        let sxy: f64 = samples.iter().map(|s| s.x * s.y).sum();
        return TimeModel {
            t1: (sxx != 0.0).then(|| sxy / sxx),
            t2: Some(0.0),
            collapsed: true,
        };
    }

    let mut sxx = 0.0;
    let mut sxz = 0.0;
    let mut szz = 0.0;
    let mut sxy = 0.0;
    let mut szy = 0.0;
    for s in samples {
        sxx += s.x * s.x;
        sxz += s.x * s.z;
        szz += s.z * s.z;
        sxy += s.x * s.y;
        szy += s.z * s.y;
    }

    let det = sxx * szz - sxz * sxz;
    if det == 0.0 {
        return TimeModel {
            t1: None,
            t2: None,
            collapsed: false,
        };
    }
    TimeModel {
        t1: Some((sxy * szz - szy * sxz) / det),
        t2: Some((sxx * szy - sxz * sxy) / det),
        collapsed: false,
    }
}

impl TimeModel {
    /// The human-readable formula written into `*_fit.csv`.
    pub fn formula(&self) -> String {
        let fmt = |v: Option<f64>| v.map_or_else(|| "?".to_string(), |x| format!("{x:.4}"));
        if self.collapsed {
            format!("t_total_ms ≈ {}·set_size", fmt(self.t1))
        } else {
            format!(
                "t_total_ms ≈ {}·set_size + {}·set_size_after_filter",
                fmt(self.t1),
                fmt(self.t2)
            )
        }
    }
}

/// Number of unordered pairs in a set of `n` elements.
#[inline]
pub const fn n_pairs(n: u64) -> u64 {
    n * n.saturating_sub(1) / 2
}

/// Through-the-origin fit `y ≈ k·pairs(n)`, with its coefficient of
/// determination taken about zero (as the JS `fitPairwiseModel` did).
#[derive(Clone, Copy, Debug)]
pub struct PairwiseModel {
    pub k: Option<f64>,
    pub r2: f64,
}

pub fn fit_pairwise_model(sizes: &[u64], totals_ms: &[f64]) -> PairwiseModel {
    debug_assert_eq!(sizes.len(), totals_ms.len());
    let xs: Vec<f64> = sizes.iter().map(|n| n_pairs(*n) as f64).collect();

    let denom: f64 = xs.iter().map(|x| x * x).sum();
    if denom == 0.0 {
        return PairwiseModel { k: None, r2: 0.0 };
    }

    let k = xs.iter().zip(totals_ms).map(|(x, y)| x * y).sum::<f64>() / denom;
    let ss_res: f64 = xs
        .iter()
        .zip(totals_ms)
        .map(|(x, y)| (y - k * x).powi(2))
        .sum();
    let ss_tot: f64 = totals_ms.iter().map(|y| y * y).sum();

    PairwiseModel {
        k: Some(k),
        r2: if ss_tot == 0.0 {
            0.0
        } else {
            1.0 - ss_res / ss_tot
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_std_of_empty_is_zero() {
        let s = mean_std(&[]);
        assert_eq!(s.mean, 0.0);
        assert_eq!(s.std, 0.0);
    }

    #[test]
    fn mean_std_uses_population_variance() {
        let s = mean_std(&[1.0, 2.0, 3.0, 4.0]);
        assert_eq!(s.mean, 2.5);
        assert!((s.std - 1.118_033_988_749_895).abs() < 1e-12);
    }

    #[test]
    fn model_collapses_when_regressors_coincide() {
        let samples: Vec<Sample> = (1..=5)
            .map(|i| {
                let x = f64::from(i);
                Sample {
                    x,
                    z: x,
                    y: 3.0 * x,
                }
            })
            .collect();
        let fit = fit_time_model(&samples);
        assert!(fit.collapsed);
        assert!((fit.t1.unwrap() - 3.0).abs() < 1e-12);
    }

    #[test]
    fn model_separates_two_regressors() {
        let samples = [
            Sample {
                x: 10.0,
                z: 1.0,
                y: 2.0 * 10.0 + 5.0,
            },
            Sample {
                x: 20.0,
                z: 4.0,
                y: 2.0 * 20.0 + 5.0 * 4.0,
            },
            Sample {
                x: 30.0,
                z: 9.0,
                y: 2.0 * 30.0 + 5.0 * 9.0,
            },
        ];
        let fit = fit_time_model(&samples);
        assert!(!fit.collapsed);
        assert!((fit.t1.unwrap() - 2.0).abs() < 1e-9);
        assert!((fit.t2.unwrap() - 5.0).abs() < 1e-9);
    }

    #[test]
    fn pairwise_model_recovers_slope() {
        let sizes = [10u64, 20, 50];
        let totals: Vec<f64> = sizes.iter().map(|n| 0.25 * n_pairs(*n) as f64).collect();
        let fit = fit_pairwise_model(&sizes, &totals);
        assert!((fit.k.unwrap() - 0.25).abs() < 1e-12);
        assert!((fit.r2 - 1.0).abs() < 1e-12);
    }
}
