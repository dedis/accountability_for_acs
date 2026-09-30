//! CFT batch construction and the two revocation strategies under measurement.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Result};
use ark_ec::CurveGroup;
use ark_ff::Field;
use rand::seq::SliceRandom;
use rand::Rng;

use crate::c4;
use babyjub::curve::{base8, rand_scalar, Fr, Point, PointAffine};
use babyjub::eddsa::{SecretKey, Signature};
use babyjub::poseidon::Poseidon;

/// One authority's key pair.
#[derive(Clone, Copy, Debug)]
pub struct KeyPair {
    pub sk: Fr,
    pub pk: Point,
}

/// Police, judge and NGO, plus the aggregate encryption key.
#[derive(Clone, Copy, Debug)]
pub struct Keys {
    pub police: KeyPair,
    pub judge: KeyPair,
    pub ngo: KeyPair,
    pub pk_ag: Point,
}

impl Keys {
    pub fn generate<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let key = |rng: &mut R| {
            let sk = rand_scalar(rng);
            KeyPair {
                sk,
                pk: base8() * sk,
            }
        };
        let police = key(rng);
        let judge = key(rng);
        let ngo = key(rng);
        Self {
            police,
            judge,
            ngo,
            pk_ag: police.pk + judge.pk + ngo.pk,
        }
    }
}

/// One conditionally-openable tag.
#[derive(Clone, Copy, Debug)]
pub struct Cft {
    pub c1: Point,
    pub c2: Point,
    pub c3: Point,
    pub c4: Signature,
    pub t: Fr,
}

/// A batch of CFTs with one identity deliberately repeated.
pub struct Batch {
    pub cfts: Vec<Cft>,
    pub n_recurring: usize,
    pub n_unique: usize,
    pub recurring_pct: f64,
    pub pid_threshold: usize,
}

/// Builds `n` CFTs, of which `recurring_pct` (at least the PID threshold) share
/// one identity. `C4 = EdDSA(poseidon(t, D2))` under that identity's key.
/// Requires at least two CFTs and a recurring fraction in `0..=1`.
pub fn build_batch<R: Rng + ?Sized>(
    poseidon: &Poseidon,
    pk_ag: Point,
    n: usize,
    recurring_pct: f64,
    rng: &mut R,
) -> Result<Batch> {
    ensure!(n >= 2, "CFT batch size must be at least 2, got {n}");
    ensure!(
        (0.0..=1.0).contains(&recurring_pct),
        "recurring fraction must be in 0..=1, got {recurring_pct}"
    );
    let pid_threshold = usize::max(2, (n as f64 * 0.1).ceil() as usize);
    let n_recurring = usize::max((n as f64 * recurring_pct).round() as usize, pid_threshold);
    let n_unique = n - n_recurring;

    let recurring = SecretKey::rand(rng);
    let recurring_id = recurring.public_key();

    let mut slots: Vec<(Point, SecretKey)> = Vec::with_capacity(n);
    slots.extend(std::iter::repeat_n((recurring_id, recurring), n_recurring));
    slots.extend((0..n_unique).map(|_| {
        let sk = SecretKey::rand(rng);
        (sk.public_key(), sk)
    }));
    slots.shuffle(rng);

    let cfts = slots
        .into_iter()
        .map(|(id_u, user_sk)| {
            let r1 = rand_scalar(rng);
            let r2 = rand_scalar(rng);
            let t = rand_scalar(rng);
            let d2 = (pk_ag * r2).into_affine();
            Cft {
                c1: base8() * r1,
                c2: base8() * r2,
                c3: id_u + pk_ag * r1,
                c4: c4::sign(poseidon, &user_sk, t, d2, rng),
                t,
            }
        })
        .collect();

    Ok(Batch {
        cfts,
        n_recurring,
        n_unique,
        recurring_pct,
        pid_threshold,
    })
}

/// Wall-clock breakdown of one scenario, in the phases the paper reports.
#[derive(Clone, Copy, Debug, Default)]
pub struct Timing {
    pub n: usize,
    pub n_after_filter: usize,
    pub pid_threshold: Option<usize>,
    pub ngo: Duration,
    pub judge: Duration,
    pub police: Duration,
    pub link: Duration,
    pub decrypt: Duration,
}

impl Timing {
    pub fn total(&self) -> Duration {
        self.link + self.decrypt
    }
}

/// One authority's partial decryption of `(C1, C2)`.
#[derive(Clone, Copy)]
struct Share {
    d1: Point,
    d2: Point,
}

#[inline]
fn partial_decrypt(cft: &Cft, sk: Fr) -> Share {
    Share {
        d1: cft.c1 * sk,
        d2: cft.c2 * sk,
    }
}

/// Direct decrypt: every CFT is opened, so `n_after_filter == n`.
pub fn bench_direct_decrypt(poseidon: &Poseidon, batch: &Batch, keys: &Keys) -> Result<Timing> {
    let cfts = &batch.cfts;
    let n = cfts.len();

    let t0 = Instant::now();
    let ngo_shares: Vec<Share> = cfts
        .iter()
        .map(|c| partial_decrypt(c, keys.ngo.sk))
        .collect();
    let ngo = t0.elapsed();

    let t0 = Instant::now();
    let judge_shares: Vec<Share> = cfts
        .iter()
        .map(|c| partial_decrypt(c, keys.judge.sk))
        .collect();
    let judge = t0.elapsed();

    let t0 = Instant::now();
    for (i, cft) in cfts.iter().enumerate() {
        let police = partial_decrypt(cft, keys.police.sk);
        let d1 = police.d1 + ngo_shares[i].d1 + judge_shares[i].d1;
        let d2 = police.d2 + ngo_shares[i].d2 + judge_shares[i].d2;
        let id_u = (cft.c3 - d1).into_affine();
        if !c4::verify(poseidon, id_u, cft.t, d2.into_affine(), &cft.c4) {
            bail!("C4 verification failed (direct-decrypt)");
        }
    }
    let police = t0.elapsed();

    Ok(Timing {
        n,
        n_after_filter: n,
        pid_threshold: None,
        ngo,
        judge,
        police,
        link: Duration::ZERO,
        decrypt: ngo + judge + police,
    })
}

/// A CFT in flight through the sequential unlink chain.
struct LinkEntry {
    c2: Point,
    c4: Signature,
    t: Fr,
    d1: Point,
    d3: Point,
}

/// Re-randomises `(D1, D3)` under one authority's key and a fresh blinding `k`.
fn batch_link<R: Rng + ?Sized>(entries: &mut [LinkEntry], sk: Fr, rng: &mut R) -> Fr {
    let k = rand_scalar(rng);
    for e in entries.iter_mut() {
        let d1 = e.d1;
        e.d3 = (e.d3 - d1 * sk) * k;
        e.d1 = d1 * k;
    }
    k
}

/// Keeps only the entries whose pseudonym occurs at least `min_count` times.
///
/// Affine normalisation is batched (one field inversion for the whole set
/// instead of one per entry, which is what the JS `ptKey` cost).
fn retain_recurring(entries: &mut Vec<LinkEntry>, min_count: usize) {
    let projective: Vec<Point> = entries.iter().map(|e| e.d3).collect();
    let pids: Vec<PointAffine> = Point::normalize_batch(&projective);

    let mut counts: HashMap<PointAffine, usize> = HashMap::with_capacity(pids.len());
    for pid in &pids {
        *counts.entry(*pid).or_insert(0) += 1;
    }

    *entries = std::mem::take(entries)
        .into_iter()
        .zip(pids)
        .filter(|(_, pid)| counts[pid] >= min_count)
        .map(|(entry, _)| entry)
        .collect();
}

/// Link then decrypt: linking touches all `n`, decryption only the recurring
/// pseudonyms that survived the filter.
pub fn bench_link_decrypt<R: Rng + ?Sized>(
    poseidon: &Poseidon,
    batch: &Batch,
    keys: &Keys,
    rng: &mut R,
) -> Result<Timing> {
    let n = batch.cfts.len();
    let min_count = batch.pid_threshold;

    let mut entries: Vec<LinkEntry> = batch
        .cfts
        .iter()
        .map(|c| LinkEntry {
            c2: c.c2,
            c4: c.c4,
            t: c.t,
            d1: c.c1,
            d3: c.c3,
        })
        .collect();

    let t0 = Instant::now();
    let k_police = batch_link(&mut entries, keys.police.sk, rng);
    let police_link = t0.elapsed();

    let t0 = Instant::now();
    let k_judge = batch_link(&mut entries, keys.judge.sk, rng);
    let judge_link = t0.elapsed();

    let t0 = Instant::now();
    let k_ngo = batch_link(&mut entries, keys.ngo.sk, rng);
    let ngo_link = t0.elapsed();

    let t0 = Instant::now();
    retain_recurring(&mut entries, min_count);
    let filter = t0.elapsed();

    let n_after = entries.len();
    let link = police_link + judge_link + ngo_link + filter;

    // Each authority unwinds its own blinding factor. The inverse is shared by
    // the whole batch; the JS recomputed it per entry.
    let t0 = Instant::now();
    let inv_ngo = k_ngo.inverse().expect("blinding factor is non-zero");
    let mut pid: Vec<Point> = entries.iter().map(|e| e.d3 * inv_ngo).collect();
    let mut d2: Vec<Point> = entries.iter().map(|e| e.c2 * keys.ngo.sk).collect();
    let ngo_dec = t0.elapsed();

    let t0 = Instant::now();
    let inv_judge = k_judge.inverse().expect("blinding factor is non-zero");
    for ((p, acc), e) in pid.iter_mut().zip(d2.iter_mut()).zip(entries.iter()) {
        *p *= inv_judge;
        *acc += e.c2 * keys.judge.sk;
    }
    let judge_dec = t0.elapsed();

    let t0 = Instant::now();
    let inv_police = k_police.inverse().expect("blinding factor is non-zero");
    for ((p, acc), e) in pid.iter().zip(d2.iter()).zip(entries.iter()) {
        let id = (*p * inv_police).into_affine();
        let d2 = (*acc + e.c2 * keys.police.sk).into_affine();
        if !c4::verify(poseidon, id, e.t, d2, &e.c4) {
            bail!("C4 verification failed (link-decrypt)");
        }
    }
    let police_dec = t0.elapsed();

    let decrypt = ngo_dec + judge_dec + police_dec;

    Ok(Timing {
        n,
        n_after_filter: n_after,
        pid_threshold: Some(min_count),
        ngo: ngo_link + ngo_dec,
        judge: judge_link + judge_dec,
        police: police_link + police_dec,
        link,
        decrypt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn both_strategies_open_a_batch() {
        let mut rng = StdRng::seed_from_u64(42);
        let poseidon = Poseidon::new();
        let keys = Keys::generate(&mut rng);

        for pct in [0.1, 0.5] {
            let batch = build_batch(&poseidon, keys.pk_ag, 40, pct, &mut rng).unwrap();
            let direct = bench_direct_decrypt(&poseidon, &batch, &keys).unwrap();
            assert_eq!(direct.n_after_filter, 40);
            assert_eq!(direct.link, Duration::ZERO);

            let linked = bench_link_decrypt(&poseidon, &batch, &keys, &mut rng).unwrap();
            assert_eq!(linked.n_after_filter, batch.n_recurring);
        }
    }

    #[test]
    fn rejects_invalid_batch_parameters() {
        let mut rng = StdRng::seed_from_u64(42);
        let poseidon = Poseidon::new();
        let keys = Keys::generate(&mut rng);
        for n in [0, 1] {
            let error = build_batch(&poseidon, keys.pk_ag, n, 0.1, &mut rng)
                .err()
                .unwrap();
            assert!(error.to_string().contains("at least 2"));
        }
        for pct in [-0.1, 1.1, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let error = build_batch(&poseidon, keys.pk_ag, 2, pct, &mut rng)
                .err()
                .unwrap();
            assert!(error.to_string().contains("fraction must be in 0..=1"));
        }
    }

    #[test]
    fn both_strategies_open_the_minimum_batch() {
        let mut rng = StdRng::seed_from_u64(42);
        let poseidon = Poseidon::new();
        let keys = Keys::generate(&mut rng);
        for pct in [0.0, 0.1, 1.0] {
            let batch = build_batch(&poseidon, keys.pk_ag, 2, pct, &mut rng).unwrap();
            assert_eq!(batch.cfts.len(), 2);
            assert_eq!(batch.pid_threshold, 2);
            assert_eq!(batch.n_recurring, 2);
            assert_eq!(batch.n_unique, 0);
            assert_eq!(
                bench_direct_decrypt(&poseidon, &batch, &keys)
                    .unwrap()
                    .n_after_filter,
                2
            );
            assert_eq!(
                bench_link_decrypt(&poseidon, &batch, &keys, &mut rng)
                    .unwrap()
                    .n_after_filter,
                2
            );
        }
    }
}
