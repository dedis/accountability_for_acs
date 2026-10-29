//! The classical CFT (ElGamal over Baby Jubjub): batch construction and the
//! two revocation strategies under measurement. The post-quantum CFT is
//! [`crate::lwe_cft`].

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::panic;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Result};
use ark_ec::CurveGroup;
use ark_ff::Field;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

use crate::c4::{self, Scheme};
use babyjub::curve::{base8, rand_scalar, Fr, Point, PointAffine};
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

/// One conditionally-openable tag, with a C4 signature of type `S`.
#[derive(Clone, Copy, Debug)]
pub struct Cft<S> {
    pub c1: Point,
    pub c2: Point,
    pub c3: Point,
    pub c4: S,
    pub t: Fr,
}

/// A batch of CFTs with one identity deliberately repeated.
pub struct Batch<S> {
    pub cfts: Vec<Cft<S>>,
    pub n_recurring: usize,
    pub n_unique: usize,
    pub recurring_pct: f64,
    pub pid_threshold: usize,
}

/// Builds `n` CFTs, of which `recurring_pct` (at least the PID threshold) share
/// one identity. `C4 = Sign(H(t, D2))` under that identity's `scheme` key (see
/// [`crate::c4`]). Key generation and signing run on all available cores.
/// Requires at least two CFTs and a recurring fraction in `0..=1`.
pub fn build_batch<S: Scheme, R: Rng + ?Sized>(
    scheme: &S,
    pk_ag: Point,
    n: usize,
    recurring_pct: f64,
    rng: &mut R,
) -> Result<Batch<S::Signature>> {
    ensure!(n >= 2, "CFT batch size must be at least 2, got {n}");
    ensure!(
        (0.0..=1.0).contains(&recurring_pct),
        "recurring fraction must be in 0..=1, got {recurring_pct}"
    );
    let pid_threshold = usize::max(2, (n as f64 * 0.1).ceil() as usize);
    let n_recurring = usize::max((n as f64 * recurring_pct).round() as usize, pid_threshold);
    let n_unique = n - n_recurring;

    // User 0 is the recurring identity; users 1..=n_unique occur once.
    let users = par_map(n_unique + 1, rng, Poseidon::new, |_, rng, _| {
        scheme.keygen(rng)
    })?;

    let mut slots: Vec<usize> = Vec::with_capacity(n);
    slots.extend(std::iter::repeat_n(0, n_recurring));
    slots.extend(1..=n_unique);
    slots.shuffle(rng);

    let cfts = par_map(n, rng, Poseidon::new, |i, rng, poseidon| {
        let (id_u, user_sk) = &users[slots[i]];
        let r1 = rand_scalar(rng);
        let r2 = rand_scalar(rng);
        let t = rand_scalar(rng);
        let d2 = (pk_ag * r2).into_affine();
        Ok(Cft {
            c1: base8() * r1,
            c2: base8() * r2,
            c3: *id_u + pk_ag * r1,
            c4: c4::sign(poseidon, scheme, user_sk, t, d2, rng)?,
            t,
        })
    })?;

    Ok(Batch {
        cfts,
        n_recurring,
        n_unique,
        recurring_pct,
        pid_threshold,
    })
}

/// Computes `f(i)` for `i` in `0..len` on all available cores and returns the
/// results in index order. Workers take the next index from a shared counter,
/// so slower cores take fewer items. Each worker has its own RNG, seeded from
/// `rng`, and its own state from `init` (a [`Poseidon`], which is not `Sync`).
pub(crate) fn par_map<T, S, R, I, F>(len: usize, rng: &mut R, init: I, f: F) -> Result<Vec<T>>
where
    T: Send,
    R: Rng + ?Sized,
    I: Fn() -> S + Sync,
    F: Fn(usize, &mut StdRng, &S) -> Result<T> + Sync,
{
    let workers = thread::available_parallelism()
        .map_or(1, NonZeroUsize::get)
        .min(len);
    let rngs = (0..workers)
        .map(|_| StdRng::from_rng(&mut *rng))
        .collect::<Result<Vec<_>, _>>()?;
    let next = AtomicUsize::new(0);
    let parts = thread::scope(|scope| {
        let handles: Vec<_> = rngs
            .into_iter()
            .map(|mut rng| {
                let (init, f, next) = (&init, &f, &next);
                scope.spawn(move || -> Result<Vec<(usize, T)>> {
                    let state = init();
                    let mut done = Vec::new();
                    for _ in 0..len {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= len {
                            break;
                        }
                        done.push((i, f(i, &mut rng, &state)?));
                    }
                    Ok(done)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| panic::resume_unwind(e)))
            .collect::<Result<Vec<_>>>()
    })?;
    let mut out: Vec<(usize, T)> = parts.into_iter().flatten().collect();
    out.sort_unstable_by_key(|&(i, _)| i);
    Ok(out.into_iter().map(|(_, x)| x).collect())
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
fn partial_decrypt<S>(cft: &Cft<S>, sk: Fr) -> Share {
    Share {
        d1: cft.c1 * sk,
        d2: cft.c2 * sk,
    }
}

/// Direct decrypt: every CFT is opened, so `n_after_filter == n`.
pub fn bench_direct_decrypt<S: Scheme>(
    poseidon: &Poseidon,
    scheme: &S,
    batch: &Batch<S::Signature>,
    keys: &Keys,
) -> Result<Timing> {
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
        if !c4::verify(poseidon, scheme, id_u, cft.t, d2.into_affine(), &cft.c4) {
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

/// A CFT in flight through the sequential unlink chain. It borrows the CFT so
/// that large C4 signatures are not copied.
struct LinkEntry<'a, S> {
    cft: &'a Cft<S>,
    d1: Point,
    d3: Point,
}

/// Re-randomises `(D1, D3)` under one authority's key and a fresh blinding `k`.
fn batch_link<S, R: Rng + ?Sized>(entries: &mut [LinkEntry<S>], sk: Fr, rng: &mut R) -> Fr {
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
fn retain_recurring<S>(entries: &mut Vec<LinkEntry<S>>, min_count: usize) {
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
pub fn bench_link_decrypt<S: Scheme, R: Rng + ?Sized>(
    poseidon: &Poseidon,
    scheme: &S,
    batch: &Batch<S::Signature>,
    keys: &Keys,
    rng: &mut R,
) -> Result<Timing> {
    let n = batch.cfts.len();
    let min_count = batch.pid_threshold;

    let mut entries: Vec<LinkEntry<S::Signature>> = batch
        .cfts
        .iter()
        .map(|cft| LinkEntry {
            cft,
            d1: cft.c1,
            d3: cft.c3,
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
    let mut d2: Vec<Point> = entries.iter().map(|e| e.cft.c2 * keys.ngo.sk).collect();
    let ngo_dec = t0.elapsed();

    let t0 = Instant::now();
    let inv_judge = k_judge.inverse().expect("blinding factor is non-zero");
    for ((p, acc), e) in pid.iter_mut().zip(d2.iter_mut()).zip(entries.iter()) {
        *p *= inv_judge;
        *acc += e.cft.c2 * keys.judge.sk;
    }
    let judge_dec = t0.elapsed();

    let t0 = Instant::now();
    let inv_police = k_police.inverse().expect("blinding factor is non-zero");
    for ((p, acc), e) in pid.iter().zip(d2.iter()).zip(entries.iter()) {
        let id = (*p * inv_police).into_affine();
        let d2 = (*acc + e.cft.c2 * keys.police.sk).into_affine();
        if !c4::verify(poseidon, scheme, id, e.cft.t, d2, &e.cft.c4) {
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
    use crate::c4::EdDsa;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn open_batch<S: Scheme>(scheme: &S, n: usize, pcts: &[f64]) {
        let mut rng = StdRng::seed_from_u64(42);
        let poseidon = Poseidon::new();
        let keys = Keys::generate(&mut rng);

        for &pct in pcts {
            let batch = build_batch(scheme, keys.pk_ag, n, pct, &mut rng).unwrap();
            let direct = bench_direct_decrypt(&poseidon, scheme, &batch, &keys).unwrap();
            assert_eq!(direct.n_after_filter, n);
            assert_eq!(direct.link, Duration::ZERO);

            let linked = bench_link_decrypt(&poseidon, scheme, &batch, &keys, &mut rng).unwrap();
            assert_eq!(linked.n_after_filter, batch.n_recurring);
        }
    }

    #[test]
    fn both_strategies_open_a_batch() {
        open_batch(&EdDsa, 40, &[0.1, 0.5]);
    }

    #[test]
    fn rejects_invalid_batch_parameters() {
        let mut rng = StdRng::seed_from_u64(42);
        let keys = Keys::generate(&mut rng);
        for n in [0, 1] {
            let error = build_batch(&EdDsa, keys.pk_ag, n, 0.1, &mut rng)
                .err()
                .unwrap();
            assert!(error.to_string().contains("at least 2"));
        }
        for pct in [-0.1, 1.1, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let error = build_batch(&EdDsa, keys.pk_ag, 2, pct, &mut rng)
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
            let batch = build_batch(&EdDsa, keys.pk_ag, 2, pct, &mut rng).unwrap();
            assert_eq!(batch.cfts.len(), 2);
            assert_eq!(batch.pid_threshold, 2);
            assert_eq!(batch.n_recurring, 2);
            assert_eq!(batch.n_unique, 0);
            assert_eq!(
                bench_direct_decrypt(&poseidon, &EdDsa, &batch, &keys)
                    .unwrap()
                    .n_after_filter,
                2
            );
            assert_eq!(
                bench_link_decrypt(&poseidon, &EdDsa, &batch, &keys, &mut rng)
                    .unwrap()
                    .n_after_filter,
                2
            );
        }
    }
}
