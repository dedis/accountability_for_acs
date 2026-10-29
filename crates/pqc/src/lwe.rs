//! Module-LWE encryption with a key shared by the three authorities: the LPR
//! scheme over `R_q = Z_q[X]/(X^256 + 1)`, `q = 8380417`, as `third_party/longfellow-zk/lib/circuits/tests/pq/
//! credential/lwe.h`, which the post-quantum credential proof checks.
//!
//! EXPERIMENTAL, NOT AUDITED. The parameters mirror the Module-LWE instance
//! of ML-DSA at the same `q`: rank `K = 5` and secrets and errors uniform in
//! `[-ETA, ETA]` with `ETA = 4` for category 3 (ML-DSA-65); `K = 7`,
//! `ETA = 2` with the `level-5` feature (ML-DSA-87). `tools/lwe_estimate.py`
//! checks with the lattice estimator that the key-share and ciphertext
//! instances cost at least as much to attack as the ML-DSA instance of the
//! same category.
//!
//! The arithmetic on secrets is constant-time. `matches_the_known_answer`
//! and the C++ `Lwe.MatchesTheRustKnownAnswer` check that this code and
//! `lwe.h` give the same ciphertext.
//!
//! The public matrix `A` (`K x K`, NTT domain) is ML-DSA's `ExpandA` of a
//! public 32-byte seed. The key has [`SLOTS`] slots, one per message
//! polynomial. Each authority contributes, per slot, `t_i = A s_i + e_i` with
//! small `s_i, e_i`, and keeps `s_i` as its share; the public key is
//! `T = sum_i t_i`, so the joint secret is `S = sum_i s_i`, as the ElGamal key
//! `P = aG + bG + cG`. Each authority publishes a commitment to `t_i` before
//! any `t_i` ([`Contribution::commitment`]). With `R, E1, E2` small:
//!
//! ```text
//! U   = A^T R + E1
//! V_j = T_j^T R + E2_j + floor(q/2) M_j
//! ```
//!
//! Decryption runs in the MPC: each authority computes its
//! [`DecryptionShare`] `[i = 0] V - <S_i, U>`; [`combine`] adds them modulo
//! `q` and rounds. A decryption share has no flooding noise: [`K`] of them
//! give the authority's key share by linear algebra. They must go only into
//! the MPC as private inputs.
//!
//! Share refresh: each authority deals shares of zero ([`Share::deal_zero`])
//! and every authority adds what it receives ([`Share::refresh`]). The sum
//! `S`, the public key and every stored ciphertext stay the same; the old
//! shares no longer decrypt with the new ones. The refreshed shares are
//! uniform modulo `q`; decryption needs only `S` to be small.

use anyhow::{bail, ensure, Result};
use rand::{CryptoRng, Rng};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::Zeroize;

use crate::shake::{Digest, DIGEST_BYTES};

/// The ML-DSA prime.
pub const Q: u32 = 8_380_417;
/// Ring degree.
pub const N: usize = 256;
/// Module rank.
pub const K: usize = if cfg!(feature = "level-5") { 7 } else { 5 };
/// Secrets and errors are uniform in `[-ETA, ETA]`.
pub const ETA: u32 = if cfg!(feature = "level-5") { 2 } else { 4 };
/// Key slots, one message polynomial each.
pub const SLOTS: usize = 3;
/// Message length: one bit per coefficient of the [`SLOTS`] polynomials.
pub const MSG_BYTES: usize = SLOTS * N / 8;
/// Authorities that share the key (police, judge, NGO).
pub const PARTIES: usize = 3;

/// Bound on `|V - <S, U> - floor(q/2) M|`: with `S = sum s_i`,
/// `E = sum e_i` (`PARTIES * ETA` per coefficient), it is
/// `E^T R + E2 - S^T E1`, at most `2 K N (PARTIES ETA) ETA + ETA`.
pub const NOISE_BOUND: u32 = (2 * K * N * PARTIES) as u32 * ETA * ETA + ETA;
// Decryption never fails: the noise stays below q/4.
const _: () = assert!(NOISE_BOUND < Q / 4);

/// A polynomial, coefficients in `[0, q)`.
pub type Poly = [u32; N];
/// `K` polynomials.
pub type Vector = [Poly; K];

/// `zetas[k] = 1753^BitRev8(k) mod q` (FIPS 204, Appendix B).
const ZETAS: [u32; N] = {
    let mut z = [0u32; N];
    let mut k = 0;
    while k < N {
        let mut e = 0;
        let mut b = 0;
        while b < 8 {
            e |= ((k >> b) & 1) << (7 - b);
            b += 1;
        }
        let mut acc = 1u64;
        let mut base = 1753u64;
        while e > 0 {
            if e & 1 == 1 {
                acc = acc * base % Q as u64;
            }
            base = base * base % Q as u64;
            e >>= 1;
        }
        z[k] = acc as u32;
        k += 1;
    }
    z
};

// Constant time: no branch, no memory index and no division depends on a
// secret value.

/// `0xffff_ffff` if `x`, as an `i32`, is negative, else 0.
#[inline]
fn sign_mask(x: u32) -> u32 {
    ((x as i32) >> 31) as u32
}

/// `x mod q` for `x` in `[0, 2q)`.
#[inline]
fn reduce_once(x: u32) -> u32 {
    let s = x.wrapping_sub(Q);
    s.wrapping_add(Q & sign_mask(s))
}

#[inline]
fn add(a: u32, b: u32) -> u32 {
    reduce_once(a + b)
}

#[inline]
fn sub(a: u32, b: u32) -> u32 {
    reduce_once(a + Q - b)
}

/// `floor(2^64 / q)`, for Barrett reduction.
const BARRETT: u128 = (1u128 << 64) / Q as u128;

#[inline]
fn mul(a: u32, b: u32) -> u32 {
    // x < 2^46, so the quotient estimate is at most 1 too small.
    let x = u64::from(a) * u64::from(b);
    let quotient = ((u128::from(x) * BARRETT) >> 64) as u64;
    reduce_once((x - quotient * u64::from(Q)) as u32)
}

/// Number-theoretic transform in place (FIPS 204, Algorithm 41).
pub fn ntt(w: &mut Poly) {
    let mut m = 0;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            m += 1;
            let z = ZETAS[m];
            for j in start..start + len {
                let t = mul(z, w[j + len]);
                w[j + len] = sub(w[j], t);
                w[j] = add(w[j], t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Inverse transform in place (FIPS 204, Algorithm 42).
pub fn inv_ntt(w: &mut Poly) {
    let mut m = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            m -= 1;
            let z = Q - ZETAS[m];
            for j in start..start + len {
                let t = w[j];
                w[j] = add(t, w[j + len]);
                w[j + len] = mul(z, sub(t, w[j + len]));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    // 256^-1 mod q.
    for x in w.iter_mut() {
        *x = mul(*x, 8_347_681);
    }
}

/// `acc += a o b` in the NTT domain.
fn mul_acc(acc: &mut Poly, a: &Poly, b: &Poly) {
    for ((x, &y), &z) in acc.iter_mut().zip(a).zip(b) {
        *x = add(*x, mul(y, z));
    }
}

fn add_assign(a: &mut Poly, b: &Poly) {
    for (x, &y) in a.iter_mut().zip(b) {
        *x = add(*x, y);
    }
}

fn ntt_of(p: &Poly) -> Poly {
    let mut r = *p;
    ntt(&mut r);
    r
}

/// `v - ETA` modulo `q`, for `v` in `[0, 2 ETA]`.
#[inline]
fn centered(v: u32) -> u32 {
    let x = v.wrapping_sub(ETA);
    x.wrapping_add(Q & sign_mask(x))
}

/// Random draws of [`small`] and [`uniform`] before they stop. Which draws
/// are rejected does not depend on the value returned.
const MAX_DRAWS: usize = 32;

/// Uniform in `[-ETA, ETA]`, as an integer modulo `q`: a random byte below the largest multiple of `2 ETA + 1`. At most 4 of 256 bytes
/// are rejected, so [`MAX_DRAWS`] rejections occur with probability below
/// `2^-192`.
fn small<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> u32 {
    const RANGE: u32 = 2 * ETA + 1;
    for _ in 0..MAX_DRAWS {
        let b = u32::from(rng.gen::<u8>());
        if b < 256 - 256 % RANGE {
            return centered(b % RANGE);
        }
    }
    panic!("the random generator gave {MAX_DRAWS} rejected bytes in a row")
}

/// Uniform modulo `q`: 23 random bits below `q`. 8191 of `2^23` values are
/// rejected, so [`MAX_DRAWS`] rejections occur with probability below
/// `2^-320`.
fn uniform<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> u32 {
    for _ in 0..MAX_DRAWS {
        let x = rng.gen::<u32>() & 0x7f_ffff;
        if x < Q {
            return x;
        }
    }
    panic!("the random generator gave {MAX_DRAWS} rejected values in a row")
}

fn small_poly<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Poly {
    std::array::from_fn(|_| small(rng))
}

fn uniform_poly<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Poly {
    std::array::from_fn(|_| uniform(rng))
}

/// SHAKE128 blocks read per polynomial of `A`, as `lwe.h`
/// (`RejNTTPoly(in, 5)`): 280 candidates for 256 coefficients.
const REJ_BLOCKS: usize = 5;

/// `RejNTTPoly(seed || col || row)` (FIPS 204, Algorithm 30), reading at most
/// [`REJ_BLOCKS`] SHAKE128 blocks.
fn rej_ntt_poly(seed: &[u8; 32], col: u8, row: u8) -> Result<Poly> {
    let mut xof = sha3::Shake128::default();
    xof.update(seed);
    xof.update(&[col, row]);
    let mut stream = [0u8; REJ_BLOCKS * 168];
    xof.finalize_xof().read(&mut stream);
    let mut p = [0u32; N];
    let mut n = 0;
    for b in stream.as_chunks::<3>().0 {
        // CoeffFromThreeBytes (FIPS 204, Algorithm 14).
        let z = u32::from(b[2] & 0x7f) << 16 | u32::from(b[1]) << 8 | u32::from(b[0]);
        if z < Q {
            p[n] = z;
            n += 1;
            if n == N {
                return Ok(p);
            }
        }
    }
    bail!("seed gives fewer than {N} coefficients in {REJ_BLOCKS} SHAKE128 blocks")
}

/// The public matrix of a seed, `a_hat[row][col]`, in the NTT domain.
pub type Matrix = Box<[Vector; K]>;

/// `ExpandA(seed)` (FIPS 204, Algorithm 32).
pub fn expand_a(seed: &[u8; 32]) -> Result<Matrix> {
    let mut a = Box::new([[[0u32; N]; K]; K]);
    for (row, r) in a.iter_mut().enumerate() {
        for (col, p) in r.iter_mut().enumerate() {
            *p = rej_ntt_poly(seed, col as u8, row as u8)?;
        }
    }
    Ok(a)
}

/// `A_hat S_hat + NTT(E)` for one slot, in the NTT domain.
fn a_times(a: &Matrix, s_hat: &Vector, e: &Vector) -> Vector {
    std::array::from_fn(|row| {
        let mut acc = ntt_of(&e[row]);
        for col in 0..K {
            mul_acc(&mut acc, &a[row][col], &s_hat[col]);
        }
        acc
    })
}

/// What one authority publishes at key generation: `t_i = A s_i + e_i` for
/// every slot, in the NTT domain.
pub struct Contribution {
    t_hat: Box<[Vector; SLOTS]>,
}

impl Contribution {
    /// What authority `who` publishes before any contribution, for the key
    /// generation of `seed`: `SHAKE256(seed || who || t_i)`. The
    /// contributions are revealed only once every commitment is public, so no
    /// authority can choose its own as a function of the others' (for example
    /// `A s + e - t_j - t_k`, which would give it the whole key). Each key
    /// generation takes a fresh seed, so a contribution revealed in an
    /// aborted one matches no later commitment.
    ///
    /// Not checked: that `t_i` is well formed (small `s_i`, `e_i` under this
    /// `A`). A malformed contribution makes every decryption fail, without
    /// showing which authority made it.
    pub fn commitment(&self, seed: &[u8; 32], who: usize) -> Digest {
        let mut xof = sha3::Shake256::default();
        xof.update(seed);
        xof.update(&(who as u64).to_le_bytes());
        for x in self.t_hat.iter().flatten().flatten() {
            xof.update(&x.to_le_bytes());
        }
        let mut out = [0u8; DIGEST_BYTES];
        xof.finalize_xof().read(&mut out);
        out
    }
}

/// One authority's secret share `s_i` of every slot, in the NTT domain. Set
/// to zero when dropped; copies the compiler makes on the stack are not.
#[derive(Clone)]
pub struct Share {
    s_hat: Box<[Vector; SLOTS]>,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.s_hat.zeroize();
    }
}

/// One authority's key generation: a small share and its contribution to
/// the public key.
pub fn contribute<R: Rng + CryptoRng + ?Sized>(a: &Matrix, rng: &mut R) -> (Share, Contribution) {
    let mut s = Box::new([[[0u32; N]; K]; SLOTS]);
    let mut e = Box::new([[[0u32; N]; K]; SLOTS]);
    for p in s.iter_mut().chain(e.iter_mut()).flatten() {
        *p = small_poly(rng);
    }
    let out = contribution_of(a, &s, &e);
    s.zeroize();
    e.zeroize();
    out
}

/// The share and the contribution of the small secret `s` and error `e`.
fn contribution_of(a: &Matrix, s: &[Vector; SLOTS], e: &[Vector; SLOTS]) -> (Share, Contribution) {
    let mut s_hat = Box::new([[[0u32; N]; K]; SLOTS]);
    let mut t_hat = Box::new([[[0u32; N]; K]; SLOTS]);
    for (((sh, t), s), e) in s_hat.iter_mut().zip(t_hat.iter_mut()).zip(s).zip(e) {
        *sh = std::array::from_fn(|c| ntt_of(&s[c]));
        *t = a_times(a, sh, e);
    }
    (Share { s_hat }, Contribution { t_hat })
}

/// The joint public key: the seed of `A` and `T = sum_i t_i`.
pub struct PublicKey {
    a: Matrix,
    t_hat: Box<[Vector; SLOTS]>,
}

impl PublicKey {
    /// The key of the authorities' contributions, each checked against the
    /// commitment its authority published first.
    pub fn new(
        seed: &[u8; 32],
        contributions: &[Contribution; PARTIES],
        commitments: &[Digest; PARTIES],
    ) -> Result<Self> {
        for (who, (c, h)) in contributions.iter().zip(commitments).enumerate() {
            ensure!(
                c.commitment(seed, who) == *h,
                "authority {who}'s contribution does not match its commitment"
            );
        }
        let mut t_hat = Box::new([[[0u32; N]; K]; SLOTS]);
        for c in contributions {
            for (t, ci) in t_hat.iter_mut().zip(c.t_hat.iter()) {
                for (p, q) in t.iter_mut().zip(ci) {
                    add_assign(p, q);
                }
            }
        }
        Ok(Self {
            a: expand_a(seed)?,
            t_hat,
        })
    }
}

/// `(U, V)`, coefficients in `[0, q)`. Only [`encrypt`] makes one.
#[derive(Clone)]
pub struct Ciphertext {
    u: Box<Vector>,
    v: Box<[Poly; SLOTS]>,
}

impl Ciphertext {
    /// Size of the ciphertext with 23-bit coefficients.
    pub const BYTES: usize = (K + SLOTS) * N * 23 / 8;

    /// `SHAKE256` of the coefficients of `U` then `V`, little-endian: the
    /// ciphertext's identity in an opening log.
    pub fn digest(&self) -> Digest {
        let mut xof = sha3::Shake256::default();
        for x in self.u.iter().chain(self.v.iter()).flatten() {
            xof.update(&x.to_le_bytes());
        }
        let mut out = [0u8; DIGEST_BYTES];
        xof.finalize_xof().read(&mut out);
        out
    }
}

/// Bit `i` of `m` (bit `i % 8` of byte `i / 8`): coefficient `i % N` of slot
/// `i / N`, as `lwe.h`.
fn bit(m: &[u8; MSG_BYTES], i: usize) -> u32 {
    u32::from(m[i / 8] >> (i % 8)) & 1
}

/// Encrypts `m` under `pk`.
pub fn encrypt<R: Rng + CryptoRng + ?Sized>(
    pk: &PublicKey,
    m: &[u8; MSG_BYTES],
    rng: &mut R,
) -> Ciphertext {
    let mut r: Vector = std::array::from_fn(|_| small_poly(rng));
    let mut e1: Vector = std::array::from_fn(|_| small_poly(rng));
    let mut e2: [Poly; SLOTS] = std::array::from_fn(|_| small_poly(rng));
    let ct = encrypt_with(pk, m, &r, &e1, &e2);
    r.zeroize();
    e1.zeroize();
    e2.zeroize();
    ct
}

/// Encrypts `m` under `pk` with the small `r`, `e1` and `e2`.
fn encrypt_with(
    pk: &PublicKey,
    m: &[u8; MSG_BYTES],
    r: &Vector,
    e1: &Vector,
    e2: &[Poly; SLOTS],
) -> Ciphertext {
    let mut r_hat: Vector = std::array::from_fn(|c| ntt_of(&r[c]));
    let u = Box::new(std::array::from_fn(|i| {
        let mut acc = [0u32; N];
        for (c, r) in r_hat.iter().enumerate() {
            mul_acc(&mut acc, &pk.a[c][i], r);
        }
        inv_ntt(&mut acc);
        add_assign(&mut acc, &e1[i]);
        acc
    }));
    let v = Box::new(std::array::from_fn(|j| {
        let mut acc = [0u32; N];
        for (t, r) in pk.t_hat[j].iter().zip(&r_hat) {
            mul_acc(&mut acc, t, r);
        }
        inv_ntt(&mut acc);
        add_assign(&mut acc, &e2[j]);
        for (k, x) in acc.iter_mut().enumerate() {
            *x = add(*x, (Q / 2) & 0u32.wrapping_sub(bit(m, j * N + k)));
        }
        acc
    }));
    r_hat.zeroize();
    Ciphertext { u, v }
}

/// One authority's additive share of `V - <S, U>`, coefficients modulo `q`.
/// Secret: see the module documentation. Set to zero when dropped.
pub struct DecryptionShare(Box<[Poly; SLOTS]>);

impl DecryptionShare {
    /// The coefficients, slot by slot.
    pub fn coefficients(&self) -> &[Poly; SLOTS] {
        &self.0
    }
}

impl Drop for DecryptionShare {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Share {
    /// This authority's decryption share: `V - <s_i, U>` for the authority
    /// with `first` set (exactly one), `-<s_i, U>` for the others.
    pub fn decrypt(&self, ct: &Ciphertext, first: bool) -> DecryptionShare {
        let u_hat: Vector = std::array::from_fn(|c| ntt_of(&ct.u[c]));
        DecryptionShare(Box::new(std::array::from_fn(|j| {
            let mut acc = [0u32; N];
            for (s, u) in self.s_hat[j].iter().zip(&u_hat) {
                mul_acc(&mut acc, s, u);
            }
            inv_ntt(&mut acc);
            let base = if first { ct.v[j] } else { [0u32; N] };
            let share = std::array::from_fn(|k| sub(base[k], acc[k]));
            acc.zeroize();
            share
        })))
    }

    /// One authority's deal of a refresh: [`PARTIES`] uniform shares of zero,
    /// the `i`-th for authority `i` (its own included). Each is sent over a
    /// private channel; dropping the deal sets it to zero.
    pub fn deal_zero<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> [Share; PARTIES] {
        let mut deal: [Share; PARTIES] = std::array::from_fn(|_| Share {
            s_hat: Box::new([[[0u32; N]; K]; SLOTS]),
        });
        let (last, rest) = deal.split_last_mut().expect("PARTIES > 0");
        for d in rest {
            for (slot, last_slot) in d.s_hat.iter_mut().zip(last.s_hat.iter_mut()) {
                for (p, lp) in slot.iter_mut().zip(last_slot.iter_mut()) {
                    *p = uniform_poly(rng);
                    for (x, y) in lp.iter_mut().zip(p.iter()) {
                        *x = sub(*x, *y);
                    }
                }
            }
        }
        deal
    }

    /// Adds the shares of zero this authority received, one from every
    /// dealer (itself included): `s_i' = s_i + sum of the deals`.
    pub fn refresh(&mut self, received: [&Share; PARTIES]) {
        for d in received {
            for (slot, ds) in self.s_hat.iter_mut().zip(d.s_hat.iter()) {
                for (p, q) in slot.iter_mut().zip(ds) {
                    add_assign(p, q);
                }
            }
        }
    }
}

/// Adds the authorities' decryption shares modulo `q` and rounds: bit 1 where
/// the sum is closer to `q/2` than to 0. In the protocol, this runs in the
/// MPC (`crates/revocation/mpc/lwe_decrypt.mpc`).
pub fn combine(shares: &[DecryptionShare; PARTIES]) -> [u8; MSG_BYTES] {
    let mut m = [0u8; MSG_BYTES];
    for j in 0..SLOTS {
        for k in 0..N {
            let w = shares.iter().fold(0, |acc, s| add(acc, s.0[j][k]));
            // Q / 4 < w and w < Q - Q / 4, from the signs of the differences.
            let one =
                (sign_mask((Q / 4).wrapping_sub(w)) & sign_mask(w.wrapping_sub(Q - Q / 4))) & 1;
            let i = j * N + k;
            m[i / 8] |= (one as u8) << (i % 8);
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Schoolbook product in `Z_q[X]/(X^256 + 1)`.
    fn negacyclic(a: &Poly, b: &Poly) -> Poly {
        let mut r = [0u32; N];
        for i in 0..N {
            for j in 0..N {
                let p = mul(a[i], b[j]);
                if i + j < N {
                    r[i + j] = add(r[i + j], p);
                } else {
                    r[i + j - N] = sub(r[i + j - N], p);
                }
            }
        }
        r
    }

    /// The authorities' shares and the public key.
    fn setup(rng: &mut StdRng) -> ([Share; PARTIES], PublicKey) {
        let seed = [7u8; 32];
        let a = expand_a(&seed).unwrap();
        let (shares, contributions): (Vec<_>, Vec<_>) =
            (0..PARTIES).map(|_| contribute(&a, rng)).unzip();
        let pk = joint_key(&seed, contributions).unwrap();
        (shares.try_into().ok().expect("PARTIES shares"), pk)
    }

    /// Commit, then reveal: the key of honest authorities.
    fn joint_key(seed: &[u8; 32], contributions: Vec<Contribution>) -> Result<PublicKey> {
        let contributions: [Contribution; PARTIES] = contributions
            .try_into()
            .ok()
            .expect("PARTIES contributions");
        let commitments = std::array::from_fn(|i| contributions[i].commitment(seed, i));
        PublicKey::new(seed, &contributions, &commitments)
    }

    #[test]
    fn a_contribution_must_match_its_commitment() {
        let mut rng = StdRng::seed_from_u64(8);
        let seed = [7u8; 32];
        let a = expand_a(&seed).unwrap();
        let mut contributions: [Contribution; PARTIES] =
            std::array::from_fn(|_| contribute(&a, &mut rng).1);
        let mut commitments = std::array::from_fn(|i| contributions[i].commitment(&seed, i));
        assert!(PublicKey::new(&seed, &contributions, &commitments).is_ok());
        // A commitment is bound to its authority.
        commitments.swap(0, 1);
        assert!(PublicKey::new(&seed, &contributions, &commitments).is_err());
        commitments.swap(0, 1);
        // Authority 2 changes its contribution after the commitments.
        contributions[2] = contribute(&a, &mut rng).1;
        let error = PublicKey::new(&seed, &contributions, &commitments)
            .err()
            .unwrap();
        assert!(error.to_string().contains("authority 2"), "{error}");
        // A commitment is bound to its key generation.
        contributions[2] = contribute(&a, &mut rng).1;
        let commitments = std::array::from_fn(|i| contributions[i].commitment(&seed, i));
        assert!(PublicKey::new(&[8u8; 32], &contributions, &commitments).is_err());
    }

    fn decrypt(shares: &[Share; PARTIES], ct: &Ciphertext) -> [u8; MSG_BYTES] {
        combine(&std::array::from_fn(|i| shares[i].decrypt(ct, i == 0)))
    }

    fn message(rng: &mut StdRng) -> [u8; MSG_BYTES] {
        std::array::from_fn(|_| rng.gen())
    }

    /// A wrong key gives about half of the 768 bits wrong; require a third.
    fn mostly_wrong(got: &[u8; MSG_BYTES], m: &[u8; MSG_BYTES]) -> bool {
        let wrong: u32 = got.iter().zip(m).map(|(a, b)| (a ^ b).count_ones()).sum();
        wrong >= (8 * MSG_BYTES / 3) as u32
    }

    #[test]
    fn samplers_are_uniform_over_their_range() {
        let mut rng = StdRng::seed_from_u64(7);
        const DRAWS: usize = 90_000;
        let range = (2 * ETA + 1) as usize;
        let mut counts = vec![0usize; range];
        for _ in 0..DRAWS {
            let x = small(&mut rng);
            let v = (x + ETA) % Q;
            assert!(v < range as u32, "small gave {x}");
            counts[v as usize] += 1;
        }
        // Each count is within 5% of DRAWS / range, at least 5 standard
        // deviations.
        for (v, &c) in counts.iter().enumerate() {
            assert!(c.abs_diff(DRAWS / range) * 20 <= DRAWS / range, "{v}: {c}");
        }
        let draws: Vec<u32> = (0..DRAWS).map(|_| uniform(&mut rng)).collect();
        assert!(draws.iter().all(|&x| x < Q));
        assert!(draws.iter().any(|&x| x < Q / 100));
        assert!(draws.iter().any(|&x| x > Q - Q / 100));
    }

    #[test]
    fn combine_rounds_at_the_quarters() {
        let share = |w: u32| DecryptionShare(Box::new([[w; N]; SLOTS]));
        let cases = [
            (0, 0),
            (1, 0),
            (Q / 4, 0),
            (Q / 4 + 1, 1),
            (Q / 2, 1),
            (Q - Q / 4 - 1, 1),
            (Q - Q / 4, 0),
            (Q - 1, 0),
        ];
        for (w, bit) in cases {
            let m = combine(&[share(w), share(0), share(0)]);
            assert_eq!(m, [0xffu8 * bit; MSG_BYTES], "w = {w}");
        }
        // The sum wraps modulo q: (q - 1) + (q - 1) + (q/2 + 2) = q/2.
        let m = combine(&[share(Q - 1), share(Q - 1), share(Q / 2 + 2)]);
        assert_eq!(m, [0xff; MSG_BYTES]);
    }

    #[test]
    fn arithmetic_matches_the_definitions() {
        let q = u64::from(Q);
        let mut rng = StdRng::seed_from_u64(6);
        let edges = [0, 1, 2, Q / 4, Q / 2, Q - Q / 4, Q - 2, Q - 1];
        let pairs = edges
            .iter()
            .flat_map(|&a| edges.iter().map(move |&b| (a, b)))
            .chain((0..100_000).map(|_| (rng.gen_range(0..Q), rng.gen_range(0..Q))));
        for (a, b) in pairs {
            let (x, y) = (u64::from(a), u64::from(b));
            assert_eq!(u64::from(add(a, b)), (x + y) % q, "{a} + {b}");
            assert_eq!(u64::from(sub(a, b)), (x + q - y) % q, "{a} - {b}");
            assert_eq!(u64::from(mul(a, b)), x * y % q, "{a} * {b}");
        }
        for v in 0..=2 * ETA {
            assert_eq!((centered(v) + ETA) % Q, v);
        }
    }

    /// Seed of the known-answer test, and of its public matrix.
    const KAT_SEED: [u8; 32] = [0x4b; 32];

    /// `SHAKE128(KAT_SEED || label)`.
    fn kat_bytes(label: &[u8], out: &mut [u8]) {
        let mut xof = sha3::Shake128::default();
        xof.update(&KAT_SEED);
        xof.update(label);
        xof.finalize_xof().read(out);
    }

    /// `P` small polynomials: byte `b` of [`kat_bytes`] gives the
    /// coefficient `b % (2 ETA + 1) - ETA`.
    fn kat_polys<const P: usize>(label: &[u8]) -> Box<[Poly; P]> {
        let mut bytes = vec![0u8; P * N];
        kat_bytes(label, &mut bytes);
        let mut p = Box::new([[0u32; N]; P]);
        for (x, &b) in p.iter_mut().flatten().zip(&bytes) {
            *x = centered(u32::from(b) % (2 * ETA + 1));
        }
        p
    }

    /// [`SLOTS`] vectors, slot by slot.
    fn kat_slots(label: &[u8]) -> Box<[Vector; SLOTS]> {
        let flat = kat_polys::<{ SLOTS * K }>(label);
        Box::new(std::array::from_fn(|j| {
            std::array::from_fn(|c| flat[j * K + c])
        }))
    }

    /// The known answer `testdata/lwe_kat_<category>.txt` next to `lwe.h`,
    /// which `Lwe.MatchesTheRustKnownAnswer` (`pq_credential_test.cc`) checks
    /// with the C++ reference and the encryption circuit. Authority `i` has
    /// the secret `s_i` and the error `e_i` of the labels `"s" i` and
    /// `"e" i`; the encryption has `r`, `e1`, `e2` of the labels `"r"`,
    /// `"e1"`, `"e2"` and the message of `"m"`. The file holds `U` and `V`,
    /// then the three commitments (Rust only: `lwe.h` has no commitments).
    /// `PQC_WRITE_LWE_KAT=1` rewrites it.
    #[test]
    fn matches_the_known_answer() {
        let a = expand_a(&KAT_SEED).unwrap();
        let (shares, contributions): (Vec<_>, Vec<_>) = (0..PARTIES as u8)
            .map(|i| contribution_of(&a, &kat_slots(&[b's', i]), &kat_slots(&[b'e', i])))
            .unzip();
        let commitments: Vec<String> = contributions
            .iter()
            .enumerate()
            .map(|(i, c)| {
                c.commitment(&KAT_SEED, i)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            })
            .collect();
        let pk = joint_key(&KAT_SEED, contributions).unwrap();
        let mut m = [0u8; MSG_BYTES];
        kat_bytes(b"m", &mut m);
        let ct = encrypt_with(
            &pk,
            &m,
            &kat_polys::<K>(b"r"),
            &kat_polys::<K>(b"e1"),
            &kat_polys::<SLOTS>(b"e2"),
        );

        let line = |name: &str, polys: &[Poly]| {
            let coefficients: Vec<String> = polys.iter().flatten().map(u32::to_string).collect();
            format!("{name} {}\n", coefficients.join(" "))
        };
        let text = line("u", &ct.u[..])
            + &line("v", &ct.v[..])
            + &format!("commitments {}\n", commitments.join(" "));
        let path = format!(
            "{}/../../third_party/longfellow-zk/lib/circuits/tests/pq/credential/testdata/lwe_kat_{}.txt",
            env!("CARGO_MANIFEST_DIR"),
            if cfg!(feature = "level-5") { 5 } else { 3 }
        );
        if std::env::var_os("PQC_WRITE_LWE_KAT").is_some() {
            std::fs::write(&path, &text).unwrap();
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);

        let shares: [Share; PARTIES] = shares.try_into().ok().expect("PARTIES shares");
        assert_eq!(decrypt(&shares, &ct), m);
    }

    /// Entries of `kZetas` in
    /// `third_party/longfellow-zk/lib/circuits/tests/pq/ml_dsa/ml_dsa_shared.h`.
    #[test]
    fn zetas_match_the_ml_dsa_table() {
        assert_eq!(ZETAS[0], 1);
        assert_eq!(ZETAS[1], 4_808_194);
        assert_eq!(ZETAS[2], 3_765_607);
        assert_eq!(ZETAS[3], 3_761_513);
        assert_eq!(ZETAS[254], 1_054_478);
        assert_eq!(ZETAS[255], 7_648_983);
    }

    #[test]
    fn ntt_product_is_the_negacyclic_product() {
        let mut rng = StdRng::seed_from_u64(1);
        let a = uniform_poly(&mut rng);
        let b = uniform_poly(&mut rng);
        let mut p = [0u32; N];
        mul_acc(&mut p, &ntt_of(&a), &ntt_of(&b));
        inv_ntt(&mut p);
        assert_eq!(p, negacyclic(&a, &b));
        let mut back = ntt_of(&a);
        inv_ntt(&mut back);
        assert_eq!(back, a);
    }

    #[test]
    fn expand_a_is_deterministic_and_seeded() {
        let a = expand_a(&[1u8; 32]).unwrap();
        assert_eq!(a, expand_a(&[1u8; 32]).unwrap());
        assert_ne!(a, expand_a(&[2u8; 32]).unwrap());
        assert!(a.iter().flatten().flatten().all(|&x| x < Q));
    }

    #[test]
    fn the_three_shares_decrypt() {
        let mut rng = StdRng::seed_from_u64(2);
        let (shares, pk) = setup(&mut rng);
        for m in [[0u8; MSG_BYTES], [0xffu8; MSG_BYTES], message(&mut rng)] {
            let ct = encrypt(&pk, &m, &mut rng);
            assert_eq!(decrypt(&shares, &ct), m);
        }
    }

    #[test]
    fn two_shares_do_not_decrypt() {
        let mut rng = StdRng::seed_from_u64(3);
        let (shares, pk) = setup(&mut rng);
        let m = message(&mut rng);
        let ct = encrypt(&pk, &m, &mut rng);
        let mut partial = shares.clone();
        partial[2] = Share {
            s_hat: Box::new([[[0u32; N]; K]; SLOTS]),
        };
        assert!(mostly_wrong(&decrypt(&partial, &ct), &m));
    }

    #[test]
    fn refresh_keeps_the_key_and_old_ciphertexts() {
        let mut rng = StdRng::seed_from_u64(4);
        let (old, pk) = setup(&mut rng);
        let m = message(&mut rng);
        let ct = encrypt(&pk, &m, &mut rng);

        // Every authority deals shares of zero; authority i receives the
        // i-th share of every deal.
        let deals: Vec<[Share; PARTIES]> =
            (0..PARTIES).map(|_| Share::deal_zero(&mut rng)).collect();
        let mut new = old.clone();
        for (i, share) in new.iter_mut().enumerate() {
            share.refresh(std::array::from_fn(|d| &deals[d][i]));
        }

        // The ciphertext encrypted before the refresh, and a new one under the
        // same public key, decrypt with the new shares.
        assert_eq!(decrypt(&new, &ct), m);
        let m2 = message(&mut rng);
        assert_eq!(decrypt(&new, &encrypt(&pk, &m2, &mut rng)), m2);

        // An old share does not decrypt with two new ones.
        for i in 0..PARTIES {
            let mut mixed = new.clone();
            mixed[i] = old[i].clone();
            assert!(
                mostly_wrong(&decrypt(&mixed, &ct), &m),
                "old share {i} still decrypts"
            );
        }
    }

    #[test]
    fn noise_stays_below_the_bound() {
        let mut rng = StdRng::seed_from_u64(5);
        let (shares, pk) = setup(&mut rng);
        let m = [0u8; MSG_BYTES];
        let ct = encrypt(&pk, &m, &mut rng);
        let ds: [DecryptionShare; PARTIES] =
            std::array::from_fn(|i| shares[i].decrypt(&ct, i == 0));
        for j in 0..SLOTS {
            for k in 0..N {
                let w = ds.iter().fold(0, |acc, s| add(acc, s.0[j][k]));
                let noise = w.min(Q - w);
                assert!(noise <= NOISE_BOUND, "noise {noise} above {NOISE_BOUND}");
            }
        }
    }
}
