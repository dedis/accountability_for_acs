//! The post-quantum CFT (`pq` feature): threshold Module-LWE encryption
//! ([`pqc::lwe`]) of `ID || r2` under the key the police, the judge and the
//! NGO share, as the post-quantum credential proof
//! (`third_party/longfellow-zk/lib/circuits/tests/pq/credential`).
//!
//! The identity is `ID = SHAKE256(pk_user, 64 bytes)`; the police finds the
//! user's public key by `ID` in a registry. The user's key is of the
//! signature chosen at compile time ([`Selected`]).
//!
//! `C4 = Sign_user(SHAKE256(t || r2))`, with `t` the event tag of the request
//! ([`pqc::shake::event_tag`]), is a private input of the presentation proof:
//! ML-DSA and SLH-DSA signatures show their public key without the message,
//! so a public C4 would identify the user. The proof shows that C4 verifies
//! under the key whose `ID` the CFT encrypts, and that the public binding
//! `h = SHAKE256(ID || r2)` ([`binding`]) hashes the encrypted message. The
//! fresh 256-bit `r2` hides `ID` in `h`.
//!
//! Opening order: every authority first verifies the proof the verifier
//! stored (it binds the ciphertext and `h`; opening an unchecked ciphertext
//! would be a decryption oracle). Each MPC run opens one CFT. After it, the
//! opened `ID || r2` must hash to `h`: a mismatch shows that an authority
//! changed its decryption share, for example to point the opening at another
//! user. The honest authorities then stop all openings, and they never open
//! a ciphertext twice ([`OpeningLog`], kept with the key). An authority that
//! changes its share, with CFTs of chosen randomness from a colluding user,
//! still learns one comparison per coefficient of one component of the joint
//! key per opening while no bit flips, and then the bits of the opening
//! that halts. This crate has no proof: it checks `h` and that the opened
//! `ID` is registered.
//!
//! Decryption: each authority computes its decryption share
//! ([`lwe::Share::decrypt`]); the MPC (`mpc/lwe_decrypt.mpc`) adds them and
//! reveals only `ID || r2`. [`bench_direct_decrypt`] combines the shares
//! natively with the same arithmetic ([`lwe::combine`]), to time the
//! authorities' work; `revocation_lwe_mpc` times the MPC.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Result};
use pqc::lwe::{self, Ciphertext, DecryptionShare, PublicKey, Share, MSG_BYTES, PARTIES};
use pqc::shake;
use pqc::sig::PqSig;
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng};

use crate::cft::{par_map, Timing};

/// The C4 signature scheme of the build.
pub type Selected = pqc::sig::Selected;
/// Name of [`Selected`].
pub const C4_NAME: &str = <Selected as PqSig>::NAME;

/// Identity length: `SHAKE256(pk, 64 bytes)` (`tr` of ML-DSA, FIPS 204).
pub const ID_BYTES: usize = 64;
/// Length of `r2`.
pub const R2_BYTES: usize = 32;
const _: () = assert!(ID_BYTES + R2_BYTES == MSG_BYTES);

/// A user identity.
pub type Id = [u8; ID_BYTES];

/// Indices of the authorities in the share arrays. The police holds the
/// share that adds `V` ([`lwe::Share::decrypt`] with `first`).
pub const POLICE: usize = 0;
pub const JUDGE: usize = 1;
pub const NGO: usize = 2;

/// The three authorities' key shares and their joint public key.
pub struct Authorities {
    pub shares: [Share; PARTIES],
    pub pk: PublicKey,
    /// The openings under this key. It lives as long as the key: a refresh
    /// keeps it, since the joint key `S` does not change.
    pub log: OpeningLog,
}

impl Authorities {
    /// Distributed key generation: a public random seed for `A`; each
    /// authority's share and contribution; every commitment published, then
    /// every contribution.
    pub fn generate<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let seed: [u8; 32] = rng.gen();
        let a = lwe::expand_a(&seed)?;
        let (s0, c0) = lwe::contribute(&a, rng);
        let (s1, c1) = lwe::contribute(&a, rng);
        let (s2, c2) = lwe::contribute(&a, rng);
        let commitments = [
            c0.commitment(&seed, 0),
            c1.commitment(&seed, 1),
            c2.commitment(&seed, 2),
        ];
        Ok(Self {
            pk: PublicKey::new(&seed, &[c0, c1, c2], &commitments)?,
            shares: [s0, s1, s2],
            log: OpeningLog::default(),
        })
    }

    /// Authority `who`'s decryption share of `ct`.
    pub fn decryption_share(&self, who: usize, ct: &Ciphertext) -> DecryptionShare {
        self.shares[who].decrypt(ct, who == POLICE)
    }

    /// Refreshes the shares (rotation): every authority deals shares of zero
    /// and adds the ones it receives. Run here in one process; in a
    /// deployment, each deal goes over private channels.
    pub fn refresh<R: Rng + CryptoRng + ?Sized>(&mut self, rng: &mut R) {
        let deals: [[Share; PARTIES]; PARTIES] = std::array::from_fn(|_| Share::deal_zero(rng));
        for (i, share) in self.shares.iter_mut().enumerate() {
            share.refresh(std::array::from_fn(|d| &deals[d][i]));
        }
    }
}

/// `ID = SHAKE256(pk, 64 bytes)`.
pub fn id_of<P: PqSig>(pk: &P::PublicKey) -> Id {
    shake::shake256(&[&P::public_key_bytes(pk)])
}

/// `h = SHAKE256(ID || r2)`, the public binding of a CFT to its message.
pub fn binding(m: &[u8; MSG_BYTES]) -> shake::Digest {
    shake::digest(&[m])
}

/// One conditionally-openable tag: the encryption of `ID || r2` and its
/// binding `h`.
pub struct Cft {
    pub ct: Ciphertext,
    pub h: shake::Digest,
}

/// What the honest authority enforces around openings, under the paper's
/// model (one honest authority of three, which aborts when it sees a
/// deviation): one CFT per MPC run, checked against its binding before the
/// next opens; no ciphertext is opened twice; and after an opening that
/// fails any check, no CFT is opened again under this key.
///
/// Why: a corrupt authority with a colluding user can open a CFT of chosen
/// randomness (`R = 0`, `E1` a unit vector) and add an offset to its
/// decryption share. Each opened bit then compares one coefficient of the
/// joint key with a threshold it chose. While no bit flips, `h` matches and
/// the opening looks honest, so it learns lower bounds; the first flip shows
/// the deviation and stops all openings. Without the halt, or with a log that
/// a restart or a refresh resets, binary search recovers the key in about 25
/// openings.
///
/// The log must live as long as the key ([`Authorities::log`]); in a
/// deployment, each honest authority keeps it on its own node, on disk. Any
/// failure halts, not only a mismatch with `h`: a crash after the reveal
/// would otherwise give an opening without a check. This lets any authority
/// stop openings, which it can do anyway by refusing.
///
/// A user may present the same ciphertext in several shows; it is opened
/// once, and that opening names the ID for all of them.
#[derive(Default)]
pub struct OpeningLog {
    opened: HashSet<shake::Digest>,
    halted: bool,
}

impl OpeningLog {
    /// Admits `cft` to an opening: `false` if its ciphertext was opened
    /// before (the earlier opening names the ID), an error once openings are
    /// halted.
    pub fn admit(&mut self, cft: &Cft) -> Result<bool> {
        ensure!(
            !self.halted,
            "openings are halted: an earlier opening failed its checks"
        );
        Ok(self.opened.insert(cft.ct.digest()))
    }

    /// Checks the opened message of `cft` against its binding.
    pub fn check(&mut self, cft: &Cft, m: &[u8; MSG_BYTES]) -> Result<()> {
        if binding(m) != cft.h {
            self.halt();
            bail!("the opened message does not match the CFT's binding: an authority deviated");
        }
        Ok(())
    }

    /// Stops all later openings, after an opening that failed a check.
    pub fn halt(&mut self) {
        self.halted = true;
    }
}

/// The users' public keys, by identity.
pub type Registry<P> = HashMap<Id, <P as PqSig>::PublicKey>;

/// A batch of CFTs with one identity deliberately repeated, and the registry
/// of its users.
pub struct Batch<P: PqSig> {
    pub cfts: Vec<Cft>,
    pub registry: Registry<P>,
    pub n_recurring: usize,
    pub n_unique: usize,
    pub recurring_pct: f64,
    pub pid_threshold: usize,
}

/// Builds `n` CFTs, of which `recurring_pct` (at least the PID threshold) share
/// one identity, as [`crate::cft::build_batch`]. Key generation, signing and
/// encryption run on all available cores. Requires at least two CFTs and a
/// recurring fraction in `0..=1`.
pub fn build_batch<P: PqSig, R: Rng + CryptoRng + ?Sized>(
    pk: &PublicKey,
    n: usize,
    recurring_pct: f64,
    rng: &mut R,
) -> Result<Batch<P>> {
    ensure!(n >= 2, "CFT batch size must be at least 2, got {n}");
    ensure!(
        (0.0..=1.0).contains(&recurring_pct),
        "recurring fraction must be in 0..=1, got {recurring_pct}"
    );
    let pid_threshold = usize::max(2, (n as f64 * 0.1).ceil() as usize);
    let n_recurring = usize::max((n as f64 * recurring_pct).round() as usize, pid_threshold);
    let n_unique = n - n_recurring;

    // User 0 is the recurring identity; users 1..=n_unique occur once.
    let users = par_map(n_unique + 1, rng, || (), |_, _, _| P::keygen())?;
    let mut registry = Registry::<P>::with_capacity(users.len());
    let mut ids = Vec::with_capacity(users.len());
    for (pk_user, _) in &users {
        let id = id_of::<P>(pk_user);
        if registry.insert(id, pk_user.clone()).is_some() {
            bail!("identity already registered");
        }
        ids.push(id);
    }

    let mut slots: Vec<usize> = Vec::with_capacity(n);
    slots.extend(std::iter::repeat_n(0, n_recurring));
    slots.extend(1..=n_unique);
    slots.shuffle(rng);

    let cfts = par_map(
        n,
        rng,
        || (),
        |i, rng, _| {
            let r2: [u8; R2_BYTES] = rng.gen();
            let mut m = [0u8; MSG_BYTES];
            m[..ID_BYTES].copy_from_slice(&ids[slots[i]]);
            m[ID_BYTES..].copy_from_slice(&r2);
            Ok(Cft {
                ct: lwe::encrypt(pk, &m, rng),
                h: binding(&m),
            })
        },
    )?;

    Ok(Batch {
        cfts,
        registry,
        n_recurring,
        n_unique,
        recurring_pct,
        pid_threshold,
    })
}

/// The registered key of the opened `ID || r2`, if any.
pub fn identify<'a, P: PqSig>(
    registry: &'a Registry<P>,
    m: &[u8; MSG_BYTES],
) -> Option<&'a P::PublicKey> {
    let id: &Id = m[..ID_BYTES].try_into().expect("ID_BYTES");
    registry.get(id)
}

/// Direct decrypt: every CFT is opened, so `n_after_filter == n`. The NGO and
/// the judge compute their decryption shares; the police computes its own,
/// combines the three as the MPC does ([`lwe::combine`]), checks the binding
/// and finds the registered key. A timing reference only: the police sees the others'
/// decryption shares, which give their key shares ([`pqc::lwe`]).
pub fn bench_direct_decrypt<P: PqSig>(
    batch: &Batch<P>,
    authorities: &mut Authorities,
) -> Result<Timing> {
    let cfts = &batch.cfts;
    let n = cfts.len();
    let shares_of = |who: usize| -> Vec<DecryptionShare> {
        cfts.iter()
            .map(|c| authorities.decryption_share(who, &c.ct))
            .collect()
    };

    let t0 = Instant::now();
    let ngo_shares = shares_of(NGO);
    let ngo = t0.elapsed();

    let t0 = Instant::now();
    let judge_shares = shares_of(JUDGE);
    let judge = t0.elapsed();

    let t0 = Instant::now();
    for ((cft, judge), ngo) in cfts.iter().zip(judge_shares).zip(ngo_shares) {
        ensure!(
            authorities.log.admit(cft)?,
            "a ciphertext of the batch was opened before"
        );
        let police = authorities.decryption_share(POLICE, &cft.ct);
        let m = lwe::combine(&[police, judge, ngo]);
        authorities.log.check(cft, &m)?;
        if identify::<P>(&batch.registry, &m).is_none() {
            authorities.log.halt();
            bail!("opened ID is not registered (direct-decrypt)");
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// The batch is small (2 recurring and 2 unique CFTs): SLH-DSA-SHAKE-192s
    /// and -256s sign in about 1.1 s.
    #[test]
    fn direct_decrypt_opens_a_batch() {
        let mut rng = StdRng::seed_from_u64(42);
        let mut authorities = Authorities::generate(&mut rng).unwrap();
        let batch = build_batch::<Selected, _>(&authorities.pk, 4, 0.5, &mut rng).unwrap();
        assert_eq!(batch.n_recurring, 2);
        assert_eq!(batch.registry.len(), 3);
        let timing = bench_direct_decrypt(&batch, &mut authorities).unwrap();
        assert_eq!(timing.n_after_filter, 4);
        assert_eq!(timing.link, Duration::ZERO);
    }

    #[test]
    fn refreshed_shares_open_old_cfts_and_keep_the_log() {
        let mut rng = StdRng::seed_from_u64(43);
        let mut authorities = Authorities::generate(&mut rng).unwrap();
        let before = build_batch::<Selected, _>(&authorities.pk, 2, 1.0, &mut rng).unwrap();
        let old = build_batch::<Selected, _>(&authorities.pk, 2, 1.0, &mut rng).unwrap();
        bench_direct_decrypt(&before, &mut authorities).unwrap();
        authorities.refresh(&mut rng);
        bench_direct_decrypt(&old, &mut authorities).unwrap();
        // The refresh keeps the key, so it keeps the log.
        let error = bench_direct_decrypt(&before, &mut authorities)
            .err()
            .unwrap();
        assert!(error.to_string().contains("opened before"), "{error}");
    }

    #[test]
    fn an_unregistered_id_is_rejected() {
        let mut rng = StdRng::seed_from_u64(44);
        let mut authorities = Authorities::generate(&mut rng).unwrap();
        let mut batch = build_batch::<Selected, _>(&authorities.pk, 2, 1.0, &mut rng).unwrap();
        batch.registry.clear();
        let error = bench_direct_decrypt(&batch, &mut authorities)
            .err()
            .unwrap();
        assert!(error.to_string().contains("not registered"), "{error}");
        assert!(authorities.log.admit(&batch.cfts[1]).is_err(), "not halted");
    }

    #[test]
    fn the_log_refuses_a_second_opening_and_halts_on_a_mismatch() {
        let mut rng = StdRng::seed_from_u64(46);
        let authorities = Authorities::generate(&mut rng).unwrap();
        let batch = build_batch::<Selected, _>(&authorities.pk, 2, 0.5, &mut rng).unwrap();
        let open = |cft: &Cft| {
            lwe::combine(&std::array::from_fn(|i| {
                authorities.decryption_share(i, &cft.ct)
            }))
        };
        let mut log = OpeningLog::default();
        let (first, second) = (&batch.cfts[0], &batch.cfts[1]);
        assert!(log.admit(first).unwrap());
        let mut m = open(first);
        log.check(first, &m).unwrap();
        assert!(!log.admit(first).unwrap(), "opened twice");
        // The same ciphertext with another binding is still the same CFT.
        let relabelled = Cft {
            ct: first.ct.clone(),
            h: [0; shake::DIGEST_BYTES],
        };
        assert!(!log.admit(&relabelled).unwrap(), "relabelled CFT opened");

        // An authority flips one bit of the opened ID.
        assert!(log.admit(second).unwrap());
        m = open(second);
        m[0] ^= 1;
        let error = log.check(second, &m).err().unwrap();
        assert!(error.to_string().contains("deviated"), "{error}");
        let error = log.admit(&batch.cfts[0]).err().unwrap();
        assert!(error.to_string().contains("halted"), "{error}");
    }

    #[test]
    fn rejects_invalid_batch_parameters() {
        let mut rng = StdRng::seed_from_u64(45);
        let authorities = Authorities::generate(&mut rng).unwrap();
        for n in [0, 1] {
            let error = build_batch::<Selected, _>(&authorities.pk, n, 0.1, &mut rng)
                .err()
                .unwrap();
            assert!(error.to_string().contains("at least 2"));
        }
        let error = build_batch::<Selected, _>(&authorities.pk, 2, 1.5, &mut rng)
            .err()
            .unwrap();
        assert!(error.to_string().contains("fraction must be in 0..=1"));
    }
}
