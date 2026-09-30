//! circomlib-compatible Poseidon over the Baby Jubjub base field.
//!
//! Replaces the `circomlibjs` `buildPoseidon()` singleton. Round constants are
//! built once per arity and reused, which is what made the JS singleton worth
//! having in the first place.

use std::cell::RefCell;

use light_poseidon::{Poseidon as Inner, PoseidonHasher};

use crate::curve::Fq;

/// Largest arity `light-poseidon` has circom parameters for (width 13).
pub const MAX_ARITY: usize = light_poseidon::MAX_X5_LEN - 1;

/// Lazily-built, reusable Poseidon instances, one per arity.
///
/// Hashing needs a scratch state, so the instances live behind a [`RefCell`]:
/// callers see a pure `hash(&self, ..)` and the type stays single-threaded,
/// which is all the sequential benchmarks need.
pub struct Poseidon {
    by_arity: Vec<RefCell<Option<Inner<Fq>>>>,
}

impl Poseidon {
    pub fn new() -> Self {
        Self {
            by_arity: (0..=MAX_ARITY).map(|_| RefCell::new(None)).collect(),
        }
    }

    /// `poseidon(inputs)`, identical to `circomlibjs`'s `poseidon(...)`.
    ///
    /// # Panics
    /// If `inputs` is empty or longer than [`MAX_ARITY`] — a wrong arity is a
    /// programming error, not an input the benchmarks can encounter.
    pub fn hash(&self, inputs: &[Fq]) -> Fq {
        let arity = inputs.len();
        assert!(
            (1..=MAX_ARITY).contains(&arity),
            "poseidon arity {arity} outside 1..={MAX_ARITY}"
        );
        let mut slot = self.by_arity[arity].borrow_mut();
        let hasher = slot.get_or_insert_with(|| {
            Inner::<Fq>::new_circom(arity).expect("circom poseidon parameters")
        });
        hasher.hash(inputs).expect("poseidon hash")
    }
}

impl Default for Poseidon {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;

    /// Reference values produced with `circomlibjs@0.1.7`.
    #[test]
    fn matches_circomlibjs() {
        let p = Poseidon::new();
        let fe = |v: u64| Fq::from(v);

        assert_eq!(
            p.hash(&[fe(1)]).into_bigint().to_string(),
            "18586133768512220936620570745912940619677854269274689475585506675881198879027"
        );
        assert_eq!(
            p.hash(&[fe(1), fe(2)]).into_bigint().to_string(),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
        assert_eq!(
            p.hash(&[fe(1), fe(2), fe(3)]).into_bigint().to_string(),
            "6542985608222806190361240322586112750744169038454362455181422643027100751666"
        );
        assert_eq!(
            p.hash(&[fe(1), fe(2), fe(3), fe(4), fe(5)])
                .into_bigint()
                .to_string(),
            "6183221330272524995739186171720101788151706631170188140075976616310159254464"
        );
    }

    #[test]
    fn matches_circomlibjs_on_wide_field_elements() {
        let p = Poseidon::new();
        let big: Fq =
            "21888242871839275222246405745257275088548364400416034343698204186575808495616"
                .parse()
                .unwrap();
        let inputs = [
            big,
            "12345678901234567890".parse().unwrap(),
            Fq::from(1u64),
            Fq::from(0u64),
            "99999999999999999999999999".parse().unwrap(),
        ];
        assert_eq!(
            p.hash(&inputs).into_bigint().to_string(),
            "8092119150866166796428442625361806364008550899680488400265480027463804218068"
        );
    }
}
