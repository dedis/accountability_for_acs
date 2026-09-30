//! Baby Jubjub in the circomlib / iden3 parameterisation.
//!
//! circomlib uses the twisted Edwards form `a·x² + y² = 1 + d·x²·y²` with
//! `a = 168700`, `d = 168696`, and publishes `Base8 = 8·G` as the generator of
//! the prime-order subgroup. Point coordinates therefore match `circomlibjs`
//! exactly, which the C4 tag binding and `prove_verify.circom` depend on.
//!
//! The base field is the BN254 scalar field and the subgroup order is the
//! `BABYJUB_ORDER` of the JavaScript sources, so [`Fr`] is the scalar type:
//! a value of type `Fr` is by construction already reduced, which is what the
//! JS `mod(...)` / `randomScalarMod(...)` helpers achieved by hand.

use ark_ec::{
    twisted_edwards::{Affine, MontCurveConfig, Projective, TECurveConfig},
    CurveConfig, PrimeGroup,
};
use ark_ff::{BigInteger, MontFp, PrimeField, UniformRand, Zero};
use rand::Rng;

pub use ark_ed_on_bn254::{Fq, Fr};

/// Baby Jubjub as circomlib parameterises it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BabyJub;

/// `Base8.x`, as hard-coded in `circomlibjs/src/babyjub.js`.
pub const BASE8_X: Fq =
    MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553");
/// `Base8.y`, as hard-coded in `circomlibjs/src/babyjub.js`.
pub const BASE8_Y: Fq =
    MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203");

impl CurveConfig for BabyJub {
    type BaseField = Fq;
    type ScalarField = Fr;

    const COFACTOR: &'static [u64] = &[8];
    const COFACTOR_INV: Fr =
        MontFp!("2394026564107420727433200628387514462817212225638746351800188703329891451411");
}

impl TECurveConfig for BabyJub {
    const COEFF_A: Fq = MontFp!("168700");
    const COEFF_D: Fq = MontFp!("168696");
    /// `Base8`, not the full-group generator: circom scalars live in the
    /// prime-order subgroup.
    const GENERATOR: Affine<Self> = Affine::new_unchecked(BASE8_X, BASE8_Y);

    type MontCurveConfig = BabyJub;
}

impl MontCurveConfig for BabyJub {
    const COEFF_A: Fq = MontFp!("168698");
    const COEFF_B: Fq = MontFp!("1");

    type TECurveConfig = BabyJub;
}

/// A Baby Jubjub point in extended projective coordinates.
pub type Point = Projective<BabyJub>;
/// A Baby Jubjub point in affine coordinates; usable as a map key.
pub type PointAffine = Affine<BabyJub>;

/// The subgroup generator `Base8 = 8·G`.
#[inline]
pub fn base8() -> Point {
    Point::generator()
}

/// A uniform non-zero scalar, the counterpart of the JS
/// `randomScalarMod(BABYJUB_ORDER, { nonZero: true })`.
///
/// The JS version reduced 32 random bytes modulo the order and was therefore
/// slightly biased; rejection sampling here is uniform.
pub fn rand_scalar<R: Rng + ?Sized>(rng: &mut R) -> Fr {
    loop {
        let s = Fr::rand(rng);
        if !s.is_zero() {
            return s;
        }
    }
}

/// Reinterprets a subgroup scalar as a base-field element.
///
/// Lossless: the subgroup order is smaller than the base-field modulus, so no
/// reduction happens. Mirrors the JS `F.e(scalarBigInt)`.
#[inline]
pub fn fr_to_fq(x: Fr) -> Fq {
    Fq::from_bigint(x.into_bigint()).expect("subgroup order < base field modulus")
}

/// Reduces a base-field element into the scalar field, as the JS
/// `mod(F.toObject(hm), BABYJUB_ORDER)` did.
#[inline]
pub fn fq_to_fr(x: Fq) -> Fr {
    Fr::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;

    /// Reference values produced with `circomlibjs@0.1.7`.
    #[test]
    fn matches_circomlibjs() {
        let b8 = base8().into_affine();
        assert_eq!(b8.x, BASE8_X);
        assert_eq!(b8.y, BASE8_Y);
        assert!(b8.is_on_curve());
        assert!(b8.is_in_correct_subgroup_assuming_on_curve());

        let k: Fr = "1234567890123456789012345".parse().unwrap();
        let p = (base8() * k).into_affine();
        assert_eq!(
            p.x.to_string(),
            "17084027705438691128279942923620192926581163627696297627213547159003096776489"
        );
        assert_eq!(
            p.y.to_string(),
            "3881444331700756826987030561315501339194664380148174259731173098087401857389"
        );

        let q = (base8() * k + base8()).into_affine();
        assert_eq!(
            q.x.to_string(),
            "4868890965890115361309652783356137926156731801348380780080109599608448123000"
        );
        assert_eq!(
            q.y.to_string(),
            "16387240194725096775186700164606574080407756875987493055581646965383765218740"
        );
    }

    #[test]
    fn subgroup_order_matches_babyjub_order_constant() {
        assert_eq!(
            Fr::MODULUS.to_string(),
            "2736030358979909402780800718157159386076813972158567259200215660948447373041"
        );
    }
}
