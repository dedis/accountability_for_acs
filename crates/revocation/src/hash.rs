//! The hash behind the classical C4 message and the PET C4 binding: Poseidon.
//! The post-quantum CFT ([`crate::lwe_cft`]) uses SHAKE256 ([`pqc::shake`]).

use babyjub::curve::Fq;
use babyjub::poseidon::Poseidon;

/// Hashes field elements to a field element with Poseidon.
#[inline]
pub fn to_fq(poseidon: &Poseidon, inputs: &[Fq]) -> Fq {
    poseidon.hash(inputs)
}
