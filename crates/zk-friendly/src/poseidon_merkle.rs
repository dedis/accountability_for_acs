//! Poseidon Merkle trees over credential claims.

use anyhow::Result;

use babyjub::curve::Fq;
use babyjub::poseidon::Poseidon;

/// A Poseidon Merkle tree.
pub type MerkleTree = crate::merkle::MerkleTree<Fq>;
/// An inclusion path in a [`MerkleTree`].
pub type MerkleProof = crate::merkle::MerkleProof<Fq>;

/// `leaf = poseidon(poseidon(claimName), claimValue)`.
pub fn build_leaf(poseidon: &Poseidon, claim_name: Fq, claim_value: Fq) -> Fq {
    let name_hash = poseidon.hash(&[claim_name]);
    poseidon.hash(&[name_hash, claim_value])
}

impl MerkleTree {
    /// The tree of `leaves`, a parent being `poseidon(left, right)`.
    pub fn build(poseidon: &Poseidon, leaves: &[Fq]) -> Result<Self> {
        Self::from_leaves(leaves, |l, r| poseidon.hash(&[*l, *r]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(poseidon: &Poseidon, n: u64) -> Vec<Fq> {
        (0..n)
            .map(|i| build_leaf(poseidon, Fq::from(i), Fq::from(i * 7 + 1)))
            .collect()
    }

    #[test]
    fn rejects_non_power_of_two() {
        let poseidon = Poseidon::new();
        assert!(MerkleTree::build(&poseidon, &leaves(&poseidon, 6)).is_err());
        assert!(MerkleTree::build(&poseidon, &[]).is_err());
    }

    #[test]
    fn proof_recomputes_the_root() {
        let poseidon = Poseidon::new();
        let leaves = leaves(&poseidon, 8);
        let tree = MerkleTree::build(&poseidon, &leaves).unwrap();
        assert_eq!(tree.depth(), 3);

        for (index, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(index, 3).unwrap();
            let root = proof.root(*leaf, |l, r| poseidon.hash(&[*l, *r]));
            assert_eq!(root, tree.root());
        }
    }
}
