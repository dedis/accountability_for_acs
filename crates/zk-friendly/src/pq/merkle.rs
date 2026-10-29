//! SHAKE256 Merkle trees over credential leaves
//! ([`super::credential::Credential::leaf`]): a parent is
//! `SHAKE256(left || right)`.

use anyhow::Result;
use pqc::shake::{self, Digest};

/// A SHAKE256 Merkle tree.
pub type MerkleTree = crate::merkle::MerkleTree<Digest>;

/// A parent node: `SHAKE256(left || right)`.
pub fn node(left: &Digest, right: &Digest) -> Digest {
    shake::digest(&[left, right])
}

/// The tree of `leaves`.
pub fn build(leaves: &[Digest]) -> Result<MerkleTree> {
    MerkleTree::from_leaves(leaves, node)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_recomputes_the_root() {
        let leaves: Vec<Digest> = (0u8..8).map(|i| shake::digest(&[&[i]])).collect();
        let tree = build(&leaves).unwrap();
        assert_eq!(tree.depth(), 3);
        for (index, leaf) in leaves.iter().enumerate() {
            assert_eq!(tree.proof(index, 3).unwrap().root(*leaf, node), tree.root());
        }
        let mut changed = leaves[5];
        changed[0] ^= 1;
        assert_ne!(tree.proof(5, 3).unwrap().root(changed, node), tree.root());
        assert!(build(&leaves[..6]).is_err());
    }
}
