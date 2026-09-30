//! Poseidon Merkle trees over credential claims.

use anyhow::{bail, Result};

use babyjub::curve::Fq;
use babyjub::poseidon::Poseidon;

/// `leaf = poseidon(poseidon(claimName), claimValue)`.
pub fn build_leaf(poseidon: &Poseidon, claim_name: Fq, claim_value: Fq) -> Fq {
    let name_hash = poseidon.hash(&[claim_name]);
    poseidon.hash(&[name_hash, claim_value])
}

/// A binary Poseidon Merkle tree over a power-of-two number of leaves.
pub struct MerkleTree {
    /// `levels[0]` are the leaves; the last level is the single root.
    levels: Vec<Vec<Fq>>,
}

impl MerkleTree {
    pub fn build(poseidon: &Poseidon, leaves: &[Fq]) -> Result<Self> {
        if leaves.is_empty() {
            bail!("MerkleTree::build: leaves must not be empty");
        }
        if !leaves.len().is_power_of_two() {
            bail!(
                "MerkleTree::build: leaf count must be a power of two, got {}",
                leaves.len()
            );
        }

        let mut levels = vec![leaves.to_vec()];
        while levels.last().expect("non-empty").len() > 1 {
            let current = levels.last().expect("non-empty");
            let next = current
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| poseidon.hash(pair))
                .collect();
            levels.push(next);
        }

        Ok(Self { levels })
    }

    pub fn root(&self) -> Fq {
        self.levels.last().expect("non-empty")[0]
    }

    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// Sibling path for `index`, truncated or extended to `depth` levels.
    pub fn proof(&self, index: usize, depth: usize) -> Result<MerkleProof> {
        if index >= self.levels[0].len() {
            bail!("MerkleTree::proof: index {index} out of range");
        }
        if depth == 0 || depth > self.depth() {
            bail!(
                "MerkleTree::proof: depth must be in 1..={}, got {depth}",
                self.depth()
            );
        }

        let mut idx = index;
        let mut path_elements = Vec::with_capacity(depth);
        let mut path_indices = Vec::with_capacity(depth);

        for level in &self.levels[..depth] {
            let is_right = idx & 1 == 1;
            let sibling = if is_right { idx - 1 } else { idx + 1 };
            path_elements.push(level[sibling]);
            path_indices.push(u8::from(is_right));
            idx /= 2;
        }

        Ok(MerkleProof {
            path_elements,
            path_indices,
        })
    }
}

/// An inclusion path: siblings bottom-up, with the side taken at each level.
pub struct MerkleProof {
    pub path_elements: Vec<Fq>,
    pub path_indices: Vec<u8>,
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
            let mut node = *leaf;
            for (sibling, side) in proof.path_elements.iter().zip(&proof.path_indices) {
                node = if *side == 1 {
                    poseidon.hash(&[*sibling, node])
                } else {
                    poseidon.hash(&[node, *sibling])
                };
            }
            assert_eq!(node, tree.root());
        }
    }
}
