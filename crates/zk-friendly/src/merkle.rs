//! Binary Merkle trees over a power-of-two number of leaves, for any node
//! type and node hash: Poseidon over the BN254 scalar field
//! ([`crate::poseidon_merkle`]) or SHAKE256 (`pq::merkle`).

use anyhow::{bail, Result};

/// A binary Merkle tree.
pub struct MerkleTree<T> {
    /// `levels[0]` are the leaves; the last level is the single root.
    levels: Vec<Vec<T>>,
}

impl<T: Copy> MerkleTree<T> {
    /// The tree of `leaves`, a parent being `node(left, right)`.
    pub fn from_leaves(leaves: &[T], node: impl Fn(&T, &T) -> T) -> Result<Self> {
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
                .map(|[left, right]| node(left, right))
                .collect();
            levels.push(next);
        }

        Ok(Self { levels })
    }

    pub fn root(&self) -> T {
        self.levels.last().expect("non-empty")[0]
    }

    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// Sibling path for `index`, truncated or extended to `depth` levels.
    pub fn proof(&self, index: usize, depth: usize) -> Result<MerkleProof<T>> {
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
pub struct MerkleProof<T> {
    pub path_elements: Vec<T>,
    pub path_indices: Vec<u8>,
}

impl<T: Copy> MerkleProof<T> {
    /// The root this path gives for `leaf`.
    pub fn root(&self, leaf: T, node: impl Fn(&T, &T) -> T) -> T {
        self.path_elements
            .iter()
            .zip(&self.path_indices)
            .fold(leaf, |acc, (sibling, &side)| {
                if side == 1 {
                    node(sibling, &acc)
                } else {
                    node(&acc, sibling)
                }
            })
    }
}
