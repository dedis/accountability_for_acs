//! Packed status-list Merkle trees with all-zero leaves, for any node type and
//! node hash: Poseidon ([`PackedTree::build`]) or SHAKE256 (`pq::revocation`).
//!
//! Every leaf is zero, so a level's two children are always equal and the whole
//! tree collapses to one hash per level. Witness generation is `O(depth)`
//! instead of `O(leaves)`.

use babyjub::curve::Fq;
use babyjub::poseidon::Poseidon;

/// Number of leaves needed for `population` credentials at `bits_per_leaf`,
/// rounded up to a power of two.
pub fn packed_leaf_count(population: u64, bits_per_leaf: u32) -> u64 {
    let leaves = population.div_ceil(u64::from(bits_per_leaf));
    leaves.next_power_of_two()
}

/// Depth of the packed tree for `population` credentials.
pub fn packed_merkle_depth(population: u64, bits_per_leaf: u32) -> u32 {
    packed_leaf_count(population, bits_per_leaf).trailing_zeros()
}

/// A uniform all-zero tree: `level_hash[i]` is the value of every node at
/// level `i`, and `level_hash[depth]` is the root.
pub struct PackedTree<T = Fq> {
    level_hash: Vec<T>,
    pub depth: u32,
    pub bits_per_leaf: u32,
}

impl<T: Copy> PackedTree<T> {
    /// The tree for `population` credentials, with leaves `zero` and a parent
    /// being `node(left, right)`.
    pub fn from_zero(
        population: u64,
        bits_per_leaf: u32,
        zero: T,
        node: impl Fn(&T, &T) -> T,
    ) -> Self {
        let depth = packed_leaf_count(population, bits_per_leaf).trailing_zeros();
        let mut level_hash = Vec::with_capacity(depth as usize + 1);
        level_hash.push(zero);
        for i in 0..depth as usize {
            let child = level_hash[i];
            level_hash.push(node(&child, &child));
        }

        Self {
            level_hash,
            depth,
            bits_per_leaf,
        }
    }

    pub fn root(&self) -> T {
        self.level_hash[self.depth as usize]
    }

    /// The leaf and the bit of `credential_index`.
    pub fn position(&self, credential_index: u64) -> (u64, u64) {
        let bits = u64::from(self.bits_per_leaf);
        (credential_index / bits, credential_index % bits)
    }

    /// The siblings of any leaf, bottom-up.
    pub fn path(&self) -> &[T] {
        &self.level_hash[..self.depth as usize]
    }
}

impl PackedTree {
    pub fn build(poseidon: &Poseidon, population: u64, bits_per_leaf: u32) -> Self {
        Self::from_zero(population, bits_per_leaf, Fq::from(0u64), |l, r| {
            poseidon.hash(&[*l, *r])
        })
    }

    /// Witness that `credential_index` is not revoked.
    pub fn proof_for(&self, credential_index: u64) -> PackedProof {
        let (leaf_index, bit_index) = self.position(credential_index);

        let path_elements = self.path().iter().map(Fq::to_string).collect();
        let path_indices = (0..self.depth)
            .map(|i| ((leaf_index >> i) & 1).to_string())
            .collect();

        PackedProof {
            leaf_index: leaf_index.to_string(),
            bit_index: bit_index.to_string(),
            leaf_value: "0".to_string(),
            path_elements,
            path_indices,
            revocation_root: self.root().to_string(),
        }
    }
}

/// The revocation half of a witness input, as decimal strings.
pub struct PackedProof {
    pub leaf_index: String,
    pub bit_index: String,
    pub leaf_value: String,
    pub path_elements: Vec<String>,
    pub path_indices: Vec<String>,
    pub revocation_root: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_matches_the_recorded_scales() {
        // Populations 2^12…2^24 at 253 bits per leaf, as the paper reports.
        assert_eq!(packed_merkle_depth(1 << 12, 253), 5);
        assert_eq!(packed_merkle_depth(1 << 16, 253), 9);
        assert_eq!(packed_merkle_depth(1 << 20, 253), 13);
        assert_eq!(packed_merkle_depth(1 << 24, 253), 17);
    }

    #[test]
    fn every_level_of_a_zero_tree_is_one_hash() {
        let poseidon = Poseidon::new();
        let tree = PackedTree::build(&poseidon, 1 << 12, 253);
        assert_eq!(tree.depth, 5);

        let mut node = Fq::from(0u64);
        for _ in 0..tree.depth {
            node = poseidon.hash(&[node, node]);
        }
        assert_eq!(node, tree.root());
    }

    #[test]
    fn packed_position_splits_index_into_leaf_and_bit() {
        let poseidon = Poseidon::new();
        let tree = PackedTree::build(&poseidon, 1 << 12, 253);
        let proof = tree.proof_for(600);
        assert_eq!(proof.leaf_index, "2");
        assert_eq!(proof.bit_index, "94");
        assert_eq!(proof.path_elements.len(), 5);
        assert_eq!(proof.path_indices, ["0", "1", "0", "0", "0"]);
    }
}
