//! The packed status list with SHAKE256: all-zero leaves of one digest, a
//! parent `SHAKE256(left || right)`, as the SHAKE256 revocation proof of the
//! standard stack (`third_party/longfellow-zk/lib/circuits/tests/ec`,
//! `PROOFS_EC_SHAKE256`).

use pqc::shake::{Digest, DIGEST_BYTES};

use super::merkle::node;
use crate::revocation_tree::PackedTree;

/// The status list of `population` credentials, `bits_per_leaf` status bits
/// per leaf.
pub fn status_tree(population: u64, bits_per_leaf: u32) -> PackedTree<Digest> {
    PackedTree::from_zero(population, bits_per_leaf, [0u8; DIGEST_BYTES], node)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_of_any_leaf_gives_the_root() {
        // 2^12 credentials, 253 bits per leaf: 17 leaves, padded to 32.
        let tree = status_tree(1 << 12, 253);
        assert_eq!(tree.depth, 5);
        let (leaf, bit) = tree.position(600);
        assert_eq!((leaf, bit), (2, 94));

        let mut acc = [0u8; DIGEST_BYTES];
        for (level, sibling) in tree.path().iter().enumerate() {
            acc = if (leaf >> level) & 1 == 1 {
                node(sibling, &acc)
            } else {
                node(&acc, sibling)
            };
        }
        assert_eq!(acc, tree.root());
    }
}
