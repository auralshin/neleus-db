use serde::{Deserialize, Serialize};

use crate::hash::{Hash, hash_typed};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_count: usize,
    pub index: usize,
    pub siblings: Vec<Hash>,
}

fn hash_pair(left: Hash, right: Hash) -> Hash {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(left.as_bytes());
    bytes[32..].copy_from_slice(right.as_bytes());
    hash_typed(b"merkle_node:", &bytes)
}

pub fn empty_root() -> Hash {
    hash_typed(b"merkle_node:", b"empty")
}

pub fn root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            next.push(hash_pair(left, right));
            i += 2;
        }
        level = next;
    }
    level[0]
}

pub fn prove_inclusion(leaves: &[Hash], index: usize) -> Option<MerkleProof> {
    if leaves.is_empty() || index >= leaves.len() {
        return None;
    }

    let mut siblings = Vec::new();
    let mut idx = index;
    let mut level = leaves.to_vec();

    while level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let sibling = if sibling_idx < level.len() {
            level[sibling_idx]
        } else {
            level[idx]
        };
        siblings.push(sibling);

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            next.push(hash_pair(left, right));
            i += 2;
        }
        level = next;
        idx /= 2;
    }

    Some(MerkleProof {
        leaf_count: leaves.len(),
        index,
        siblings,
    })
}

pub fn verify_inclusion(root_hash: Hash, leaf_hash: Hash, proof: &MerkleProof) -> bool {
    if proof.leaf_count == 0 || proof.index >= proof.leaf_count {
        return false;
    }

    let mut expected_levels = 0usize;
    let mut len = proof.leaf_count;
    while len > 1 {
        expected_levels += 1;
        len = len.div_ceil(2);
    }
    if expected_levels != proof.siblings.len() {
        return false;
    }

    let mut idx = proof.index;
    let mut current = leaf_hash;
    for sibling in &proof.siblings {
        current = if idx % 2 == 0 {
            hash_pair(current, *sibling)
        } else {
            hash_pair(*sibling, current)
        };
        idx /= 2;
    }

    current == root_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_typed;

    fn hs(n: u8) -> Hash {
        hash_typed(b"leaf:", &[n])
    }

    #[test]
    fn merkle_empty_root_stable() {
        assert_eq!(empty_root(), empty_root());
    }

    #[test]
    fn merkle_single_leaf_root_is_leaf() {
        let leaf = hs(1);
        assert_eq!(root(&[leaf]), leaf);
    }

    #[test]
    fn merkle_proof_verifies_for_each_leaf_even() {
        let leaves = vec![hs(1), hs(2), hs(3), hs(4)];
        let r = root(&leaves);
        for (idx, leaf) in leaves.iter().enumerate() {
            let p = prove_inclusion(&leaves, idx).unwrap();
            assert!(verify_inclusion(r, *leaf, &p));
        }
    }

    #[test]
    fn merkle_proof_verifies_for_each_leaf_odd() {
        let leaves = vec![hs(1), hs(2), hs(3), hs(4), hs(5)];
        let r = root(&leaves);
        for (idx, leaf) in leaves.iter().enumerate() {
            let p = prove_inclusion(&leaves, idx).unwrap();
            assert!(verify_inclusion(r, *leaf, &p));
        }
    }

    #[test]
    fn merkle_invalid_index_fails() {
        let leaves = vec![hs(1), hs(2)];
        assert!(prove_inclusion(&leaves, 2).is_none());
    }

    #[test]
    fn merkle_wrong_leaf_fails() {
        let leaves = vec![hs(1), hs(2), hs(3)];
        let r = root(&leaves);
        let p = prove_inclusion(&leaves, 0).unwrap();
        assert!(!verify_inclusion(r, hs(9), &p));
    }

    #[test]
    fn merkle_wrong_root_fails() {
        let leaves = vec![hs(1), hs(2), hs(3)];
        let p = prove_inclusion(&leaves, 0).unwrap();
        let wrong = root(&[hs(4), hs(5)]);
        assert!(!verify_inclusion(wrong, hs(1), &p));
    }

    #[test]
    fn merkle_tampered_proof_fails() {
        let leaves = vec![hs(1), hs(2), hs(3), hs(4)];
        let r = root(&leaves);
        let mut p = prove_inclusion(&leaves, 1).unwrap();
        p.siblings[0] = hs(9);
        assert!(!verify_inclusion(r, hs(2), &p));
    }
}
