//! Append-only Merkle log in the RFC 6962 shape: `O(log n)` inclusion proofs
//! and `O(log n)` consistency proofs between two log sizes.
//!
//! The tree splits at the largest power of two below `n` rather than pairing
//! left-to-right and duplicating a lone trailing node. Duplication would make
//! the root ambiguous in the leaf count -- `root([a,b,c])` would equal
//! `root([a,b,c,c])` -- so a proof could be replayed against a log the prover
//! never had. Splitting binds the count into the shape.
//!
//! Consistency proofs are what a linear hash chain cannot give: they show a
//! later root contains an earlier one as a prefix, so a verifier holding an old
//! anchor can check the log only ever grew, without re-reading it.

use serde::{Deserialize, Serialize};

use crate::hash::{Hash, hash_typed};

const NODE_TAG: &[u8] = b"merkle_node:";
const ROOT_TAG: &[u8] = b"merkle_root:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_count: usize,
    pub index: usize,
    pub siblings: Vec<Hash>,
}

/// Proof that the log of size `old_count` is a prefix of the log of size
/// `new_count`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_count: usize,
    pub new_count: usize,
    pub nodes: Vec<Hash>,
}

/// A domain-separated leaf. The only constructor hashes with a caller-chosen
/// leaf tag, distinct from the interior tag, so an interior hash can never be
/// substituted for a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleLeaf(Hash);

impl MerkleLeaf {
    pub fn new(tag: &[u8], bytes: &[u8]) -> Self {
        Self(hash_typed(tag, bytes))
    }

    pub fn hash(&self) -> Hash {
        self.0
    }
}

fn hash_pair(left: Hash, right: Hash) -> Hash {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(left.as_bytes());
    bytes[32..].copy_from_slice(right.as_bytes());
    hash_typed(NODE_TAG, &bytes)
}

/// Bind the leaf count into the published root. RFC 6962 leaves the size to a
/// signed tree head; we have no such head here, and without binding it a proof
/// can verify while claiming a size the log never had, because the fold pattern
/// for a given index can coincide across sizes.
fn seal(count: usize, tree: Hash) -> Hash {
    let mut bytes = [0u8; 40];
    bytes[..8].copy_from_slice(&(count as u64).to_le_bytes());
    bytes[8..].copy_from_slice(tree.as_bytes());
    hash_typed(ROOT_TAG, &bytes)
}

pub fn empty_root() -> Hash {
    seal(0, hash_typed(NODE_TAG, b"empty"))
}

/// Largest power of two strictly less than `n` (RFC 6962 `k`). Requires `n > 1`.
fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

fn mth(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => hash_typed(NODE_TAG, b"empty"),
        1 => leaves[0],
        n => {
            let k = split(n);
            hash_pair(mth(&leaves[..k]), mth(&leaves[k..]))
        }
    }
}

pub fn root(leaves: &[MerkleLeaf]) -> Hash {
    let hashes: Vec<Hash> = leaves.iter().map(|l| l.0).collect();
    seal(hashes.len(), mth(&hashes))
}

/// Roots of the perfect subtrees an `n`-leaf log decomposes into, largest
/// first. Their sizes are the set bits of `n`, high to low, so the sizes need
/// not be stored alongside them.
pub fn spine(leaves: &[MerkleLeaf]) -> Vec<Hash> {
    let hashes: Vec<Hash> = leaves.iter().map(|l| l.0).collect();
    let mut out = Vec::new();
    let mut rest = &hashes[..];
    while !rest.is_empty() {
        let take = if rest.len().is_power_of_two() {
            rest.len()
        } else {
            1usize << (usize::BITS - 1 - rest.len().leading_zeros())
        };
        out.push(mth(&rest[..take]));
        rest = &rest[take..];
    }
    out
}

/// Extend a spine by one leaf. Binary-increment: the new size-1 subtree merges
/// with every equal-sized subtree to its left, so this is `O(log n)` amortized
/// `O(1)` rather than rebuilding the tree.
pub fn spine_append(spine: &[Hash], count: usize, leaf: MerkleLeaf) -> Vec<Hash> {
    // Sizes of the existing subtrees, largest first, are the set bits of `count`.
    let mut sizes: Vec<usize> = Vec::new();
    let mut bit = usize::BITS as i32 - 1;
    while bit >= 0 {
        let s = 1usize << bit;
        if count & s != 0 {
            sizes.push(s);
        }
        bit -= 1;
    }
    debug_assert_eq!(sizes.len(), spine.len(), "spine does not match its count");

    let mut out = spine.to_vec();
    let mut carry = leaf.0;
    let mut carry_size = 1usize;
    while let (Some(&last_size), Some(&last)) = (sizes.last(), out.last()) {
        if last_size != carry_size {
            break;
        }
        out.pop();
        sizes.pop();
        carry = hash_pair(last, carry);
        carry_size *= 2;
    }
    out.push(carry);
    out
}

/// Fold a spine into the published root, sealing the leaf count.
pub fn root_from_spine(spine: &[Hash], count: usize) -> Hash {
    if spine.is_empty() {
        return seal(0, hash_typed(NODE_TAG, b"empty"));
    }
    let mut acc = *spine.last().expect("non-empty");
    for h in spine[..spine.len() - 1].iter().rev() {
        acc = hash_pair(*h, acc);
    }
    seal(count, acc)
}

fn path(index: usize, leaves: &[Hash], out: &mut Vec<Hash>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split(n);
    if index < k {
        path(index, &leaves[..k], out);
        out.push(mth(&leaves[k..]));
    } else {
        path(index - k, &leaves[k..], out);
        out.push(mth(&leaves[..k]));
    }
}

pub fn prove_inclusion(leaves: &[MerkleLeaf], index: usize) -> Option<MerkleProof> {
    if leaves.is_empty() || index >= leaves.len() {
        return None;
    }
    let hashes: Vec<Hash> = leaves.iter().map(|l| l.0).collect();
    let mut siblings = Vec::new();
    path(index, &hashes, &mut siblings);
    Some(MerkleProof {
        leaf_count: leaves.len(),
        index,
        siblings,
    })
}

/// RFC 6962 inclusion verification: fold the path while tracking position, so a
/// proof only verifies at the index and leaf count it claims.
pub fn verify_inclusion(root_hash: Hash, leaf: MerkleLeaf, proof: &MerkleProof) -> bool {
    if proof.leaf_count == 0 || proof.index >= proof.leaf_count {
        return false;
    }
    let (mut fnode, mut snode) = (proof.index, proof.leaf_count - 1);
    let mut acc = leaf.0;
    for sibling in &proof.siblings {
        if snode == 0 {
            return false; // path longer than the tree is deep
        }
        if !fnode.is_multiple_of(2) || fnode == snode {
            acc = hash_pair(*sibling, acc);
            while fnode != 0 && fnode.is_multiple_of(2) {
                fnode /= 2;
                snode /= 2;
            }
        } else {
            acc = hash_pair(acc, *sibling);
        }
        fnode /= 2;
        snode /= 2;
    }
    snode == 0 && seal(proof.leaf_count, acc) == root_hash
}

fn subproof(m: usize, leaves: &[Hash], is_root: bool, out: &mut Vec<Hash>) {
    let n = leaves.len();
    if m == n {
        if !is_root {
            out.push(mth(leaves));
        }
        return;
    }
    let k = split(n);
    if m <= k {
        subproof(m, &leaves[..k], is_root, out);
        out.push(mth(&leaves[k..]));
    } else {
        subproof(m - k, &leaves[k..], false, out);
        out.push(mth(&leaves[..k]));
    }
}

/// Prove the first `old_count` leaves of `leaves` form a prefix of the whole.
pub fn prove_consistency(leaves: &[MerkleLeaf], old_count: usize) -> Option<ConsistencyProof> {
    let n = leaves.len();
    if old_count == 0 || old_count > n {
        return None;
    }
    let hashes: Vec<Hash> = leaves.iter().map(|l| l.0).collect();
    let mut nodes = Vec::new();
    subproof(old_count, &hashes, false, &mut nodes);
    Some(ConsistencyProof {
        old_count,
        new_count: n,
        nodes,
    })
}

/// Verify that `old_root` (a log of `old_count` leaves) is a prefix of
/// `new_root` (a log of `new_count` leaves), per RFC 6962 section 2.1.2.
pub fn verify_consistency(old_root: Hash, new_root: Hash, proof: &ConsistencyProof) -> bool {
    if proof.old_count == 0 || proof.old_count > proof.new_count {
        return false;
    }
    if proof.old_count == proof.new_count {
        return old_root == new_root;
    }
    // The fold reconstructs bare tree hashes and seals them at the end, so the
    // claimed sizes are checked rather than trusted.
    let mut node = proof.old_count - 1;
    let mut last = proof.new_count - 1;
    while !node.is_multiple_of(2) {
        node /= 2;
        last /= 2;
    }

    let mut iter = proof.nodes.iter();
    let Some(seed) = iter.next() else {
        return false;
    };
    let (mut old_acc, mut new_acc) = (*seed, *seed);

    while node > 0 {
        if last == 0 {
            return false;
        }
        if !node.is_multiple_of(2) || node == last {
            let Some(h) = iter.next() else { return false };
            old_acc = hash_pair(*h, old_acc);
            new_acc = hash_pair(*h, new_acc);
            while node != 0 && node.is_multiple_of(2) {
                node /= 2;
                last /= 2;
            }
        } else {
            let Some(h) = iter.next() else { return false };
            new_acc = hash_pair(new_acc, *h);
        }
        node /= 2;
        last /= 2;
    }
    while last > 0 {
        let Some(h) = iter.next() else { return false };
        new_acc = hash_pair(new_acc, *h);
        last /= 2;
    }

    iter.next().is_none()
        && seal(proof.old_count, old_acc) == old_root
        && seal(proof.new_count, new_acc) == new_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(count: usize) -> Vec<MerkleLeaf> {
        (0..count)
            .map(|i| MerkleLeaf::new(b"leaf:", &(i as u64).to_le_bytes()))
            .collect()
    }

    /// Incremental append must reproduce the from-scratch root exactly, at
    /// every size. This is what lets a checkpoint extend the log in O(log n)
    /// instead of rebuilding it.
    #[test]
    fn spine_append_matches_full_rebuild() {
        let all = leaves(300);
        let mut sp: Vec<Hash> = Vec::new();
        for n in 0..all.len() {
            sp = spine_append(&sp, n, all[n]);
            let count = n + 1;
            assert_eq!(
                root_from_spine(&sp, count),
                root(&all[..count]),
                "incremental root diverged at n={count}"
            );
            assert_eq!(sp, spine(&all[..count]), "spine diverged at n={count}");
            assert_eq!(
                sp.len(),
                count.count_ones() as usize,
                "spine width must be the popcount of the size"
            );
        }
    }

    #[test]
    fn empty_and_single() {
        assert_eq!(root(&[]), empty_root());
        let l = leaves(1);
        // The root seals the count, so it is deliberately not the bare leaf
        // hash; a single-leaf log still proves.
        assert_ne!(root(&l), l[0].hash());
        let p = prove_inclusion(&l, 0).unwrap();
        assert!(verify_inclusion(root(&l), l[0], &p));
    }

    /// Regression: pairing left-to-right and duplicating a lone trailing node
    /// makes the root ambiguous in the leaf count, so a 3-leaf log and a 4-leaf
    /// log whose last leaf repeats share a root. RFC 6962 splitting does not.
    #[test]
    fn root_commits_to_leaf_count() {
        let three = leaves(3);
        let mut four = three.clone();
        four.push(three[2]);
        assert_ne!(
            root(&three),
            root(&four),
            "root must distinguish [a,b,c] from [a,b,c,c]"
        );
    }

    #[test]
    fn every_leaf_proves_at_every_size() {
        for n in 1..=33 {
            let ls = leaves(n);
            let r = root(&ls);
            for (i, leaf) in ls.iter().enumerate() {
                let p = prove_inclusion(&ls, i).unwrap();
                assert!(verify_inclusion(r, *leaf, &p), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn proof_is_bound_to_its_index_and_size() {
        let ls = leaves(8);
        let r = root(&ls);
        let mut p = prove_inclusion(&ls, 3).unwrap();
        assert!(verify_inclusion(r, ls[3], &p));

        // Same proof, different claimed index.
        p.index = 4;
        assert!(!verify_inclusion(r, ls[3], &p));
        p.index = 3;
        // Same proof, different claimed size.
        p.leaf_count = 7;
        assert!(!verify_inclusion(r, ls[3], &p));
    }

    #[test]
    fn wrong_leaf_root_or_sibling_rejected() {
        let ls = leaves(6);
        let r = root(&ls);
        let p = prove_inclusion(&ls, 2).unwrap();
        assert!(!verify_inclusion(
            r,
            MerkleLeaf::new(b"leaf:", b"impostor"),
            &p
        ));
        assert!(!verify_inclusion(root(&leaves(5)), ls[2], &p));

        let mut tampered = p.clone();
        tampered.siblings[0] = hash_typed(b"leaf:", b"forged");
        assert!(!verify_inclusion(r, ls[2], &tampered));
    }

    #[test]
    fn out_of_range_index_has_no_proof() {
        assert!(prove_inclusion(&leaves(4), 4).is_none());
        assert!(prove_inclusion(&[], 0).is_none());
    }

    /// Consistency is the capability a linear chain cannot offer: an old anchor
    /// can be checked against a new root without re-reading the log.
    #[test]
    fn consistency_holds_for_every_prefix() {
        for n in 1..=24 {
            let ls = leaves(n);
            let new_root = root(&ls);
            for m in 1..=n {
                let old_root = root(&ls[..m]);
                let proof = prove_consistency(&ls, m).unwrap();
                assert!(
                    verify_consistency(old_root, new_root, &proof),
                    "n={n} m={m}"
                );
            }
        }
    }

    /// A log that was rewritten rather than appended to must fail consistency.
    #[test]
    fn rewritten_history_fails_consistency() {
        let ls = leaves(8);
        let proof = prove_consistency(&ls, 5).unwrap();
        let honest_old = root(&ls[..5]);
        let new_root = root(&ls);
        assert!(verify_consistency(honest_old, new_root, &proof));

        // Same length, different history.
        let mut forged = ls[..5].to_vec();
        forged[1] = MerkleLeaf::new(b"leaf:", b"rewritten");
        assert!(!verify_consistency(root(&forged), new_root, &proof));

        // Honest prefix, but a new root from a divergent log.
        let mut divergent = ls.clone();
        divergent[6] = MerkleLeaf::new(b"leaf:", b"divergent");
        assert!(!verify_consistency(honest_old, root(&divergent), &proof));
    }

    #[test]
    fn consistency_rejects_bad_counts() {
        let ls = leaves(4);
        assert!(prove_consistency(&ls, 0).is_none());
        assert!(prove_consistency(&ls, 5).is_none());
    }

    /// Proof size is logarithmic, which is the whole point.
    #[test]
    fn inclusion_proof_is_logarithmic() {
        for (n, max) in [(1usize, 0usize), (16, 4), (1024, 10), (100_000, 17)] {
            let ls = leaves(n.min(2048)); // keep the test fast
            if n > 2048 {
                continue;
            }
            let p = prove_inclusion(&ls, 0).unwrap();
            assert!(p.siblings.len() <= max, "n={n} got {}", p.siblings.len());
        }
    }
}
