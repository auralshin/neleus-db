use std::cmp::Ordering;
use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::blob_store::BlobStore;
use crate::canonical::from_cbor;
use crate::hash::{Hash, hash_typed};
use crate::merkle::{MerkleProof, prove_inclusion, root as merkle_root, verify_inclusion};
use crate::object_store::ObjectStore;
use crate::wal::{Wal, WalOp};

const STATE_TAG: &[u8] = b"state_node:";
const STATE_LEAF_TAG: &[u8] = b"state_leaf:";
const STATE_MANIFEST_LEAF_TAG: &[u8] = b"state_manifest_leaf:";
const STATE_SCHEMA_VERSION: u32 = 1;

pub type StateRoot = Hash;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueRef {
    Value(Hash),
    Tombstone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentEntry {
    pub key: Vec<u8>,
    pub value: ValueRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSegment {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub entries: Vec<SegmentEntry>,
    pub merkle_root: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateManifest {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub segments: Vec<Hash>, // newest first
    #[serde(default = "Hash::zero")]
    pub segments_merkle_root: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryProof {
    pub entry: SegmentEntry,
    pub proof: MerkleProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonInclusionProof {
    pub insertion_index: usize,
    pub left: Option<EntryProof>,
    pub right: Option<EntryProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentKeyProof {
    Inclusion(EntryProof),
    NonInclusion(NonInclusionProof),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentVerdict {
    Value(Hash),
    Tombstone,
    NotPresent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentScanProof {
    pub segment_hash: Hash,
    pub manifest_proof: MerkleProof,
    pub segment_merkle_root: Hash,
    pub segment_leaf_count: usize,
    pub key_proof: SegmentKeyProof,
    pub verdict: SegmentVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateOutcome {
    Found(Hash),
    Deleted,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProof {
    pub manifest_schema_version: u32,
    pub manifest_segment_count: usize,
    pub manifest_segments_root: Hash,
    pub scans: Vec<SegmentScanProof>,
    pub outcome: StateOutcome,
}

#[derive(Clone, Debug)]
pub struct StateStore {
    objects: ObjectStore,
    blobs: BlobStore,
    wal: Wal,
}

impl StateStore {
    pub fn new(objects: ObjectStore, blobs: BlobStore, wal: Wal) -> Self {
        Self {
            objects,
            blobs,
            wal,
        }
    }

    pub fn empty_root(&self) -> Result<StateRoot> {
        let empty = new_state_manifest(vec![]);
        self.store_manifest(&empty)
    }

    pub fn get(&self, root: StateRoot, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let manifest = self.load_manifest_or_empty(root)?;
        for segment_hash in &manifest.segments {
            let segment = self.load_segment(*segment_hash)?;
            match find_key(&segment.entries, key) {
                Ok(idx) => match segment.entries[idx].value {
                    ValueRef::Value(value_hash) => return Ok(Some(self.blobs.get(value_hash)?)),
                    ValueRef::Tombstone => return Ok(None),
                },
                Err(_) => continue,
            }
        }
        Ok(None)
    }

    pub fn set(&self, root: StateRoot, key: &[u8], value: &[u8]) -> Result<StateRoot> {
        let wal_path =
            self.wal
                .begin_entry(&Wal::make_state_entry(WalOp::StateSet, root, key.len()))?;

        let result = (|| {
            let manifest = self.load_manifest_or_empty(root)?;
            let value_hash = self.blobs.put(value)?;
            let segment = StateSegment::from_entries(vec![SegmentEntry {
                key: key.to_vec(),
                value: ValueRef::Value(value_hash),
            }])?;
            let segment_hash = self.store_segment(&segment)?;
            let new_manifest =
                new_state_manifest(prepend_segment(segment_hash, &manifest.segments));
            self.store_manifest(&new_manifest)
        })();

        if result.is_ok() {
            self.wal.end(&wal_path)?;
        }
        result
    }

    pub fn del(&self, root: StateRoot, key: &[u8]) -> Result<StateRoot> {
        let wal_path =
            self.wal
                .begin_entry(&Wal::make_state_entry(WalOp::StateDel, root, key.len()))?;

        let result = (|| {
            let manifest = self.load_manifest_or_empty(root)?;
            let segment = StateSegment::from_entries(vec![SegmentEntry {
                key: key.to_vec(),
                value: ValueRef::Tombstone,
            }])?;
            let segment_hash = self.store_segment(&segment)?;
            let new_manifest =
                new_state_manifest(prepend_segment(segment_hash, &manifest.segments));
            self.store_manifest(&new_manifest)
        })();

        if result.is_ok() {
            self.wal.end(&wal_path)?;
        }
        result
    }

    pub fn compact(&self, root: StateRoot) -> Result<StateRoot> {
        let wal_path =
            self.wal
                .begin_entry(&Wal::make_state_entry(WalOp::StateCompact, root, 0))?;

        let result = (|| {
            let manifest = self.load_manifest_or_empty(root)?;
            let mut visible: BTreeMap<Vec<u8>, ValueRef> = BTreeMap::new();

            for segment_hash in &manifest.segments {
                let segment = self.load_segment(*segment_hash)?;
                for entry in segment.entries {
                    visible.entry(entry.key).or_insert(entry.value);
                }
            }

            let merged_entries: Vec<SegmentEntry> = visible
                .into_iter()
                .filter_map(|(key, value)| match value {
                    ValueRef::Value(h) => Some(SegmentEntry {
                        key,
                        value: ValueRef::Value(h),
                    }),
                    ValueRef::Tombstone => None,
                })
                .collect();

            if merged_entries.is_empty() {
                return self.store_manifest(&new_state_manifest(vec![]));
            }

            let merged_segment = StateSegment::from_entries(merged_entries)?;
            let merged_hash = self.store_segment(&merged_segment)?;
            self.store_manifest(&new_state_manifest(vec![merged_hash]))
        })();

        if result.is_ok() {
            self.wal.end(&wal_path)?;
        }

        result
    }

    pub fn proof(&self, root: StateRoot, key: &[u8]) -> Result<StateProof> {
        let manifest = self.load_manifest_or_empty(root)?;
        let manifest_leaves = manifest_segment_leaves(&manifest.segments);

        let mut scans = Vec::new();
        let mut outcome = StateOutcome::Missing;

        for (idx, segment_hash) in manifest.segments.iter().enumerate() {
            let segment = self.load_segment(*segment_hash)?;
            let manifest_proof = prove_inclusion(&manifest_leaves, idx)
                .ok_or_else(|| anyhow!("failed to build manifest inclusion proof"))?;
            let scan = build_segment_scan(*segment_hash, segment, manifest_proof, key)?;

            match scan.verdict {
                SegmentVerdict::Value(h) => {
                    scans.push(scan);
                    outcome = StateOutcome::Found(h);
                    break;
                }
                SegmentVerdict::Tombstone => {
                    scans.push(scan);
                    outcome = StateOutcome::Deleted;
                    break;
                }
                SegmentVerdict::NotPresent => scans.push(scan),
            }
        }

        Ok(StateProof {
            manifest_schema_version: manifest.schema_version,
            manifest_segment_count: manifest.segments.len(),
            manifest_segments_root: manifest.segments_merkle_root,
            scans,
            outcome,
        })
    }

    pub fn verify_proof(&self, root: StateRoot, key: &[u8], proof: &StateProof) -> bool {
        let manifest = match self.load_manifest_or_empty(root) {
            Ok(m) => m,
            Err(_) => return false,
        };

        if proof.manifest_schema_version != manifest.schema_version {
            return false;
        }
        if proof.manifest_segment_count != manifest.segments.len() {
            return false;
        }
        if proof.manifest_segments_root != manifest.segments_merkle_root {
            return false;
        }
        if proof.scans.len() > manifest.segments.len() {
            return false;
        }

        let mut computed_outcome = StateOutcome::Missing;
        let mut terminal = None;

        for (idx, scan) in proof.scans.iter().enumerate() {
            if manifest.segments.get(idx).copied() != Some(scan.segment_hash) {
                return false;
            }

            if scan.manifest_proof.index != idx {
                return false;
            }

            let leaf = manifest_segment_leaf_hash(scan.segment_hash);
            if !verify_inclusion(manifest.segments_merkle_root, leaf, &scan.manifest_proof) {
                return false;
            }

            let segment = match self.load_segment(scan.segment_hash) {
                Ok(s) => s,
                Err(_) => return false,
            };

            if segment.merkle_root != scan.segment_merkle_root {
                return false;
            }
            if segment.entries.len() != scan.segment_leaf_count {
                return false;
            }
            if !segment_is_sorted_unique(&segment.entries) {
                return false;
            }

            let verdict_terminal = match &scan.key_proof {
                SegmentKeyProof::Inclusion(ep) => {
                    if ep.entry.key.as_slice() != key {
                        return false;
                    }
                    if !verify_entry_proof(&segment, ep) {
                        return false;
                    }
                    match ep.entry.value {
                        ValueRef::Value(h) => {
                            if scan.verdict != SegmentVerdict::Value(h) {
                                return false;
                            }
                            Some(StateOutcome::Found(h))
                        }
                        ValueRef::Tombstone => {
                            if scan.verdict != SegmentVerdict::Tombstone {
                                return false;
                            }
                            Some(StateOutcome::Deleted)
                        }
                    }
                }
                SegmentKeyProof::NonInclusion(np) => {
                    if scan.verdict != SegmentVerdict::NotPresent {
                        return false;
                    }
                    if !verify_non_inclusion(&segment, key, np) {
                        return false;
                    }
                    None
                }
            };

            if let Some(outcome) = verdict_terminal {
                terminal = Some(idx);
                computed_outcome = outcome;
                break;
            }
        }

        match terminal {
            Some(i) => {
                if proof.scans.len() != i + 1 {
                    return false;
                }
            }
            None => {
                if proof.scans.len() != manifest.segments.len() {
                    return false;
                }
                computed_outcome = StateOutcome::Missing;
            }
        }

        computed_outcome == proof.outcome
    }

    fn load_manifest_or_empty(&self, root: StateRoot) -> Result<StateManifest> {
        if self.objects.exists(root) {
            return self.load_manifest(root);
        }

        let empty_root = self.empty_root()?;
        if root == empty_root {
            return Ok(new_state_manifest(vec![]));
        }

        Err(anyhow!("state root {} not found", root))
    }

    fn store_manifest(&self, manifest: &StateManifest) -> Result<StateRoot> {
        self.objects.put_serialized(STATE_TAG, manifest)
    }

    fn load_manifest(&self, hash: StateRoot) -> Result<StateManifest> {
        let bytes = self.objects.get_typed_bytes(STATE_TAG, hash)?;
        let computed = hash_typed(STATE_TAG, &bytes);
        if computed != hash {
            return Err(anyhow!("manifest hash mismatch for {}", hash));
        }
        let mut manifest: StateManifest = from_cbor(&bytes)?;
        migrate_manifest(&mut manifest);
        Ok(manifest)
    }

    fn store_segment(&self, segment: &StateSegment) -> Result<Hash> {
        self.objects.put_serialized(STATE_TAG, segment)
    }

    fn load_segment(&self, hash: Hash) -> Result<StateSegment> {
        let bytes = self.objects.get_typed_bytes(STATE_TAG, hash)?;
        let computed = hash_typed(STATE_TAG, &bytes);
        if computed != hash {
            return Err(anyhow!("segment hash mismatch for {}", hash));
        }
        let mut segment: StateSegment = from_cbor(&bytes)?;
        if segment.schema_version == 0 {
            segment.schema_version = STATE_SCHEMA_VERSION;
        }
        Ok(segment)
    }
}

impl StateSegment {
    pub fn from_entries(mut entries: Vec<SegmentEntry>) -> Result<Self> {
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        if !segment_is_sorted_unique(&entries) {
            return Err(anyhow!("segment entries must have unique sorted keys"));
        }

        let leaves: Vec<Hash> = entries.iter().map(leaf_hash).collect();
        let merkle_root = merkle_root(&leaves);
        Ok(Self {
            schema_version: STATE_SCHEMA_VERSION,
            entries,
            merkle_root,
        })
    }
}

fn default_schema_version() -> u32 {
    STATE_SCHEMA_VERSION
}

fn new_state_manifest(segments: Vec<Hash>) -> StateManifest {
    StateManifest {
        schema_version: STATE_SCHEMA_VERSION,
        segments_merkle_root: merkle_root(&manifest_segment_leaves(&segments)),
        segments,
    }
}

fn migrate_manifest(manifest: &mut StateManifest) {
    if manifest.schema_version == 0 {
        manifest.schema_version = STATE_SCHEMA_VERSION;
    }
    let expected = merkle_root(&manifest_segment_leaves(&manifest.segments));
    if manifest.segments_merkle_root == Hash::zero() || manifest.segments_merkle_root != expected {
        manifest.segments_merkle_root = expected;
    }
}

#[cfg(test)]
fn hash_state_object<T: Serialize>(obj: &T) -> Result<Hash> {
    let bytes = crate::canonical::to_cbor(obj)?;
    Ok(hash_typed(STATE_TAG, &bytes))
}

fn prepend_segment(newest: Hash, existing: &[Hash]) -> Vec<Hash> {
    let mut out = Vec::with_capacity(existing.len() + 1);
    out.push(newest);
    out.extend_from_slice(existing);
    out
}

fn find_key(entries: &[SegmentEntry], key: &[u8]) -> std::result::Result<usize, usize> {
    entries.binary_search_by(|e| compare_key(e.key.as_slice(), key))
}

fn compare_key(a: &[u8], b: &[u8]) -> Ordering {
    a.cmp(b)
}

fn segment_is_sorted_unique(entries: &[SegmentEntry]) -> bool {
    entries
        .windows(2)
        .all(|w| w[0].key.as_slice() < w[1].key.as_slice())
}

fn manifest_segment_leaf_hash(segment_hash: Hash) -> Hash {
    hash_typed(STATE_MANIFEST_LEAF_TAG, segment_hash.as_bytes())
}

fn manifest_segment_leaves(segments: &[Hash]) -> Vec<Hash> {
    segments
        .iter()
        .copied()
        .map(manifest_segment_leaf_hash)
        .collect()
}

fn leaf_hash(entry: &SegmentEntry) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(entry.key.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&entry.key);

    match entry.value {
        ValueRef::Value(h) => {
            bytes.push(1);
            bytes.extend_from_slice(h.as_bytes());
        }
        ValueRef::Tombstone => bytes.push(0),
    }

    hash_typed(STATE_LEAF_TAG, &bytes)
}

fn build_segment_scan(
    segment_hash: Hash,
    segment: StateSegment,
    manifest_proof: MerkleProof,
    key: &[u8],
) -> Result<SegmentScanProof> {
    let leaves: Vec<Hash> = segment.entries.iter().map(leaf_hash).collect();

    match find_key(&segment.entries, key) {
        Ok(index) => {
            let entry = segment.entries[index].clone();
            let proof = prove_inclusion(&leaves, index)
                .ok_or_else(|| anyhow!("failed to build inclusion proof"))?;
            let verdict = match entry.value {
                ValueRef::Value(h) => SegmentVerdict::Value(h),
                ValueRef::Tombstone => SegmentVerdict::Tombstone,
            };
            Ok(SegmentScanProof {
                segment_hash,
                manifest_proof,
                segment_merkle_root: segment.merkle_root,
                segment_leaf_count: segment.entries.len(),
                key_proof: SegmentKeyProof::Inclusion(EntryProof { entry, proof }),
                verdict,
            })
        }
        Err(ins) => {
            let left = if ins > 0 {
                let idx = ins - 1;
                Some(EntryProof {
                    entry: segment.entries[idx].clone(),
                    proof: prove_inclusion(&leaves, idx)
                        .ok_or_else(|| anyhow!("failed to build left neighbor proof"))?,
                })
            } else {
                None
            };

            let right = if ins < segment.entries.len() {
                Some(EntryProof {
                    entry: segment.entries[ins].clone(),
                    proof: prove_inclusion(&leaves, ins)
                        .ok_or_else(|| anyhow!("failed to build right neighbor proof"))?,
                })
            } else {
                None
            };

            Ok(SegmentScanProof {
                segment_hash,
                manifest_proof,
                segment_merkle_root: segment.merkle_root,
                segment_leaf_count: segment.entries.len(),
                key_proof: SegmentKeyProof::NonInclusion(NonInclusionProof {
                    insertion_index: ins,
                    left,
                    right,
                }),
                verdict: SegmentVerdict::NotPresent,
            })
        }
    }
}

fn verify_entry_proof(segment: &StateSegment, entry_proof: &EntryProof) -> bool {
    let idx = entry_proof.proof.index;
    if segment.entries.get(idx) != Some(&entry_proof.entry) {
        return false;
    }

    let leaf = leaf_hash(&entry_proof.entry);
    verify_inclusion(segment.merkle_root, leaf, &entry_proof.proof)
}

fn verify_non_inclusion(segment: &StateSegment, key: &[u8], np: &NonInclusionProof) -> bool {
    let len = segment.entries.len();
    if np.insertion_index > len {
        return false;
    }

    if np.insertion_index < len && segment.entries[np.insertion_index].key.as_slice() == key {
        return false;
    }

    match &np.left {
        Some(left) => {
            if !verify_entry_proof(segment, left) {
                return false;
            }
            if left.proof.index + 1 != np.insertion_index {
                return false;
            }
            if !(left.entry.key.as_slice() < key) {
                return false;
            }
        }
        None => {
            if np.insertion_index != 0 {
                return false;
            }
        }
    }

    match &np.right {
        Some(right) => {
            if !verify_entry_proof(segment, right) {
                return false;
            }
            if right.proof.index != np.insertion_index {
                return false;
            }
            if !(key < right.entry.key.as_slice()) {
                return false;
            }
        }
        None => {
            if np.insertion_index != len {
                return false;
            }
        }
    }

    if let (Some(left), Some(right)) = (&np.left, &np.right)
        && !(left.entry.key.as_slice() < right.entry.key.as_slice())
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use tempfile::TempDir;

    use super::*;

    fn store(tmp: &TempDir) -> StateStore {
        let objects = ObjectStore::new(tmp.path().join("objects"));
        objects.ensure_dir().unwrap();
        let blobs = BlobStore::new(tmp.path().join("blobs"));
        blobs.ensure_dir().unwrap();
        StateStore::new(objects, blobs, Wal::new(tmp.path().join("wal")))
    }

    #[test]
    fn empty_root_get_none() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let root = s.empty_root().unwrap();
        assert_eq!(s.get(root, b"missing").unwrap(), None);
    }

    #[test]
    fn set_get_single_key() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let root0 = s.empty_root().unwrap();
        let root1 = s.set(root0, b"k", b"v").unwrap();
        assert_eq!(s.get(root1, b"k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn overwrite_key_returns_latest_value() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let root0 = s.empty_root().unwrap();
        let root1 = s.set(root0, b"k", b"v1").unwrap();
        let root2 = s.set(root1, b"k", b"v2").unwrap();
        assert_eq!(s.get(root2, b"k").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn old_roots_remain_readable() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let root0 = s.empty_root().unwrap();
        let root1 = s.set(root0, b"k", b"v1").unwrap();
        let root2 = s.set(root1, b"k", b"v2").unwrap();
        assert_eq!(s.get(root1, b"k").unwrap(), Some(b"v1".to_vec()));
        assert_eq!(s.get(root2, b"k").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn delete_removes_value() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"k", b"v").unwrap();
        let r2 = s.del(r1, b"k").unwrap();
        assert_eq!(s.get(r2, b"k").unwrap(), None);
    }

    #[test]
    fn delete_missing_key_still_creates_new_root() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.del(r0, b"missing").unwrap();
        assert_ne!(r0, r1);
    }

    #[test]
    fn multiple_keys_independent() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"a", b"1").unwrap();
        let r2 = s.set(r1, b"b", b"2").unwrap();
        assert_eq!(s.get(r2, b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(s.get(r2, b"b").unwrap(), Some(b"2".to_vec()));
    }

    #[test]
    fn tombstone_wins_over_older_value() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"k", b"1").unwrap();
        let r2 = s.del(r1, b"k").unwrap();
        let r3 = s.set(r2, b"other", b"x").unwrap();
        assert_eq!(s.get(r3, b"k").unwrap(), None);
    }

    #[test]
    fn segment_order_newest_first() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"k", b"1").unwrap();
        let r2 = s.set(r1, b"k", b"2").unwrap();
        let m: StateManifest = s.load_manifest_or_empty(r2).unwrap();
        assert_eq!(m.segments.len(), 2);
        let newer: StateSegment = s.load_segment(m.segments[0]).unwrap();
        assert_eq!(
            newer.entries[0].value,
            ValueRef::Value(s.blobs.put(b"2").unwrap())
        );
    }

    #[test]
    fn manifest_merkle_root_matches_segments() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"a", b"1").unwrap();
        let m = s.load_manifest_or_empty(r1).unwrap();
        let leaves = m
            .segments
            .iter()
            .copied()
            .map(super::manifest_segment_leaf_hash)
            .collect::<Vec<_>>();
        assert_eq!(m.segments_merkle_root, merkle_root(&leaves));
    }

    #[test]
    fn compact_reduces_segments_and_preserves_values() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"a", b"1").unwrap();
        let r2 = s.set(r1, b"a", b"2").unwrap();
        let r3 = s.set(r2, b"b", b"3").unwrap();
        let r4 = s.del(r3, b"b").unwrap();
        let compacted = s.compact(r4).unwrap();

        let manifest = s.load_manifest_or_empty(compacted).unwrap();
        assert!(manifest.segments.len() <= 1);
        assert_eq!(s.get(compacted, b"a").unwrap(), Some(b"2".to_vec()));
        assert_eq!(s.get(compacted, b"b").unwrap(), None);
    }

    #[test]
    fn proof_membership_verifies() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"k", b"v").unwrap();
        let p = s.proof(r1, b"k").unwrap();
        assert!(s.verify_proof(r1, b"k", &p));
        assert!(matches!(p.outcome, StateOutcome::Found(_)));
    }

    #[test]
    fn proof_non_membership_verifies() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"a", b"1").unwrap();
        let p = s.proof(r1, b"z").unwrap();
        assert!(s.verify_proof(r1, b"z", &p));
        assert_eq!(p.outcome, StateOutcome::Missing);
    }

    #[test]
    fn proof_deleted_verifies() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"k", b"v").unwrap();
        let r2 = s.del(r1, b"k").unwrap();
        let p = s.proof(r2, b"k").unwrap();
        assert!(s.verify_proof(r2, b"k", &p));
        assert_eq!(p.outcome, StateOutcome::Deleted);
    }

    #[test]
    fn proof_wrong_key_fails() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"k", b"v").unwrap();
        let p = s.proof(r1, b"k").unwrap();
        assert!(!s.verify_proof(r1, b"x", &p));
    }

    #[test]
    fn proof_wrong_root_fails() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"k", b"v").unwrap();
        let p = s.proof(r1, b"k").unwrap();
        assert!(!s.verify_proof(r0, b"k", &p));
    }

    #[test]
    fn proof_tampered_manifest_proof_fails() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"k", b"v").unwrap();
        let mut p = s.proof(r1, b"k").unwrap();
        p.scans[0].manifest_proof.index = 1;
        assert!(!s.verify_proof(r1, b"k", &p));
    }

    #[test]
    fn proof_tampered_entry_fails() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"k", b"v").unwrap();
        let mut p = s.proof(r1, b"k").unwrap();
        match &mut p.scans[0].key_proof {
            SegmentKeyProof::Inclusion(ep) => ep.entry.key = b"x".to_vec(),
            _ => panic!("expected inclusion"),
        }
        assert!(!s.verify_proof(r1, b"k", &p));
    }

    #[test]
    fn set_same_input_same_root() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let a = s.set(r0, b"k", b"v").unwrap();
        let b = s.set(r0, b"k", b"v").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn set_different_value_changes_root() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let a = s.set(r0, b"k", b"v1").unwrap();
        let b = s.set(r0, b"k", b"v2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn load_missing_root_errors() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let missing = Hash::zero();
        assert!(s.get(missing, b"k").is_err());
    }

    #[test]
    fn proof_for_empty_root_missing() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r = s.empty_root().unwrap();
        let p = s.proof(r, b"k").unwrap();
        assert_eq!(p.outcome, StateOutcome::Missing);
        assert!(s.verify_proof(r, b"k", &p));
    }

    #[test]
    fn hash_state_object_is_stable() {
        let m = new_state_manifest(vec![]);
        assert_eq!(
            hash_state_object(&m).unwrap(),
            hash_state_object(&m).unwrap()
        );
    }

    fn random_property(seed: u64) {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let mut rng = StdRng::seed_from_u64(seed);

        let mut root = s.empty_root().unwrap();
        let mut model: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        let keys: Vec<Vec<u8>> = (0..12).map(|i| format!("k{i}").into_bytes()).collect();

        for _ in 0..200 {
            let k = keys[rng.gen_range(0..keys.len())].clone();
            let op = rng.gen_range(0..4);
            if op < 2 {
                let val_len = rng.gen_range(1..8);
                let val: Vec<u8> = (0..val_len).map(|_| rng.gen_range(0u8..=255u8)).collect();
                root = s.set(root, &k, &val).unwrap();
                model.insert(k.clone(), Some(val));
            } else if op == 2 {
                root = s.del(root, &k).unwrap();
                model.insert(k.clone(), None);
            } else {
                root = s.compact(root).unwrap();
                // Compaction does not change logical view.
            }

            for probe in &keys {
                let got = s.get(root, probe).unwrap();
                let expected = model.get(probe).cloned().flatten();
                assert_eq!(got, expected);
            }
        }
    }

    macro_rules! prop_test {
        ($name:ident, $seed:expr) => {
            #[test]
            fn $name() {
                random_property($seed);
            }
        };
    }

    prop_test!(property_random_ops_seed_1, 1);
    prop_test!(property_random_ops_seed_2, 2);
    prop_test!(property_random_ops_seed_3, 3);
    prop_test!(property_random_ops_seed_4, 4);
    prop_test!(property_random_ops_seed_5, 5);
    prop_test!(property_random_ops_seed_6, 6);
    prop_test!(property_random_ops_seed_7, 7);
    prop_test!(property_random_ops_seed_8, 8);
    prop_test!(property_random_ops_seed_9, 9);
    prop_test!(property_random_ops_seed_10, 10);
}
