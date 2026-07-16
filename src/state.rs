use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::blob_store::BlobStore;
use crate::canonical::{from_cbor, to_cbor};
use crate::hash::{Hash, hash_blob, hash_typed};
use crate::object_store::ObjectStore;

const STATE_TAG: &[u8] = b"state_node:";
const LEVEL_TAG: &[u8] = b"state_level:";
const STATE_SCHEMA_VERSION: u32 = 3;

/// Fanout knob: a key is a boundary at level L iff `key_level(key) > L`, and
/// `key_level` counts leading zero bits of `hash(key)` in groups of this many
/// bits. 5 bits ⇒ boundary probability 1/32 per level ⇒ average fanout 32 ⇒
/// depth ~log32(n) (≈4 for millions of keys). Bigger ⇒ shallower reads, wider
/// proofs.
const BITS_PER_LEVEL: u32 = 5;

/// Height cap. The level rule is content-defined, so an adversarial key set
/// could otherwise inflate height; capping bounds it (and guarantees the
/// bottom-up build terminates). Far above any non-adversarial tree.
const MAX_LEVEL: u32 = 16;

pub type StateRoot = Hash;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueRef {
    /// Blob ref for values above [`INLINE_VALUE_MAX`] (dedup pays for the file).
    Value(Hash),
    /// Small values stored in the node: no per-value blob file, no blob read.
    Inline(Vec<u8>),
}

/// A content-addressed prolly-tree (Merkle Search Tree) node. Leaves hold the
/// key/value entries; branches route by `last_key` (the largest key in each
/// child subtree). Children are referenced by content hash, so a node's hash
/// transitively commits to its whole subtree — the tree is its own Merkle
/// commitment. Boundaries derive from `key_level`, so the shape is a pure
/// function of the key set (history independent ⇒ canonical root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeItems {
    Leaf(Vec<(Vec<u8>, ValueRef)>),
    Branch(Vec<(Vec<u8>, Hash)>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateNode {
    pub level: u32,
    pub items: NodeItems,
}

/// State version anchor. `root` is the content hash of the trie root node, or
/// `None` for the empty state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateManifest {
    pub schema_version: u32,
    pub root: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateOutcome {
    Found(Hash),
    Missing,
}

/// A single root→leaf search path. Each element is the actual node on the
/// path; its content hash is recomputed and checked against the parent's
/// routing pointer, anchoring the path to the state root. Length is the tree
/// height — O(log_B n).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProof {
    pub manifest_schema_version: u32,
    pub root: Option<Hash>,
    pub path: Vec<StateNode>,
    pub outcome: StateOutcome,
}

#[derive(Clone, Debug)]
pub struct StateStore {
    objects: ObjectStore,
    blobs: BlobStore,
    empty_root: Arc<OnceLock<StateRoot>>,
    node_cache: Arc<std::sync::RwLock<std::collections::HashMap<Hash, Arc<StateNode>>>>,
    manifest_cache:
        Arc<std::sync::RwLock<std::collections::HashMap<StateRoot, Arc<StateManifest>>>>,
}

/// Cache entry cap; overflow clears (perf reset, never a correctness event).
const STATE_CACHE_CAP: usize = 8192;

/// Values at or below this many bytes are stored inline in the node.
pub const INLINE_VALUE_MAX: usize = 512;

impl StateStore {
    pub fn new(objects: ObjectStore, blobs: BlobStore) -> Self {
        Self {
            objects,
            blobs,
            empty_root: Arc::new(OnceLock::new()),
            node_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            manifest_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn encode_value(&self, value: &[u8]) -> Result<ValueRef> {
        if value.len() <= INLINE_VALUE_MAX {
            Ok(ValueRef::Inline(value.to_vec()))
        } else {
            Ok(ValueRef::Value(self.blobs.put(value)?))
        }
    }

    fn read_value(&self, value: &ValueRef) -> Result<Vec<u8>> {
        match value {
            ValueRef::Value(h) => self.blobs.get(*h),
            ValueRef::Inline(bytes) => Ok(bytes.clone()),
        }
    }

    pub fn empty_root(&self) -> Result<StateRoot> {
        if let Some(cached) = self.empty_root.get() {
            return Ok(*cached);
        }
        let root = self.store_manifest(&new_state_manifest(None))?;
        let _ = self.empty_root.set(root);
        Ok(*self.empty_root.get().unwrap_or(&root))
    }

    pub fn get(&self, root: StateRoot, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let manifest = self.load_manifest_or_empty(root)?;
        let mut cursor = manifest.root;
        while let Some(hash) = cursor {
            let node = self.load_node(hash)?;
            match &node.items {
                NodeItems::Leaf(entries) => {
                    return match entries.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
                        Ok(i) => Ok(Some(self.read_value(&entries[i].1)?)),
                        Err(_) => Ok(None),
                    };
                }
                NodeItems::Branch(entries) => {
                    cursor = Some(entries[route(entries, key)].1);
                }
            }
        }
        Ok(None)
    }

    pub fn set(&self, root: StateRoot, key: &[u8], value: &[u8]) -> Result<StateRoot> {
        let manifest = self.load_manifest_or_empty(root)?;
        let value = self.encode_value(value)?;
        let new_root = match manifest.root {
            None => self.build_from_sorted(vec![(key.to_vec(), value)])?,
            Some(h) => {
                let level = self.load_node(h)?.level;
                let entries = self.insert_into(h, key, value)?;
                Some(self.finish_root(entries, level)?)
            }
        };
        self.store_manifest(&new_state_manifest(new_root))
    }

    pub fn del(&self, root: StateRoot, key: &[u8]) -> Result<StateRoot> {
        let manifest = self.load_manifest_or_empty(root)?;
        let new_root = match manifest.root {
            None => None,
            Some(h) => {
                let level = self.load_node(h)?.level;
                let entries = self.delete_from(h, key)?;
                if entries.is_empty() {
                    None
                } else {
                    Some(self.finish_root(entries, level)?)
                }
            }
        };
        self.store_manifest(&new_state_manifest(new_root))
    }

    /// Set multiple key-value pairs in one new state version. Last write wins.
    pub fn set_many(&self, root: StateRoot, pairs: &[(&[u8], &[u8])]) -> Result<StateRoot> {
        if pairs.is_empty() {
            return Ok(root);
        }
        let mut deduped: BTreeMap<Vec<u8>, &[u8]> = BTreeMap::new();
        for (k, v) in pairs {
            deduped.insert(k.to_vec(), v);
        }
        let ops: Vec<(Vec<u8>, Option<&[u8]>)> =
            deduped.into_iter().map(|(k, v)| (k, Some(v))).collect();
        self.apply_batch(root, ops)
    }

    /// Delete multiple keys in one new state version.
    pub fn del_many(&self, root: StateRoot, keys: &[&[u8]]) -> Result<StateRoot> {
        if keys.is_empty() {
            return Ok(root);
        }
        let mut deduped: BTreeMap<Vec<u8>, Option<&[u8]>> = BTreeMap::new();
        for k in keys {
            deduped.insert(k.to_vec(), None);
        }
        self.apply_batch(root, deduped.into_iter().collect())
    }

    /// Mixed sets and deletes in one new state version. `None` value = delete.
    /// Last occurrence per key wins. The coalescer's flush primitive.
    pub fn write_many(&self, root: StateRoot, ops: &[(&[u8], Option<&[u8]>)]) -> Result<StateRoot> {
        if ops.is_empty() {
            return Ok(root);
        }
        let mut deduped: BTreeMap<Vec<u8>, Option<&[u8]>> = BTreeMap::new();
        for (k, v) in ops {
            deduped.insert(k.to_vec(), *v);
        }
        self.apply_batch(root, deduped.into_iter().collect())
    }

    /// Apply a sorted, deduped batch. An empty base bulk-builds the canonical
    /// tree in one pass (each node written once); a populated base folds
    /// incremental inserts/deletes.
    fn apply_batch(
        &self,
        root: StateRoot,
        ops: Vec<(Vec<u8>, Option<&[u8]>)>,
    ) -> Result<StateRoot> {
        let manifest = self.load_manifest_or_empty(root)?;
        if manifest.root.is_none() {
            let mut entries = Vec::new();
            for (key, value) in ops {
                if let Some(bytes) = value {
                    entries.push((key, self.encode_value(bytes)?));
                }
            }
            let new_root = self.build_from_sorted(entries)?;
            return self.store_manifest(&new_state_manifest(new_root));
        }
        let mut cur = manifest.root;
        for (key, value) in ops {
            cur = match (cur, value) {
                (None, Some(bytes)) => {
                    let v = self.encode_value(bytes)?;
                    self.build_from_sorted(vec![(key, v)])?
                }
                (None, None) => None,
                (Some(h), Some(bytes)) => {
                    let v = self.encode_value(bytes)?;
                    let level = self.load_node(h)?.level;
                    let entries = self.insert_into(h, &key, v)?;
                    Some(self.finish_root(entries, level)?)
                }
                (Some(h), None) => {
                    let level = self.load_node(h)?.level;
                    let entries = self.delete_from(h, &key)?;
                    if entries.is_empty() {
                        None
                    } else {
                        Some(self.finish_root(entries, level)?)
                    }
                }
            };
        }
        self.store_manifest(&new_state_manifest(cur))
    }

    /// The tree is always canonical (shape is a pure function of the key set),
    /// so compaction is a no-op kept for API/callsite stability.
    pub fn compact(&self, root: StateRoot) -> Result<StateRoot> {
        self.load_manifest_or_empty(root)?;
        Ok(root)
    }

    /// Visible keys under `prefix` with value commitments, BST-sorted.
    pub fn scan_prefix(&self, root: StateRoot, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Hash)>> {
        let manifest = self.load_manifest_or_empty(root)?;
        let mut out = Vec::new();
        if let Some(h) = manifest.root {
            let upper = prefix_upper(prefix);
            self.collect_prefix(h, prefix, upper.as_deref(), None, &mut out)?;
        }
        Ok(out)
    }

    fn collect_prefix(
        &self,
        node_hash: Hash,
        prefix: &[u8],
        upper: Option<&[u8]>,
        lower: Option<&[u8]>,
        out: &mut Vec<(Vec<u8>, Hash)>,
    ) -> Result<()> {
        let node = self.load_node(node_hash)?;
        match &node.items {
            NodeItems::Leaf(entries) => {
                for (k, v) in entries {
                    if k.starts_with(prefix) {
                        out.push((k.clone(), value_commit(v)));
                    }
                }
            }
            NodeItems::Branch(entries) => {
                let mut lo = lower;
                for (last_key, child) in entries {
                    // Child covers keys in (lo, last_key]. Descend only if that
                    // range can intersect [prefix, upper).
                    let above_start = last_key.as_slice() >= prefix;
                    let below_end = match (lo, upper) {
                        (Some(l), Some(u)) => l < u,
                        _ => true,
                    };
                    if above_start && below_end {
                        self.collect_prefix(*child, prefix, upper, lo, out)?;
                    }
                    lo = Some(last_key.as_slice());
                }
            }
        }
        Ok(())
    }

    pub fn proof(&self, root: StateRoot, key: &[u8]) -> Result<StateProof> {
        let manifest = self.load_manifest_or_empty(root)?;
        let mut path = Vec::new();
        let mut cursor = manifest.root;
        let mut outcome = StateOutcome::Missing;
        while let Some(hash) = cursor {
            let node = self.load_node(hash)?;
            path.push((*node).clone());
            match &node.items {
                NodeItems::Leaf(entries) => {
                    if let Ok(i) = entries.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
                        outcome = StateOutcome::Found(value_commit(&entries[i].1));
                    }
                    break;
                }
                NodeItems::Branch(entries) => {
                    cursor = Some(entries[route(entries, key)].1);
                }
            }
        }
        Ok(StateProof {
            manifest_schema_version: manifest.schema_version,
            root: manifest.root,
            path,
            outcome,
        })
    }

    /// Verify a proof against the state `root`, from the root hash alone: each
    /// path node's content hash is recomputed and checked against its parent's
    /// routing pointer, and the routing at every branch must match `key`, so
    /// the path is provably the search path and the prover cannot hide a
    /// present key or invent an absent one.
    pub fn verify_proof(&self, root: StateRoot, key: &[u8], proof: &StateProof) -> bool {
        let manifest = match self.load_manifest_or_empty(root) {
            Ok(m) => m,
            Err(_) => return false,
        };
        if proof.manifest_schema_version != manifest.schema_version {
            return false;
        }
        if proof.root != manifest.root {
            return false;
        }
        if manifest.root.is_none() {
            return proof.path.is_empty() && proof.outcome == StateOutcome::Missing;
        }
        if proof.path.is_empty() {
            return false;
        }
        let hashes: Vec<Hash> = match proof
            .path
            .iter()
            .map(node_hash)
            .collect::<Result<Vec<Hash>>>()
        {
            Ok(h) => h,
            Err(_) => return false,
        };
        if Some(hashes[0]) != manifest.root {
            return false;
        }

        for i in 0..proof.path.len() {
            let node = &proof.path[i];
            let last = i + 1 == proof.path.len();
            match &node.items {
                NodeItems::Leaf(entries) => {
                    if !last || !leaf_sorted_unique(entries) {
                        return false;
                    }
                    return match entries.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
                        Ok(j) => proof.outcome == StateOutcome::Found(value_commit(&entries[j].1)),
                        Err(_) => proof.outcome == StateOutcome::Missing,
                    };
                }
                NodeItems::Branch(entries) => {
                    if last || entries.is_empty() || !branch_sorted_unique(entries) {
                        return false;
                    }
                    if entries[route(entries, key)].1 != hashes[i + 1] {
                        return false;
                    }
                }
            }
        }
        false
    }

    /// Every hash reachable from state `root`: the manifest, its nodes, and
    /// each entry's value blob. GC asks the state store rather than re-deriving
    /// the DAG shape.
    pub fn reachable_from(&self, root: StateRoot) -> Result<Vec<Hash>> {
        let manifest = self.load_manifest_or_empty(root)?;
        let mut out = Vec::new();
        if self.objects.exists(root) {
            out.push(root);
        }
        let mut stack: Vec<Hash> = manifest.root.into_iter().collect();
        while let Some(hash) = stack.pop() {
            out.push(hash);
            let node = self.load_node(hash)?;
            match &node.items {
                NodeItems::Leaf(entries) => {
                    for (_, v) in entries {
                        if let ValueRef::Value(h) = v {
                            out.push(*h);
                        }
                    }
                }
                NodeItems::Branch(entries) => {
                    stack.extend(entries.iter().map(|(_, h)| *h));
                }
            }
        }
        Ok(out)
    }

    // ---------- tree construction ----------

    /// Build the canonical tree from sorted-unique leaf entries, bottom-up,
    /// writing each node once. The boundary rule (`key_level`) is a pure
    /// function of the key, so this is the unique tree for that key set — the
    /// oracle every incremental write must match.
    fn build_from_sorted(&self, entries: Vec<(Vec<u8>, ValueRef)>) -> Result<Option<Hash>> {
        if entries.is_empty() {
            return Ok(None);
        }
        let mut level = 0u32;
        let mut nodes = self.chunk_leaf(&entries)?;
        while nodes.len() > 1 {
            level += 1;
            nodes = self.chunk_branch(level, &nodes)?;
        }
        Ok(Some(nodes[0].1))
    }

    /// Cut `entries` into leaf nodes after every boundary key (`key_level > 0`),
    /// store each, and return the parent routing entries `(last_key, hash)`.
    fn chunk_leaf(&self, entries: &[(Vec<u8>, ValueRef)]) -> Result<Vec<(Vec<u8>, Hash)>> {
        let mut out = Vec::new();
        let mut cur: Vec<(Vec<u8>, ValueRef)> = Vec::new();
        for (k, v) in entries {
            cur.push((k.clone(), v.clone()));
            if key_level(k) > 0 {
                out.push(self.store_leaf(std::mem::take(&mut cur))?);
            }
        }
        if !cur.is_empty() {
            out.push(self.store_leaf(cur)?);
        }
        Ok(out)
    }

    /// Cut branch routing entries into nodes after every key that is a boundary
    /// at this level (`key_level > level`).
    fn chunk_branch(
        &self,
        level: u32,
        entries: &[(Vec<u8>, Hash)],
    ) -> Result<Vec<(Vec<u8>, Hash)>> {
        let mut out = Vec::new();
        let mut cur: Vec<(Vec<u8>, Hash)> = Vec::new();
        for (k, h) in entries {
            cur.push((k.clone(), *h));
            if key_level(k) > level {
                out.push(self.store_branch(level, std::mem::take(&mut cur))?);
            }
        }
        if !cur.is_empty() {
            out.push(self.store_branch(level, cur)?);
        }
        Ok(out)
    }

    fn store_leaf(&self, entries: Vec<(Vec<u8>, ValueRef)>) -> Result<(Vec<u8>, Hash)> {
        let last_key = entries.last().expect("non-empty chunk").0.clone();
        let hash = self.store_node(&StateNode {
            level: 0,
            items: NodeItems::Leaf(entries),
        })?;
        Ok((last_key, hash))
    }

    fn store_branch(&self, level: u32, entries: Vec<(Vec<u8>, Hash)>) -> Result<(Vec<u8>, Hash)> {
        let last_key = entries.last().expect("non-empty chunk").0.clone();
        let hash = self.store_node(&StateNode {
            level,
            items: NodeItems::Branch(entries),
        })?;
        Ok((last_key, hash))
    }

    /// Build levels up from the replacement entries of the old root, then drop
    /// a non-canonical single-child branch root (a delete can leave one).
    fn finish_root(&self, mut entries: Vec<(Vec<u8>, Hash)>, mut level: u32) -> Result<Hash> {
        while entries.len() > 1 {
            level += 1;
            entries = self.chunk_branch(level, &entries)?;
        }
        let mut root = entries[0].1;
        loop {
            let node = self.load_node(root)?;
            match &node.items {
                NodeItems::Branch(es) if es.len() == 1 => root = es[0].1,
                _ => break,
            }
        }
        Ok(root)
    }

    /// Insert/replace `(key, value)` in the subtree at `node_hash`, returning
    /// the replacement routing entries for that subtree (1, or more if a new
    /// boundary key split it).
    fn insert_into(
        &self,
        node_hash: Hash,
        key: &[u8],
        value: ValueRef,
    ) -> Result<Vec<(Vec<u8>, Hash)>> {
        let node = self.load_node(node_hash)?;
        match &node.items {
            NodeItems::Leaf(entries) => {
                let mut items = entries.clone();
                match items.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
                    Ok(i) => items[i].1 = value,
                    Err(i) => items.insert(i, (key.to_vec(), value)),
                }
                self.chunk_leaf(&items)
            }
            NodeItems::Branch(entries) => {
                let idx = route(entries, key);
                let new_children = self.insert_into(entries[idx].1, key, value)?;
                let mut items = entries.clone();
                items.splice(idx..idx + 1, new_children);
                self.chunk_branch(node.level, &items)
            }
        }
    }

    /// Remove `key` from the subtree at `node_hash`, returning the replacement
    /// routing entries (empty if the subtree became empty). Merges fall out of
    /// re-running the cut rule after the key (and any boundary it was) is gone.
    fn delete_from(&self, node_hash: Hash, key: &[u8]) -> Result<Vec<(Vec<u8>, Hash)>> {
        let node = self.load_node(node_hash)?;
        match &node.items {
            NodeItems::Leaf(entries) => {
                let mut items = entries.clone();
                if let Ok(i) = items.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
                    items.remove(i);
                }
                if items.is_empty() {
                    return Ok(Vec::new());
                }
                self.chunk_leaf(&items)
            }
            NodeItems::Branch(entries) => {
                let idx = route(entries, key);
                let new_children = self.delete_from(entries[idx].1, key)?;
                let mut items = entries.clone();
                items.splice(idx..idx + 1, new_children);
                if items.is_empty() {
                    return Ok(Vec::new());
                }
                self.chunk_branch(node.level, &items)
            }
        }
    }

    // ---------- object IO + caches ----------

    fn load_manifest_or_empty(&self, root: StateRoot) -> Result<Arc<StateManifest>> {
        if let Some(m) = self
            .manifest_cache
            .read()
            .expect("manifest cache poisoned")
            .get(&root)
        {
            return Ok(Arc::clone(m));
        }
        if self.objects.exists(root) {
            return self.load_manifest(root);
        }
        let empty_root = self.empty_root()?;
        if root == empty_root {
            return Ok(Arc::new(new_state_manifest(None)));
        }
        Err(anyhow!("state root {} not found", root))
    }

    fn cache_manifest(&self, root: StateRoot, manifest: Arc<StateManifest>) {
        let mut cache = self
            .manifest_cache
            .write()
            .expect("manifest cache poisoned");
        if cache.len() >= STATE_CACHE_CAP {
            cache.clear();
        }
        cache.insert(root, manifest);
    }

    fn cache_node(&self, hash: Hash, node: Arc<StateNode>) {
        let mut cache = self.node_cache.write().expect("node cache poisoned");
        if cache.len() >= STATE_CACHE_CAP {
            cache.clear();
        }
        cache.insert(hash, node);
    }

    fn store_manifest(&self, manifest: &StateManifest) -> Result<StateRoot> {
        let root = self.objects.put_serialized(STATE_TAG, manifest)?;
        self.cache_manifest(root, Arc::new(manifest.clone()));
        Ok(root)
    }

    fn load_manifest(&self, hash: StateRoot) -> Result<Arc<StateManifest>> {
        let bytes = self.objects.get_typed_bytes(STATE_TAG, hash)?;
        if hash_typed(STATE_TAG, &bytes) != hash {
            return Err(anyhow!("manifest hash mismatch for {}", hash));
        }
        let manifest: Arc<StateManifest> = Arc::new(from_cbor(&bytes)?);
        self.cache_manifest(hash, Arc::clone(&manifest));
        Ok(manifest)
    }

    fn store_node(&self, node: &StateNode) -> Result<Hash> {
        let hash = self.objects.put_serialized(STATE_TAG, node)?;
        self.cache_node(hash, Arc::new(node.clone()));
        Ok(hash)
    }

    fn load_node(&self, hash: Hash) -> Result<Arc<StateNode>> {
        if let Some(n) = self
            .node_cache
            .read()
            .expect("node cache poisoned")
            .get(&hash)
        {
            return Ok(Arc::clone(n));
        }
        let bytes = self.objects.get_typed_bytes(STATE_TAG, hash)?;
        if hash_typed(STATE_TAG, &bytes) != hash {
            return Err(anyhow!("node hash mismatch for {}", hash));
        }
        let node: Arc<StateNode> = Arc::new(from_cbor(&bytes)?);
        self.cache_node(hash, Arc::clone(&node));
        Ok(node)
    }
}

fn new_state_manifest(root: Option<Hash>) -> StateManifest {
    StateManifest {
        schema_version: STATE_SCHEMA_VERSION,
        root,
    }
}

/// Content hash of a node, recomputed without store access — must match
/// `ObjectStore::put_serialized(STATE_TAG, node)` so proofs verify offline.
fn node_hash(node: &StateNode) -> Result<Hash> {
    Ok(hash_typed(STATE_TAG, &to_cbor(node)?))
}

fn value_commit(value: &ValueRef) -> Hash {
    match value {
        ValueRef::Value(h) => *h,
        ValueRef::Inline(bytes) => hash_blob(bytes),
    }
}

/// Boundary level of a key: leading zero bits of `hash(key)` divided by
/// `BITS_PER_LEVEL`, capped. A key is a boundary at level L iff this is `> L`.
fn key_level(key: &[u8]) -> u32 {
    let h = hash_typed(LEVEL_TAG, key);
    let mut zeros = 0u32;
    for &b in h.as_bytes() {
        if b == 0 {
            zeros += 8;
        } else {
            zeros += b.leading_zeros();
            break;
        }
    }
    (zeros / BITS_PER_LEVEL).min(MAX_LEVEL)
}

/// Route to the child whose subtree covers `key`: the first entry whose
/// `last_key >= key`, or the last child when `key` exceeds every `last_key`.
fn route(entries: &[(Vec<u8>, Hash)], key: &[u8]) -> usize {
    let idx = entries.partition_point(|(lk, _)| lk.as_slice() < key);
    idx.min(entries.len() - 1)
}

fn leaf_sorted_unique(entries: &[(Vec<u8>, ValueRef)]) -> bool {
    !entries.is_empty() && entries.windows(2).all(|w| w[0].0 < w[1].0)
}

fn branch_sorted_unique(entries: &[(Vec<u8>, Hash)]) -> bool {
    !entries.is_empty() && entries.windows(2).all(|w| w[0].0 < w[1].0)
}

/// Smallest key strictly greater than every key starting with `prefix`, or
/// `None` when `prefix` is empty or all `0xFF` (no upper bound).
fn prefix_upper(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    while let Some(last) = upper.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return Some(upper);
        }
        upper.pop();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_store::BlobStore;
    use crate::object_store::ObjectStore;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use tempfile::TempDir;

    fn store(tmp: &TempDir) -> StateStore {
        let objects = ObjectStore::new(tmp.path().join("objects"));
        objects.ensure_dir().unwrap();
        let blobs = BlobStore::new(tmp.path().join("blobs"));
        blobs.ensure_dir().unwrap();
        StateStore::new(objects, blobs)
    }

    /// Rebuild the canonical root for `model` directly — the oracle incremental
    /// writes must match.
    fn oracle_root(s: &StateStore, model: &BTreeMap<Vec<u8>, Vec<u8>>) -> Option<Hash> {
        let entries: Vec<(Vec<u8>, ValueRef)> = model
            .iter()
            .map(|(k, v)| (k.clone(), s.encode_value(v).unwrap()))
            .collect();
        s.build_from_sorted(entries).unwrap()
    }

    #[test]
    fn empty_root_get_none() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let root = s.empty_root().unwrap();
        assert_eq!(s.get(root, b"missing").unwrap(), None);
    }

    #[test]
    fn set_get_overwrite_delete() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let r1 = s.set(r0, b"k", b"v1").unwrap();
        assert_eq!(s.get(r1, b"k").unwrap(), Some(b"v1".to_vec()));
        let r2 = s.set(r1, b"k", b"v2").unwrap();
        assert_eq!(s.get(r2, b"k").unwrap(), Some(b"v2".to_vec()));
        // old root still readable
        assert_eq!(s.get(r1, b"k").unwrap(), Some(b"v1".to_vec()));
        let r3 = s.del(r2, b"k").unwrap();
        assert_eq!(s.get(r3, b"k").unwrap(), None);
        // emptied state returns to the canonical empty root
        assert_eq!(r3, r0);
    }

    #[test]
    fn large_value_round_trips_via_blob() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let big = vec![7u8; INLINE_VALUE_MAX + 100];
        let r1 = s.set(r0, b"k", &big).unwrap();
        assert_eq!(s.get(r1, b"k").unwrap(), Some(big));
    }

    #[test]
    fn many_keys_read_back() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let mut root = s.empty_root().unwrap();
        for i in 0..2000u32 {
            root = s.set(root, format!("key_{i:05}").as_bytes(), b"v").unwrap();
        }
        for i in 0..2000u32 {
            assert_eq!(
                s.get(root, format!("key_{i:05}").as_bytes()).unwrap(),
                Some(b"v".to_vec())
            );
        }
        assert_eq!(s.get(root, b"key_99999").unwrap(), None);
    }

    #[test]
    fn insertion_order_independent_root() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let keys: Vec<String> = (0..200).map(|i| format!("k{i:04}")).collect();
        let forward = {
            let mut r = r0;
            for k in &keys {
                r = s.set(r, k.as_bytes(), b"v").unwrap();
            }
            r
        };
        let reverse = {
            let mut r = r0;
            for k in keys.iter().rev() {
                r = s.set(r, k.as_bytes(), b"v").unwrap();
            }
            r
        };
        assert_eq!(forward, reverse);
    }

    #[test]
    fn bulk_build_matches_sequential_root() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r0 = s.empty_root().unwrap();
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..500)
            .map(|i| {
                (
                    format!("key_{i:05}").into_bytes(),
                    format!("v{i}").into_bytes(),
                )
            })
            .collect();
        let refs: Vec<(&[u8], &[u8])> = pairs
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();

        let bulk = s.set_many(r0, &refs).unwrap();
        let mut seq = r0;
        for (k, v) in &pairs {
            seq = s.set(seq, k, v).unwrap();
        }
        assert_eq!(bulk, seq, "set_many bulk build diverged from sequential");
    }

    #[test]
    fn proofs_membership_and_non_membership() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let mut root = s.empty_root().unwrap();
        for i in 0..1000u32 {
            root = s.set(root, format!("key_{i:05}").as_bytes(), b"v").unwrap();
        }
        let present = s.proof(root, b"key_00042").unwrap();
        assert!(matches!(present.outcome, StateOutcome::Found(_)));
        assert!(s.verify_proof(root, b"key_00042", &present));

        let absent = s.proof(root, b"key_99999").unwrap();
        assert_eq!(absent.outcome, StateOutcome::Missing);
        assert!(s.verify_proof(root, b"key_99999", &absent));

        // O(log_B n): a 1000-key tree proves in a handful of nodes, not 1000.
        assert!(
            absent.path.len() <= 6,
            "proof path was {} nodes",
            absent.path.len()
        );
    }

    #[test]
    fn proof_for_empty_root_missing() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let r = s.empty_root().unwrap();
        let p = s.proof(r, b"k").unwrap();
        assert_eq!(p.outcome, StateOutcome::Missing);
        assert!(p.path.is_empty());
        assert!(s.verify_proof(r, b"k", &p));
    }

    #[test]
    fn scan_prefix_returns_sorted_matches() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let mut r = s.empty_root().unwrap();
        for k in [
            b"p/3".as_slice(),
            b"p/1",
            b"q/9",
            b"p/2",
            b"a",
            b"p/10",
            b"zzz",
        ] {
            r = s.set(r, k, b"v").unwrap();
        }
        let keys: Vec<Vec<u8>> = s
            .scan_prefix(r, b"p/")
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            keys,
            vec![
                b"p/1".to_vec(),
                b"p/10".to_vec(),
                b"p/2".to_vec(),
                b"p/3".to_vec()
            ]
        );
    }

    #[test]
    fn scan_prefix_empty_returns_all_sorted() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let mut r = s.empty_root().unwrap();
        let mut expected: Vec<Vec<u8>> = Vec::new();
        for i in 0..300u32 {
            let k = format!("k{i:04}").into_bytes();
            r = s.set(r, &k, b"v").unwrap();
            expected.push(k);
        }
        expected.sort();
        let got: Vec<Vec<u8>> = s
            .scan_prefix(r, b"")
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn load_missing_root_errors() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        assert!(s.get(Hash::zero(), b"k").is_err());
    }

    #[test]
    fn empty_root_is_memoized_and_skips_redundant_writes() {
        use crate::cas::CasStore;
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let h1 = s.empty_root().unwrap();
        let cas_path = CasStore::new(tmp.path().join("objects")).path_for(h1);
        assert!(cas_path.exists());
        std::fs::remove_file(&cas_path).unwrap();
        let h2 = s.empty_root().unwrap();
        assert_eq!(h1, h2);
        assert!(
            !cas_path.exists(),
            "empty_root re-stored — memoization bypassed"
        );
    }

    /// Golden vector: locks the on-disk node/manifest encoding. A change here
    /// means the byte format moved — update intentionally, never to make a
    /// failing test pass.
    #[test]
    fn golden_root_hash() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let mut root = s.empty_root().unwrap();
        for (k, v) in [
            (b"alpha".as_slice(), b"1".as_slice()),
            (b"bravo", b"2"),
            (b"charlie", b"3"),
            (b"delta", b"4"),
        ] {
            root = s.set(root, k, v).unwrap();
        }
        assert_eq!(
            root.to_string(),
            "65f3a311333022cb0a16e6dff0902eb31c57cc6a698b2e3ebeae04c6bce6681b",
            "state root format changed"
        );
    }

    fn random_property(seed: u64) {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let mut rng = StdRng::seed_from_u64(seed);
        let mut root = s.empty_root().unwrap();
        let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let keys: Vec<Vec<u8>> = (0..40).map(|i| format!("k{i:03}").into_bytes()).collect();

        for _ in 0..400 {
            let k = keys[rng.gen_range(0..keys.len())].clone();
            if rng.gen_range(0..3) < 2 {
                let v = format!("v{}", rng.gen_range(0..1000)).into_bytes();
                root = s.set(root, &k, &v).unwrap();
                model.insert(k.clone(), v);
            } else {
                root = s.del(root, &k).unwrap();
                model.remove(&k);
            }
            // Incremental root must equal the from-scratch canonical build.
            let manifest_root = s.load_manifest_or_empty(root).unwrap().root;
            assert_eq!(
                manifest_root,
                oracle_root(&s, &model),
                "incremental diverged from canonical"
            );
            // Every probe reads correctly and its proof verifies.
            for probe in &keys {
                assert_eq!(s.get(root, probe).unwrap(), model.get(probe).cloned());
                let p = s.proof(root, probe).unwrap();
                assert!(s.verify_proof(root, probe, &p));
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
    prop_test!(property_seed_1, 1);
    prop_test!(property_seed_2, 2);
    prop_test!(property_seed_3, 3);
    prop_test!(property_seed_4, 4);
    prop_test!(property_seed_5, 5);

    /// Forged proofs must be rejected.
    mod adversarial {
        use super::*;

        fn setup() -> (TempDir, StateStore, StateRoot) {
            let tmp = TempDir::new().unwrap();
            let s = store(&tmp);
            let mut root = s.empty_root().unwrap();
            for i in 0..500u32 {
                root = s.set(root, format!("key_{i:05}").as_bytes(), b"v").unwrap();
            }
            (tmp, s, root)
        }

        #[test]
        fn forged_found_for_absent_key_rejected() {
            let (_t, s, root) = setup();
            let mut p = s.proof(root, b"absent").unwrap();
            assert_eq!(p.outcome, StateOutcome::Missing);
            p.outcome = StateOutcome::Found(crate::hash::hash_typed(b"blob:", b"fake"));
            assert!(!s.verify_proof(root, b"absent", &p));
        }

        #[test]
        fn forged_missing_for_present_key_rejected() {
            let (_t, s, root) = setup();
            let mut p = s.proof(root, b"key_00100").unwrap();
            assert!(matches!(p.outcome, StateOutcome::Found(_)));
            p.outcome = StateOutcome::Missing;
            assert!(!s.verify_proof(root, b"key_00100", &p));
        }

        #[test]
        fn wrong_root_anchor_rejected() {
            let (_t, s, root) = setup();
            let mut p = s.proof(root, b"key_00100").unwrap();
            p.root = Some(crate::hash::hash_typed(b"forged:", b"root"));
            assert!(!s.verify_proof(root, b"key_00100", &p));
        }

        #[test]
        fn tampered_leaf_rejected() {
            let (_t, s, root) = setup();
            let mut p = s.proof(root, b"key_00100").unwrap();
            if let NodeItems::Leaf(entries) = &mut p.path.last_mut().unwrap().items {
                entries[0].1 = ValueRef::Inline(b"forged".to_vec());
            }
            assert!(!s.verify_proof(root, b"key_00100", &p));
        }

        #[test]
        fn truncated_path_rejected() {
            let (_t, s, root) = setup();
            let mut p = s.proof(root, b"key_00100").unwrap();
            if p.path.len() > 1 {
                p.path.pop();
                assert!(!s.verify_proof(root, b"key_00100", &p));
            }
        }
    }
}
