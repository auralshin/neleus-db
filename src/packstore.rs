//! Loose-object consolidation for one content-addressed (`CasStore`) root.
//!
//! ```text
//! pack/pack-<id>.pack   "NELPACK1" | u32 ver | u32 count
//!                       per entry (hash-sorted): 32B hash | u64 len | data
//!                       footer: 32B BLAKE3 over the above
//! pack/pack-<id>.idx    "NELIDX01" | u32 ver | u32 count
//!                       per entry (hash-sorted): 32B hash | u64 offset | u64 len
//!                       footer: 32B BLAKE3 over the above
//! ```
//!
//! `<id>` = the `.pack` footer hex, so identical object sets pack identically.
//! Bytes are copied verbatim from disk (below the crypto boundary), so packing
//! needs no password. Crash-safe: the pack is fsynced before any loose copy is
//! deleted, so a crash mid-delete leaves both forms readable.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow, bail};
use blake3::Hasher;

use crate::atomic::{build_temp_name, maybe_sync_dir, maybe_sync_file};
use crate::hash::Hash;

const PACK_MAGIC: &[u8; 8] = b"NELPACK1";
const IDX_MAGIC: &[u8; 8] = b"NELIDX01";
const FORMAT_VERSION: u32 = 1;

/// Subdirectory under a CAS root holding `.pack`/`.idx` files. Not a valid
/// shard name (shards are two hex chars), so it never collides with object
/// storage.
pub const PACK_DIR: &str = "pack";

/// Where one packed object lives: which `.pack` file and the byte slice in it.
#[derive(Debug, Clone)]
struct PackLoc {
    pack_path: Arc<PathBuf>,
    offset: u64,
    len: u64,
}

/// Summary of a single pack on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackInfo {
    pub id: String,
    pub entries: usize,
    pub bytes: u64,
}

/// Outcome of a [`pack_loose`] run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RepackStats {
    /// Loose objects consolidated into the new pack.
    pub packed_objects: usize,
    /// Total object bytes written into the pack (excludes header/footer).
    pub pack_bytes: u64,
    /// Loose files removed after packing.
    pub reclaimed_loose: usize,
}

/// In-memory index over a CAS root's `pack/` dir, consulted on a loose miss.
/// A repack is seen only by `PackSet`s loaded after it; reopen to refresh.
#[derive(Debug, Default)]
pub struct PackSet {
    entries: std::collections::HashMap<Hash, PackLoc>,
}

impl PackSet {
    /// Load every `pack/*.idx`. Bails on a corrupt `.idx` or missing `.pack`.
    pub fn load(cas_root: &Path) -> Result<Self> {
        let dir = cas_root.join(PACK_DIR);
        let mut entries = std::collections::HashMap::new();
        let read_dir = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading pack dir {}", dir.display())),
        };

        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("idx") {
                continue;
            }
            let pack_path = Arc::new(path.with_extension("pack"));
            if !pack_path.exists() {
                bail!("pack index {} has no matching .pack file", path.display());
            }
            load_idx_into(&path, &pack_path, &mut entries)?;
        }
        Ok(Self { entries })
    }

    pub fn contains(&self, hash: Hash) -> bool {
        self.entries.contains_key(&hash)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Every object hash held across all loaded packs.
    pub fn hashes(&self) -> Vec<Hash> {
        self.entries.keys().copied().collect()
    }

    /// `(hash, data_len)` for every packed object.
    pub fn entry_lens(&self) -> Vec<(Hash, u64)> {
        self.entries.iter().map(|(h, l)| (*h, l.len)).collect()
    }

    /// As [`Self::entry_lens`], plus the pack each entry lives in, so callers
    /// can apply per-pack policy (freshness) without a second index load.
    pub fn entry_lens_with_pack(&self) -> Vec<(Hash, u64, PathBuf)> {
        self.entries
            .iter()
            .map(|(h, l)| (*h, l.len, l.pack_path.as_ref().clone()))
            .collect()
    }

    /// Verbatim on-disk bytes of a packed object, or `None` if not packed.
    pub fn get(&self, hash: Hash) -> Result<Option<Vec<u8>>> {
        let Some(loc) = self.entries.get(&hash) else {
            return Ok(None);
        };
        let mut f = File::open(loc.pack_path.as_path())
            .with_context(|| format!("opening pack {}", loc.pack_path.display()))?;
        f.seek(SeekFrom::Start(loc.offset))?;
        let mut buf = vec![0u8; loc.len as usize];
        f.read_exact(&mut buf).with_context(|| {
            format!(
                "reading packed object {hash} from {}",
                loc.pack_path.display()
            )
        })?;
        Ok(Some(buf))
    }
}

fn load_idx_into(
    idx_path: &Path,
    pack_path: &Arc<PathBuf>,
    out: &mut std::collections::HashMap<Hash, PackLoc>,
) -> Result<()> {
    let bytes = fs::read(idx_path).with_context(|| format!("reading {}", idx_path.display()))?;
    // magic(8) + ver(4) + count(4) + footer(32) minimum
    if bytes.len() < 48 {
        bail!("pack index too short: {}", idx_path.display());
    }
    let (body, footer) = bytes.split_at(bytes.len() - 32);
    if blake3::hash(body).as_bytes() != footer {
        bail!("pack index integrity check failed: {}", idx_path.display());
    }
    if &body[0..8] != IDX_MAGIC {
        bail!(
            "not a neleus pack index (bad magic): {}",
            idx_path.display()
        );
    }
    let version = u32::from_le_bytes(body[8..12].try_into().unwrap());
    if version != FORMAT_VERSION {
        bail!(
            "unsupported pack index version {version}: {}",
            idx_path.display()
        );
    }
    let count = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
    let mut p = 16usize;
    for _ in 0..count {
        if p + 48 > body.len() {
            bail!("pack index truncated: {}", idx_path.display());
        }
        let hash = Hash::from_bytes(body[p..p + 32].try_into().unwrap());
        let offset = u64::from_le_bytes(body[p + 32..p + 40].try_into().unwrap());
        let len = u64::from_le_bytes(body[p + 40..p + 48].try_into().unwrap());
        p += 48;
        out.insert(
            hash,
            PackLoc {
                pack_path: Arc::clone(pack_path),
                offset,
                len,
            },
        );
    }
    Ok(())
}

/// A content file in a CAS root: name is a 64-char lowercase hex hash.
fn parse_content_name(name: &str) -> Option<Hash> {
    if name.len() != 64 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    name.parse::<Hash>().ok()
}

/// Enumerate every loose content object under `cas_root`, skipping the `pack/`
/// dir and atomic-write temp leftovers. Returns `(hash, path)` pairs.
pub fn loose_objects(cas_root: &Path) -> Result<Vec<(Hash, PathBuf)>> {
    let mut out = Vec::new();
    walk_shards(cas_root, &mut out)?;
    Ok(out)
}

fn walk_shards(cas_root: &Path, out: &mut Vec<(Hash, PathBuf)>) -> Result<()> {
    let top = match fs::read_dir(cas_root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", cas_root.display())),
    };
    for shard1 in top {
        let shard1 = shard1?;
        if !shard1.file_type()?.is_dir() {
            continue;
        }
        // Skip the pack/ subdir; shard dirs are two hex chars.
        if shard1.file_name() == PACK_DIR {
            continue;
        }
        for shard2 in fs::read_dir(shard1.path())? {
            let shard2 = shard2?;
            if !shard2.file_type()?.is_dir() {
                continue;
            }
            for obj in fs::read_dir(shard2.path())? {
                let obj = obj?;
                if !obj.file_type()?.is_file() {
                    continue;
                }
                let name = obj.file_name();
                let Some(name) = name.to_str() else { continue };
                if let Some(hash) = parse_content_name(name) {
                    out.push((hash, obj.path()));
                }
                // Non-content names (temp leftovers) are ignored.
            }
        }
    }
    Ok(())
}

/// Consolidate every loose object under `cas_root` into one new pack, then
/// remove the loose copies. Already-packed objects are untouched, so repeated
/// calls accumulate one pack each. No-op when nothing is loose.
pub fn pack_loose(cas_root: &Path) -> Result<RepackStats> {
    let mut loose = loose_objects(cas_root)?;
    if loose.is_empty() {
        return Ok(RepackStats::default());
    }
    loose.sort_by_key(|a| a.0);
    loose.dedup_by(|a, b| a.0 == b.0);

    let pack_dir = cas_root.join(PACK_DIR);
    fs::create_dir_all(&pack_dir)
        .with_context(|| format!("creating pack dir {}", pack_dir.display()))?;

    // One file in memory at a time.
    let sources = loose.iter().map(|(h, path)| {
        let path = path.clone();
        (*h, move || {
            fs::read(&path).with_context(|| format!("reading {}", path.display()))
        })
    });
    // Age of the newest object going in, captured before the loose files are
    // unlinked. GC's freshness test asks "could this pack hold something too new
    // to sweep", so a pack rebuilt from old content must keep the old content's
    // age. Without it, `repack` stamps everything now and the next
    // `gc --prune` reclaims nothing for a whole grace window.
    let newest = newest_mtime(loose.iter().map(|(_, p)| p.as_path()));
    let info = write_pack(&pack_dir, loose.len(), sources)?;
    if let Some(mtime) = newest {
        stamp_pack_age(&pack_dir, &info.id, mtime)?;
    }

    // Pack is durable; deleting loose copies now cannot lose data.
    let mut reclaimed = 0usize;
    for (_, path) in &loose {
        match fs::remove_file(path) {
            Ok(()) => reclaimed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing loose {}", path.display())),
        }
    }
    prune_empty_shard_dirs(cas_root)?;

    Ok(RepackStats {
        packed_objects: info.entries,
        pack_bytes: info.bytes,
        reclaimed_loose: reclaimed,
    })
}

/// Drop packed objects not in `live` (GC's prune of already-packed garbage). A
/// fully-live pack is left as-is; a partially-dead one is rewritten to keep only
/// the live entries; a fully-dead one is removed. Returns `(removed, bytes)`.
///
/// `cutoff` protects packs written too recently to be sure they are garbage: a
/// peer can write a pack whose objects are not yet reachable from any ref, and
/// deleting those would lose committed content.
pub fn rewrite_packs_keeping(
    cas_root: &Path,
    live: &HashSet<Hash>,
    cutoff: SystemTime,
) -> Result<(usize, u64, usize)> {
    rewrite_packs(cas_root, Some(cutoff), |h| !live.contains(h))
}

/// Drop exactly `targets` from whichever packs hold them (authorized erasure).
///
/// Unlike [`rewrite_packs_keeping`], the survivor set is derived per pack from
/// that pack's own index, so a pack written concurrently, or one this handle's
/// cached index has never seen, keeps all of its objects instead of being
/// classified wholly dead and unlinked.
pub fn rewrite_packs_dropping(cas_root: &Path, targets: &HashSet<Hash>) -> Result<(usize, u64)> {
    let (removed, bytes, _) = rewrite_packs(cas_root, None, |h| targets.contains(h))?;
    Ok((removed, bytes))
}

fn rewrite_packs(
    cas_root: &Path,
    cutoff: Option<SystemTime>,
    is_dead: impl Fn(&Hash) -> bool,
) -> Result<(usize, u64, usize)> {
    let pack_dir = cas_root.join(PACK_DIR);
    let read_dir = match fs::read_dir(&pack_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0, 0)),
        Err(e) => return Err(e).with_context(|| format!("reading {}", pack_dir.display())),
    };

    let mut idx_paths = Vec::new();
    for entry in read_dir {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("idx") {
            idx_paths.push(path);
        }
    }

    let mut removed_objects = 0usize;
    let mut removed_bytes = 0u64;
    let mut skipped_objects = 0usize;
    for idx_path in idx_paths {
        let pack_path = idx_path.with_extension("pack");
        if let Some(cutoff) = cutoff
            && pack_is_fresh(&pack_path, cutoff)
        {
            // Report what the grace held back, or the caller reports "no
            // garbage" when there is garbage it merely declined to touch.
            let mut held = std::collections::HashMap::new();
            let arc = Arc::new(pack_path.clone());
            if load_idx_into(&idx_path, &arc, &mut held).is_ok() {
                skipped_objects += held.keys().filter(|h| is_dead(h)).count();
            }
            continue;
        }
        let mut map = std::collections::HashMap::new();
        let pack_arc = Arc::new(pack_path.clone());
        load_idx_into(&idx_path, &pack_arc, &mut map)?;

        let dead: Vec<(Hash, PackLoc)> = map
            .iter()
            .filter(|(h, _)| is_dead(h))
            .map(|(h, l)| (*h, l.clone()))
            .collect();
        if dead.is_empty() {
            continue; // nothing to drop; keep pack untouched
        }
        for (_, loc) in &dead {
            removed_objects += 1;
            removed_bytes += loc.len;
        }

        let live_locs: Vec<(Hash, PackLoc)> =
            map.into_iter().filter(|(h, _)| !is_dead(h)).collect();

        if !live_locs.is_empty() {
            let mut ordered = live_locs;
            ordered.sort_by_key(|a| a.0);
            let count = ordered.len();
            let src_path = pack_path.clone();
            let sources = ordered.into_iter().map(move |(h, loc)| {
                let pp = src_path.clone();
                (h, move || {
                    let mut f = File::open(&pp)
                        .with_context(|| format!("opening pack {}", pp.display()))?;
                    read_slice(&mut f, loc.offset, loc.len)
                })
            });
            // Survivors are exactly as old as they were; carry the age across so
            // rewriting a pack does not reset its contents' grace clock.
            let inherited = fs::metadata(&pack_path).and_then(|m| m.modified()).ok();
            let info = write_pack(&pack_dir, count, sources)?;
            if let Some(mtime) = inherited {
                stamp_pack_age(&pack_dir, &info.id, mtime)?;
            }
        }

        // New pack (if any) is durable; drop the old pair.
        fs::remove_file(&idx_path).ok();
        fs::remove_file(&pack_path).ok();
    }
    Ok((removed_objects, removed_bytes, skipped_objects))
}

/// A pack too young to be sure its contents are garbage: its objects may be
/// committed but not yet reachable from any ref.
fn pack_is_fresh(pack_path: &Path, cutoff: SystemTime) -> bool {
    match fs::metadata(pack_path).and_then(|m| m.modified()) {
        Ok(modified) => modified >= cutoff,
        Err(_) => true, // unknown age: protect
    }
}

/// Newest modification time across `paths`, ignoring any that cannot be stat'd.
fn newest_mtime<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Option<SystemTime> {
    paths
        .into_iter()
        .filter_map(|p| fs::metadata(p).and_then(|m| m.modified()).ok())
        .max()
}

/// Give a freshly written pack the age of the content it holds, so consolidating
/// old objects does not make them look new to [`pack_is_fresh`].
fn stamp_pack_age(pack_dir: &Path, id: &str, mtime: SystemTime) -> Result<()> {
    let path = pack_dir.join(format!("pack-{id}.pack"));
    let f = OpenOptions::new()
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {} to stamp its age", path.display()))?;
    f.set_times(fs::FileTimes::new().set_modified(mtime))
        .with_context(|| format!("stamping {}", path.display()))?;
    Ok(())
}

/// Dry-run counterpart to [`rewrite_packs_keeping`]: count packed objects not in
/// `live` without modifying any pack. Applies the same freshness protection, so
/// the dry run reports what a real prune would actually remove.
pub fn packed_garbage(
    cas_root: &Path,
    live: &HashSet<Hash>,
    cutoff: SystemTime,
) -> Result<(usize, u64, usize)> {
    let packs = PackSet::load(cas_root)?;
    let mut count = 0usize;
    let mut bytes = 0u64;
    let mut skipped = 0usize;
    for (hash, len, pack_path) in packs.entry_lens_with_pack() {
        if live.contains(&hash) {
            continue;
        }
        if pack_is_fresh(&pack_path, cutoff) {
            skipped += 1;
            continue;
        }
        count += 1;
        bytes += len;
    }
    Ok((count, bytes, skipped))
}

fn read_slice(f: &mut File, offset: u64, len: u64) -> Result<Vec<u8>> {
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// List every pack under `cas_root`, sorted by id.
pub fn list_packs(cas_root: &Path) -> Result<Vec<PackInfo>> {
    let dir = cas_root.join(PACK_DIR);
    let read_dir = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut out = Vec::new();
    for entry in read_dir {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("idx") {
            continue;
        }
        let pack_path = Arc::new(path.with_extension("pack"));
        let mut map = std::collections::HashMap::new();
        load_idx_into(&path, &pack_path, &mut map)?;
        let bytes: u64 = map.values().map(|l| l.len).sum();
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("pack-"))
            .unwrap_or("?")
            .to_string();
        out.push(PackInfo {
            id,
            entries: map.len(),
            bytes,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Write `count` hash-sorted objects into a new pack + index. Each source is a
/// thunk, so only one object is held in memory at a time.
pub(crate) fn write_pack<I, F>(pack_dir: &Path, count: usize, sources: I) -> Result<PackInfo>
where
    I: IntoIterator<Item = (Hash, F)>,
    F: FnOnce() -> Result<Vec<u8>>,
{
    let count_u32: u32 = count
        .try_into()
        .map_err(|_| anyhow!("too many objects to pack"))?;

    let pack_tmp = pack_dir.join(build_temp_name("pack")?);
    let mut w = BufWriter::new(
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&pack_tmp)
            .with_context(|| format!("creating temp pack {}", pack_tmp.display()))?,
    );
    let mut h = Hasher::new();
    let mut pos = 0u64;
    let mut data_bytes = 0u64;

    wh(&mut w, &mut h, &mut pos, PACK_MAGIC)?;
    wh(&mut w, &mut h, &mut pos, &FORMAT_VERSION.to_le_bytes())?;
    wh(&mut w, &mut h, &mut pos, &count_u32.to_le_bytes())?;

    let mut idx_entries: Vec<(Hash, u64, u64)> = Vec::with_capacity(count);
    for (hash, source) in sources {
        let data = source()?;
        let len = data.len() as u64;
        wh(&mut w, &mut h, &mut pos, hash.as_bytes())?;
        wh(&mut w, &mut h, &mut pos, &len.to_le_bytes())?;
        let offset = pos;
        wh(&mut w, &mut h, &mut pos, &data)?;
        idx_entries.push((hash, offset, len));
        data_bytes += len;
    }
    if idx_entries.len() != count {
        bail!(
            "pack source count mismatch: declared {count}, wrote {}",
            idx_entries.len()
        );
    }

    let pack_id = h.finalize();
    let pack_id_hex = pack_id.to_hex().to_string();
    w.write_all(pack_id.as_bytes())?; // footer (not hashed)
    let f = w.into_inner().map_err(|e| anyhow!("flushing pack: {e}"))?;
    maybe_sync_file(&f)?;
    drop(f);

    let pack_final = pack_dir.join(format!("pack-{pack_id_hex}.pack"));
    fs::rename(&pack_tmp, &pack_final)
        .with_context(|| format!("finalizing pack {}", pack_final.display()))?;

    write_idx(pack_dir, &pack_id_hex, count_u32, &idx_entries)?;
    maybe_sync_dir(pack_dir)?;

    Ok(PackInfo {
        id: pack_id_hex,
        entries: count,
        bytes: data_bytes,
    })
}

fn write_idx(pack_dir: &Path, id: &str, count: u32, entries: &[(Hash, u64, u64)]) -> Result<()> {
    let mut body = Vec::with_capacity(16 + entries.len() * 48);
    body.extend_from_slice(IDX_MAGIC);
    body.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    body.extend_from_slice(&count.to_le_bytes());
    for (hash, offset, len) in entries {
        body.extend_from_slice(hash.as_bytes());
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&len.to_le_bytes());
    }
    let footer = blake3::hash(&body);

    let idx_tmp = pack_dir.join(build_temp_name("idx")?);
    {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&idx_tmp)
            .with_context(|| format!("creating temp idx {}", idx_tmp.display()))?;
        f.write_all(&body)?;
        f.write_all(footer.as_bytes())?;
        maybe_sync_file(&f)?;
    }
    let idx_final = pack_dir.join(format!("pack-{id}.idx"));
    fs::rename(&idx_tmp, &idx_final)
        .with_context(|| format!("finalizing idx {}", idx_final.display()))?;
    Ok(())
}

/// Write `bytes` to `w`, fold into `h`, advance `pos`.
fn wh<W: Write>(w: &mut W, h: &mut Hasher, pos: &mut u64, bytes: &[u8]) -> Result<()> {
    w.write_all(bytes)?;
    h.update(bytes);
    *pos += bytes.len() as u64;
    Ok(())
}

/// Remove now-empty shard dirs (`ab/`, `ab/cd/`) left after packing. Best
/// effort: a non-empty dir (concurrent writer landed a new object) is left.
fn prune_empty_shard_dirs(cas_root: &Path) -> Result<()> {
    let top = match fs::read_dir(cas_root) {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    for shard1 in top.flatten() {
        if !shard1.path().is_dir() || shard1.file_name() == PACK_DIR {
            continue;
        }
        if let Ok(inner) = fs::read_dir(shard1.path()) {
            for shard2 in inner.flatten() {
                if shard2.path().is_dir() {
                    let _ = fs::remove_dir(shard2.path()); // fails if non-empty
                }
            }
        }
        let _ = fs::remove_dir(shard1.path());
    }
    Ok(())
}

/// Read a pack body and verify its integrity footer, returning the contained
/// hashes. Used by tests and the `pack-list` verifier.
pub fn verify_pack(pack_path: &Path) -> Result<Vec<Hash>> {
    let mut r = BufReader::new(
        File::open(pack_path).with_context(|| format!("opening {}", pack_path.display()))?,
    );
    let mut all = Vec::new();
    r.read_to_end(&mut all)?;
    if all.len() < 48 {
        bail!("pack too short: {}", pack_path.display());
    }
    let (body, footer) = all.split_at(all.len() - 32);
    if blake3::hash(body).as_bytes() != footer {
        bail!("pack integrity check failed: {}", pack_path.display());
    }
    if &body[0..8] != PACK_MAGIC {
        bail!("not a neleus pack (bad magic): {}", pack_path.display());
    }
    let count = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
    let mut hashes = Vec::with_capacity(count);
    let mut p = 16usize;
    for _ in 0..count {
        let hash = Hash::from_bytes(body[p..p + 32].try_into().unwrap());
        let len = u64::from_le_bytes(body[p + 32..p + 40].try_into().unwrap()) as usize;
        p += 40 + len;
        hashes.push(hash);
    }
    Ok(hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::CasStore;
    use crate::hash::hash_blob;
    use tempfile::TempDir;

    fn loose_count(cas_root: &Path) -> usize {
        loose_objects(cas_root).unwrap().len()
    }

    /// Cutoff far enough ahead that no pack counts as fresh.
    fn no_grace() -> SystemTime {
        SystemTime::now() + std::time::Duration::from_secs(3600)
    }

    #[test]
    fn fresh_packs_are_protected_from_pruning() {
        let tmp = TempDir::new().unwrap();
        let cas = CasStore::new(tmp.path());
        cas.ensure_dir().unwrap();
        cas.put_and_hash(b"young", hash_blob).unwrap();
        pack_loose(tmp.path()).unwrap();

        // Cutoff in the past: the pack was written after it, so it is too young
        // to sweep even though nothing references its contents.
        let cutoff = SystemTime::now() - std::time::Duration::from_secs(3600);
        let (removed, _, _) = rewrite_packs_keeping(tmp.path(), &HashSet::new(), cutoff).unwrap();
        assert_eq!(removed, 0);
        assert!(!PackSet::load(tmp.path()).unwrap().is_empty());
        assert_eq!(
            packed_garbage(tmp.path(), &HashSet::new(), cutoff)
                .unwrap()
                .0,
            0,
            "dry run must agree with the prune it predicts"
        );
    }

    #[test]
    fn repacking_preserves_content_age() {
        let tmp = TempDir::new().unwrap();
        let cas = CasStore::new(tmp.path());
        cas.ensure_dir().unwrap();
        let h = cas.put_and_hash(b"old", hash_blob).unwrap();

        // Age the loose object well past any grace window.
        let old = SystemTime::now() - std::time::Duration::from_secs(7200);
        let f = OpenOptions::new()
            .write(true)
            .open(cas.path_for(h))
            .unwrap();
        f.set_times(fs::FileTimes::new().set_modified(old)).unwrap();
        drop(f);

        pack_loose(tmp.path()).unwrap();

        // Consolidation must not reset the clock. A cutoff between the content's
        // age and now has to still see this pack as sweepable, or `db repack`
        // makes `db gc --prune` a no-op for a whole grace window.
        let cutoff = SystemTime::now() - std::time::Duration::from_secs(3600);
        let (removed, _, skipped) =
            rewrite_packs_keeping(tmp.path(), &HashSet::new(), cutoff).unwrap();
        assert_eq!(skipped, 0, "a repacked old object must not look fresh");
        assert_eq!(removed, 1);
    }

    #[test]
    fn dropping_leaves_packs_it_was_not_asked_about() {
        let tmp = TempDir::new().unwrap();
        let cas = CasStore::new(tmp.path());
        cas.ensure_dir().unwrap();
        let doomed = cas.put_and_hash(b"doomed", hash_blob).unwrap();
        let bystander = cas.put_and_hash(b"bystander", hash_blob).unwrap();
        pack_loose(tmp.path()).unwrap();

        // A second pack this caller knows nothing about.
        let other = crate::hash::hash_blob(b"other");
        fs::create_dir_all(tmp.path().join(PACK_DIR)).unwrap();
        write_pack(
            &tmp.path().join(PACK_DIR),
            1,
            std::iter::once((other, || Ok(b"other".to_vec()))),
        )
        .unwrap();

        let targets: HashSet<Hash> = std::iter::once(doomed).collect();
        let (removed, _) = rewrite_packs_dropping(tmp.path(), &targets).unwrap();
        assert_eq!(removed, 1);

        let packs = PackSet::load(tmp.path()).unwrap();
        assert!(!packs.contains(doomed));
        assert!(packs.contains(bystander));
        assert!(packs.contains(other), "unrelated pack must survive");
    }

    #[test]
    fn pack_then_read_back_through_packset() {
        let tmp = TempDir::new().unwrap();
        let cas = CasStore::new(tmp.path());
        cas.ensure_dir().unwrap();
        let h1 = cas.put_and_hash(b"alpha", hash_blob).unwrap();
        let h2 = cas.put_and_hash(b"beta", hash_blob).unwrap();
        assert_eq!(loose_count(tmp.path()), 2);

        let stats = pack_loose(tmp.path()).unwrap();
        assert_eq!(stats.packed_objects, 2);
        assert_eq!(stats.reclaimed_loose, 2);
        assert_eq!(loose_count(tmp.path()), 0);

        let packs = PackSet::load(tmp.path()).unwrap();
        assert!(packs.contains(h1));
        assert!(packs.contains(h2));
        assert_eq!(packs.get(h1).unwrap().unwrap(), b"alpha");
        assert_eq!(packs.get(h2).unwrap().unwrap(), b"beta");
    }

    #[test]
    fn packing_is_deterministic() {
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();
        for root in [tmp1.path(), tmp2.path()] {
            let cas = CasStore::new(root);
            cas.ensure_dir().unwrap();
            cas.put_and_hash(b"one", hash_blob).unwrap();
            cas.put_and_hash(b"two", hash_blob).unwrap();
            pack_loose(root).unwrap();
        }
        let read = |root: &Path| {
            let d = root.join(PACK_DIR);
            let mut files: Vec<_> = fs::read_dir(&d)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            files.sort();
            files
                .iter()
                .map(|p| (p.file_name().unwrap().to_owned(), fs::read(p).unwrap()))
                .collect::<Vec<_>>()
        };
        assert_eq!(read(tmp1.path()), read(tmp2.path()));
    }

    #[test]
    fn pack_loose_is_noop_when_empty() {
        let tmp = TempDir::new().unwrap();
        let stats = pack_loose(tmp.path()).unwrap();
        assert_eq!(stats, RepackStats::default());
    }

    #[test]
    fn corrupt_idx_footer_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let cas = CasStore::new(tmp.path());
        cas.ensure_dir().unwrap();
        cas.put_and_hash(b"x", hash_blob).unwrap();
        pack_loose(tmp.path()).unwrap();

        let idx = fs::read_dir(tmp.path().join(PACK_DIR))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().and_then(|e| e.to_str()) == Some("idx"))
            .unwrap();
        let mut bytes = fs::read(&idx).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&idx, &bytes).unwrap();

        let err = PackSet::load(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("integrity"), "got: {err}");
    }

    #[test]
    fn rewrite_packs_keeping_drops_dead_entries() {
        let tmp = TempDir::new().unwrap();
        let cas = CasStore::new(tmp.path());
        cas.ensure_dir().unwrap();
        let keep = cas.put_and_hash(b"keep", hash_blob).unwrap();
        let drop = cas.put_and_hash(b"drop", hash_blob).unwrap();
        pack_loose(tmp.path()).unwrap();

        let mut live = HashSet::new();
        live.insert(keep);
        let (removed, _, _) = rewrite_packs_keeping(tmp.path(), &live, no_grace()).unwrap();
        assert_eq!(removed, 1);

        let packs = PackSet::load(tmp.path()).unwrap();
        assert!(packs.contains(keep));
        assert!(!packs.contains(drop));
        assert_eq!(packs.get(keep).unwrap().unwrap(), b"keep");
    }

    #[test]
    fn rewrite_packs_keeping_removes_fully_dead_pack() {
        let tmp = TempDir::new().unwrap();
        let cas = CasStore::new(tmp.path());
        cas.ensure_dir().unwrap();
        cas.put_and_hash(b"gone", hash_blob).unwrap();
        pack_loose(tmp.path()).unwrap();

        let (removed, _, _) =
            rewrite_packs_keeping(tmp.path(), &HashSet::new(), no_grace()).unwrap();
        assert_eq!(removed, 1);
        assert!(PackSet::load(tmp.path()).unwrap().is_empty());
        // No .pack/.idx left behind.
        let remaining: Vec<_> = fs::read_dir(tmp.path().join(PACK_DIR))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("pack") | Some("idx")
                )
            })
            .collect();
        assert!(remaining.is_empty(), "leftover pack files: {remaining:?}");
    }

    #[test]
    fn verify_pack_lists_contained_hashes() {
        let tmp = TempDir::new().unwrap();
        let cas = CasStore::new(tmp.path());
        cas.ensure_dir().unwrap();
        let a = cas.put_and_hash(b"aa", hash_blob).unwrap();
        let b = cas.put_and_hash(b"bb", hash_blob).unwrap();
        pack_loose(tmp.path()).unwrap();

        let pack = fs::read_dir(tmp.path().join(PACK_DIR))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().and_then(|e| e.to_str()) == Some("pack"))
            .unwrap();
        let mut hashes = verify_pack(&pack).unwrap();
        hashes.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(hashes, want);
    }
}
