//! Single-file pack/unpack for self-contained backup and transport.
//!
//! A pack is one opaque file (`pg_dump`-style) holding the whole database tree:
//!
//! ```text
//! magic "NELEUSPK" | u32 version | u32 entry_count
//! per entry (sorted by path): u32 path_len | path | u32 mode | u64 data_len | data
//! footer: 32-byte BLAKE3 over everything above
//! ```
//!
//! Entries are sorted by path, so the same tree always packs to identical bytes.
//! The footer makes corruption/tampering detectable before any file is restored.
//!
//! `pack` is a **cold copy**: it walks the filesystem without opening the DB, so
//! it needs no encryption password and copies ciphertext verbatim. Because it is
//! not an MVCC snapshot, the DB should be quiesced (no concurrent writers) — or
//! opened once to flush WAL recovery — before packing; packing a live DB can
//! capture a torn tree. `wal/` is included so `unpack`→`open` replays or discards
//! any pending entries; only lock files and atomic-write temp leftovers are
//! excluded.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use blake3::Hasher;

use crate::atomic::build_temp_name;
use crate::compression;

const MAGIC: &[u8; 8] = b"NELEUSPK";
/// Uncompressed pack: each entry's `data` is the verbatim file bytes.
const FORMAT_VERSION: u32 = 1;
/// Compressed pack: each entry's `data` is the zstd frame of the file bytes,
/// and `data_len` is the compressed length. Restore decompresses per entry.
const FORMAT_VERSION_COMPRESSED: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackStats {
    pub entries: usize,
    pub bytes: u64,
}

struct WalkEntry {
    rel: String,
    abs: PathBuf,
    mode: u32,
    len: u64,
}

/// Export `db_root` into a single self-contained pack file at `out_file`.
///
/// With `compress`, each entry's bytes are zstd-framed (format v2); this shrinks
/// packs of plaintext databases but gains little on an already-compressed or
/// encrypted DB whose on-disk bytes are near-incompressible. `bytes` in the
/// returned stats is always the logical (uncompressed) size.
pub fn pack(db_root: &Path, out_file: &Path, compress: bool) -> Result<PackStats> {
    if !db_root.join("meta").join("config.json").exists() {
        bail!(
            "not a neleus-db database (missing meta/config.json): {}",
            db_root.display()
        );
    }

    let entries = collect_entries(db_root)?;
    let count: u32 = entries
        .len()
        .try_into()
        .map_err(|_| anyhow!("too many files to pack"))?;

    let file = File::create(out_file)
        .with_context(|| format!("creating pack file {}", out_file.display()))?;
    let mut w = BufWriter::new(file);
    let mut h = Hasher::new();

    let version = if compress {
        FORMAT_VERSION_COMPRESSED
    } else {
        FORMAT_VERSION
    };
    write_hashed(&mut w, &mut h, MAGIC)?;
    write_hashed(&mut w, &mut h, &version.to_le_bytes())?;
    write_hashed(&mut w, &mut h, &count.to_le_bytes())?;

    let mut total_bytes = 0u64;
    for e in &entries {
        let path_bytes = e.rel.as_bytes();
        let path_len: u32 = path_bytes
            .len()
            .try_into()
            .map_err(|_| anyhow!("path too long: {}", e.rel))?;
        write_hashed(&mut w, &mut h, &path_len.to_le_bytes())?;
        write_hashed(&mut w, &mut h, path_bytes)?;
        write_hashed(&mut w, &mut h, &e.mode.to_le_bytes())?;

        if compress {
            let raw = fs::read(&e.abs).with_context(|| format!("reading {}", e.abs.display()))?;
            // A concurrent writer can change a file mid-pack; refuse rather than
            // emit an inconsistent pack.
            if raw.len() as u64 != e.len {
                bail!(
                    "file changed size during pack: {} (expected {}, read {})",
                    e.rel,
                    e.len,
                    raw.len()
                );
            }
            let framed = compression::compress(&raw)?;
            let framed_len: u64 = framed.len() as u64;
            write_hashed(&mut w, &mut h, &framed_len.to_le_bytes())?;
            write_hashed(&mut w, &mut h, &framed)?;
        } else {
            write_hashed(&mut w, &mut h, &e.len.to_le_bytes())?;
            let mut rf =
                File::open(&e.abs).with_context(|| format!("opening {}", e.abs.display()))?;
            let written = copy_hashed(&mut rf, &mut w, &mut h)?;
            if written != e.len {
                bail!(
                    "file changed size during pack: {} (expected {}, read {})",
                    e.rel,
                    e.len,
                    written
                );
            }
        }
        total_bytes += e.len;
    }

    w.write_all(h.finalize().as_bytes())?;
    w.flush()?;
    drop(w);

    harden_output_file(out_file)?;
    Ok(PackStats {
        entries: entries.len(),
        bytes: total_bytes,
    })
}

/// Restore a database directory at `db_root` from `pack_file`.
///
/// Streams into a sibling staging directory, verifies the integrity footer,
/// then `rename`s into place. Refuses a non-empty `db_root` unless `force`.
/// With `force`, the old directory is removed before the rename — that swap is
/// not crash-atomic (a crash in the window leaves the staging dir for manual
/// recovery).
pub fn unpack(pack_file: &Path, db_root: &Path, force: bool) -> Result<PackStats> {
    if dir_occupied(db_root)? && !force {
        bail!(
            "target {} already exists and is not empty; pass --force to overwrite",
            db_root.display()
        );
    }

    let file = File::open(pack_file)
        .with_context(|| format!("opening pack file {}", pack_file.display()))?;
    let mut r = BufReader::new(file);
    let mut h = Hasher::new();

    let mut magic = [0u8; 8];
    read_hashed(&mut r, &mut h, &mut magic)?;
    if &magic != MAGIC {
        bail!("not a neleus-db pack file (bad magic)");
    }
    let version = read_u32_hashed(&mut r, &mut h)?;
    let compressed = match version {
        FORMAT_VERSION => false,
        FORMAT_VERSION_COMPRESSED => true,
        other => bail!("unsupported pack format version {other}"),
    };
    let count = read_u32_hashed(&mut r, &mut h)?;

    let staging = staging_path(db_root)?;
    if staging.exists() {
        fs::remove_dir_all(&staging).ok();
    }
    create_dir_all_hardened(&staging)?;

    // Restore into staging; on any error, drop staging so we never leave a
    // half-written tree behind.
    let restored = restore_into(&mut r, &mut h, &staging, count, compressed);
    let total_bytes = match restored {
        Ok(b) => b,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    // Footer is NOT fed to the hasher; it is the expected digest of the prefix.
    let mut footer = [0u8; 32];
    if let Err(e) = r.read_exact(&mut footer) {
        let _ = fs::remove_dir_all(&staging);
        return Err(anyhow!("pack truncated: missing integrity footer: {e}"));
    }
    if footer != *h.finalize().as_bytes() {
        let _ = fs::remove_dir_all(&staging);
        bail!("pack integrity check failed: content hash mismatch (corrupt or tampered)");
    }

    if db_root.exists() {
        fs::remove_dir_all(db_root)
            .with_context(|| format!("removing existing target {}", db_root.display()))?;
    } else if let Some(parent) = db_root.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::rename(&staging, db_root)
        .with_context(|| format!("moving unpacked db into {}", db_root.display()))?;
    harden_dir(db_root)?;

    Ok(PackStats {
        entries: count as usize,
        bytes: total_bytes,
    })
}

/// Verify a pack's integrity footer and structural/path safety without writing
/// anything to disk. Returns the entry count and total stored data bytes
/// (compressed bytes for a v2 pack).
pub fn verify(pack_file: &Path) -> Result<PackStats> {
    let file = File::open(pack_file)
        .with_context(|| format!("opening pack file {}", pack_file.display()))?;
    let mut r = BufReader::new(file);
    let mut h = Hasher::new();

    let mut magic = [0u8; 8];
    read_hashed(&mut r, &mut h, &mut magic)?;
    if &magic != MAGIC {
        bail!("not a neleus-db pack file (bad magic)");
    }
    let version = read_u32_hashed(&mut r, &mut h)?;
    if version != FORMAT_VERSION && version != FORMAT_VERSION_COMPRESSED {
        bail!("unsupported pack format version {version}");
    }
    let count = read_u32_hashed(&mut r, &mut h)?;

    let mut total = 0u64;
    for _ in 0..count {
        let path_len = read_u32_hashed(&mut r, &mut h)? as usize;
        let mut path_buf = vec![0u8; path_len];
        read_hashed(&mut r, &mut h, &mut path_buf)?;
        let rel = String::from_utf8(path_buf).map_err(|_| anyhow!("invalid utf-8 path in pack"))?;
        // Reject path traversal here too, so verify flags a malicious pack
        // before anyone runs the real restore.
        safe_join(Path::new("verify"), &rel)?;
        let _mode = read_u32_hashed(&mut r, &mut h)?;
        let data_len = read_u64_hashed(&mut r, &mut h)?;
        skip_hashed(&mut r, &mut h, data_len)?;
        total += data_len;
    }

    let mut footer = [0u8; 32];
    r.read_exact(&mut footer)
        .map_err(|e| anyhow!("pack truncated: missing integrity footer: {e}"))?;
    if footer != *h.finalize().as_bytes() {
        bail!("pack integrity check failed: content hash mismatch (corrupt or tampered)");
    }
    Ok(PackStats {
        entries: count as usize,
        bytes: total,
    })
}

fn skip_hashed<R: Read>(r: &mut R, h: &mut Hasher, mut len: u64) -> Result<()> {
    let mut buf = [0u8; 64 * 1024];
    while len > 0 {
        let want = len.min(buf.len() as u64) as usize;
        let n = r.read(&mut buf[..want])?;
        if n == 0 {
            bail!("pack truncated while reading {len} more bytes");
        }
        h.update(&buf[..n]);
        len -= n as u64;
    }
    Ok(())
}

fn restore_into<R: Read>(
    r: &mut R,
    h: &mut Hasher,
    staging: &Path,
    count: u32,
    compressed: bool,
) -> Result<u64> {
    let mut total_bytes = 0u64;
    for _ in 0..count {
        let path_len = read_u32_hashed(r, h)? as usize;
        let mut path_buf = vec![0u8; path_len];
        read_hashed(r, h, &mut path_buf)?;
        let rel = String::from_utf8(path_buf).map_err(|_| anyhow!("invalid utf-8 path in pack"))?;
        let mode = read_u32_hashed(r, h)?;
        let data_len = read_u64_hashed(r, h)?;

        let dest = safe_join(staging, &rel)?;
        if let Some(parent) = dest.parent() {
            create_dir_all_hardened(parent)?;
        }
        // `data_len` is the stored length: raw bytes (v1) or the zstd frame
        // length (v2). The compressed path buffers and inflates per entry; the
        // raw path streams.
        let written = if compressed {
            write_file_compressed(r, h, &dest, data_len)?
        } else {
            write_file_streamed(r, h, &dest, data_len)?;
            data_len
        };
        harden_restored_file(&dest, mode)?;
        total_bytes += written;
    }
    Ok(total_bytes)
}

fn collect_entries(db_root: &Path) -> Result<Vec<WalkEntry>> {
    let mut out = Vec::new();
    walk(db_root, db_root, &mut out)?;
    out.sort_by(|a, b| a.rel.as_bytes().cmp(b.rel.as_bytes()));
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<WalkEntry>) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("reading dir {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk(root, &path, out)?;
            continue;
        }
        if !ft.is_file() {
            continue; // skip symlinks and special files
        }
        let rel = relative_slash(root, &path)?;
        if is_excluded(&path) {
            continue;
        }
        let meta = entry.metadata()?;
        out.push(WalkEntry {
            rel,
            abs: path,
            mode: mode_of(&meta),
            len: meta.len(),
        });
    }
    Ok(())
}

fn relative_slash(root: &Path, path: &Path) -> Result<String> {
    use std::path::Component;
    let rel = path
        .strip_prefix(root)
        .with_context(|| format!("{} not under {}", path.display(), root.display()))?;
    let mut parts = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            _ => bail!("unexpected path component in {}", rel.display()),
        }
    }
    Ok(parts.join("/"))
}

/// Transient files that must not enter a pack: lock files and atomic-write temp
/// leftovers. WAL files are intentionally kept — `open` replays or discards them.
fn is_excluded(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return true;
    };
    if name.ends_with(".lock") {
        return true;
    }
    crate::atomic::parse_temp_pid(name).is_some()
}

/// Join a pack-relative path onto `base`, rejecting absolute paths and any
/// `.`/`..` component so a malicious pack cannot write outside the target.
fn safe_join(base: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() {
        bail!("empty path in pack");
    }
    let mut out = base.to_path_buf();
    for part in rel.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            bail!("unsafe path in pack: {rel}");
        }
        out.push(part);
    }
    Ok(out)
}

fn write_file_streamed<R: Read>(r: &mut R, h: &mut Hasher, dest: &Path, len: u64) -> Result<()> {
    let file = File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut w = BufWriter::new(file);
    let mut remaining = len;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = r.read(&mut buf[..want])?;
        if n == 0 {
            bail!("pack truncated while reading {} bytes for {}", len, dest.display());
        }
        w.write_all(&buf[..n])?;
        h.update(&buf[..n]);
        remaining -= n as u64;
    }
    w.flush()?;
    Ok(())
}

/// Read a `len`-byte zstd frame (feeding the integrity hasher), inflate it, and
/// write the original bytes to `dest`. Returns the inflated size.
fn write_file_compressed<R: Read>(r: &mut R, h: &mut Hasher, dest: &Path, len: u64) -> Result<u64> {
    let mut framed = vec![0u8; len as usize];
    r.read_exact(&mut framed)
        .map_err(|e| anyhow!("pack truncated reading {len} bytes for {}: {e}", dest.display()))?;
    h.update(&framed);
    let raw = compression::decompress_if_compressed(&framed)?;
    let file = File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut w = BufWriter::new(file);
    w.write_all(&raw)?;
    w.flush()?;
    Ok(raw.len() as u64)
}

fn staging_path(db_root: &Path) -> Result<PathBuf> {
    let parent = db_root
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let name = db_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("neleus_db");
    Ok(parent.join(build_temp_name(&format!("{name}.unpack"))?))
}

fn dir_occupied(p: &Path) -> Result<bool> {
    if !p.exists() {
        return Ok(false);
    }
    if !p.is_dir() {
        return Ok(true);
    }
    Ok(fs::read_dir(p)?.next().is_some())
}

fn write_hashed<W: Write>(w: &mut W, h: &mut Hasher, bytes: &[u8]) -> Result<()> {
    w.write_all(bytes)?;
    h.update(bytes);
    Ok(())
}

fn copy_hashed<R: Read, W: Write>(r: &mut R, w: &mut W, h: &mut Hasher) -> Result<u64> {
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n])?;
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok(total)
}

fn read_hashed<R: Read>(r: &mut R, h: &mut Hasher, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf)?;
    h.update(buf);
    Ok(())
}

fn read_u32_hashed<R: Read>(r: &mut R, h: &mut Hasher) -> Result<u32> {
    let mut b = [0u8; 4];
    read_hashed(r, h, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64_hashed<R: Read>(r: &mut R, h: &mut Hasher) -> Result<u64> {
    let mut b = [0u8; 8];
    read_hashed(r, h, &mut b)?;
    Ok(u64::from_le_bytes(b))
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> u32 {
    0o600
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode on {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn harden_output_file(p: &Path) -> Result<()> {
    set_mode(p, 0o600)
}

/// Owner-only restore: keep the owner bits, strip group/other, never below rw.
fn harden_restored_file(p: &Path, captured_mode: u32) -> Result<()> {
    set_mode(p, (captured_mode & 0o700).max(0o600))
}

fn harden_dir(p: &Path) -> Result<()> {
    set_mode(p, 0o700)
}

/// Create `p` and any missing ancestors, hardening each directory we create to
/// `0o700`. Pre-existing directories (e.g. the staging dir's real parent) are
/// left untouched.
fn create_dir_all_hardened(p: &Path) -> Result<()> {
    if p.exists() {
        return Ok(());
    }
    if let Some(parent) = p.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_dir_all_hardened(parent)?;
    }
    match fs::create_dir(p) {
        Ok(()) => harden_dir(p),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).with_context(|| format!("creating dir {}", p.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use tempfile::TempDir;

    fn make_db(root: &Path) {
        Database::init(root).unwrap();
        let db = Database::open(root).unwrap();
        let _ = db.blob_store.put(b"hello world").unwrap();
        let _ = db.state_set_at_head("main", b"k", b"v").unwrap();
        let _ = db
            .create_commit_at_head("main", "agent", "msg", vec![])
            .unwrap();
    }

    /// Build pack bytes with arbitrary entries and a valid footer, for crafting
    /// malicious/edge-case inputs in tests.
    fn build_pack(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut h = Hasher::new();
        let mut put = |out: &mut Vec<u8>, b: &[u8]| {
            out.extend_from_slice(b);
            h.update(b);
        };
        put(&mut out, MAGIC);
        put(&mut out, &FORMAT_VERSION.to_le_bytes());
        put(&mut out, &(entries.len() as u32).to_le_bytes());
        for (path, mode, data) in entries {
            put(&mut out, &(path.len() as u32).to_le_bytes());
            put(&mut out, path.as_bytes());
            put(&mut out, &mode.to_le_bytes());
            put(&mut out, &(data.len() as u64).to_le_bytes());
            put(&mut out, data);
        }
        out.extend_from_slice(h.finalize().as_bytes());
        out
    }

    #[test]
    fn pack_unpack_round_trip() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src_db");
        make_db(&src);
        let blob_h = Database::open(&src).unwrap().blob_store.put(b"hello world").unwrap();

        let pack_file = tmp.path().join("out.neleus");
        pack(&src, &pack_file, false).unwrap();
        assert!(pack_file.exists());

        let dst = tmp.path().join("dst_db");
        unpack(&pack_file, &dst, false).unwrap();

        let db = Database::open(&dst).unwrap();
        assert_eq!(db.blob_store.get(blob_h).unwrap(), b"hello world");
        let root = db.resolve_state_root("main").unwrap();
        assert_eq!(db.state_store.get(root, b"k").unwrap(), Some(b"v".to_vec()));
        assert!(db.refs.head_get("main").unwrap().is_some());
    }

    #[test]
    fn pack_is_deterministic() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("db");
        make_db(&src);
        let p1 = tmp.path().join("a.neleus");
        let p2 = tmp.path().join("b.neleus");
        pack(&src, &p1, false).unwrap();
        pack(&src, &p2, false).unwrap();
        assert_eq!(fs::read(&p1).unwrap(), fs::read(&p2).unwrap());
    }

    #[test]
    fn tamper_is_detected() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("db");
        make_db(&src);
        let pf = tmp.path().join("p.neleus");
        pack(&src, &pf, false).unwrap();

        // Flip a footer byte: every entry still parses, but the prefix digest
        // no longer matches the stored footer.
        let mut bytes = fs::read(&pf).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&pf, &bytes).unwrap();

        let dst = tmp.path().join("dst");
        let err = unpack(&pf, &dst, false).unwrap_err();
        assert!(err.to_string().contains("integrity"), "got: {err}");
        assert!(!dst.exists(), "corrupt unpack must leave no target dir");
    }

    #[test]
    fn rejects_path_traversal() {
        let tmp = TempDir::new().unwrap();
        let bytes = build_pack(&[("../escape.txt", 0o600, b"pwned")]);
        let pf = tmp.path().join("evil.neleus");
        fs::write(&pf, &bytes).unwrap();

        let dst = tmp.path().join("sub").join("dst");
        let err = unpack(&pf, &dst, false).unwrap_err();
        assert!(err.to_string().contains("unsafe path"), "got: {err}");
        assert!(!tmp.path().join("sub").join("escape.txt").exists());
        assert!(!dst.exists());
    }

    #[test]
    fn refuses_to_clobber_nonempty_target() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("db");
        make_db(&src);
        let pf = tmp.path().join("p.neleus");
        pack(&src, &pf, false).unwrap();

        let dst = tmp.path().join("dst");
        fs::create_dir_all(&dst).unwrap();
        fs::write(dst.join("existing.txt"), b"keep").unwrap();

        let err = unpack(&pf, &dst, false).unwrap_err();
        assert!(err.to_string().contains("already exists"), "got: {err}");

        unpack(&pf, &dst, true).unwrap();
        assert!(!dst.join("existing.txt").exists());
        Database::open(&dst).unwrap();
    }

    #[test]
    fn excludes_locks_and_temps_keeps_wal() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("db");
        make_db(&src);
        fs::write(src.join("meta").join("recovery.lock"), b"pid=1").unwrap();
        fs::write(
            src.join("blobs").join(format!(".x.tmp-{}-1-0", i32::MAX as u32)),
            b"orphan",
        )
        .unwrap();
        fs::write(src.join("wal").join("pending.wal"), b"wal-bytes").unwrap();

        let pf = tmp.path().join("p.neleus");
        pack(&src, &pf, false).unwrap();
        let dst = tmp.path().join("dst");
        unpack(&pf, &dst, false).unwrap();

        assert!(!dst.join("meta").join("recovery.lock").exists());
        assert!(
            !dst.join("blobs")
                .join(format!(".x.tmp-{}-1-0", i32::MAX as u32))
                .exists()
        );
        assert_eq!(fs::read(dst.join("wal").join("pending.wal")).unwrap(), b"wal-bytes");
    }

    #[cfg(unix)]
    #[test]
    fn perms_are_hardened() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("db");
        make_db(&src);
        let pf = tmp.path().join("p.neleus");
        pack(&src, &pf, false).unwrap();

        let pack_mode = fs::metadata(&pf).unwrap().permissions().mode() & 0o777;
        assert_eq!(pack_mode, 0o600);

        let dst = tmp.path().join("dst");
        unpack(&pf, &dst, false).unwrap();

        let dir_mode = fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let cfg = dst.join("meta").join("config.json");
        let file_mode = fs::metadata(&cfg).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn compressed_pack_is_smaller_and_round_trips() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("db");
        make_db(&src);
        // A compressible blob so v2 visibly shrinks.
        let big = "x".repeat(8192);
        let h = Database::open(&src)
            .unwrap()
            .blob_store
            .put(big.as_bytes())
            .unwrap();

        let raw_pf = tmp.path().join("raw.neleus");
        let z_pf = tmp.path().join("z.neleus");
        let raw_stats = pack(&src, &raw_pf, false).unwrap();
        let z_stats = pack(&src, &z_pf, true).unwrap();
        // Logical (uncompressed) size is reported identically.
        assert_eq!(raw_stats.bytes, z_stats.bytes);
        assert!(
            fs::metadata(&z_pf).unwrap().len() < fs::metadata(&raw_pf).unwrap().len(),
            "compressed pack should be smaller"
        );

        let dst = tmp.path().join("dst");
        unpack(&z_pf, &dst, false).unwrap();
        let db = Database::open(&dst).unwrap();
        assert_eq!(db.blob_store.get(h).unwrap(), big.as_bytes());
    }

    #[test]
    fn verify_accepts_good_pack_and_rejects_tampered() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("db");
        make_db(&src);
        let pf = tmp.path().join("p.neleus");
        let stats = pack(&src, &pf, true).unwrap();

        let v = verify(&pf).unwrap();
        assert_eq!(v.entries, stats.entries);
        // verify must not create any target dir.
        assert!(!tmp.path().join("dst").exists());

        let mut bytes = fs::read(&pf).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&pf, &bytes).unwrap();
        let err = verify(&pf).unwrap_err();
        assert!(err.to_string().contains("integrity"), "got: {err}");
    }

    #[test]
    fn verify_rejects_path_traversal() {
        let tmp = TempDir::new().unwrap();
        let bytes = build_pack(&[("../escape.txt", 0o600, b"pwned")]);
        let pf = tmp.path().join("evil.neleus");
        fs::write(&pf, &bytes).unwrap();
        let err = verify(&pf).unwrap_err();
        assert!(err.to_string().contains("unsafe path"), "got: {err}");
    }
}
