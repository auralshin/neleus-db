use anyhow::Result;
use neleus_db::Database;
use tempfile::TempDir;

fn main() -> Result<()> {
    let temp_dir = TempDir::new()?;
    Database::init(temp_dir.path())?;
    let db = Database::open(temp_dir.path())?;

    let content = b"Hello, neleus-db! This is an immutable blob.";
    let hash = db.blob_store.put(content)?;
    println!("Stored blob with hash: {}", hash);

    let retrieved = db.blob_store.get(hash)?;
    println!("Retrieved: {}", String::from_utf8_lossy(&retrieved));

    assert_eq!(content.as_slice(), &retrieved);
    println!("Content matches!");

    let same_hash = db.blob_store.put(content)?;
    assert_eq!(hash, same_hash);
    println!("Content deduplication works (same hash)");

    Ok(())
}
