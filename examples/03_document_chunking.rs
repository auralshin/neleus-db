use anyhow::Result;
use neleus_db::Database;
use neleus_db::manifest::ChunkingSpec;
use tempfile::TempDir;

fn main() -> Result<()> {
    let temp_dir = TempDir::new()?;
    Database::init(temp_dir.path())?;
    let db = Database::open(temp_dir.path())?;

    let document = b"The quick brown fox jumps over the lazy dog. \
                     This is a sample document that will be chunked. \
                     Neleus DB provides deterministic chunking with overlap. \
                     Each chunk is content-addressed and immutable.";

    let chunking = ChunkingSpec {
        method: "fixed".to_string(),
        chunk_size: 50,
        overlap: 10,
    };

    let manifest_hash = db.manifest_store.put_doc_manifest_from_bytes(
        &db.blob_store,
        "example_document".to_string(),
        document,
        chunking,
        None,
    )?;
    println!("Stored doc manifest: {}", manifest_hash);

    let manifest = db.manifest_store.get_doc_manifest(manifest_hash)?;
    println!("Original document hash: {}", manifest.original);
    println!("Chunk count: {}", manifest.chunks.len());

    for (i, chunk_hash) in manifest.chunks.iter().enumerate() {
        let chunk_data = db.blob_store.get(*chunk_hash)?;
        println!(
            "Chunk {} ({} bytes): {}",
            i,
            chunk_data.len(),
            String::from_utf8_lossy(&chunk_data)
        );
    }

    Ok(())
}
