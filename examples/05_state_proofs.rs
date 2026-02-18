use anyhow::Result;
use neleus_db::Database;
use neleus_db::state::StateOutcome;
use tempfile::TempDir;

fn main() -> Result<()> {
    let temp_dir = TempDir::new()?;
    Database::init(temp_dir.path())?;
    let db = Database::open(temp_dir.path())?;

    let base_root = db.state_store.empty_root()?;
    let r1 = db.state_store.set(base_root, b"key_a", b"value_a")?;
    let r2 = db.state_store.set(r1, b"key_b", b"value_b")?;
    let r3 = db.state_store.set(r2, b"key_c", b"value_c")?;
    println!("State root: {}", r3);

    let proof = db.state_store.proof(r3, b"key_b")?;
    let verified = db.state_store.verify_proof(r3, b"key_b", &proof);
    println!("Membership proof verified: {}", verified);
    match proof.outcome {
        StateOutcome::Found(value_hash) => {
            let value = db.blob_store.get(value_hash)?;
            println!("Found value for key_b: {}", String::from_utf8_lossy(&value));
        }
        StateOutcome::Deleted => println!("key_b was deleted"),
        StateOutcome::Missing => println!("key_b is missing"),
    }

    let missing_proof = db.state_store.proof(r3, b"key_missing")?;
    let missing_verified = db.state_store.verify_proof(r3, b"key_missing", &missing_proof);
    println!("Non-membership proof verified: {}", missing_verified);

    let r4 = db.state_store.del(r3, b"key_b")?;
    let deleted_proof = db.state_store.proof(r4, b"key_b")?;
    let deleted_verified = db.state_store.verify_proof(r4, b"key_b", &deleted_proof);
    println!("Deletion proof verified: {}", deleted_verified);
    match deleted_proof.outcome {
        StateOutcome::Deleted => println!("Deletion correctly proven"),
        _ => println!("Unexpected deletion proof outcome"),
    }

    Ok(())
}
