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
            // `value_hash` is the proof's content commitment; fetch the bytes via
            // the state store (values <512B live inline, not in BlobStore).
            let value = db.state_store.get(r3, b"key_b")?.expect("key_b present");
            println!(
                "Found value for key_b ({value_hash}): {}",
                String::from_utf8_lossy(&value)
            );
        }
        StateOutcome::Missing => println!("key_b is missing"),
    }

    let missing_proof = db.state_store.proof(r3, b"key_missing")?;
    let missing_verified = db
        .state_store
        .verify_proof(r3, b"key_missing", &missing_proof);
    println!("Non-membership proof verified: {}", missing_verified);

    let r4 = db.state_store.del(r3, b"key_b")?;
    let deleted_proof = db.state_store.proof(r4, b"key_b")?;
    let deleted_verified = db.state_store.verify_proof(r4, b"key_b", &deleted_proof);
    println!("Deletion proof verified: {}", deleted_verified);
    match deleted_proof.outcome {
        StateOutcome::Missing => println!("Deletion correctly proven (key now absent)"),
        StateOutcome::Found(_) => println!("Unexpected: key_b still present"),
    }

    Ok(())
}
