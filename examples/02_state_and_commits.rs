use anyhow::{Result, anyhow};
use neleus_db::Database;
use tempfile::TempDir;

fn main() -> Result<()> {
    let temp_dir = TempDir::new()?;
    Database::init(temp_dir.path())?;
    let db = Database::open(temp_dir.path())?;

    let head = "main";
    let author = "agent_1";

    let base_root = db
        .refs
        .state_get(head)?
        .unwrap_or(db.state_store.empty_root()?);

    let root1 = db.state_store.set(base_root, b"user_name", b"Alice")?;
    let root2 = db.state_store.set(root1, b"user_age", b"30")?;
    let root3 = db.state_store.set(root2, b"user_city", b"San Francisco")?;
    db.refs.state_set(head, root3)?;

    let commit1 = db.commit_store.create_commit(
        vec![],
        root3,
        vec![],
        author.to_string(),
        "Initial user profile".to_string(),
    )?;
    db.refs.head_set(head, commit1)?;
    println!("Created commit: {}", commit1);

    let name = db
        .state_store
        .get(root3, b"user_name")?
        .ok_or_else(|| anyhow!("key not found"))?;
    println!("Stored name: {}", String::from_utf8_lossy(&name));

    let root4 = db.state_store.set(root3, b"user_city", b"New York")?;
    db.refs.state_set(head, root4)?;

    let parent = db
        .refs
        .head_get(head)?
        .ok_or_else(|| anyhow!("head not found"))?;
    let commit2 = db.commit_store.create_commit(
        vec![parent],
        root4,
        vec![],
        author.to_string(),
        "Updated city".to_string(),
    )?;
    db.refs.head_set(head, commit2)?;
    println!("Created second commit: {}", commit2);

    let old_city = db
        .state_store
        .get(root3, b"user_city")?
        .ok_or_else(|| anyhow!("key not found"))?;
    let new_city = db
        .state_store
        .get(root4, b"user_city")?
        .ok_or_else(|| anyhow!("key not found"))?;

    println!("Old city (root3): {}", String::from_utf8_lossy(&old_city));
    println!("New city (root4): {}", String::from_utf8_lossy(&new_city));
    println!("Time-travel queries work");

    Ok(())
}
