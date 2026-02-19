use anyhow::Result;
use neleus_db::{Database, Evidence, ProvenanceManifest, ProvenanceRecord, SourceType};
use tempfile::TempDir;

fn main() -> Result<()> {
    let temp_dir = TempDir::new()?;
    Database::init(temp_dir.path())?;
    let db = Database::open(temp_dir.path())?;

    let agent_id = "assistant_v1";

    let source_doc = b"The capital of France is Paris. Population: 2.1M.";
    let source_blob = db.blob_store.put(source_doc)?;
    println!("Stored source document: {}", source_blob);

    let mut record = ProvenanceRecord::new(
        "claim_001".to_string(),
        "The capital of France is Paris".to_string(),
        agent_id.to_string(),
        0.95,
    );

    let evidence = Evidence {
        source_blob,
        source_type: SourceType::Document,
        extracted_text: "The capital of France is Paris".to_string(),
        position: Some((0, 31)),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        metadata: {
            let mut m = std::collections::BTreeMap::new();
            m.insert("extraction_method".to_string(), "substring".to_string());
            m
        },
    };

    record.add_evidence(evidence);
    record = record
        .with_reasoning("Direct quote from authoritative source document".to_string())
        .with_tags(vec!["geography".to_string(), "fact".to_string()]);

    record.validate()?;
    println!("\n✓ Created provenance record:");
    println!("  Claim: {}", record.claim_text);
    println!("  Confidence: {}", record.confidence);
    println!("  Evidence count: {}", record.evidence.len());

    let mut manifest = ProvenanceManifest::new(agent_id.to_string());
    manifest.add_record(record)?;

    let tool_output = b"API response: {temperature: 22C, condition: sunny}";
    let tool_blob = db.blob_store.put(tool_output)?;

    let mut weather_record = ProvenanceRecord::new(
        "claim_002".to_string(),
        "Current weather is sunny, 22C".to_string(),
        agent_id.to_string(),
        0.88,
    );

    weather_record.add_evidence(Evidence {
        source_blob: tool_blob,
        source_type: SourceType::ToolOutput,
        extracted_text: String::from_utf8_lossy(tool_output).to_string(),
        position: None,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        metadata: {
            let mut m = std::collections::BTreeMap::new();
            m.insert("tool".to_string(), "weather_api".to_string());
            m
        },
    });

    weather_record = weather_record.with_tags(vec!["weather".to_string(), "realtime".to_string()]);
    manifest.add_record(weather_record)?;

    let manifest_json = serde_json::to_vec(&manifest)?;
    let manifest_hash = db.blob_store.put(&manifest_json)?;
    println!("\n✓ Stored provenance manifest: {}", manifest_hash);

    let retrieved_json = db.blob_store.get(manifest_hash)?;
    let retrieved_manifest: ProvenanceManifest = serde_json::from_slice(&retrieved_json)?;

    println!(
        "\nRetrieved manifest with {} records",
        retrieved_manifest.records.len()
    );

    if let Some(claim) = retrieved_manifest.find_by_claim_id("claim_001") {
        println!("\nFound claim by ID:");
        println!("  Text: {}", claim.claim_text);
        println!("  Confidence: {}", claim.confidence);
        println!("  Evidence sources: {}", claim.evidence.len());

        for (i, ev) in claim.evidence.iter().enumerate() {
            println!(
                "    Evidence {}: {:?} from {}",
                i + 1,
                ev.source_type,
                ev.source_blob
            );
        }
    }

    let geography_claims = retrieved_manifest.find_by_tag("geography");
    println!(
        "\nFound {} claims tagged 'geography'",
        geography_claims.len()
    );

    println!("\nProvenance tracking complete!");

    Ok(())
}
