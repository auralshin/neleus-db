use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::clock::now_unix;
use crate::hash::Hash;
use crate::manifest::ManifestStore;

const PROVENANCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    ToolOutput,
    WebPage,
    UserInput,
    Document,
    ApiResponse,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Content-addressed hash of the source blob (chunk, document, tool output, …).
    pub source_blob: Hash,
    pub source_type: SourceType,
    /// Byte span within the source blob, `(start, end)`, where the evidence text lives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<(usize, usize)>,
    pub timestamp: u64,
    /// Arbitrary caller-supplied key-value tags for filtering and display.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub schema_version: u32,
    /// Caller-chosen stable identifier for this claim, used for lookup and deduplication.
    pub claim_id: String,
    pub claim_text: String,
    /// The `RunManifest` hash that produced this claim. Links provenance back to the
    /// exact inputs, retrieved chunks, and model that made the assertion.
    pub run_manifest: Hash,
    pub agent_id: String,
    pub evidence: Vec<Evidence>,
    pub timestamp: u64,
    /// Confidence in \[0.0, 1.0\].
    pub confidence: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl ProvenanceRecord {
    /// Evidence must be added before the record validates for storage.
    pub fn new(
        claim_id: String,
        claim_text: String,
        run_manifest: Hash,
        agent_id: String,
        confidence: f32,
    ) -> Self {
        // Silent fallback to 0 mirrors prior behavior — provenance metadata is
        // recorded best-effort; a broken clock shouldn't fail claim creation.
        let timestamp = now_unix().unwrap_or(0);
        Self {
            schema_version: PROVENANCE_SCHEMA_VERSION,
            claim_id,
            claim_text,
            run_manifest,
            agent_id,
            evidence: Vec::new(),
            timestamp,
            confidence,
            reasoning: None,
            tags: Vec::new(),
        }
    }

    pub fn add_evidence(&mut self, evidence: Evidence) -> &mut Self {
        self.evidence.push(evidence);
        self
    }

    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.reasoning = Some(reasoning.into());
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// # Errors
    /// Empty `claim_id`, `confidence` outside \[0.0, 1.0\], or empty `evidence`.
    pub fn validate(&self) -> Result<()> {
        if self.claim_id.is_empty() {
            return Err(anyhow::anyhow!("claim_id cannot be empty"));
        }
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(anyhow::anyhow!(
                "confidence must be in [0.0, 1.0], got {}",
                self.confidence
            ));
        }
        if self.evidence.is_empty() {
            return Err(anyhow::anyhow!(
                "provenance record requires at least one piece of evidence"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceManifest {
    pub schema_version: u32,
    pub agent_id: String,
    pub created_at: u64,
    pub records: Vec<ProvenanceRecord>,
}

impl ProvenanceManifest {
    pub fn new(agent_id: impl Into<String>) -> Self {
        let created_at = now_unix().unwrap_or(0);
        Self {
            schema_version: PROVENANCE_SCHEMA_VERSION,
            agent_id: agent_id.into(),
            created_at,
            records: Vec::new(),
        }
    }

    /// # Errors
    /// `record.validate()` failed.
    pub fn add_record(&mut self, record: ProvenanceRecord) -> Result<&mut Self> {
        record.validate()?;
        self.records.push(record);
        Ok(self)
    }

    pub fn find_by_claim_id(&self, claim_id: &str) -> Option<&ProvenanceRecord> {
        self.records.iter().find(|r| r.claim_id == claim_id)
    }

    pub fn find_by_tag(&self, tag: &str) -> Vec<&ProvenanceRecord> {
        self.records
            .iter()
            .filter(|r| r.tags.iter().any(|t| t == tag))
            .collect()
    }

    pub fn claim_confidence(&self, claim_id: &str) -> Option<f32> {
        self.find_by_claim_id(claim_id).map(|r| r.confidence)
    }
}

#[derive(Clone, Debug)]
pub struct ProvenanceStore {
    manifests: ManifestStore,
}

impl ProvenanceStore {
    pub fn new(manifests: ManifestStore) -> Self {
        Self { manifests }
    }

    /// # Errors
    /// A record fails validation, or the object-store write fails.
    pub fn put(&self, manifest: &ProvenanceManifest) -> Result<Hash> {
        for record in &manifest.records {
            record.validate()?;
        }
        self.manifests.put_manifest(manifest)
    }

    pub fn get(&self, hash: Hash) -> Result<ProvenanceManifest> {
        self.manifests.get_manifest(hash)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::manifest::ManifestStore;
    use crate::object_store::ObjectStore;

    fn store(tmp: &TempDir) -> ProvenanceStore {
        let objects = ObjectStore::new(tmp.path().join("objects"));
        objects.ensure_dir().unwrap();
        ProvenanceStore::new(ManifestStore::new(objects))
    }

    fn evidence(blob: Hash) -> Evidence {
        Evidence {
            source_blob: blob,
            source_type: SourceType::Document,
            span: Some((0, 64)),
            timestamp: 1_700_000_000,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn record_validates_ok() {
        let mut r = ProvenanceRecord::new(
            "c1".into(),
            "the policy allows X".into(),
            Hash::zero(),
            "agent-v1".into(),
            0.9,
        );
        r.add_evidence(evidence(Hash::zero()));
        assert!(r.validate().is_ok());
    }

    #[test]
    fn record_rejects_empty_claim_id() {
        let mut r =
            ProvenanceRecord::new("".into(), "claim".into(), Hash::zero(), "agent".into(), 0.5);
        r.add_evidence(evidence(Hash::zero()));
        assert!(r.validate().is_err());
    }

    #[test]
    fn record_rejects_out_of_range_confidence() {
        let mut r = ProvenanceRecord::new(
            "c1".into(),
            "claim".into(),
            Hash::zero(),
            "agent".into(),
            1.5,
        );
        r.add_evidence(evidence(Hash::zero()));
        assert!(r.validate().is_err());
    }

    #[test]
    fn record_rejects_empty_evidence() {
        let r = ProvenanceRecord::new(
            "c1".into(),
            "claim".into(),
            Hash::zero(),
            "agent".into(),
            0.8,
        );
        assert!(r.validate().is_err());
    }

    #[test]
    fn manifest_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = store(&tmp);

        let mut manifest = ProvenanceManifest::new("test-agent");
        let mut record = ProvenanceRecord::new(
            "c1".into(),
            "the policy allows email reset".into(),
            Hash::zero(),
            "test-agent".into(),
            0.88,
        );
        record.add_evidence(evidence(Hash::zero()));
        manifest.add_record(record).unwrap();

        let hash = store.put(&manifest).unwrap();
        let loaded = store.get(hash).unwrap();
        assert_eq!(loaded.records.len(), 1);
        assert_eq!(loaded.records[0].claim_id, "c1");
        assert!((loaded.records[0].confidence - 0.88).abs() < f32::EPSILON);
    }

    #[test]
    fn find_by_tag_works() {
        let mut manifest = ProvenanceManifest::new("a");
        let mut r =
            ProvenanceRecord::new("c1".into(), "claim".into(), Hash::zero(), "a".into(), 0.7);
        r.add_evidence(evidence(Hash::zero()));
        r = r.with_tags(vec!["security".into(), "pii".into()]);
        manifest.add_record(r).unwrap();

        assert_eq!(manifest.find_by_tag("security").len(), 1);
        assert_eq!(manifest.find_by_tag("missing").len(), 0);
    }

    #[test]
    fn store_rejects_invalid_record() {
        let tmp = TempDir::new().unwrap();
        let store = store(&tmp);

        // confidence out of range — store must reject without writing
        let mut manifest = ProvenanceManifest::new("a");
        let r = ProvenanceRecord::new("c1".into(), "x".into(), Hash::zero(), "a".into(), 2.0);
        // validate() not called by add_record yet because evidence is also missing
        manifest.records.push(r); // bypass add_record to inject invalid record
        assert!(store.put(&manifest).is_err());
    }
}
