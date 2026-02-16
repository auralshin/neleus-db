use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceType {
    ToolOutput,
    WebPage,
    UserInput,
    Document,
    ApiResponse,
    Custom(String),
}

impl SourceType {
    pub fn as_str(&self) -> &str {
        match self {
            SourceType::ToolOutput => "tool_output",
            SourceType::WebPage => "web_page",
            SourceType::UserInput => "user_input",
            SourceType::Document => "document",
            SourceType::ApiResponse => "api_response",
            SourceType::Custom(s) => s,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub source_blob: Hash,

    #[serde(with = "source_type_serde")]
    pub source_type: SourceType,
    pub extracted_text: String,
    pub position: Option<(usize, usize)>,
    pub timestamp: u64,
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
}

mod source_type_serde {
    use super::SourceType;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(source_type: &SourceType, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(source_type.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SourceType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "tool_output" => SourceType::ToolOutput,
            "web_page" => SourceType::WebPage,
            "user_input" => SourceType::UserInput,
            "document" => SourceType::Document,
            "api_response" => SourceType::ApiResponse,
            custom => SourceType::Custom(custom.to_string()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub claim_id: String,
    pub claim_text: String,
    pub evidence: Vec<Evidence>,
    pub agent_id: String,
    pub timestamp: u64,
    pub confidence: f32,
    pub reasoning: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_provenance_version")]
    pub schema_version: u32,
}

fn default_provenance_version() -> u32 {
    1
}

impl ProvenanceRecord {
    pub fn new(claim_id: String, claim_text: String, agent_id: String, confidence: f32) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            claim_id,
            claim_text,
            evidence: Vec::new(),
            agent_id,
            timestamp,
            confidence,
            reasoning: None,
            tags: Vec::new(),
            schema_version: 1,
        }
    }

    pub fn add_evidence(&mut self, evidence: Evidence) -> &mut Self {
        self.evidence.push(evidence);
        self
    }

    pub fn add_evidence_batch(&mut self, evidence: Vec<Evidence>) -> &mut Self {
        self.evidence.extend(evidence);
        self
    }

    /// Set reasoning for how evidence supports the claim
    pub fn with_reasoning(mut self, reasoning: String) -> Self {
        self.reasoning = Some(reasoning);
        self
    }

    /// Add tags for organization
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Validate provenance record (returns error if invalid)
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.claim_id.is_empty() {
            return Err(anyhow::anyhow!("claim_id cannot be empty"));
        }

        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(anyhow::anyhow!(
                "confidence must be between 0.0 and 1.0, got {}",
                self.confidence
            ));
        }

        if self.evidence.is_empty() {
            return Err(anyhow::anyhow!(
                "provenance record must have at least one piece of evidence"
            ));
        }

        Ok(())
    }
}

/// Manifest for storing provenance records
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceManifest {
    /// Schema version
    #[serde(default = "default_provenance_version")]
    pub schema_version: u32,

    /// List of provenance records
    pub records: Vec<ProvenanceRecord>,

    /// When manifest was created
    pub created_at: u64,

    /// Agent that created this manifest
    pub agent_id: String,
}

impl ProvenanceManifest {
    /// Create new empty provenance manifest
    pub fn new(agent_id: String) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            schema_version: 1,
            records: Vec::new(),
            created_at,
            agent_id,
        }
    }

    /// Add a provenance record
    pub fn add_record(&mut self, record: ProvenanceRecord) -> anyhow::Result<&mut Self> {
        record.validate()?;
        self.records.push(record);
        Ok(self)
    }

    /// Find records by claim ID
    pub fn find_by_claim_id(&self, claim_id: &str) -> Option<&ProvenanceRecord> {
        self.records.iter().find(|r| r.claim_id == claim_id)
    }

    /// Find records by tag
    pub fn find_by_tag(&self, tag: &str) -> Vec<&ProvenanceRecord> {
        self.records
            .iter()
            .filter(|r| r.tags.contains(&tag.to_string()))
            .collect()
    }

    /// Find records by agent
    pub fn find_by_agent(&self, agent_id: &str) -> Vec<&ProvenanceRecord> {
        self.records
            .iter()
            .filter(|r| r.agent_id == agent_id)
            .collect()
    }

    /// Get confidence score for a claim
    pub fn get_claim_confidence(&self, claim_id: &str) -> Option<f32> {
        self.find_by_claim_id(claim_id).map(|r| r.confidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_evidence() {
        let evidence = Evidence {
            source_blob: Hash::zero(),
            source_type: SourceType::ToolOutput,
            extracted_text: "Tool result".to_string(),
            position: Some((0, 11)),
            timestamp: 1234567890,
            metadata: Default::default(),
        };

        assert_eq!(evidence.source_type, SourceType::ToolOutput);
        assert_eq!(evidence.extracted_text, "Tool result");
    }

    #[test]
    fn create_provenance_record() {
        let record = ProvenanceRecord::new(
            "claim_1".to_string(),
            "The agent decided to run task X".to_string(),
            "agent_1".to_string(),
            0.95,
        );

        assert_eq!(record.claim_id, "claim_1");
        assert_eq!(record.confidence, 0.95);
        assert!(record.evidence.is_empty());
    }

    #[test]
    fn provenance_with_evidence() {
        let evidence = Evidence {
            source_blob: Hash::zero(),
            source_type: SourceType::UserInput,
            extracted_text: "user wants X".to_string(),
            position: None,
            timestamp: 1234567890,
            metadata: Default::default(),
        };

        let mut record = ProvenanceRecord::new(
            "claim_1".to_string(),
            "Decided to do X".to_string(),
            "agent_1".to_string(),
            0.9,
        );

        record.add_evidence(evidence);
        assert_eq!(record.evidence.len(), 1);
        assert!(record.validate().is_ok());
    }

    #[test]
    fn provenance_manifest() {
        let mut manifest = ProvenanceManifest::new("agent_1".to_string());

        let evidence = Evidence {
            source_blob: Hash::zero(),
            source_type: SourceType::ToolOutput,
            extracted_text: "result".to_string(),
            position: None,
            timestamp: 1234567890,
            metadata: Default::default(),
        };

        let mut record = ProvenanceRecord::new(
            "claim_1".to_string(),
            "test claim".to_string(),
            "agent_1".to_string(),
            0.8,
        );

        record.add_evidence(evidence);
        manifest.add_record(record).unwrap();

        assert_eq!(manifest.records.len(), 1);
        assert!(manifest.find_by_claim_id("claim_1").is_some());
        assert_eq!(manifest.get_claim_confidence("claim_1"), Some(0.8));
    }

    #[test]
    fn invalid_confidence() {
        let mut record = ProvenanceRecord::new(
            "claim_1".to_string(),
            "test".to_string(),
            "agent_1".to_string(),
            1.5, // Invalid: > 1.0
        );

        record.add_evidence(Evidence {
            source_blob: Hash::zero(),
            source_type: SourceType::UserInput,
            extracted_text: "evidence".to_string(),
            position: None,
            timestamp: 1234567890,
            metadata: Default::default(),
        });

        assert!(record.validate().is_err());
    }

    #[test]
    fn find_by_tag() {
        let mut manifest = ProvenanceManifest::new("agent_1".to_string());

        let evidence = Evidence {
            source_blob: Hash::zero(),
            source_type: SourceType::ToolOutput,
            extracted_text: "result".to_string(),
            position: None,
            timestamp: 1234567890,
            metadata: Default::default(),
        };

        let mut record = ProvenanceRecord::new(
            "claim_1".to_string(),
            "test claim".to_string(),
            "agent_1".to_string(),
            0.8,
        );

        record = record.with_tags(vec!["important".to_string(), "decision".to_string()]);
        record.add_evidence(evidence);

        manifest.add_record(record).unwrap();

        let results = manifest.find_by_tag("important");
        assert_eq!(results.len(), 1);
    }
}
