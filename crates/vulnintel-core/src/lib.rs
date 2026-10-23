pub mod matching;
pub mod storage;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub summary: String,
    #[serde(default)]
    pub ecosystems: Vec<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub source_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizedAdvisory {
    pub advisory: Advisory,
    pub categories: Vec<String>,
}

pub fn categorize(advisory: Advisory) -> CategorizedAdvisory {
    let mut tags = BTreeSet::new();
    for ecosystem in &advisory.ecosystems {
        tags.insert(format!("ecosystem:{}", ecosystem.to_lowercase()));
    }
    if let Some(severity) = &advisory.severity {
        tags.insert(format!("severity:{}", severity.to_lowercase()));
    }
    CategorizedAdvisory {
        advisory,
        categories: tags.into_iter().collect(),
    }
}

/// Merge only identical primary IDs. Alias resolution requires verified identity mappings.
pub fn deduplicate(advisories: impl IntoIterator<Item = Advisory>) -> Vec<Advisory> {
    let mut records: BTreeMap<String, Advisory> = BTreeMap::new();
    for advisory in advisories {
        records
            .entry(advisory.id.clone())
            .and_modify(|existing| {
                existing.aliases.extend(advisory.aliases.clone());
                existing.aliases.sort();
                existing.aliases.dedup();
                existing.source_urls.extend(advisory.source_urls.clone());
                existing.source_urls.sort();
                existing.source_urls.dedup();
            })
            .or_insert(advisory);
    }
    records.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorizes_once() {
        let advisory = Advisory {
            id: "CVE-TEST".into(),
            aliases: vec![],
            summary: "test".into(),
            ecosystems: vec!["npm".into(), "npm".into()],
            severity: Some("HIGH".into()),
            source_urls: vec![],
        };
        assert_eq!(
            categorize(advisory).categories,
            vec!["ecosystem:npm", "severity:high"]
        );
    }

    #[test]
    fn merges_same_id_provenance() {
        let advisory = Advisory {
            id: "CVE-TEST".into(),
            aliases: vec![],
            summary: "test".into(),
            ecosystems: vec![],
            severity: None,
            source_urls: vec!["https://a.example".into()],
        };
        let mut other = advisory.clone();
        other.source_urls = vec!["https://b.example".into()];
        let result = deduplicate(vec![advisory, other]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].source_urls.len(), 2);
    }
}
