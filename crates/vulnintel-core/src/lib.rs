use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    #[serde(default)] pub aliases: Vec<String>,
    pub summary: String,
    #[serde(default)] pub ecosystems: Vec<String>,
    #[serde(default)] pub severity: Option<String>,
    #[serde(default)] pub source_urls: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizedAdvisory {
    pub advisory: Advisory,
    pub categories: Vec<String>,
}
pub fn categorize(advisory: Advisory) -> CategorizedAdvisory {
    let mut tags = BTreeSet::new();
    for e in &advisory.ecosystems { tags.insert(format!("ecosystem:{}", e.to_lowercase())); }
    if let Some(s) = &advisory.severity { tags.insert(format!("severity:{}", s.to_lowercase())); }
    CategorizedAdvisory { advisory, categories: tags.into_iter().collect() }
}
/// Only exact primary IDs merge. Cross-source alias resolution requires validated mappings.
pub fn deduplicate(advisories: impl IntoIterator<Item=Advisory>) -> Vec<Advisory> {
    let mut records: BTreeMap<String, Advisory> = BTreeMap::new();
    for advisory in advisories {
        records.entry(advisory.id.clone()).and_modify(|existing| {
            existing.aliases.extend(advisory.aliases.clone());
            existing.aliases.sort(); existing.aliases.dedup();
            existing.source_urls.extend(advisory.source_urls.clone());
            existing.source_urls.sort(); existing.source_urls.dedup();
        }).or_insert(advisory);
    }
    records.into_values().collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn categorizes_once() {
        let a = Advisory { id: "CVE-TEST".into(), aliases: vec![], summary: "test".into(), ecosystems: vec!["npm".into(),"npm".into()], severity: Some("HIGH".into()), source_urls: vec![] };
        assert_eq!(categorize(a).categories, vec!["ecosystem:npm", "severity:high"]);
    }
    #[test]
    fn merges_same_id_provenance() {
        let a = Advisory { id: "CVE-TEST".into(), aliases: vec![], summary: "test".into(), ecosystems: vec![], severity: None, source_urls: vec!["https://a.example".into()] };
        let mut b = a.clone(); b.source_urls = vec!["https://b.example".into()];
        let r = deduplicate(vec![a,b]);
        assert_eq!(r.len(),1);
        assert_eq!(r[0].source_urls.len(),2);
    }
}
