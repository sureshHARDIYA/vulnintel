//! Conservative normalization of public advisory feeds.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub source: String,
    pub source_id: String,
    pub summary: Option<String>,
    pub severity: Option<String>,
    pub published: Option<String>,
    pub known_exploited: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnifiedAdvisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub evidence: Vec<Evidence>,
}

fn field<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

fn cve(id: &str) -> bool {
    let parts: Vec<_> = id.split('-').collect();
    parts.len() == 3
        && parts[0] == "CVE"
        && parts[1].len() == 4
        && parts[1].bytes().all(|b| b.is_ascii_digit())
        && parts[2].len() >= 4
        && parts[2].bytes().all(|b| b.is_ascii_digit())
}

fn make(id: &str, alias: Option<&str>, evidence: Evidence) -> UnifiedAdvisory {
    UnifiedAdvisory {
        id: id.to_owned(),
        aliases: alias.map(|a| vec![a.to_owned()]).unwrap_or_default(),
        evidence: vec![evidence],
    }
}

/// GitHub explicitly declares a CVE alias through cve_id.
pub fn github(v: &Value) -> Result<Vec<UnifiedAdvisory>, String> {
    let rows = v.as_array().ok_or("GitHub: expected array")?;
    rows.iter()
        .map(|row| {
            let ghsa = field(row, "ghsa_id").ok_or("Missing GHSA ID")?;
            if !ghsa.starts_with("GHSA-") {
                return Err("Invalid GHSA ID".to_owned());
            }
            let alias = field(row, "cve_id").filter(|id| cve(id));
            let id = alias.unwrap_or(ghsa);
            Ok(make(
                id,
                alias.map(|_| ghsa),
                Evidence {
                    source: "github".into(),
                    source_id: ghsa.into(),
                    summary: field(row, "summary").map(str::to_owned),
                    severity: field(row, "severity").map(str::to_owned),
                    published: field(row, "published_at").map(str::to_owned),
                    known_exploited: false,
                },
            ))
        })
        .collect()
}

pub fn nvd(v: &Value) -> Result<Vec<UnifiedAdvisory>, String> {
    let rows = v.get("vulnerabilities").and_then(Value::as_array).ok_or("NVD: expected vulnerabilities")?;
    rows.iter()
        .map(|row| {
            let entry = row.get("cve").ok_or("Missing CVE")?;
            let id = field(entry, "id").ok_or("Missing CVE ID")?;
            if !cve(id) {
                return Err("Invalid CVE ID".to_owned());
            }
            let summary = entry.get("descriptions").and_then(Value::as_array)
                .and_then(|a| a.iter().find(|d| field(d, "lang") == Some("en")))
                .and_then(|d| field(d, "value")).map(str::to_owned);
            Ok(make(
                id,
                None,
                Evidence {
                    source: "nvd".into(),
                    source_id: id.into(),
                    summary,
                    severity: None,
                    published: field(entry, "published").map(str::to_owned),
                    known_exploited: false,
                },
            ))
        })
        .collect()
}

pub fn kev(v: &Value) -> Result<Vec<UnifiedAdvisory>, String> {
    let rows = v.get("vulnerabilities").and_then(Value::as_array).ok_or("KEV: expected vulnerabilities")?;
    rows.iter()
        .map(|row| {
            let id = field(row, "cveID").ok_or("Missing CVE ID")?;
            if !cve(id) {
                return Err("Invalid CVE ID".to_owned());
            }
            Ok(make(
                id,
                None,
                Evidence {
                    source: "cisa_kev".into(),
                    source_id: id.into(),
                    summary: field(row, "shortDescription").map(str::to_owned),
                    severity: None,
                    published: field(row, "dateAdded").map(str::to_owned),
                    known_exploited: true,
                },
            ))
        })
        .collect()
}

/// Merge only identical CVEs or the same GHSA; preserve every source assertion.
pub fn consolidate(records: impl IntoIterator<Item = UnifiedAdvisory>) -> Vec<UnifiedAdvisory> {
    let mut grouped: BTreeMap<String, UnifiedAdvisory> = BTreeMap::new();
    for mut record in records {
        let key = record.id.clone();
        let item = grouped.entry(key.clone()).or_insert_with(|| UnifiedAdvisory {
            id: key,
            aliases: Vec::new(),
            evidence: Vec::new(),
        });
        item.aliases.append(&mut record.aliases);
        item.evidence.append(&mut record.evidence);
    }
    for item in grouped.values_mut() {
        item.aliases.sort();
        item.aliases.dedup();
        item.evidence.sort_by(|a, b| a.source.cmp(&b.source).then(a.source_id.cmp(&b.source_id)));
        item.evidence.dedup();
    }
    grouped.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn joins_explicit_cve_alias_without_losing_evidence() {
        let a = github(&json!([{"ghsa_id":"GHSA-aaaa-bbbb-cccc","cve_id":"CVE-2024-12345","summary":"GitHub"}])).unwrap();
        let b = nvd(&json!({"vulnerabilities":[{"cve":{"id":"CVE-2024-12345"}}]})).unwrap();
        let merged = consolidate(a.into_iter().chain(b));
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].evidence.len(), 2);
        assert_eq!(merged[0].aliases, vec!["GHSA-aaaa-bbbb-cccc"]);
    }

    #[test]
    fn does_not_guess_aliases() {
        let a = github(&json!([{"ghsa_id":"GHSA-aaaa-bbbb-cccc"}])).unwrap();
        let b = nvd(&json!({"vulnerabilities":[{"cve":{"id":"CVE-2024-12345"}}]})).unwrap();
        assert_eq!(consolidate(a.into_iter().chain(b)).len(), 2);
    }

    #[test]
    fn kev_is_not_severity() {
        let a = kev(&json!({"vulnerabilities":[{"cveID":"CVE-2024-12345"}]})).unwrap();
        assert!(a[0].evidence[0].known_exploited);
        assert_eq!(a[0].evidence[0].severity, None);
    }
}
