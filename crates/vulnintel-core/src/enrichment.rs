//! Source-preserving CISA KEV and FIRST EPSS enrichment, joined by explicit CVE IDs.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KevEvidence {
    pub date_added: String,
    pub due_date: Option<String>,
    pub catalog_version: Option<String>,
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpssEvidence {
    pub probability: f64,
    pub percentile: f64,
    pub model_date: String,
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatIntel {
    pub cve: String,
    pub kev: Option<KevEvidence>,
    pub epss: Option<EpssEvidence>,
}

fn valid_cve(id: &str) -> bool {
    let parts: Vec<_> = id.split('-').collect();
    parts.len() == 3
        && parts[0] == "CVE"
        && parts[1].len() == 4
        && parts[1].bytes().all(|b| b.is_ascii_digit())
        && parts[2].len() >= 4
        && parts[2].bytes().all(|b| b.is_ascii_digit())
}

fn required<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Missing {key}"))
}

/// The caller supplies a UTC observation timestamp from the ingestion boundary.
pub fn parse_kev(feed: &Value, observed_at: &str) -> Result<BTreeMap<String, KevEvidence>, String> {
    if observed_at.is_empty() {
        return Err("Missing observation timestamp".into());
    }
    let rows = feed
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or("KEV feed missing vulnerabilities")?;
    let version = feed
        .get("catalogVersion")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut result = BTreeMap::new();
    for row in rows {
        let id = required(row, "cveID")?;
        if !valid_cve(id) || result.contains_key(id) {
            return Err(format!("Invalid or duplicate KEV CVE: {id}"));
        }
        result.insert(
            id.to_owned(),
            KevEvidence {
                date_added: required(row, "dateAdded")?.to_owned(),
                due_date: row.get("dueDate").and_then(Value::as_str).map(str::to_owned),
                catalog_version: version.clone(),
                observed_at: observed_at.to_owned(),
            },
        );
    }
    Ok(result)
}

fn fraction(row: &Value, field: &str) -> Result<f64, String> {
    let raw = required(row, field)?;
    let value: f64 = raw.parse().map_err(|_| format!("Invalid {field}"))?;
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(format!("{field} must be between 0 and 1"));
    }
    Ok(value)
}

/// EPSS is a probability estimate, not evidence of active exploitation.
pub fn parse_epss(feed: &Value, observed_at: &str) -> Result<BTreeMap<String, EpssEvidence>, String> {
    if observed_at.is_empty() {
        return Err("Missing observation timestamp".into());
    }
    let rows = feed
        .get("data")
        .and_then(Value::as_array)
        .ok_or("EPSS feed missing data")?;
    let mut result = BTreeMap::new();
    for row in rows {
        let id = required(row, "cve")?;
        if !valid_cve(id) || result.contains_key(id) {
            return Err(format!("Invalid or duplicate EPSS CVE: {id}"));
        }
        result.insert(
            id.to_owned(),
            EpssEvidence {
                probability: fraction(row, "epss")?,
                percentile: fraction(row, "percentile")?,
                model_date: required(row, "date")?.to_owned(),
                observed_at: observed_at.to_owned(),
            },
        );
    }
    Ok(result)
}

/// Join only exact, validated CVE identifiers; missing source evidence stays None.
pub fn join(
    cves: impl IntoIterator<Item = String>,
    kev: &BTreeMap<String, KevEvidence>,
    epss: &BTreeMap<String, EpssEvidence>,
) -> Vec<ThreatIntel> {
    let mut ids: Vec<_> = cves.into_iter().filter(|id| valid_cve(id)).collect();
    ids.sort();
    ids.dedup();
    ids.into_iter()
        .map(|cve| ThreatIntel {
            kev: kev.get(&cve).cloned(),
            epss: epss.get(&cve).cloned(),
            cve,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verified_joins_preserve_meaning_and_freshness() {
        let kev = parse_kev(
            &json!({"catalogVersion":"2026.10","vulnerabilities":[{"cveID":"CVE-2026-12345","dateAdded":"2026-10-20"}]}),
            "2026-10-23T08:00:00Z",
        ).unwrap();
        let epss = parse_epss(
            &json!({"data":[{"cve":"CVE-2026-12345","epss":"0.042","percentile":"0.81","date":"2026-10-22"}]}),
            "2026-10-23T08:05:00Z",
        ).unwrap();
        let joined = join(vec!["CVE-2026-12345".into(), "CVE-2026-99999".into()], &kev, &epss);
        assert_eq!(joined.len(), 2);
        assert_eq!(joined[0].kev.as_ref().unwrap().catalog_version.as_deref(), Some("2026.10"));
        assert_eq!(joined[0].epss.as_ref().unwrap().probability, 0.042);
        assert!(joined[1].kev.is_none());
        assert!(joined[1].epss.is_none());
    }

    #[test]
    fn rejects_invalid_scores_and_duplicate_cves() {
        let bad = json!({"data":[{"cve":"CVE-2026-12345","epss":"1.5","percentile":"0.8","date":"2026-10-22"}]});
        assert!(parse_epss(&bad, "2026-10-23T08:00:00Z").is_err());
        let dup = json!({"vulnerabilities":[
            {"cveID":"CVE-2026-12345","dateAdded":"2026-10-20"},
            {"cveID":"CVE-2026-12345","dateAdded":"2026-10-21"}
        ]});
        assert!(parse_kev(&dup, "2026-10-23T08:00:00Z").is_err());
    }
}
