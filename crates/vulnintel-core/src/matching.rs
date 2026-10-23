//! Conservative matching against an OSV query response.
//! Only a successful, exact package+version OSV query can establish an affected match.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    Affected,
    Unaffected,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchEvidence {
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub status: Exposure,
    pub advisory_ids: Vec<String>,
    pub source: String,
}

/// Call only with a validated successful response from OSV's /v1/query.
/// Empty results mean no known OSV match, not proof that the software is safe.
pub fn match_osv_response(ecosystem: &str, package: &str, version: &str, response: &Value) -> MatchEvidence {
    let vulns = response.get("vulns").and_then(Value::as_array);
    let ids = vulns.map(|entries| {
        entries.iter().filter_map(|v| v.get("id").and_then(Value::as_str).map(str::to_owned)).collect::<Vec<_>>()
    }).unwrap_or_default();
    let status = match vulns {
        None => Exposure::Unknown,
        Some(entries) if entries.is_empty() => Exposure::Unaffected,
        Some(_) if ids.is_empty() => Exposure::Unknown,
        Some(_) => Exposure::Affected,
    };
    MatchEvidence {
        ecosystem: ecosystem.to_owned(),
        package: package.to_owned(),
        version: version.to_owned(),
        status,
        advisory_ids: ids,
        source: "osv".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn known_match() {
        let result = match_osv_response("npm", "lodash", "4.17.20", &json!({"vulns":[{"id":"GHSA-test"}]}));
        assert_eq!(result.status, Exposure::Affected);
    }
    #[test]
    fn malformed_is_unknown() {
        let result = match_osv_response("npm", "lodash", "4.17.20", &json!({}));
        assert_eq!(result.status, Exposure::Unknown);
    }
}
