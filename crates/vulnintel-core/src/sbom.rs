//! Conservative SBOM inventory extraction; unsupported or ambiguous entries remain unknown.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchStatus {
    Affected,
    NoKnownMatch,
    Unknown,
}

/// Parse CycloneDX JSON 1.x components or SPDX JSON packages.
/// Inventory extraction alone does not establish vulnerability exposure.
pub fn parse(value: &Value) -> Result<Vec<Component>, String> {
    let (items, spdx) = if value.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        (value.get("components").and_then(Value::as_array), false)
    } else if value
        .get("spdxVersion")
        .and_then(Value::as_str)
        .is_some_and(|s| s.starts_with("SPDX-2."))
    {
        (value.get("packages").and_then(Value::as_array), true)
    } else {
        return Err("Unsupported SBOM format".into());
    };
    let items = items.ok_or("SBOM missing component or package array")?;
    let mut result = Vec::with_capacity(items.len());
    for item in items {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("SBOM entry missing name")?;
        let version_key = if spdx { "versionInfo" } else { "version" };
        let version = item
            .get(version_key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && *s != "NOASSERTION")
            .map(str::to_owned);
        let mut purl = item.get("purl").and_then(Value::as_str).map(str::to_owned);
        let mut cpe = item.get("cpe").and_then(Value::as_str).map(str::to_owned);
        if spdx {
            if let Some(refs) = item.get("externalRefs").and_then(Value::as_array) {
                for reference in refs {
                    let kind = reference
                        .get("referenceType")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let locator = reference.get("referenceLocator").and_then(Value::as_str);
                    match kind {
                        "purl" => {
                            if purl.is_none() {
                                purl = locator.map(str::to_owned);
                            }
                        }
                        "cpe23Type" | "cpe22Type" if cpe.is_none() => {
                            cpe = locator.map(str::to_owned);
                        }
                        _ => {}
                    }
                }
            }
        }
        result.push(Component {
            name: name.to_owned(),
            version,
            purl,
            cpe,
        });
    }
    Ok(result)
}

/// Explicitly refuses to infer 'not affected' from missing advisory evidence.
pub fn exposure_without_advisory(_component: &Component) -> MatchStatus {
    MatchStatus::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cyclone_dx_extracts_purl() {
        let doc = json!({"bomFormat":"CycloneDX","specVersion":"1.6","components":[
            {"name":"example","version":"1.2.3","purl":"pkg:npm/example@1.2.3"}
        ]});
        let parts = parse(&doc).unwrap();
        assert_eq!(parts[0].purl.as_deref(), Some("pkg:npm/example@1.2.3"));
        assert_eq!(exposure_without_advisory(&parts[0]), MatchStatus::Unknown);
    }

    #[test]
    fn spdx_extracts_external_references() {
        let doc = json!({"spdxVersion":"SPDX-2.3","packages":[
            {"name":"library","versionInfo":"2.0","externalRefs":[
                {"referenceType":"purl","referenceLocator":"pkg:pypi/library@2.0"}
            ]}
        ]});
        assert_eq!(
            parse(&doc).unwrap()[0].purl.as_deref(),
            Some("pkg:pypi/library@2.0")
        );
    }

    #[test]
    fn rejects_unknown_format() {
        assert!(parse(&json!({"packages":[]})).is_err());
    }
}
