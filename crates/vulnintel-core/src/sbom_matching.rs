//! Connect SBOM package inventory to verified OSV package-version query results.
use crate::matching::{match_osv_response, Exposure, MatchEvidence};
use crate::sbom::Component;
use serde_json::Value;

/// Minimal supported PURL mapping. Unsupported qualifiers, subpaths and types
/// remain Unknown rather than risking an incorrect negative finding.
pub fn osv_coordinates(component: &Component) -> Option<(String, String, String)> {
    let purl = component.purl.as_deref()?.strip_prefix("pkg:")?;
    let (identity, version) = purl.split_once('@')?;
    if version.is_empty() || version.contains(['?', '#']) {
        return None;
    }
    let (kind, name) = identity.split_once('/')?;
    if name.is_empty() || name.contains(['?', '#']) {
        return None;
    }
    let ecosystem = match kind {
        "npm" => "npm",
        "pypi" => "PyPI",
        "cargo" => "crates.io",
        "maven" => "Maven",
        "golang" => "Go",
        "nuget" => "NuGet",
        "gem" => "RubyGems",
        _ => return None,
    };
    if component.version.as_deref().is_some_and(|v| v != version) {
        return None;
    }
    Some((ecosystem.into(), name.into(), version.into()))
}

/// Only a successful exact OSV query may return NoKnownAdvisory.
pub fn match_component(component: &Component, response: Option<&Value>) -> MatchEvidence {
    if let (Some((ecosystem, name, version)), Some(response)) =
        (osv_coordinates(component), response)
    {
        return match_osv_response(&ecosystem, &name, &version, response);
    }
    MatchEvidence {
        ecosystem: String::new(),
        package: component.name.clone(),
        version: component.version.clone().unwrap_or_default(),
        status: Exposure::Unknown,
        advisory_ids: Vec::new(),
        source: "osv".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom;
    use serde_json::json;

    #[test]
    fn sbom_to_osv_evidence_pipeline() {
        let doc = json!({"bomFormat":"CycloneDX","components":[
            {"name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"},
            {"name":"opaque","version":"1.0"}
        ]});
        let components = sbom::parse(&doc).unwrap();
        let affected = match_component(&components[0], Some(&json!({"vulns":[{"id":"GHSA-example"}]})));
        assert_eq!(affected.status, Exposure::Affected);
        assert_eq!(affected.advisory_ids, vec!["GHSA-example"]);
        assert_eq!(match_component(&components[1], None).status, Exposure::Unknown);
        assert_eq!(
            match_component(&components[0], Some(&json!({"vulns":[]}))).status,
            Exposure::NoKnownAdvisory
        );
    }
}
