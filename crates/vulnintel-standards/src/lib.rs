//! Parse externally obtained OWASP ASVS requirements.
//! ASVS content is not bundled or relicensed with this MIT crate.
use serde::Deserialize;
use std::{error::Error, io::Read};

#[derive(Debug, Clone, Deserialize)]
pub struct AsvsRequirement {
    pub chapter_id: String,
    pub chapter_name: String,
    pub section_id: String,
    pub section_name: String,
    pub req_id: String,
    pub req_description: String,
    #[serde(rename = "L")]
    pub level: String,
}

pub fn parse_asvs_csv(reader: impl Read) -> Result<Vec<AsvsRequirement>, Box<dyn Error + Send + Sync>> {
    let mut csv = csv::Reader::from_reader(reader);
    let mut requirements = Vec::new();
    for record in csv.deserialize() {
        let item: AsvsRequirement = record?;
        if item.req_id.is_empty() || item.req_description.is_empty() {
            return Err("ASVS requirement is missing an ID or description".into());
        }
        requirements.push(item);
    }
    if requirements.is_empty() {
        return Err("ASVS CSV contains no requirements".into());
    }
    Ok(requirements)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_asvs() {
        let input = "chapter_id,chapter_name,section_id,section_name,req_id,req_description,L\nV1,Encoding,V1.1,Architecture,V1.1.1,Verify input,2\n";
        let records = parse_asvs_csv(input.as_bytes()).unwrap();
        assert_eq!(records[0].req_id, "V1.1.1");
    }
}
