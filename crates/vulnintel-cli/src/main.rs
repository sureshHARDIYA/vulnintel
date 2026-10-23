use std::io::{self, Read};
use vulnintel_core::{categorize, deduplicate, Advisory};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let advisories: Vec<Advisory> = serde_json::from_str(&input)?;
    let result: Vec<_> = deduplicate(advisories)
        .into_iter()
        .map(categorize)
        .collect();
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
