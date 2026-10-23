use std::{
    env,
    error::Error,
    io::{self, Read},
};
use vulnintel_core::{categorize, deduplicate, matching::match_osv_response, normalization, Advisory};
use vulnintel_sources as feeds;

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("normalize") && args.len() == 2 {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        let payload: serde_json::Value = serde_json::from_str(&input)?;
        let records = match args[1].as_str() {
            "github" => normalization::github(&payload),
            "nvd" => normalization::nvd(&payload),
            "kev" => normalization::kev(&payload),
            _ => return Err("Expected normalize github|nvd|kev".into()),
        }?;
        println!("{}", serde_json::to_string_pretty(&normalization::consolidate(records))?);
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("fetch") {
        let client = feeds::client()?;
        let data = match args.get(1).map(String::as_str) {
            Some("github") => feeds::github_advisories(&client, 1, 20)?,
            Some("nvd") => feeds::nvd_recent(&client, 20, env::var("NVD_API_KEY").ok().as_deref())?,
            Some("kev") => feeds::cisa_kev(&client)?,
            Some("epss") if args.len() == 3 => feeds::epss(&client, &args[2])?,
            Some("osv") if args.len() == 5 => {
                feeds::osv_package(&client, &args[2], &args[3], &args[4])?
            }
            _ => return Err("Usage: vulnintel-cli fetch github|nvd|kev|epss CVE-ID|osv ECOSYSTEM PACKAGE VERSION".into()),
        };
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("match") && args.len() == 4 {
        let client = feeds::client()?;
        let response = feeds::osv_package(&client, &args[1], &args[2], &args[3])?;
        let evidence = match_osv_response(&args[1], &args[2], &args[3], &response);
        println!("{}", serde_json::to_string_pretty(&evidence)?);
        return Ok(());
    }
    if !args.is_empty() {
        return Err("Usage: vulnintel-cli [fetch ... | match ECOSYSTEM PACKAGE VERSION] (default: process advisory JSON on stdin)".into());
    }
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
