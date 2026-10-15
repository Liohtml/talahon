//! Analyse a raw alert read from stdin and print the prompt block and the
//! full JSON analysis: `cargo run -p talahon-intel --example analyze < alert.json`.

use std::io::Read;

use talon_intel::{analyze_alert, triage::TriageContext};

fn main() -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let alert: serde_json::Value = serde_json::from_str(&input)?;
    let analysis = analyze_alert(&alert, &TriageContext::default());
    println!("{}", analysis.to_prompt_block());
    println!("{}", serde_json::to_string_pretty(&analysis)?);
    Ok(())
}
