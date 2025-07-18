use crate::security_analyzer::SecurityAnalyzer;
use crate::TtnMessage;
use std::fs::File;
use std::io::BufReader;
use anyhow::Result;

pub async fn test_security_analysis() -> Result<()> {
    println!("Testing security analysis...");

    // Load a sample message from your test data
    let file = File::open("lorawan_dataset.json")?;
    let reader = BufReader::new(file);
    let messages: Vec<TtnMessage> = serde_json::from_reader(reader)?;

    if let Some(message) = messages.first() {
        // Create analyzer and run analysis
        let analyzer = SecurityAnalyzer::new();
        let findings = analyzer.analyze_message(message);

        println!("Security analysis completed with {} findings", findings.len());
        for finding in findings {
            println!("  - {}: {}", finding.check, finding.details);
        }
    } else {
        println!("No test messages found in dataset");
    }

    Ok(())
}
