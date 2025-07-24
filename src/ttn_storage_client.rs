use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use anyhow::Result;
use tracing::{info, error, warn};
use std::path::Path;
use std::fs::File;
use std::io::BufReader;
use crate::{TtnMessage, PacketRecord};

/// JSON file import client for processing TTN message storage exports.
#[derive(Debug, Clone)]
pub struct JsonFileImporter {
    // Removed HTTP client and API-related fields
}

/// Import progress tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportProgress {
    pub status: ImportStatus,
    pub total_messages: u32,
    pub processed_messages: u32,
    pub imported_messages: u32,
    pub failed_messages: u32,
    pub current_file: Option<String>,
    pub error_messages: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub estimated_completion: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImportStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// Import job configuration for JSON files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportJobConfig {
    pub file_paths: Vec<String>, // JSON file paths to import
    pub device_ids_filter: Option<Vec<String>>, // Optional device ID filter
    pub batch_size: u32,
}

impl JsonFileImporter {
    /// Create a new JSON file importer.
    pub fn new() -> Self {
        Self {}
    }

    /// Import messages from a single JSON file.
    /// The JSON file should contain an array of TtnMessage objects.
    pub async fn import_from_file(&self, file_path: &Path) -> Result<Vec<TtnMessage>> {
        info!("📂 Importing messages from JSON file: {}", file_path.display());

        let file = File::open(file_path)
            .map_err(|e| anyhow::anyhow!("Failed to open file {}: {}", file_path.display(), e))?;

        let reader = BufReader::new(file);

        // Try to parse as an array of TtnMessage objects
        let messages: Result<Vec<TtnMessage>, _> = serde_json::from_reader(reader);

        match messages {
            Ok(msgs) => {
                info!("✅ Successfully parsed {} messages from {}", msgs.len(), file_path.display());
                Ok(msgs)
            }
            Err(e) => {
                // Try to parse as a single TtnMessage object
                let file = File::open(file_path)?;
                let reader = BufReader::new(file);

                match serde_json::from_reader::<_, TtnMessage>(reader) {
                    Ok(single_message) => {
                        info!("✅ Successfully parsed single message from {}", file_path.display());
                        Ok(vec![single_message])
                    }
                    Err(_) => {
                        // Try to parse as JSONL (JSON Lines) format
                        self.parse_jsonl_file(file_path)
                    }
                }
            }
        }
    }

    /// Parse JSONL (JSON Lines) format where each line is a separate JSON object
    fn parse_jsonl_file(&self, file_path: &Path) -> Result<Vec<TtnMessage>> {
        use std::io::{BufRead, BufReader};

        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let mut messages = Vec::new();
        let mut line_number = 0;

        for line in reader.lines() {
            line_number += 1;
            let line = line?;

            if line.trim().is_empty() {
                continue; // Skip empty lines
            }

            match serde_json::from_str::<TtnMessage>(&line) {
                Ok(message) => messages.push(message),
                Err(e) => {
                    warn!("Failed to parse line {} in {}: {}", line_number, file_path.display(), e);
                }
            }
        }

        if messages.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid TTN messages found in file {}. Expected JSON array, single JSON object, or JSONL format.",
                file_path.display()
            ));
        }

        info!("✅ Successfully parsed {} messages from JSONL file {}", messages.len(), file_path.display());
        Ok(messages)
    }

    /// Import messages from multiple JSON files based on configuration
    pub async fn import_from_files(&self, config: &ImportJobConfig) -> Result<Vec<TtnMessage>> {
        let mut all_messages = Vec::new();

        for file_path_str in &config.file_paths {
            let file_path = Path::new(file_path_str);

            if !file_path.exists() {
                warn!("⚠️ File does not exist: {}", file_path.display());
                continue;
            }

            match self.import_from_file(file_path).await {
                Ok(mut messages) => {
                    // Apply device ID filter if specified
                    if let Some(ref device_filter) = config.device_ids_filter {
                        messages.retain(|msg| {
                            if let Some(ref end_device_ids) = msg.end_device_ids {
                                device_filter.contains(&end_device_ids.device_id)
                            } else {
                                false // Exclude messages without device IDs when filtering
                            }
                        });
                    }

                    info!("📦 Added {} messages from {}", messages.len(), file_path.display());
                    all_messages.extend(messages);
                }
                Err(e) => {
                    error!("❌ Failed to import from {}: {}", file_path.display(), e);
                    return Err(e);
                }
            }
        }

        info!("✅ Total imported messages: {}", all_messages.len());
        Ok(all_messages)
    }

    /// Convert TTN message to our internal format.
    pub fn convert_message_to_packet_record(
        &self,
        message: &TtnMessage,
        auditor: &crate::LoRaWanAuditor,
    ) -> Result<PacketRecord> {
        // Run security analysis on the message
        let findings = auditor.audit_packet(message);

        // Parse the timestamp. The `received_at` field is the authoritative source.
        let processed_at = match &message.received_at {
            Some(timestamp) => DateTime::parse_from_rfc3339(timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            None => Utc::now(),
        };

        Ok(PacketRecord {
            message: message.clone(),
            findings,
            processed_at,
        })
    }

    /// Validate that the JSON files exist and are readable
    pub fn validate_files(&self, file_paths: &[String]) -> Result<()> {
        for file_path_str in file_paths {
            let file_path = Path::new(file_path_str);

            if !file_path.exists() {
                return Err(anyhow::anyhow!("File does not exist: {}", file_path.display()));
            }

            if !file_path.is_file() {
                return Err(anyhow::anyhow!("Path is not a file: {}", file_path.display()));
            }

            // Try to open the file to check readability
            File::open(file_path)
                .map_err(|e| anyhow::anyhow!("Cannot read file {}: {}", file_path.display(), e))?;
        }

        info!("✅ All {} files validated successfully", file_paths.len());
        Ok(())
    }

    /// Get sample of messages from files for preview
    pub async fn preview_files(&self, file_paths: &[String], sample_size: usize) -> Result<Vec<TtnMessage>> {
        let mut sample_messages = Vec::new();

        for file_path_str in file_paths {
            let file_path = Path::new(file_path_str);

            match self.import_from_file(file_path).await {
                Ok(messages) => {
                    let take_count = std::cmp::min(sample_size, messages.len());
                    sample_messages.extend(messages.into_iter().take(take_count));

                    if sample_messages.len() >= sample_size {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Failed to preview file {}: {}", file_path.display(), e);
                }
            }
        }

        Ok(sample_messages)
    }
}

/// Utility functions for file handling
pub mod file_utils {
    use std::path::Path;
    use anyhow::Result;

    /// Check if a file has a valid JSON extension
    pub fn is_json_file(file_path: &Path) -> bool {
        match file_path.extension() {
            Some(ext) => ext == "json" || ext == "jsonl",
            None => false,
        }
    }

    /// Get file size in human-readable format
    pub fn get_file_size_human(file_path: &Path) -> Result<String> {
        let metadata = std::fs::metadata(file_path)?;
        let size = metadata.len();

        const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
        let mut size_f = size as f64;
        let mut unit_index = 0;

        while size_f >= 1024.0 && unit_index < UNITS.len() - 1 {
            size_f /= 1024.0;
            unit_index += 1;
        }

        Ok(format!("{:.1} {}", size_f, UNITS[unit_index]))
    }

    /// Validate JSON file format by attempting to parse the first few lines
    pub fn validate_json_format(file_path: &Path) -> Result<String> {
        use std::io::{BufRead, BufReader};
        use std::fs::File;

        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut first_line = String::new();
        reader.read_line(&mut first_line)?;

        if first_line.trim().starts_with('[') {
            Ok("JSON Array".to_string())
        } else if first_line.trim().starts_with('{') {
            // Check if it's JSONL by reading a second line
            let mut second_line = String::new();
            match reader.read_line(&mut second_line) {
                Ok(0) => Ok("Single JSON Object".to_string()), // No second line
                Ok(_) => {
                    if second_line.trim().starts_with('{') {
                        Ok("JSONL (JSON Lines)".to_string())
                    } else {
                        Ok("Single JSON Object".to_string())
                    }
                }
                Err(_) => Ok("Single JSON Object".to_string()),
            }
        } else {
            Err(anyhow::anyhow!("Invalid JSON format: file does not start with '[' or '{{'"))
        }
    }
}
