use std::path::Path;
use std::fs::File;
use std::io::BufReader;
use pcap_file::pcap::PcapReader;
use chrono::{DateTime, Utc};
use anyhow::Result;
use tracing::{info, debug};
use crate::PacketRecord;
use crate::security_analyzer::SecurityAnalyzer;
use crate::vector_db::{VectorDatabase, PacketLike};

#[derive(Debug)]
pub struct DatasetProcessor {
    security_analyzer: SecurityAnalyzer,
    vector_db: Option<VectorDatabase>,
}

#[derive(Debug, Clone)]
pub struct ProcessingStats {
    pub total_packets: usize,
    pub valid_packets: usize,
    pub invalid_packets: usize,
    pub total_findings: usize,
    pub processing_time_ms: u64,
    pub packets_per_second: f64,
}

#[derive(Debug, Clone)]
pub enum DatasetFormat {
    Json,
    JsonLines,
    Pcap,
    Csv,
    Parquet,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OfflinePacket {
    pub id: String,
    pub device_id: String,
    pub timestamp: DateTime<Utc>,
    pub frame_counter: Option<u32>,
    pub rssi: Option<i32>,
    pub snr: Option<f64>,
    pub spreading_factor: Option<u8>,
    pub frequency: Option<String>,
    pub gateway_count: usize,
    pub payload: Option<String>,
    pub findings: Vec<AuditFinding>,
    pub source_file: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditFinding {
    pub check: String,
    pub severity: String,
    pub details: String,
    pub recommendation: Option<String>,
}

impl PacketLike for OfflinePacket {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn get_device_id(&self) -> String {
        self.device_id.clone()
    }

    fn get_timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn get_frame_counter(&self) -> Option<u32> {
        self.frame_counter
    }

    fn get_rssi(&self) -> Option<i32> {
        self.rssi
    }

    fn get_snr(&self) -> Option<f64> {
        self.snr
    }

    fn get_spreading_factor(&self) -> Option<u8> {
        self.spreading_factor
    }

    fn get_frequency(&self) -> Option<String> {
        self.frequency.clone()
    }

    fn get_gateway_count(&self) -> usize {
        self.gateway_count
    }

    fn get_payload_size(&self) -> usize {
        self.payload.as_ref().map(|p| p.len()).unwrap_or(0)
    }

    fn get_findings_count(&self) -> usize {
        self.findings.len()
    }

    fn get_severity_score(&self) -> f32 {
        self.findings.iter().map(|f| {
            match f.severity.as_str() {
                "Critical" => 1.0,
                "High" => 0.75,
                "Medium" => 0.5,
                "Low" => 0.25,
                _ => 0.1,
            }
        }).sum::<f32>() / self.findings.len().max(1) as f32
    }

    fn get_network_features(&self) -> Vec<f32> {
        let mut features = Vec::new();

        // Frame counter feature
        features.push(self.frame_counter.unwrap_or(0) as f32 / 65536.0);

        // Signal strength features
        features.push((self.rssi.unwrap_or(-200) + 200) as f32 / 200.0);
        features.push((self.snr.unwrap_or(-20.0) + 20.0) as f32 / 40.0);

        // Spreading factor
        features.push(self.spreading_factor.unwrap_or(7) as f32 / 12.0);

        // Gateway count
        features.push(self.gateway_count as f32 / 10.0);

        // Payload size
        features.push(self.get_payload_size() as f32 / 255.0);

        // Findings features
        features.push(self.get_findings_count() as f32 / 10.0);
        features.push(self.get_severity_score());

        features
    }
}

impl PacketLike for PacketRecord {
    fn get_id(&self) -> String {
        uuid::Uuid::new_v4().to_string() // Generate a new ID since PacketRecord doesn't have one
    }

    fn get_device_id(&self) -> String {
        self.message.end_device_ids.as_ref()
            .map(|ids| ids.device_id.clone())
            .unwrap_or_default()
    }

    fn get_timestamp(&self) -> DateTime<Utc> {
        self.processed_at
    }

    fn get_frame_counter(&self) -> Option<u32> {
        self.message.uplink_message.as_ref()
            .and_then(|msg| msg.f_cnt)
    }

    fn get_rssi(&self) -> Option<i32> {
        self.message.uplink_message.as_ref()
            .and_then(|msg| msg.rx_metadata.as_ref())
            .and_then(|metadata| metadata.first())
            .and_then(|rx| rx.rssi)
    }

    fn get_snr(&self) -> Option<f64> {
        self.message.uplink_message.as_ref()
            .and_then(|msg| msg.rx_metadata.as_ref())
            .and_then(|metadata| metadata.first())
            .and_then(|rx| rx.snr)
    }

    fn get_spreading_factor(&self) -> Option<u8> {
        self.message.uplink_message.as_ref()
            .and_then(|msg| msg.settings.as_ref())
            .and_then(|settings| settings.data_rate.as_ref())
            .and_then(|dr| dr.lora.as_ref())
            .and_then(|lora| lora.spreading_factor)
    }

    fn get_frequency(&self) -> Option<String> {
        self.message.uplink_message.as_ref()
            .and_then(|msg| msg.settings.as_ref())
            .and_then(|settings| settings.frequency.clone())
    }

    fn get_gateway_count(&self) -> usize {
        self.message.uplink_message.as_ref()
            .and_then(|msg| msg.rx_metadata.as_ref())
            .map(|metadata| metadata.len())
            .unwrap_or(0)
    }

    fn get_payload_size(&self) -> usize {
        self.message.uplink_message.as_ref()
            .and_then(|msg| msg.frm_payload.as_ref())
            .map(|payload| payload.len())
            .unwrap_or(0)
    }

    fn get_findings_count(&self) -> usize {
        self.findings.len()
    }

    fn get_severity_score(&self) -> f32 {
        if self.findings.is_empty() {
            return 0.0;
        }

        let total_score: f32 = self.findings.iter().map(|f| {
            match f.severity {
                crate::Severity::Critical => 1.0,
                crate::Severity::High => 0.75,
                crate::Severity::Medium => 0.5,
                crate::Severity::Low => 0.25,
                crate::Severity::Info => 0.1,
            }
        }).sum();

        total_score / self.findings.len() as f32
    }

    fn get_network_features(&self) -> Vec<f32> {
        let mut features = Vec::new();

        // Frame counter feature
        features.push(self.get_frame_counter().unwrap_or(0) as f32 / 65536.0);

        // Signal strength features
        features.push((self.get_rssi().unwrap_or(-200) + 200) as f32 / 200.0);
        features.push((self.get_snr().unwrap_or(-20.0) + 20.0) as f32 / 40.0);

        // Spreading factor
        features.push(self.get_spreading_factor().unwrap_or(7) as f32 / 12.0);

        // Gateway count
        features.push(self.get_gateway_count() as f32 / 10.0);

        // Payload size
        features.push(self.get_payload_size() as f32 / 255.0);

        // Findings features
        features.push(self.get_findings_count() as f32 / 10.0);
        features.push(self.get_severity_score());

        features
    }
}

impl DatasetProcessor {
    pub async fn new(vector_db_url: Option<&str>) -> Result<Self> {
        Ok(Self {
            security_analyzer: SecurityAnalyzer::new(),
            vector_db: match vector_db_url {
                Some(_url) => Some(VectorDatabase::new("offline_packets").await?),
                None => None,
            },
        })
    }

    pub async fn process_pcap_file(&self, path: &Path) -> Result<Vec<PacketRecord>> {
        info!("Processing PCAP file: {}", path.display());
        let _file = File::open(path)?;
        let _pcap_reader = PcapReader::new(_file)?;
        let records = Vec::new();

        // For now, since pcap-file doesn't have next_packet, we'll use a simple approach
        // This is a placeholder - you'd need to implement proper PCAP parsing
        debug!("PCAP processing not fully implemented - returning empty results");

        info!("Processed {} packets from PCAP file", records.len());
        Ok(records)
    }

    pub async fn process_json_file(&self, path: &Path) -> Result<Vec<PacketRecord>> {
        info!("Processing JSON file: {}", path.display());
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let messages: Vec<crate::TtnMessage> = serde_json::from_reader(reader)?;
        let mut records = Vec::new();

        for message in messages {
            let record = self.process_ttn_message(message).await?;
            records.push(record);
        }

        info!("Processed {} messages from JSON file", records.len());
        Ok(records)
    }

    async fn process_packet(&self, packet: LoRaWANPacket) -> Result<PacketRecord> {
        let ttn_message = self.convert_to_ttn_message(packet);
        self.process_ttn_message(ttn_message).await
    }

    async fn process_ttn_message(&self, message: crate::TtnMessage) -> Result<PacketRecord> {
        let processed_at = Utc::now();

        // Analyze security aspects
        let findings = self.security_analyzer.analyze_message(&message);

        let record = PacketRecord {
            message,
            processed_at,
            findings,
        };

        // Store in vector database if available
        if let Some(db) = &self.vector_db {
            db.store_packet(&record).await?;
        }

        Ok(record)
    }

    fn extract_lorawan_packet(&self, _packet: &pcap_file::pcap::PcapParser) -> Option<LoRaWANPacket> {
        // Extract LoRaWAN packet from pcap packet
        // This is a placeholder - implement based on your pcap format
        None
    }

    fn convert_to_ttn_message(&self, packet: LoRaWANPacket) -> crate::TtnMessage {
        // Convert LoRaWAN packet to TTN message format
        // This is a placeholder - implement based on your needs
        crate::TtnMessage {
            end_device_ids: Some(crate::EndDeviceIds {
                device_id: packet.device_id,
                application_ids: None,
                dev_eui: None,
                join_eui: None,
            }),
            uplink_message: Some(crate::UplinkMessage {
                f_cnt: None,
                f_port: None,
                frm_payload: Some(hex::encode(packet.payload)),
                decoded_payload: None,
                rx_metadata: None,
                settings: None,
                received_at: Some(packet.timestamp.to_rfc3339()),
                consumed_airtime: None,
            }),
            received_at: Some(packet.timestamp.to_rfc3339()),
            correlation_ids: None,
        }
    }
}

#[derive(Debug)]
struct LoRaWANPacket {
    // Add fields based on your PCAP format
    device_id: String,
    payload: Vec<u8>,
    timestamp: DateTime<Utc>,
}
