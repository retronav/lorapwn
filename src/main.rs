mod vector_db;
mod dataset_processor;
mod security_analyzer;
mod test_db;
mod test_security;
mod test_rl;
mod rl_pipeline;

use crate::vector_db::{PacketLike, VectorDatabase, ClusteringResults, ClusteringConfig};
use uuid::Uuid;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use tower_http::services::ServeDir;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rumqttc::{AsyncClient, MqttOptions, QoS};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::mpsc,
    time::sleep,
};
use tracing::{error, info, debug};

// ==============================================================================
// 1. Enhanced Data Structures for TTN V3 Messages
// ==============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtnMessage {
    pub end_device_ids: Option<EndDeviceIds>,
    pub uplink_message: Option<UplinkMessage>,
    pub received_at: Option<String>,
    pub correlation_ids: Option<Vec<String>>,
}

impl Default for TtnMessage {
    fn default() -> Self {
        Self {
            end_device_ids: None,
            uplink_message: None,
            received_at: None,
            correlation_ids: None,
        }
    }
}

// Add packet deduplication key structure
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct PacketKey {
    device_id: String,
    frame_counter: Option<u32>,
    timestamp_minute: i64, // Rounded to minute for time-based deduplication
}

impl PacketKey {
    fn from_message(message: &TtnMessage) -> Option<Self> {
        let device_id = message.end_device_ids.as_ref()?.device_id.clone();
        let frame_counter = message.uplink_message.as_ref()?.f_cnt;

        // Use received_at timestamp, or current time if not available
        let timestamp = if let Some(received_at) = &message.received_at {
            chrono::DateTime::parse_from_rfc3339(received_at)
                .map(|dt| dt.timestamp())
                .unwrap_or_else(|_| Utc::now().timestamp())
        } else {
            Utc::now().timestamp()
        };

        // Round to minute for deduplication window
        let timestamp_minute = timestamp / 60;

        Some(PacketKey {
            device_id,
            frame_counter,
            timestamp_minute,
        })
    }
}

// Enhanced message that consolidates multiple gateway receptions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidatedTtnMessage {
    pub base_message: TtnMessage,
    pub all_rx_metadata: Vec<RxMetadata>,
    pub gateway_count: usize,
}

impl ConsolidatedTtnMessage {
    fn new(message: TtnMessage) -> Self {
        let all_rx_metadata = message.uplink_message.as_ref()
            .and_then(|msg| msg.rx_metadata.as_ref())
            .cloned()
            .unwrap_or_default();

        let gateway_count = all_rx_metadata.len();

        Self {
            base_message: message,
            all_rx_metadata,
            gateway_count,
        }
    }

    fn merge_with(&mut self, other: TtnMessage) {
        // Add gateway metadata from the other message
        if let Some(other_metadata) = other.uplink_message
            .and_then(|msg| msg.rx_metadata) {
            self.all_rx_metadata.extend(other_metadata);
        }

        self.gateway_count = self.all_rx_metadata.len();

        // Update the base message's rx_metadata with consolidated data
        if let Some(ref mut uplink) = self.base_message.uplink_message {
            uplink.rx_metadata = Some(self.all_rx_metadata.clone());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndDeviceIds {
    pub device_id: String,
    pub application_ids: Option<ApplicationIds>,
    pub dev_eui: Option<String>,
    pub join_eui: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationIds {
    pub application_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UplinkMessage {
    pub f_cnt: Option<u32>,
    pub f_port: Option<u8>,
    pub frm_payload: Option<String>,
    pub decoded_payload: Option<Value>,
    pub rx_metadata: Option<Vec<RxMetadata>>,
    pub settings: Option<DataRateSettings>,
    pub received_at: Option<String>,
    pub consumed_airtime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RxMetadata {
    pub gateway_ids: Option<GatewayIds>,
    pub rssi: Option<i32>,
    pub channel_rssi: Option<i32>,
    pub snr: Option<f64>,
    pub uplink_token: Option<String>,
    pub channel_index: Option<u32>,
    pub location: Option<Location>,
    pub time: Option<String>,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub altitude: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayIds {
    pub gateway_id: String,
    pub eui: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRateSettings {
    pub data_rate: Option<DataRate>,
    pub coding_rate: Option<String>,
    pub frequency: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRate {
    pub lora: Option<LoraSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoraSettings {
    pub bandwidth: Option<u32>,
    pub spreading_factor: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceState {
    pub device_id: String,
    pub last_fcnt: Option<u32>,
    pub last_seen: DateTime<Utc>,
    pub first_seen: DateTime<Utc>,
    pub packet_count: u64,
    pub total_findings: u64,
    pub last_gateway: Option<String>,
    pub avg_rssi: Option<f64>,
    pub last_location: Option<Location>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub check: String,
    pub severity: Severity,
    pub details: String,
    pub timestamp: DateTime<Utc>,
    pub device_id: String,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketRecord {
    pub message: TtnMessage,
    pub findings: Vec<AuditFinding>,
    pub processed_at: DateTime<Utc>,
}

impl PacketLike for PacketRecord {
    fn get_id(&self) -> String {
        // Always generate a proper UUID instead of using correlation IDs which may not be valid UUIDs
        Uuid::new_v4().to_string()
    }

    fn get_device_id(&self) -> String {
        self.message.end_device_ids.as_ref().map_or("unknown".to_string(), |ids| ids.device_id.clone())
    }

    fn get_timestamp(&self) -> DateTime<Utc> {
        self.message.received_at.as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(self.processed_at)
    }

    fn get_frame_counter(&self) -> Option<u32> {
        self.message.uplink_message.as_ref().and_then(|up| up.f_cnt)
    }

    fn get_rssi(&self) -> Option<i32> {
        self.message.uplink_message.as_ref()
            .and_then(|up| up.rx_metadata.as_ref())
            .and_then(|meta| meta.iter().filter_map(|m| m.rssi).max())
    }

    fn get_snr(&self) -> Option<f64> {
        self.message.uplink_message.as_ref()
            .and_then(|up| up.rx_metadata.as_ref())
            .and_then(|meta| {
                meta.iter()
                    .filter_map(|m| m.snr)
                    .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            })
    }

    fn get_spreading_factor(&self) -> Option<u8> {
        self.message.uplink_message.as_ref()
            .and_then(|up| up.settings.as_ref())
            .and_then(|s| s.data_rate.as_ref())
            .and_then(|dr| dr.lora.as_ref())
            .and_then(|lora| lora.spreading_factor)
    }

    fn get_frequency(&self) -> Option<String> {
        self.message.uplink_message.as_ref()
            .and_then(|up| up.settings.as_ref())
            .and_then(|s| s.frequency.clone())
    }

    fn get_gateway_count(&self) -> usize {
        self.message.uplink_message.as_ref()
            .and_then(|up| up.rx_metadata.as_ref())
            .map_or(0, |meta| meta.len())
    }

    fn get_payload_size(&self) -> usize {
        self.message.uplink_message.as_ref()
            .and_then(|up| up.frm_payload.as_ref())
            .map_or(0, |p| p.len() / 2) // Hex string, so 2 chars per byte
    }

    fn get_findings_count(&self) -> usize {
        self.findings.len()
    }

    fn get_severity_score(&self) -> f32 {
        self.findings.iter().map(|f| {
            match f.severity {
                Severity::Critical => 1.0,
                Severity::High => 0.7,
                Severity::Medium => 0.4,
                Severity::Low => 0.1,
                Severity::Info => 0.0,
            }
        }).sum()
    }

    fn get_network_features(&self) -> Vec<f32> {
        let mut features = Vec::new();
        features.push(self.get_rssi().unwrap_or(-150) as f32);
        features.push(self.get_snr().unwrap_or(0.0) as f32);
        features.push(self.get_spreading_factor().unwrap_or(0) as f32);
        features.push(self.get_gateway_count() as f32);
        features.push(self.get_payload_size() as f32);
        features
    }
}

// ==============================================================================
// 2. Enhanced TTN V3 Client with Better Error Handling
// ==============================================================================

pub struct TtnClient {
    client: AsyncClient,
    app_id: String,
    cluster: String,
}

impl TtnClient {
    pub fn new(app_id: String, access_key: String, cluster: String) -> Result<(Self, mpsc::Receiver<TtnMessage>), Box<dyn std::error::Error>> {
        let mqtt_server = format!("{}.cloud.thethings.network", cluster);
        let mqtt_user = format!("{}@ttn", app_id);
        let client_id = format!("lorawan-auditor-{}", chrono::Utc::now().timestamp());

        let mut mqttoptions = MqttOptions::new(client_id, mqtt_server, 8883);
        mqttoptions.set_credentials(mqtt_user, access_key);
        mqttoptions.set_transport(rumqttc::Transport::tls_with_default_config());
        mqttoptions.set_keep_alive(Duration::from_secs(60));
        mqttoptions.set_clean_session(true);

        let (client, mut eventloop) = AsyncClient::new(mqttoptions, 100);
        let (tx, rx) = mpsc::channel(1000);

        // Spawn task to handle MQTT events with retry logic
        let client_clone = client.clone();
        let app_id_clone = app_id.clone();

        tokio::spawn(async move {
            let mut retry_count = 0;
            let max_retries = 5;

            loop {
                match eventloop.poll().await {
                    Ok(rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish))) => {
                        retry_count = 0; // Reset retry count on successful message

                        if let Ok(payload_str) = String::from_utf8(publish.payload.to_vec()) {
                            debug!("Received payload on topic {}: {}", publish.topic, payload_str);

                            match serde_json::from_str::<TtnMessage>(&payload_str) {
                                Ok(message) => {
                                    if let Err(e) = tx.send(message).await {
                                        error!("Failed to send message to channel: {}", e);
                                    }
                                }
                                Err(e) => error!("Failed to parse TTN message: {} - Payload: {}", e, payload_str),
                            }
                        }
                    }
                    Ok(rumqttc::Event::Incoming(rumqttc::Packet::ConnAck(_))) => {
                        info!("Connected to TTN MQTT broker");
                        retry_count = 0;

                        // Subscribe to uplink topic
                        let topic = format!("v3/{}@ttn/devices/+/up", app_id_clone);
                        if let Err(e) = client_clone.subscribe(&topic, QoS::AtMostOnce).await {
                            error!("Failed to subscribe to topic {}: {}", topic, e);
                        } else {
                            info!("Subscribed to topic: {}", topic);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("MQTT error (attempt {}/{}): {}", retry_count + 1, max_retries, e);
                        retry_count += 1;

                        if retry_count >= max_retries {
                            error!("Max retries reached. Stopping MQTT client.");
                            break;
                        }

                        let delay = Duration::from_secs(2u64.pow(retry_count.min(4))); // Exponential backoff
                        sleep(delay).await;
                    }
                }
            }
        });

        Ok((Self {
            client,
            app_id,
            cluster,
        }, rx))
    }
}

// ==============================================================================
// 3. Enhanced LoRaWAN Auditing Framework
// ==============================================================================

pub struct LoRaWanAuditor {
    device_states: Arc<RwLock<HashMap<String, DeviceState>>>,
    frame_counter_gap_threshold: u32,
    weak_signal_rssi_threshold: i32,
    seen_packets: Arc<RwLock<HashMap<PacketKey, ()>>>, // Track seen packets for deduplication
}

impl LoRaWanAuditor {
    pub fn new() -> Self {
        Self {
            device_states: Arc::new(RwLock::new(HashMap::new())),
            frame_counter_gap_threshold: 10,
            weak_signal_rssi_threshold: -110,
            seen_packets: Arc::new(RwLock::new(HashMap::new())), // Initialize seen packets map
        }
    }

    pub fn audit_packet(&self, message: &TtnMessage) -> Vec<AuditFinding> {
        let mut findings = Vec::new();

        if let (Some(device_ids), Some(uplink)) = (&message.end_device_ids, &message.uplink_message) {
            let device_id = &device_ids.device_id;

            // Perform frame counter check BEFORE updating device state
            findings.extend(self.check_frame_counter(device_id, uplink));

            // Update device state AFTER checking frame counter
            self.update_device_state(device_id, uplink);

            // Perform other audits
            findings.extend(self.check_signal_strength(device_id, uplink));
            findings.extend(self.check_payload(device_id, uplink));
            findings.extend(self.check_data_rate(device_id, uplink));
            findings.extend(self.check_gateway_coverage(device_id, uplink));
        }

        findings
    }

    fn update_device_state(&self, device_id: &str, uplink: &UplinkMessage) {
        let mut states = self.device_states.write();
        let now = Utc::now();

        let state = states.entry(device_id.to_string()).or_insert(DeviceState {
            device_id: device_id.to_string(),
            last_fcnt: None,
            last_seen: now,
            first_seen: now,
            packet_count: 0,
            total_findings: 0,
            last_gateway: None,
            avg_rssi: None,
            last_location: None,
        });

        state.last_fcnt = uplink.f_cnt;
        state.last_seen = now;
        state.packet_count += 1;

        // Update gateway info
        if let Some(rx_metadata) = &uplink.rx_metadata {
            if let Some(best_gateway) = rx_metadata.iter()
                .max_by_key(|gw| gw.rssi.unwrap_or(-200)) {
                if let Some(gw_ids) = &best_gateway.gateway_ids {
                    state.last_gateway = Some(gw_ids.gateway_id.clone());
                }

                // Update average RSSI
                if let Some(rssi) = best_gateway.rssi {
                    state.avg_rssi = Some(
                        state.avg_rssi.map_or(rssi as f64, |avg| (avg + rssi as f64) / 2.0)
                    );
                }

                // Update location if available
                if let Some(location) = &best_gateway.location {
                    state.last_location = Some(location.clone());
                }
            }
        }
    }

    fn check_frame_counter(&self, device_id: &str, uplink: &UplinkMessage) -> Vec<AuditFinding> {
        let mut findings = Vec::new();

        if let Some(current_fcnt) = uplink.f_cnt {
            let states = self.device_states.read();
            if let Some(state) = states.get(device_id) {
                if let Some(last_fcnt) = state.last_fcnt {
                    let gap = current_fcnt.saturating_sub(last_fcnt);

                    if gap > self.frame_counter_gap_threshold {
                        findings.push(AuditFinding {
                            check: "Frame Counter Gap".to_string(),
                            severity: Severity::High,
                            details: format!(
                                "Large gap detected. Last: {}, Current: {} (Gap: {})",
                                last_fcnt, current_fcnt, gap
                            ),
                            timestamp: Utc::now(),
                            device_id: device_id.to_string(),
                            recommendation: Some("Check for potential packet loss or device reset".to_string()),
                        });
                    } else if current_fcnt <= last_fcnt {
                        findings.push(AuditFinding {
                            check: "Frame Counter Reset/Replay".to_string(),
                            severity: Severity::Critical,
                            details: format!(
                                "Frame counter did not increment. Last: {}, Current: {}",
                                last_fcnt, current_fcnt
                            ),
                            timestamp: Utc::now(),
                            device_id: device_id.to_string(),
                            recommendation: Some("Check device for potential reset or replay attack".to_string()),
                        });
                    }
                }
            }
        }

        findings
    }

    fn check_signal_strength(&self, device_id: &str, uplink: &UplinkMessage) -> Vec<AuditFinding> {
        let mut findings = Vec::new();

        if let Some(rx_metadata) = &uplink.rx_metadata {
            let best_rssi = rx_metadata
                .iter()
                .filter_map(|gw| gw.rssi)
                .max()
                .unwrap_or(-200);

            if best_rssi < self.weak_signal_rssi_threshold {
                findings.push(AuditFinding {
                    check: "Weak Signal".to_string(),
                    severity: Severity::Medium,
                    details: format!(
                        "Packet received with very weak signal (Best RSSI: {} dBm)",
                        best_rssi
                    ),
                    timestamp: Utc::now(),
                    device_id: device_id.to_string(),
                    recommendation: Some("Consider moving the device closer to a gateway or checking antenna".to_string()),
                });
            }
        }

        findings
    }

    fn check_payload(&self, device_id: &str, uplink: &UplinkMessage) -> Vec<AuditFinding> {
        let mut findings = Vec::new();

        if uplink.decoded_payload.is_none() || uplink.decoded_payload.as_ref().unwrap().is_null() {
            findings.push(AuditFinding {
                check: "Empty Decoded Payload".to_string(),
                severity: Severity::Low,
                details: "No decoded payload found. Ensure a payload formatter is active.".to_string(),
                timestamp: Utc::now(),
                device_id: device_id.to_string(),
                recommendation: Some("Check payload formatter configuration in TTN console".to_string()),
            });
        }

        findings
    }

    fn check_data_rate(&self, device_id: &str, uplink: &UplinkMessage) -> Vec<AuditFinding> {
        let mut findings = Vec::new();

        if let Some(settings) = &uplink.settings {
            if let Some(data_rate) = &settings.data_rate {
                if let Some(lora) = &data_rate.lora {
                    // Check for suboptimal spreading factor
                    if let Some(sf) = lora.spreading_factor {
                        if sf > 10 {
                            findings.push(AuditFinding {
                                check: "High Spreading Factor".to_string(),
                                severity: Severity::Medium,
                                details: format!(
                                    "High spreading factor detected (SF{}). This reduces data rate and increases airtime.",
                                    sf
                                ),
                                timestamp: Utc::now(),
                                device_id: device_id.to_string(),
                                recommendation: Some("Consider optimizing device placement or using ADR".to_string()),
                            });
                        }
                    }
                }
            }
        }

        findings
    }

    fn check_gateway_coverage(&self, device_id: &str, uplink: &UplinkMessage) -> Vec<AuditFinding> {
        let mut findings = Vec::new();

        if let Some(rx_metadata) = &uplink.rx_metadata {
            let gateway_count = rx_metadata.len();

            if gateway_count == 1 {
                findings.push(AuditFinding {
                    check: "Single Gateway Coverage".to_string(),
                    severity: Severity::Medium,
                    details: format!(
                        "Packet received by only one gateway ({})",
                        rx_metadata[0].gateway_ids.as_ref()
                            .map(|g| g.gateway_id.as_str())
                            .unwrap_or("unknown")
                    ),
                    timestamp: Utc::now(),
                    device_id: device_id.to_string(),
                    recommendation: Some("Consider adding more gateways in the area for redundancy".to_string()),
                });
            } else if gateway_count == 0 {
                findings.push(AuditFinding {
                    check: "No Gateway Metadata".to_string(),
                    severity: Severity::High,
                    details: "No gateway metadata found in uplink message".to_string(),
                    timestamp: Utc::now(),
                    device_id: device_id.to_string(),
                    recommendation: None,
                });
            }
        }

        findings
    }

    pub fn get_device_statistics(&self) -> HashMap<String, DeviceState> {
        self.device_states.read().clone()
    }
}

// ==============================================================================
// 4. Application State and Pipeline Manager
// ==============================================================================

#[derive(Clone)]
pub struct AppState {
    pub auditor: Arc<LoRaWanAuditor>,
    pub packets: Arc<RwLock<Vec<PacketRecord>>>,
    pub ttn_config: Arc<RwLock<Option<TtnConfig>>>,
    pub vector_db: Arc<VectorDatabase>,
    pub clustering_results: Arc<RwLock<Option<ClusteringResults>>>,
    pub clustering_config: Arc<RwLock<ClusteringConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtnConfig {
    pub app_id: String,
    pub cluster: String,
    pub is_connected: bool,
}

#[derive(Debug, Deserialize)]
pub struct ConnectRequest {
    pub app_id: String,
    pub access_key: String,
    pub cluster: String,
}

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    pub limit: Option<usize>,
    pub device_id: Option<String>,
    pub severity: Option<String>,
}

impl AppState {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            auditor: Arc::new(LoRaWanAuditor::new()),
            packets: Arc::new(RwLock::new(Vec::new())),
            ttn_config: Arc::new(RwLock::new(None)),
            vector_db: Arc::new(VectorDatabase::new("lorawan_packets").await?),
            clustering_results: Arc::new(RwLock::new(None)),
            clustering_config: Arc::new(RwLock::new(ClusteringConfig::default())),
        })
    }

    pub async fn add_packet(&self, message: TtnMessage, findings: Vec<AuditFinding>) {
        let record = PacketRecord {
            message,
            findings,
            processed_at: Utc::now(),
        };

        // Store in vector database
        if let Err(e) = self.vector_db.store_packet(&record).await {
            error!("Failed to store packet in vector DB: {}", e);
        }

        let mut packets = self.packets.write();
        packets.insert(0, record); // Insert at beginning for newest first

        // Keep only last 1000 packets to prevent memory issues
        if packets.len() > 1000 {
            packets.truncate(1000);
        }
    }

    pub fn get_packets(&self, params: &QueryParams) -> Vec<PacketRecord> {
        let packets = self.packets.read();
        let limit = params.limit.unwrap_or(100).min(1000);

        let filtered: Vec<PacketRecord> = packets
            .iter()
            .filter(|packet| {
                // Filter by device_id if specified
                if let Some(ref device_id) = params.device_id {
                    if let Some(ref end_device_ids) = packet.message.end_device_ids {
                        if &end_device_ids.device_id != device_id {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                // Filter by severity if specified
                if let Some(ref severity) = params.severity {
                    let has_severity = packet.findings.iter().any(|f| {
                        match (&f.severity, severity.as_str()) {
                            (Severity::Critical, "critical") => true,
                            (Severity::High, "high") => true,
                            (Severity::Medium, "medium") => true,
                            (Severity::Low, "low") => true,
                            _ => false,
                        }
                    });
                    if !has_severity {
                        return false;
                    }
                }

                true
            })
            .take(limit)
            .cloned()
            .collect();

        filtered
    }

    pub async fn run_clustering_analysis(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.clustering_config.read().clone();
        info!("🔍 Starting clustering analysis with config: {:?}", config);

        match self.vector_db.run_comprehensive_clustering(&config).await {
            Ok(results) => {
                info!("✅ Clustering analysis completed successfully");
                *self.clustering_results.write() = Some(results);
                Ok(())
            }
            Err(e) => {
                error!("❌ Clustering analysis failed: {}", e);
                Err(e)
            }
        }
    }

    pub fn get_clustering_results(&self) -> Option<ClusteringResults> {
        self.clustering_results.read().clone()
    }
}

// ==============================================================================
// 5. Web API Handlers
// ==============================================================================

pub async fn health_check() -> &'static str {
    "LoRaWAN Auditing Pipeline is running"
}

pub async fn dashboard() -> Html<String> {
    let html_content = fs::read_to_string("templates/dashboard.html")
        .unwrap_or_else(|_| "<h1>Error loading dashboard template</h1>".to_string());
    Html(html_content)
}

pub async fn analysis_dashboard() -> Html<String> {
    let html_content = fs::read_to_string("templates/analysis.html")
        .unwrap_or_else(|_| "<h1>Error loading analysis template</h1>".to_string());
    Html(html_content)
}

pub async fn get_packets(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
) -> Json<Vec<PacketRecord>> {
    Json(state.get_packets(&params))
}

pub async fn get_statistics(State(state): State<AppState>) -> Json<serde_json::Value> {
    let packets = state.packets.read();
    let device_states = state.auditor.get_device_statistics();

    let total_packets = packets.len();
    let total_findings: usize = packets.iter().map(|p| p.findings.len()).sum();
    let unique_devices = device_states.len();

    let severity_counts = packets
        .iter()
        .flat_map(|p| &p.findings)
        .fold(HashMap::new(), |mut acc, finding| {
            let severity = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            *acc.entry(severity.to_string()).or_insert(0) += 1;
            acc
        });

    let connection_status = state.ttn_config.read().as_ref().map(|c| c.is_connected).unwrap_or(false);

    Json(serde_json::json!({
        "total_packets": total_packets,
        "total_findings": total_findings,
        "unique_devices": unique_devices,
        "severity_counts": severity_counts,
        "connection_status": connection_status,
        "device_states": device_states
    }))
}

pub async fn connect_ttn(
    State(state): State<AppState>,
    Json(request): Json<ConnectRequest>,
) -> Result<&'static str, (StatusCode, &'static str)> {
    info!("🔗 Attempting to connect to TTN with app_id: {}", request.app_id);

    match TtnClient::new(request.app_id.clone(), request.access_key, request.cluster.clone()) {
        Ok((client, mut rx)) => {
            // Update configuration
            *state.ttn_config.write() = Some(TtnConfig {
                app_id: request.app_id.clone(),
                cluster: request.cluster.clone(),
                is_connected: true,
            });

            // Store client reference for potential disconnection
            let state_clone = state.clone();

            tokio::spawn(async move {
                info!("📡 Starting TTN message processing task");

                while let Some(message) = rx.recv().await {
                    debug!("📦 Received TTN message for device: {:?}",
                        message.end_device_ids.as_ref().map(|ids| &ids.device_id));

                    // Audit the packet
                    let findings = state_clone.auditor.audit_packet(&message);

                    // Log findings if any
                    if !findings.is_empty() {
                        info!("🚨 Found {} security findings for device: {:?}",
                            findings.len(),
                            message.end_device_ids.as_ref().map(|ids| &ids.device_id));

                        for finding in &findings {
                            match finding.severity {
                                Severity::Critical | Severity::High => {
                                    error!("🔴 {} - {}: {}", finding.severity, finding.check, finding.details);
                                }
                                Severity::Medium => {
                                    info!("🟡 {} - {}: {}", finding.severity, finding.check, finding.details);
                                }
                                _ => {
                                    debug!("🟢 {} - {}: {}", finding.severity, finding.check, finding.details);
                                }
                            }
                        }
                    }

                    // Store the packet
                    state_clone.add_packet(message, findings).await;
                }

                info!("📡 TTN message processing task ended");
            });

            info!("✅ Successfully connected to TTN");
            Ok("Successfully connected to TTN")
        }
        Err(e) => {
            error!("❌ Failed to connect to TTN: {}", e);
            Err((StatusCode::BAD_REQUEST, "Failed to connect to TTN"))
        }
    }
}

pub async fn disconnect_ttn(State(state): State<AppState>) -> &'static str {
    *state.ttn_config.write() = None;
    info!("🔌 Disconnected from TTN");
    "Disconnected from TTN"
}

pub async fn get_clustering_analysis(State(state): State<AppState>) -> Json<Value> {
    match state.get_clustering_results() {
        Some(results) => Json(serde_json::to_value(results).unwrap_or_default()),
        None => {
            // Trigger new analysis if none exists
            if let Err(e) = state.run_clustering_analysis().await {
                error!("Failed to run clustering analysis: {}", e);
            }
            Json(serde_json::json!({"status": "analysis_running", "message": "Clustering analysis started"}))
        }
    }
}

pub async fn trigger_clustering_analysis(State(state): State<AppState>) -> Json<Value> {
    match state.run_clustering_analysis().await {
        Ok(_) => Json(serde_json::json!({"status": "success", "message": "Clustering analysis completed"})),
        Err(e) => Json(serde_json::json!({"status": "error", "message": format!("Analysis failed: {}", e)})),
    }
}

pub async fn update_clustering_config(
    State(state): State<AppState>,
    Json(new_config): Json<ClusteringConfig>,
) -> Json<Value> {
    *state.clustering_config.write() = new_config;
    Json(serde_json::json!({"status": "success", "message": "Clustering configuration updated"}))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("🚀 Starting LoRaWAN Auditing Pipeline...");

    // Initialize application state
    let app_state = AppState::new().await?;

    info!("📊 Initialized application state with vector database");

    // Start background clustering task
    let clustering_state = app_state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Run every hour
        loop {
            interval.tick().await;
            if let Err(e) = clustering_state.run_clustering_analysis().await {
                error!("Background clustering analysis failed: {}", e);
            }
        }
    });

    // Build the router
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/analysis", get(analysis_dashboard))
        .route("/health", get(health_check))
        .route("/api/packets", get(get_packets))
        .route("/api/statistics", get(get_statistics))
        .route("/api/connect", post(connect_ttn))
        .route("/api/disconnect", post(disconnect_ttn))
        .route("/api/clustering-analysis", get(get_clustering_analysis))
        .route("/api/trigger-clustering", post(trigger_clustering_analysis))
        .route("/api/clustering-config", post(update_clustering_config))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(app_state);

    info!("🌐 Starting web server on http://0.0.0.0:3000");
    info!("🔗 Dashboard available at: http://localhost:3000");
    info!("📈 Analysis dashboard available at: http://localhost:3000/analysis");

    // Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
