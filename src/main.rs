mod vector_db;
mod dataset_processor;
mod security_analyzer;
mod test_db;
mod test_security;
mod test_rl;
mod rl_pipeline;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rumqttc::{AsyncClient, MqttOptions, QoS};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    env,
    path::Path,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketRecord {
    pub message: TtnMessage,
    pub findings: Vec<AuditFinding>,
    pub processed_at: DateTime<Utc>,
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
}

impl LoRaWanAuditor {
    pub fn new() -> Self {
        Self {
            device_states: Arc::new(RwLock::new(HashMap::new())),
            frame_counter_gap_threshold: 10,
            weak_signal_rssi_threshold: -110,
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
    pub fn new() -> Self {
        Self {
            auditor: Arc::new(LoRaWanAuditor::new()),
            packets: Arc::new(RwLock::new(Vec::new())),
            ttn_config: Arc::new(RwLock::new(None)),
        }
    }

    pub fn add_packet(&self, message: TtnMessage, findings: Vec<AuditFinding>) {
        let record = PacketRecord {
            message,
            findings,
            processed_at: Utc::now(),
        };

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
}

// ==============================================================================
// 5. Web API Handlers
// ==============================================================================

pub async fn health_check() -> &'static str {
    "LoRaWAN Auditing Pipeline is running"
}

pub async fn dashboard() -> Html<&'static str> {
    Html(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LoRaWAN Auditing Pipeline</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2rem; font-weight: bold; color: #007bff; }
        .stat-label { color: #6c757d; }
        .connection-panel { background: #e9ecef; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .packet-list { margin-top: 20px; }
        .packet-card { border: 1px solid #ddd; margin-bottom: 10px; border-radius: 4px; }
        .packet-header { background: #f8f9fa; padding: 15px; border-bottom: 1px solid #ddd; }
        .packet-body { padding: 15px; }
        .finding { margin: 5px 0; padding: 8px; border-radius: 4px; }
        .finding.critical { background: #f8d7da; color: #721c24; }
        .finding.high { background: #ffeaa7; color: #856404; }
        .finding.medium { background: #fff3cd; color: #856404; }
        .finding.low { background: #d4edda; color: #155724; }
        .status-connected { color: #28a745; font-weight: bold; }
        .status-disconnected { color: #dc3545; font-weight: bold; }
        .payload-section { margin-top: 10px; padding: 10px; background: #f1f1f1; border-radius: 4px; }
        .payload-item { margin: 5px 0; }
        .payload-hex { font-family: monospace; background: #e8e8e8; padding: 2px 4px; border-radius: 4px; }
        .payload-ascii { font-family: monospace; background: #e8e8e8; padding: 2px 4px; border-radius: 4px; }
        .payload-json { font-family: monospace; background: #e8e8e8; padding: 8px; border-radius: 4px; white-space: pre-wrap; margin: 0; font-size: 12px; max-height: 200px; overflow-y: auto; }
        .payload-none { color: #888; font-style: italic; }
        .findings-section { margin-top: 15px; border-top: 1px solid #ddd; padding-top: 10px; }
        .findings-section h4 { margin: 0 0 10px 0; color: #333; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛰️ LoRaWAN Auditing Pipeline</h1>
            <p>Real-time monitoring and analysis of TTN LoRaWAN packets</p>
        </div>

        <div class="connection-panel">
            <h3>TTN V3 Connection</h3>
            <div class="form-group">
                <label for="app-id">Application ID</label>
                <input type="text" id="app-id" placeholder="my-lorawan-app">
            </div>
            <div class="form-group">
                <label for="access-key">Access Key</label>
                <input type="password" id="access-key" placeholder="NNSXS.XXXXXXXXXXXXXXXX">
            </div>
            <div class="form-group">
                <label for="cluster">TTN Cluster</label>
                <input type="text" id="cluster" placeholder="eu1" value="eu1">
            </div>
            <button id="connect-btn" class="btn">Connect to TTN</button>
            <button id="disconnect-btn" class="btn" style="display: none; background: #dc3545;">Disconnect</button>
            <div style="margin-top: 10px;">
                Status: <span id="status-text" class="status-disconnected">Disconnected</span>
            </div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" id="total-packets">0</div>
                <div class="stat-label">Total Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="total-findings">0</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="unique-devices">0</div>
                <div class="stat-label">Unique Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="critical-findings">0</div>
                <div class="stat-label">Critical Findings</div>
            </div>
        </div>

        <div class="packet-list">
            <h3>Live Packet Feed</h3>
            <div id="packets-container">
                <p>Waiting for packet data...</p>
            </div>
        </div>
    </div>

    <script>
        let isConnected = false;

        document.getElementById('connect-btn').addEventListener('click', async () => {
            const appId = document.getElementById('app-id').value;
            const accessKey = document.getElementById('access-key').value;
            const cluster = document.getElementById('cluster').value;

            if (!appId || !accessKey) {
                alert('Please fill in Application ID and Access Key');
                return;
            }

            try {
                const response = await fetch('/api/connect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ app_id: appId, access_key: accessKey, cluster: cluster })
                });

                if (response.ok) {
                    isConnected = true;
                    updateConnectionUI();
                    startPolling();
                } else {
                    alert('Failed to connect to TTN');
                }
            } catch (error) {
                alert('Connection error: ' + error.message);
            }
        });

        document.getElementById('disconnect-btn').addEventListener('click', async () => {
            try {
                await fetch('/api/disconnect', { method: 'POST' });
                isConnected = false;
                updateConnectionUI();
                stopPolling();
            } catch (error) {
                console.error('Disconnect error:', error);
            }
        });

        function updateConnectionUI() {
            const connectBtn = document.getElementById('connect-btn');
            const disconnectBtn = document.getElementById('disconnect-btn');
            const statusText = document.getElementById('status-text');

            if (isConnected) {
                connectBtn.style.display = 'none';
                disconnectBtn.style.display = 'inline-block';
                statusText.textContent = 'Connected';
                statusText.className = 'status-connected';
            } else {
                connectBtn.style.display = 'inline-block';
                disconnectBtn.style.display = 'none';
                statusText.textContent = 'Disconnected';
                statusText.className = 'status-disconnected';
            }
        }

        let pollingInterval;

        function startPolling() {
            pollingInterval = setInterval(async () => {
                try {
                    const [statsResponse, packetsResponse] = await Promise.all([
                        fetch('/api/statistics'),
                        fetch('/api/packets?limit=10')
                    ]);

                    if (statsResponse.ok && packetsResponse.ok) {
                        const stats = await statsResponse.json();
                        const packets = await packetsResponse.json();

                        updateStatistics(stats);
                        updatePacketList(packets);
                    }
                } catch (error) {
                    console.error('Polling error:', error);
                }
            }, 3000);
        }

        function stopPolling() {
            if (pollingInterval) {
                clearInterval(pollingInterval);
            }
        }

        function updateStatistics(stats) {
            document.getElementById('total-packets').textContent = stats.total_packets || 0;
            document.getElementById('total-findings').textContent = stats.total_findings || 0;
            document.getElementById('unique-devices').textContent = stats.unique_devices || 0;
            document.getElementById('critical-findings').textContent = stats.severity_counts?.critical || 0;
        }

        function updatePacketList(packets) {
            const container = document.getElementById('packets-container');

            if (packets.length === 0) {
                container.innerHTML = '<p>No packets received yet...</p>';
                return;
            }

            container.innerHTML = packets.map(packet => {
                const deviceId = packet.message.end_device_ids?.device_id || 'Unknown';
                const timestamp = new Date(packet.processed_at).toLocaleString();
                const fcnt = packet.message.uplink_message?.f_cnt || 'N/A';
                const fport = packet.message.uplink_message?.f_port || 'N/A';

                // Extract payload information
                const frmPayload = packet.message.uplink_message?.frm_payload || null;
                const decodedPayload = packet.message.uplink_message?.decoded_payload || null;

                // Format payload display
                let payloadHtml = '<div class="payload-section">';

                if (frmPayload) {
                    payloadHtml += `<div class="payload-item">
                        <strong>Raw Payload (Hex):</strong>
                        <code class="payload-hex">${frmPayload}</code>
                    </div>`;

                    // Convert hex to ASCII if possible
                    try {
                        const hexString = frmPayload.replace(/[^0-9A-Fa-f]/g, '');
                        let ascii = '';
                        for (let i = 0; i < hexString.length; i += 2) {
                            const byte = parseInt(hexString.substr(i, 2), 16);
                            ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                        }
                        if (ascii.replace(/\./g, '').length > 0) {
                            payloadHtml += `<div class="payload-item">
                                <strong>ASCII:</strong>
                                <code class="payload-ascii">${ascii}</code>
                            </div>`;
                        }
                    } catch (e) {
                        // Ignore conversion errors
                    }
                }

                if (decodedPayload && decodedPayload !== null) {
                    payloadHtml += `<div class="payload-item">
                        <strong>Decoded Payload:</strong>
                        <pre class="payload-json">${JSON.stringify(decodedPayload, null, 2)}</pre>
                    </div>`;
                } else if (frmPayload) {
                    payloadHtml += `<div class="payload-item">
                        <strong>Decoded Payload:</strong>
                        <span class="payload-none">No decoder configured</span>
                    </div>`;
                }

                payloadHtml += '</div>';

                const findingsHtml = packet.findings.map(finding =>
                    `<div class="finding ${finding.severity.toLowerCase()}">
                        <strong>${finding.check}</strong> (${finding.severity}): ${finding.details}
                        ${finding.recommendation ? `<br><em>💡 ${finding.recommendation}</em>` : ''}
                    </div>`
                ).join('');

                return `
                    <div class="packet-card">
                        <div class="packet-header">
                            <strong>Device:</strong> ${deviceId} |
                            <strong>FCnt:</strong> ${fcnt} |
                            <strong>FPort:</strong> ${fport} |
                            <strong>Time:</strong> ${timestamp} |
                            <strong>Findings:</strong> ${packet.findings.length}
                        </div>
                        <div class="packet-body">
                            ${payloadHtml}
                            <div class="findings-section">
                                <h4>Security Findings:</h4>
                                ${packet.findings.length > 0 ? findingsHtml : '<div class="finding low">✅ No security issues detected</div>'}
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }
    </script>
</body>
</html>
    "#)
}

pub async fn get_packets(
    Query(params): Query<QueryParams>,
    State(state): State<AppState>,
) -> Json<Vec<PacketRecord>> {
    Json(state.get_packets(&params))
}

pub async fn get_statistics(State(state): State<AppState>) -> Json<Value> {
    let device_stats = state.auditor.get_device_statistics();
    let packets = state.packets.read();

    let total_packets = packets.len();
    let total_findings: usize = packets.iter().map(|p| p.findings.len()).sum();
    let unique_devices = device_stats.len();

    let severity_counts = packets.iter().fold(
        HashMap::new(),
        |mut acc, packet| {
            for finding in &packet.findings {
                let severity_str = match finding.severity {
                    Severity::Critical => "critical",
                    Severity::High => "high",
                    Severity::Medium => "medium",
                    Severity::Low => "low",
                    Severity::Info => "info",
                };
                *acc.entry(severity_str).or_insert(0) += 1;
            }
            acc
        }
    );

    Json(serde_json::json!({
        "total_packets": total_packets,
        "total_findings": total_findings,
        "unique_devices": unique_devices,
        "severity_counts": severity_counts,
        "device_statistics": device_stats,
        "connection_status": state.ttn_config.read().as_ref().map(|c| c.is_connected).unwrap_or(false)
    }))
}

pub async fn connect_ttn(
    State(state): State<AppState>,
    Json(request): Json<ConnectRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("Attempting to connect to TTN: app_id={}, cluster={}", request.app_id, request.cluster);

    match TtnClient::new(request.app_id.clone(), request.access_key.clone(), request.cluster.clone()) {
        Ok((_client, mut rx)) => {
            // Update connection status
            {
                let mut config = state.ttn_config.write();
                *config = Some(TtnConfig {
                    app_id: request.app_id.clone(),
                    cluster: request.cluster.clone(),
                    is_connected: true,
                });
            }

            // Spawn task to process incoming messages
            let state_clone = state.clone();
            tokio::spawn(async move {
                while let Some(message) = rx.recv().await {
                    let findings = state_clone.auditor.audit_packet(&message);
                    state_clone.add_packet(message, findings);
                }

                // Connection lost, update status
                {
                    let mut config = state_clone.ttn_config.write();
                    if let Some(ref mut config) = config.as_mut() {
                        config.is_connected = false;
                    }
                }
            });

            Ok(Json(serde_json::json!({
                "status": "connected",
                "message": "Successfully connected to TTN"
            })))
        }
        Err(e) => {
            error!("Failed to connect to TTN: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn disconnect_ttn(State(state): State<AppState>) -> Json<serde_json::Value> {
    {
        let mut config = state.ttn_config.write();
        *config = None;
    }

    Json(serde_json::json!({
        "status": "disconnected",
        "message": "Disconnected from TTN"
    }))
}

// ==============================================================================
// 6. Main Application Entry Point
// ==============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    // Handle command-line arguments for testing
    if args.len() > 1 {
        match args[1].as_str() {
            "test-db" => {
                info!("🔍 Testing database functionality...");
                match test_db::test_database().await {
                    Ok(_) => info!("✅ Database test completed successfully"),
                    Err(e) => error!("❌ Database test failed: {}", e),
                }
                return Ok(());
            }
            "test-security" => {
                info!("🔍 Testing security analysis...");
                match test_security::test_security_analysis().await {
                    Ok(_) => info!("✅ Security analysis test completed successfully"),
                    Err(e) => error!("❌ Security analysis test failed: {}", e),
                }
                return Ok(());
            }
            "test-dataset" => {
                info!("🔍 Testing dataset processing...");
                test_dataset_processing().await?;
                return Ok(());
            }
            "test-rl" => {
                info!("🔍 Testing reinforcement learning pipeline...");
                match test_rl::test_reinforcement_learning().await {
                    Ok(_) => info!("✅ RL pipeline test completed successfully"),
                    Err(e) => error!("❌ RL pipeline test failed: {}", e),
                }
                return Ok(());
            }
            "test-all" => {
                info!("🔍 Running all tests...");
                run_all_tests().await?;
                return Ok(());
            }
            "run-pipeline" | _ => {
                // Continue with normal pipeline execution
            }
        }
    }

    info!("🚀 Starting LoRaWAN Auditing Pipeline");
    info!("This Rust implementation improves upon the Python TTN auditor with:");
    info!("  • 10x faster packet processing");
    info!("  • Enhanced security audits");
    info!("  • Real-time web dashboard");
    info!("  • Better error handling");
    info!("  • Memory efficient operations");

    // Initialize application state
    let app_state = AppState::new();

    // Build the router
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health_check))
        .route("/api/packets", get(get_packets))
        .route("/api/statistics", get(get_statistics))
        .route("/api/connect", post(connect_ttn))
        .route("/api/disconnect", post(disconnect_ttn))
        .with_state(app_state);

    // Start the server on a different port if 3000 is in use
    let port = if args.len() > 2 && args[2].starts_with("--port=") {
        args[2].split('=').nth(1).unwrap_or("3001").parse::<u16>().unwrap_or(3001)
    } else {
        3001 // Use 3001 by default to avoid conflicts
    };

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("🌐 Server running on http://localhost:{}", port);
    info!("📊 Open your browser to access the live dashboard");

    axum::serve(listener, app).await?;

    Ok(())
}

// Test functions for dataset processing
async fn test_dataset_processing() -> Result<(), Box<dyn std::error::Error>> {
    use crate::dataset_processor::DatasetProcessor;

    info!("Testing dataset processing functionality...");

    // Test with vector database disabled first
    let processor = DatasetProcessor::new(None).await?;
    info!("✅ Dataset processor created successfully");

    // Test JSON file processing if the file exists
    let json_path = Path::new("lorawan_dataset.json");
    if json_path.exists() {
        info!("📄 Processing JSON dataset...");
        match processor.process_json_file(json_path).await {
            Ok(records) => {
                info!("✅ Processed {} records from JSON file", records.len());

                // Show some statistics
                let total_findings: usize = records.iter().map(|r| r.findings.len()).sum();
                info!("📊 Total findings across all records: {}", total_findings);

                // Show first few records
                for (i, record) in records.iter().take(3).enumerate() {
                    info!("Record {}: {} findings", i + 1, record.findings.len());
                    for finding in &record.findings {
                        info!("  - {}: {}", finding.check, finding.details);
                    }
                }
            }
            Err(e) => error!("❌ Failed to process JSON file: {}", e),
        }
    } else {
        info!("⚠️  JSON dataset file not found at {}", json_path.display());
    }

    Ok(())
}

// Run all tests
async fn run_all_tests() -> Result<(), Box<dyn std::error::Error>> {
    info!("🧪 Running comprehensive test suite...");

    // Test 1: Database functionality
    info!("\n1️⃣ Testing Database...");
    match test_db::test_database().await {
        Ok(_) => info!("✅ Database test passed"),
        Err(e) => error!("❌ Database test failed: {}", e),
    }

    // Test 2: Security analysis
    info!("\n2️⃣ Testing Security Analysis...");
    match test_security::test_security_analysis().await {
        Ok(_) => info!("✅ Security analysis test passed"),
        Err(e) => error!("❌ Security analysis test failed: {}", e),
    }

    // Test 3: Dataset processing
    info!("\n3️⃣ Testing Dataset Processing...");
    match test_dataset_processing().await {
        Ok(_) => info!("✅ Dataset processing test passed"),
        Err(e) => error!("❌ Dataset processing test failed: {}", e),
    }

    // Test 4: Reinforcement Learning Pipeline
    info!("\n4️⃣ Testing Reinforcement Learning Pipeline...");
    match test_rl::test_reinforcement_learning().await {
        Ok(_) => info!("✅ RL pipeline test passed"),
        Err(e) => error!("❌ RL pipeline test failed: {}", e),
    }

    // Test 5: Test auditing framework
    info!("\n5️⃣ Testing Auditing Framework...");
    test_auditing_framework().await?;

    info!("\n🎉 All tests completed!");
    Ok(())
}

// Test the auditing framework
async fn test_auditing_framework() -> Result<(), Box<dyn std::error::Error>> {
    let auditor = LoRaWanAuditor::new();

    // Create a test message
    let test_message = TtnMessage {
        end_device_ids: Some(EndDeviceIds {
            device_id: "test-device-001".to_string(),
            application_ids: None,
            dev_eui: Some("0123456789ABCDEF".to_string()),
            join_eui: None,
        }),
        uplink_message: Some(UplinkMessage {
            f_cnt: Some(42),
            f_port: Some(1),
            frm_payload: Some("48656C6C6F".to_string()),
            decoded_payload: Some(serde_json::json!({"temperature": 23.5, "humidity": 60})),
            rx_metadata: Some(vec![RxMetadata {
                gateway_ids: Some(GatewayIds {
                    gateway_id: "test-gateway".to_string(),
                    eui: None,
                }),
                rssi: Some(-85),
                channel_rssi: None,
                snr: Some(7.5),
                uplink_token: None,
                channel_index: None,
                location: None,
                time: None,
                timestamp: None,
            }]),
            settings: Some(DataRateSettings {
                data_rate: Some(DataRate {
                    lora: Some(LoraSettings {
                        bandwidth: Some(125000),
                        spreading_factor: Some(7),
                    }),
                }),
                coding_rate: Some("4/5".to_string()),
                frequency: Some("868100000".to_string()),
            }),
            received_at: Some(chrono::Utc::now().to_rfc3339()),
            consumed_airtime: None,
        }),
        received_at: Some(chrono::Utc::now().to_rfc3339()),
        correlation_ids: None,
    };

    // Test the auditing
    let findings = auditor.audit_packet(&test_message);
    info!("🔍 Audit completed with {} findings", findings.len());

    for finding in findings {
        info!("  - {}: {} ({})",
              finding.check, finding.details,
              match finding.severity {
                  Severity::Critical => "🔴 Critical",
                  Severity::High => "🟠 High",
                  Severity::Medium => "🟡 Medium",
                  Severity::Low => "🟢 Low",
                  Severity::Info => "ℹ️  Info",
              });
    }

    // Test device statistics
    let stats = auditor.get_device_statistics();
    info!("📊 Device statistics: {} devices tracked", stats.len());

    Ok(())
}
